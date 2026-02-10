/**
 * Two-instance share-with E2E tests.
 * API path: A sends share via POST /api/shares/outgoing, B accepts in inbox.
 * UI path: A sends share via /ui/outgoing form, B accepts in inbox.
 */

import { test, expect, Page } from '@playwright/test';
import { basename } from 'path';
import { rmSync } from 'fs';
import {
  buildBinary,
  startTwoServers,
  stopServer,
  createShareableFile,
  ServerInstance,
} from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

async function login(page: Page, baseURL: string) {
  await page.goto(`${baseURL}/ui/login`);
  await page.fill('#username', 'admin');
  await page.fill('#password', 'testpassword123');
  await page.click('#submit-btn');
  await page.waitForURL('**/ui/inbox', { timeout: 5000 });
}

/**
 * Asserts that a server's discovery endpoint advertises strict signature support.
 */
async function assertStrictDiscovery(page: Page, baseURL: string) {
  const res = await page.request.get(`${baseURL}/.well-known/ocm`);
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.capabilities).toContain('http-sig');
  expect(body.criteria).toContain('http-request-signatures');
}

test.describe('Two-Instance Share With (API)', () => {
  let serverA: ServerInstance;
  let serverB: ServerInstance;
  let shareFilePath: string;

  test.beforeEach(async () => {
    [serverA, serverB] = await startTwoServers(binaryPath, { mode: 'strict' });
    shareFilePath = createShareableFile();
  });

  test.afterEach(async () => {
    if (serverA) stopServer(serverA);
    if (serverB) stopServer(serverB);
    if (shareFilePath) rmSync(shareFilePath, { force: true });
  });

  test('A sends share to B, B accepts via inbox', async ({ page }) => {
    // Verify both servers advertise strict signature support
    await assertStrictDiscovery(page, serverA.baseURL);
    await assertStrictDiscovery(page, serverB.baseURL);

    // Login to server A
    await login(page, serverA.baseURL);

    // Send outgoing share from A to B via API
    const shareResponse = await page.request.post(
      `${serverA.baseURL}/api/shares/outgoing`,
      {
        data: {
          receiverDomain: `localhost:${serverB.port}`,
          shareWith: `admin@localhost:${serverB.port}`,
          localPath: shareFilePath,
          permissions: ['read'],
        },
      },
    );
    expect(shareResponse.status()).toBe(201);

    const shareBody = await shareResponse.json();
    expect(shareBody.status).toBe('sent');

    // Login to server B (same page -- cookies are per-origin).
    // login() already lands on /ui/inbox, so no extra navigation needed.
    await login(page, serverB.baseURL);

    // Wait for the share to appear
    await page.waitForSelector('.share-item', { timeout: 10000 });

    // Verify the share name matches the file basename
    const expectedName = basename(shareFilePath);
    await expect(page.locator('.share-name')).toContainText(expectedName);
    await expect(page.locator('.share-status')).toContainText('pending');

    // Accept the share
    await page.click('.btn-accept');

    // Wait for accepted status
    await page.waitForSelector('.status-accepted', { timeout: 5000 });
    await expect(page.locator('.share-status')).toContainText('accepted');
  });
});

test.describe('Two-Instance Share With (UI)', () => {
  let serverA: ServerInstance;
  let serverB: ServerInstance;
  let shareFilePath: string;

  test.beforeEach(async () => {
    [serverA, serverB] = await startTwoServers(binaryPath, { mode: 'strict' });
    shareFilePath = createShareableFile();
  });

  test.afterEach(async () => {
    if (serverA) stopServer(serverA);
    if (serverB) stopServer(serverB);
    if (shareFilePath) rmSync(shareFilePath, { force: true });
  });

  test('A sends share via Outgoing UI, B accepts via inbox', async ({ page }) => {
    // Verify both servers advertise strict signature support
    await assertStrictDiscovery(page, serverA.baseURL);
    await assertStrictDiscovery(page, serverB.baseURL);

    // Login to server A
    await login(page, serverA.baseURL);

    // Navigate to A's outgoing UI
    await page.goto(`${serverA.baseURL}/ui/outgoing`);
    await page.waitForSelector('#outgoing-share-form');

    // Fill the share form
    await page.fill('#share-with', `admin@localhost:${serverB.port}`);
    await page.fill('#local-path', shareFilePath);

    // Submit the form
    await page.click('#share-submit');

    // Wait for success message
    await page.waitForSelector('#share-result', { state: 'visible', timeout: 10000 });
    await expect(page.locator('#share-result')).toContainText('Share sent successfully');

    // Login to server B (same page -- cookies are per-origin).
    // login() lands on /ui/inbox, so the share should appear there.
    await login(page, serverB.baseURL);

    // Wait for the share to appear
    await page.waitForSelector('.share-item', { timeout: 10000 });

    // Verify the share name matches the file basename
    const expectedName = basename(shareFilePath);
    await expect(page.locator('.share-name')).toContainText(expectedName);
    await expect(page.locator('.share-status')).toContainText('pending');

    // Accept the share
    await page.click('.btn-accept');

    // Wait for accepted status
    await page.waitForSelector('.status-accepted', { timeout: 5000 });
    await expect(page.locator('.share-status')).toContainText('accepted');
  });
});
