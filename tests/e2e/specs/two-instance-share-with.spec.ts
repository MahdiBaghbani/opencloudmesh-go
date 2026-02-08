/**
 * Two-instance share-with E2E test.
 * A sends an outgoing share to B via the API; B accepts it in the inbox UI.
 */

import { test, expect } from '@playwright/test';
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

test.describe('Two-Instance Share With (API)', () => {
  let serverA: ServerInstance;
  let serverB: ServerInstance;
  let shareFilePath: string;

  test.beforeEach(async () => {
    [serverA, serverB] = await startTwoServers(binaryPath, { mode: 'dev' });
    shareFilePath = createShareableFile();
  });

  test.afterEach(async () => {
    if (serverA) stopServer(serverA);
    if (serverB) stopServer(serverB);
    if (shareFilePath) rmSync(shareFilePath, { force: true });
  });

  async function login(page: import('@playwright/test').Page, baseURL: string) {
    await page.goto(`${baseURL}/ui/login`);
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });
  }

  test('A sends share to B, B accepts via inbox', async ({ page }) => {
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
