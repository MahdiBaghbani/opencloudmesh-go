/**
 * Two-instance invite flow E2E tests.
 * A creates invite via /ui/outgoing, B imports and accepts via API.
 * Accept triggers cross-instance HTTPS call (B -> A's /ocm/invite-accepted).
 */

import { test, expect, Page } from '@playwright/test';
import {
  buildBinary,
  startTwoServers,
  stopServer,
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

test.describe('Two-Instance Invite Flow', () => {
  let serverA: ServerInstance;
  let serverB: ServerInstance;

  test.beforeEach(async () => {
    [serverA, serverB] = await startTwoServers(binaryPath, { mode: 'dev' });
  });

  test.afterEach(async () => {
    if (serverA) stopServer(serverA);
    if (serverB) stopServer(serverB);
  });

  test('A creates invite, B imports and accepts', async ({ page }) => {
    // Step 1: Login to A
    await login(page, serverA.baseURL);

    // Step 2: Create invite on A via Outgoing UI
    await page.goto(`${serverA.baseURL}/ui/outgoing`);
    await page.click('#invite-create-btn');
    await page.waitForSelector('#invite-result', { state: 'visible', timeout: 5000 });

    const inviteString = await page.locator('#invite-string').inputValue();
    expect(inviteString.length).toBeGreaterThan(0);

    // Step 3: Login to B (same page, cookies are per-origin)
    await login(page, serverB.baseURL);

    // Step 4: Import invite on B via API
    const importResponse = await page.request.post(
      `${serverB.baseURL}/api/inbox/invites/import`,
      { data: { inviteString } },
    );
    expect(importResponse.status()).toBe(201);

    const importBody = await importResponse.json();
    const inviteId: string = importBody.id;
    expect(inviteId).toBeTruthy();
    expect(importBody.status).toBe('pending');

    // Step 5: Accept invite on B via API (triggers HTTPS call to A's /ocm/invite-accepted)
    const acceptResponse = await page.request.post(
      `${serverB.baseURL}/api/inbox/invites/${inviteId}/accept`,
    );
    expect(acceptResponse.status()).toBe(200);

    const acceptBody = await acceptResponse.json();
    expect(acceptBody.status).toBe('accepted');

    // Step 6: Verify B's invite list shows accepted status
    const listResponse = await page.request.get(
      `${serverB.baseURL}/api/inbox/invites`,
    );
    expect(listResponse.status()).toBe(200);

    const listBody = await listResponse.json();
    const invite = listBody.invites.find((inv: { id: string }) => inv.id === inviteId);
    expect(invite).toBeTruthy();
    expect(invite.status).toBe('accepted');
  });
});
