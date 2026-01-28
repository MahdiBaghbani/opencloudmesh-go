/**
 * Accept incoming share E2E tests.
 * Tests accepting and declining shares via the inbox UI.
 */

import { test, expect } from '@playwright/test';
import { buildBinary, startServer, stopServer, ServerInstance } from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Accept Share Flow', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'accept-test', mode: 'dev' });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  /**
   * Helper to login and navigate to inbox.
   */
  async function loginAndNavigateToInbox(page: import('@playwright/test').Page) {
    await page.goto(`${server.baseURL}/ui/login`);
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });
  }

  /**
   * Helper to create a test share via API.
   * This simulates receiving a share from another server.
   * shareWith provider part must match the server's public_origin host:port.
   */
  async function createTestShare(request: import('@playwright/test').APIRequestContext, options: {
    name: string;
    sender?: string;
    status?: string;
  }) {
    // Derive provider from the running server's base URL so the shareWith
    // provider part matches the public_origin host:port used for provider matching.
    const serverURL = new URL(server.baseURL);
    const provider = serverURL.host; // includes port when non-default

    // The /ocm/shares endpoint accepts incoming shares from other servers
    const sharePayload = {
      shareWith: `admin@${provider}`,
      name: options.name,
      providerId: `provider-${Date.now()}`,
      owner: options.sender || 'sender@remote.example.com',
      sender: options.sender || 'sender@remote.example.com',
      shareType: 'user',
      resourceType: 'file',
      protocol: {
        name: 'webdav',
        webdav: {
          uri: `https://remote.example.com/webdav/${Date.now()}`,
          sharedSecret: `secret-${Date.now()}`,
          permissions: ['read'],
        },
      },
    };

    const response = await request.post(`${server.baseURL}/ocm/shares`, {
      headers: { 'Content-Type': 'application/json' },
      data: sharePayload,
    });

    return response;
  }

  test('inbox loads shares from API', async ({ page, request }) => {
    // Create a test share first
    await createTestShare(request, { name: 'Test Document.pdf' });

    await loginAndNavigateToInbox(page);

    // Wait for shares to load
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Verify share is displayed
    await expect(page.locator('.share-item')).toHaveCount(1);
    await expect(page.locator('.share-name')).toContainText('Test Document.pdf');
    await expect(page.locator('.share-status')).toContainText('pending');
  });

  test('pending share shows accept and decline buttons', async ({ page, request }) => {
    await createTestShare(request, { name: 'Shared File.docx' });

    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Verify action buttons are present
    await expect(page.locator('.btn-accept')).toBeVisible();
    await expect(page.locator('.btn-decline')).toBeVisible();
  });

  test('clicking accept changes share status', async ({ page, request }) => {
    await createTestShare(request, { name: 'Accept Me.txt' });

    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Click accept
    await page.click('.btn-accept');

    // Wait for status to change
    await page.waitForSelector('.status-accepted', { timeout: 5000 });

    // Verify status changed
    await expect(page.locator('.share-status')).toContainText('accepted');

    // Action buttons should be gone for accepted share
    await expect(page.locator('.btn-accept')).toHaveCount(0);
    await expect(page.locator('.btn-decline')).toHaveCount(0);
  });

  test('clicking decline changes share status', async ({ page, request }) => {
    await createTestShare(request, { name: 'Decline Me.txt' });

    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Click decline
    await page.click('.btn-decline');

    // Wait for status to change
    await page.waitForSelector('.status-declined', { timeout: 5000 });

    // Verify status changed
    await expect(page.locator('.share-status')).toContainText('declined');
  });

  test('tab filter shows only pending shares', async ({ page, request }) => {
    // Create multiple shares
    await createTestShare(request, { name: 'Pending Share.pdf' });
    await createTestShare(request, { name: 'Also Pending.pdf' });

    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Accept one share via UI
    await page.locator('.btn-accept').first().click();
    await page.waitForSelector('.status-accepted', { timeout: 5000 });

    // Click Pending tab
    await page.click('.tab[data-filter="pending"]');

    // Should show only pending shares
    await expect(page.locator('.status-pending')).toBeVisible();
    // Should NOT show accepted shares
    await expect(page.locator('.status-accepted')).toHaveCount(0);
  });

  test('tab filter shows only accepted shares', async ({ page, request }) => {
    // Create a share
    await createTestShare(request, { name: 'To Be Accepted.pdf' });

    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Accept via UI
    await page.click('.btn-accept');
    await page.waitForSelector('.status-accepted', { timeout: 5000 });

    // Click Accepted tab
    await page.click('.tab[data-filter="accepted"]');

    // Should show only accepted shares
    await expect(page.locator('.status-accepted')).toBeVisible();
    await expect(page.locator('.status-pending')).toHaveCount(0);
  });

  test('empty state shows when no shares match filter', async ({ page }) => {
    await loginAndNavigateToInbox(page);

    // With no shares, should show empty state in the share list
    const shareList = page.locator('#share-list');
    await expect(shareList.locator('.empty-state')).toBeVisible();
    await expect(shareList).toContainText('No shares yet');
  });

  test('multiple shares can be managed', async ({ page, request }) => {
    // Create multiple shares
    await createTestShare(request, { name: 'File 1.txt' });
    await createTestShare(request, { name: 'File 2.txt' });
    await createTestShare(request, { name: 'File 3.txt' });

    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Should show all 3 shares
    await expect(page.locator('.share-item')).toHaveCount(3);

    // Accept the first one
    await page.locator('.btn-accept').first().click();
    await page.waitForSelector('.status-accepted', { timeout: 5000 });

    // Now we should have 1 accepted and 2 pending
    await expect(page.locator('.status-accepted')).toHaveCount(1);
    await expect(page.locator('.status-pending')).toHaveCount(2);
  });
});
