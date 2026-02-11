/**
 * Inbox UI development tests (single-server, seeded data).
 * Verifies Phase 5 UI elements: data attributes, protocol details toggle,
 * verify-access error display, and invite attributes.
 * No two-server overhead -- share seeded via direct POST to /ocm/shares.
 */

import { test, expect } from '@playwright/test';
import {
  buildBinary,
  startServer,
  stopServer,
  ServerInstance,
} from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Inbox UI', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'inbox-ui-test', mode: 'dev' });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  async function loginAndNavigateToInbox(page: import('@playwright/test').Page) {
    await page.goto(`${server.baseURL}/ui/login`);
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });
  }

  /**
   * Seeds a test share via the server-to-server /ocm/shares endpoint.
   * shareWith provider part must match the server's public_origin host:port.
   */
  async function createTestShare(request: import('@playwright/test').APIRequestContext) {
    const serverURL = new URL(server.baseURL);
    const provider = serverURL.host;

    const response = await request.post(`${server.baseURL}/ocm/shares`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        shareWith: `admin@${provider}`,
        name: 'ui-test-file.txt',
        providerId: `ui-test-provider-${Date.now()}`,
        owner: 'testowner@fake-sender.example.com',
        sender: 'testsender@fake-sender.example.com',
        shareType: 'user',
        resourceType: 'file',
        protocol: {
          name: 'webdav',
          webdav: {
            uri: 'ui-test-webdav-id',
            sharedSecret: 'test-secret-123',
            permissions: ['read'],
          },
        },
      },
    });

    expect(response.status()).toBe(201);
    return response;
  }

  test('existing selectors: share-item, share-name, share-status', async ({ page, request }) => {
    await createTestShare(request);
    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    await expect(page.locator('.share-item')).toHaveCount(1);
    await expect(page.locator('.share-name')).toContainText('ui-test-file.txt');
    await expect(page.locator('.share-status')).toContainText('pending');
    await expect(page.locator('.share-item')).toHaveAttribute('data-share-id', /.+/);
  });

  test('accepted share gets data-test-resource-name attribute', async ({ page, request }) => {
    await createTestShare(request);
    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Before accept: no data-test-resource-name
    await expect(page.locator('.share-item')).not.toHaveAttribute('data-test-resource-name', /.*/);

    await page.click('.btn-accept');
    await page.waitForSelector('.status-accepted', { timeout: 5000 });

    await expect(page.locator('.share-item')).toHaveAttribute(
      'data-test-resource-name',
      'ui-test-file.txt',
    );
    // Accept/decline buttons gone after accepting
    await expect(page.locator('.btn-accept')).toHaveCount(0);
    await expect(page.locator('.btn-decline')).toHaveCount(0);
  });

  test('protocol details toggle shows and hides details with redacted secret', async ({
    page,
    request,
  }) => {
    await createTestShare(request);
    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    const toggleBtn = page.locator('[data-ocm-action="toggle-protocol-details"]');
    const detailsContainer = page.locator('[data-ocm-field="protocol-details"]');

    // Initially hidden
    await expect(detailsContainer).toBeHidden();

    // Click to show
    await toggleBtn.click();
    await expect(detailsContainer).toBeVisible();

    // Wait for the lazy fetch to complete (replaces "Loading...")
    await expect(detailsContainer.locator('.protocol-json')).not.toContainText('Loading...');

    // Secret is masked
    await expect(detailsContainer).toContainText('[REDACTED]');
    // Protocol name present
    await expect(detailsContainer).toContainText('webdav');

    // Click again to hide
    await toggleBtn.click();
    await expect(detailsContainer).toBeHidden();
  });

  test('verify-access displays error for unreachable remote', async ({ page, request }) => {
    await createTestShare(request);
    await loginAndNavigateToInbox(page);
    await page.waitForSelector('.share-item', { timeout: 5000 });

    // Must accept first (verify-access requires accepted status)
    await page.click('.btn-accept');
    await page.waitForSelector('.status-accepted', { timeout: 5000 });

    const verifyBtn = page.locator('[data-ocm-action="verify-access"]');
    const verifyResult = page.locator('[data-ocm-field="verify-access-result"]');

    // Initially hidden
    await expect(verifyResult).toBeHidden();

    // Click verify (will fail -- no real remote WebDAV server)
    await verifyBtn.click();

    // Wait for result (access client tries outbound calls that will fail; generous timeout)
    await expect(verifyResult).toBeVisible({ timeout: 15000 });

    // Should show error styling and a reason code
    await expect(verifyResult).toHaveClass(/error/);
    // The result text includes the reason code in parentheses
    const resultText = await verifyResult.textContent();
    expect(resultText).toBeTruthy();
    expect(resultText).toContain('Failed');
  });

  test('invite data-test-invite-sender on accepted invite', async ({ page }) => {
    // Create invite on this server, import and accept on the same server.
    // Acceptance triggers a self-referential /ocm/invite-accepted call which
    // works in dev mode (SSRF off, same TLS CA).
    // Uses page.request (not the standalone request fixture) so session cookies
    // are shared with the logged-in page context.

    await loginAndNavigateToInbox(page);

    // Step 1: create invite via outgoing UI
    await page.goto(`${server.baseURL}/ui/outgoing`);
    await page.click('#invite-create-btn');
    await page.waitForSelector('#invite-result', { state: 'visible', timeout: 5000 });
    const inviteString = await page.locator('#invite-string').inputValue();
    expect(inviteString.length).toBeGreaterThan(0);

    // Step 2: import invite on the same server via API (authenticated)
    const importResponse = await page.request.post(
      `${server.baseURL}/api/inbox/invites/import`,
      { data: { inviteString } },
    );
    expect(importResponse.status()).toBe(201);
    const importBody = await importResponse.json();
    const inviteId: string = importBody.id;
    expect(inviteId).toBeTruthy();

    // Step 3: accept invite via API (self-referential callback to /ocm/invite-accepted)
    const acceptResponse = await page.request.post(
      `${server.baseURL}/api/inbox/invites/${inviteId}/accept`,
    );
    expect(acceptResponse.status()).toBe(200);

    // Step 4: navigate to inbox and check invite attributes
    await page.goto(`${server.baseURL}/ui/inbox`);
    await page.waitForSelector('.invite-item', { timeout: 5000 });

    const inviteItem = page.locator('.invite-item');
    await expect(inviteItem).toHaveAttribute('data-test-invite-sender', /.+/);

    // Invite shows as accepted
    await expect(inviteItem.locator('.share-status')).toContainText('accepted');
  });
});
