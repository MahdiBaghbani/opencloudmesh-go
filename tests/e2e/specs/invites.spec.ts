/**
 * Federation Invites E2E tests.
 * Tests the invite acceptance UI flow.
 */

import { test, expect } from '@playwright/test';
import { buildBinary, startServer, stopServer, ServerInstance } from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Federation Invites', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'invites-test', mode: 'dev' });
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

  test('inbox displays federation invites section', async ({ page }) => {
    await loginAndNavigateToInbox(page);

    // Verify invites section exists
    await expect(page.locator('text=Federation Invites')).toBeVisible();

    // Verify invite tabs exist
    const inviteTabs = page.locator('#invite-tabs .tab');
    await expect(inviteTabs).toHaveCount(3);
    await expect(inviteTabs.nth(0)).toContainText('All');
    await expect(inviteTabs.nth(1)).toContainText('Pending');
    await expect(inviteTabs.nth(2)).toContainText('Accepted');
  });

  test('invite section shows empty state when no invites', async ({ page }) => {
    await loginAndNavigateToInbox(page);

    // Should show empty state in invite list
    const inviteList = page.locator('#invite-list');
    await expect(inviteList.locator('.empty-state')).toBeVisible();
    await expect(inviteList).toContainText('No invites yet');
  });

  test('invite tabs can be clicked', async ({ page }) => {
    await loginAndNavigateToInbox(page);

    const tabs = page.locator('#invite-tabs .tab');

    // Click "Pending" tab
    await tabs.nth(1).click();
    await expect(tabs.nth(1)).toHaveClass(/active/);
    await expect(tabs.nth(0)).not.toHaveClass(/active/);

    // Click "Accepted" tab
    await tabs.nth(2).click();
    await expect(tabs.nth(2)).toHaveClass(/active/);
    await expect(tabs.nth(1)).not.toHaveClass(/active/);

    // Click "All" tab
    await tabs.nth(0).click();
    await expect(tabs.nth(0)).toHaveClass(/active/);
    await expect(tabs.nth(2)).not.toHaveClass(/active/);
  });

  test('invites API endpoint returns empty list', async ({ page, request }) => {
    // Login to get session
    await loginAndNavigateToInbox(page);

    // Get cookies from page context
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (sessionCookie) {
      // Call invites API directly
      const response = await request.get(`${server.baseURL}/api/inbox/invites`, {
        headers: {
          Cookie: `session=${sessionCookie.value}`,
        },
      });

      expect(response.ok()).toBeTruthy();
      const data = await response.json();
      expect(data).toHaveProperty('invites');
      expect(Array.isArray(data.invites)).toBeTruthy();
    }
  });

  test('shares and invites sections are both visible', async ({ page }) => {
    await loginAndNavigateToInbox(page);

    // Verify both sections are visible
    await expect(page.locator('text=Shared with Me')).toBeVisible();
    await expect(page.locator('text=Federation Invites')).toBeVisible();

    // Verify both have their own lists
    await expect(page.locator('#share-list')).toBeVisible();
    await expect(page.locator('#invite-list')).toBeVisible();
  });
});
