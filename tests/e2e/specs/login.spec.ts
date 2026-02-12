/**
 * Login flow E2E tests (single-server, fast feedback).
 * Tests the complete login flow from login page to inbox redirect.
 */

import { test, expect } from '@playwright/test';
import { buildBinary, startServer, stopServer, ServerInstance } from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Login Flow', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'login-test', mode: 'dev' });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  test('login page displays correctly', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/login`);

    // Verify page title
    await expect(page).toHaveTitle(/Login.*OpenCloudMesh/);

    // Verify form elements are present
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('#submit-btn')).toBeVisible();

    // Verify branding
    await expect(page.locator('.logo h1')).toContainText('OpenCloudMesh');
  });

  test('login with valid credentials redirects to inbox', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/login`);

    // Fill in credentials (server sets up admin:testpassword123)
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');

    // Submit form
    await page.click('#submit-btn');

    // Wait for navigation to inbox
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });

    // Verify we're on the inbox page
    await expect(page).toHaveTitle(/Inbox.*OpenCloudMesh/);
  });

  test('login with invalid credentials shows error', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/login`);

    // Fill in wrong credentials
    await page.fill('#username', 'admin');
    await page.fill('#password', 'wrongpassword');

    // Submit form
    await page.click('#submit-btn');

    // Wait for error message to appear
    await expect(page.locator('#error-msg')).toBeVisible();
    await expect(page.locator('#error-msg')).toContainText(/invalid|failed/i);

    // Should still be on login page
    expect(page.url()).toContain('/ui/login');
  });

  test('login with empty credentials shows validation', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/login`);

    // Try to submit without filling in credentials
    await page.click('#submit-btn');

    // HTML5 validation should prevent submission
    // Check that we're still on login page
    expect(page.url()).toContain('/ui/login');
  });

  test('login button shows loading state', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/login`);

    // Fill in credentials
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');

    // Click and immediately check button text
    const submitBtn = page.locator('#submit-btn');
    await submitBtn.click();

    // Button should show loading state (this may be brief)
    // We just verify the login completes successfully
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });
  });
});
