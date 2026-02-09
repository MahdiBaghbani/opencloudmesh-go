/**
 * WAYF (Where Are You From) and accept-invite page E2E tests.
 * Single-instance with WAYF enabled. Tests page load, element visibility,
 * session gating on accept-invite, and post-login display of token/provider.
 */

import { test, expect, Page } from '@playwright/test';
import { buildBinary, startServer, stopServer, ServerInstance } from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('WAYF and Accept Invite', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, {
      name: 'wayf-test',
      mode: 'dev',
      extraConfig: '[http.services.ui.wayf]\nenabled = true\n',
    });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  async function login(page: Page) {
    await page.goto(`${server.baseURL}/ui/login`);
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });
  }

  async function createInviteToken(page: Page): Promise<string> {
    const response = await page.request.post(
      `${server.baseURL}/api/invites/outgoing`,
    );
    expect(response.status()).toBe(201);
    const body = await response.json();
    expect(body.token).toBeTruthy();
    return body.token as string;
  }

  test('WAYF page loads with heading and manual discovery input', async ({ page }) => {
    await login(page);
    const token = await createInviteToken(page);

    await page.goto(`${server.baseURL}/ui/wayf?token=${token}`);

    // Subtitle/heading is visible
    const subtitle = page.locator('.subtitle');
    await expect(subtitle).toBeVisible();
    await expect(subtitle).toContainText('Select your home provider');

    // Manual discovery input and button are visible
    await expect(page.locator('#manual-url')).toBeVisible();
    await expect(page.locator('#discover-btn')).toBeVisible();

    // Providers container exists (empty state because no trust groups configured)
    const providersContainer = page.locator('#providers-container');
    await expect(providersContainer).toBeVisible();
    await expect(providersContainer).toContainText('No federation providers configured');

    // No-token warning should NOT be visible (we have a valid token)
    await expect(page.locator('#no-token-warning')).not.toBeVisible();
  });

  test('WAYF page shows warning when no token provided', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/wayf`);

    await expect(page.locator('#no-token-warning')).toBeVisible();
    await expect(page.locator('#no-token-warning')).toContainText('No invite token found');
  });

  test('accept-invite redirects to login when unauthenticated', async ({ page }) => {
    await login(page);
    const token = await createInviteToken(page);

    // Clear session by navigating with a fresh context approach:
    // delete the session cookie so the next request is unauthenticated
    await page.context().clearCookies();

    await page.goto(
      `${server.baseURL}/ui/accept-invite?token=${token}&providerDomain=localhost:${server.port}`,
    );

    // Auth middleware redirects GET /ui/accept-invite to /ui/login?redirect=...
    await page.waitForURL('**/ui/login**', { timeout: 5000 });
    expect(page.url()).toContain('/ui/login');
    expect(page.url()).toContain('redirect=');
  });

  test('accept-invite loads after login with token and provider info', async ({ page }) => {
    await login(page);
    const token = await createInviteToken(page);

    await page.goto(
      `${server.baseURL}/ui/accept-invite?token=${token}&providerDomain=localhost:${server.port}`,
    );

    // Form is visible with token and provider info
    await expect(page.locator('#invite-form')).toBeVisible();
    await expect(page.locator('#display-token')).toContainText(token);
    await expect(page.locator('#display-provider')).toContainText(`localhost:${server.port}`);

    // Accept button is visible
    await expect(page.locator('#accept-btn')).toBeVisible();
    await expect(page.locator('#accept-btn')).toContainText('Accept Invite');

    // Missing-params message should NOT be visible
    await expect(page.locator('#missing-params')).not.toBeVisible();
  });
});
