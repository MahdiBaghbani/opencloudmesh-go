// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * WAYF (Where Are You From) and accept-invite page E2E tests.
 * Single-instance with WAYF enabled. Covers public WAYF, token query param,
 * local providerDomain, manual /ocm-aux/discover redirect to inviteAcceptDialog,
 * protected accept-invite with login round trip, and session-authenticated accept.
 */

import { test, expect, Page } from '@playwright/test';
import { buildBinary, startServer, stopServer, ServerInstance } from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

/**
 * Parses an invite string (base64 of "token@providerDomain") into its parts.
 * Split on the last '@' because tokens may contain '@'.
 */
function parseInviteString(inviteString: string): { token: string; providerDomain: string } {
  const decoded = Buffer.from(inviteString, 'base64').toString();
  const lastAt = decoded.lastIndexOf('@');
  if (lastAt === -1) {
    throw new Error(`Invalid invite string: no '@' found in decoded value`);
  }
  return {
    token: decoded.substring(0, lastAt),
    providerDomain: decoded.substring(lastAt + 1),
  };
}

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

  async function createInviteTokenViaUI(page: Page): Promise<string> {
    await page.goto(`${server.baseURL}/ui/outgoing`);
    await page.click('#invite-create-btn');
    await page.waitForSelector('#invite-result', { state: 'visible', timeout: 5000 });
    const inviteString = await page.locator('#invite-string').inputValue();
    expect(inviteString.length).toBeGreaterThan(0);
    return inviteString;
  }

  test('WAYF page loads with heading and manual discovery input', async ({ page }) => {
    await login(page);
    const inviteString = await createInviteTokenViaUI(page);
    const { token } = parseInviteString(inviteString);

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

  test('WAYF page is public without session when WAYF enabled', async ({ page }) => {
    await page.context().clearCookies();

    await page.goto(`${server.baseURL}/ui/wayf?token=public-wayf-token`);

    await expect(page).toHaveURL(/\/ui\/wayf/);
    await expect(page.locator('.subtitle')).toBeVisible();
    await expect(page.locator('.subtitle')).toContainText('Select your home provider');
    await expect(page.locator('#no-token-warning')).not.toBeVisible();
  });

  test('accept-invite redirects to login when unauthenticated', async ({ page }) => {
    await login(page);
    const inviteString = await createInviteTokenViaUI(page);
    const { token, providerDomain } = parseInviteString(inviteString);

    // Clear session by deleting the session cookie
    await page.context().clearCookies();

    await page.goto(
      `${server.baseURL}/ui/accept-invite?token=${token}&providerDomain=${providerDomain}`,
    );

    // Auth middleware redirects GET /ui/accept-invite to /ui/login?redirect=...
    await page.waitForURL('**/ui/login**', { timeout: 5000 });
    expect(page.url()).toContain('/ui/login');
    expect(page.url()).toContain('redirect=');
  });

  test('accept-invite login redirect round trip preserves query and lands on accept page', async ({
    page,
  }) => {
    await login(page);
    const inviteString = await createInviteTokenViaUI(page);
    const { token, providerDomain } = parseInviteString(inviteString);

    await page.context().clearCookies();

    const acceptPath =
      `/ui/accept-invite?token=${encodeURIComponent(token)}` +
      `&providerDomain=${encodeURIComponent(providerDomain)}`;
    await page.goto(`${server.baseURL}${acceptPath}`);

    await page.waitForURL('**/ui/login**', { timeout: 5000 });
    const loginURL = new URL(page.url());
    expect(loginURL.pathname).toBe('/ui/login');

    const redirectParam = loginURL.searchParams.get('redirect');
    expect(redirectParam).toBeTruthy();
    const redirectURL = new URL(redirectParam!, server.baseURL);
    expect(redirectURL.pathname).toBe('/ui/accept-invite');
    expect(redirectURL.searchParams.get('token')).toBe(token);
    expect(redirectURL.searchParams.get('providerDomain')).toBe(providerDomain);

    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');

    await page.waitForURL('**/ui/accept-invite**', { timeout: 5000 });
    const landedURL = new URL(page.url());
    expect(landedURL.pathname).toBe('/ui/accept-invite');
    expect(landedURL.searchParams.get('token')).toBe(token);
    expect(landedURL.searchParams.get('providerDomain')).toBe(providerDomain);

    await expect(page.locator('#invite-form')).toBeVisible();
    await expect(page.locator('#display-token')).toContainText(token);
    await expect(page.locator('#display-provider')).toContainText(providerDomain);
    await expect(page.locator('#accept-btn')).toBeVisible();
    await expect(page.locator('#missing-params')).not.toBeVisible();
  });

  test('accept-invite loads after login with token and provider info', async ({ page }) => {
    await login(page);
    const inviteString = await createInviteTokenViaUI(page);
    const { token, providerDomain } = parseInviteString(inviteString);

    await page.goto(
      `${server.baseURL}/ui/accept-invite?token=${token}&providerDomain=${providerDomain}`,
    );

    // Form is visible with token and provider info
    await expect(page.locator('#invite-form')).toBeVisible();
    await expect(page.locator('#display-token')).toContainText(token);
    await expect(page.locator('#display-provider')).toContainText(providerDomain);

    // Accept button is visible
    await expect(page.locator('#accept-btn')).toBeVisible();
    await expect(page.locator('#accept-btn')).toContainText('Accept Invite');

    // Missing-params message should NOT be visible
    await expect(page.locator('#missing-params')).not.toBeVisible();
  });

  test('WAYF manual discover redirects to accept-invite with token and providerDomain', async ({
    page,
  }) => {
    await login(page);
    const inviteString = await createInviteTokenViaUI(page);
    const { token, providerDomain } = parseInviteString(inviteString);

    expect(providerDomain).toContain(`localhost:${server.port}`);

    await page.context().clearCookies();

    await page.goto(`${server.baseURL}/ui/wayf?token=${encodeURIComponent(token)}`);
    await expect(page.locator('#discover-btn')).toBeVisible();

    await page.fill('#manual-url', server.baseURL);
    await page.click('#discover-btn');

    await page.waitForSelector('#discover-result .provider-item', {
      state: 'visible',
      timeout: 15000,
    });
    await page.click('#discover-result .provider-item');

    await page.waitForURL('**/ui/login**', { timeout: 10000 });

    const loginURL = new URL(page.url());
    const redirectParam = loginURL.searchParams.get('redirect');
    expect(redirectParam).toBeTruthy();

    const redirectURL = new URL(redirectParam!, server.baseURL);
    expect(redirectURL.pathname).toBe('/ui/accept-invite');
    expect(redirectURL.searchParams.get('token')).toBe(token);
    expect(redirectURL.searchParams.get('providerDomain')).toBe(providerDomain);
  });

  test('single-provider WAYF discover completes accept via session-authenticated API', async ({
    page,
  }) => {
    await login(page);
    const inviteString = await createInviteTokenViaUI(page);
    const { token, providerDomain } = parseInviteString(inviteString);

    await page.context().clearCookies();

    await page.goto(`${server.baseURL}/ui/wayf?token=${encodeURIComponent(token)}`);
    await page.fill('#manual-url', server.baseURL);
    await page.click('#discover-btn');

    await page.waitForSelector('#discover-result .provider-item', {
      state: 'visible',
      timeout: 15000,
    });
    await page.click('#discover-result .provider-item');

    await page.waitForURL('**/ui/login**', { timeout: 10000 });
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');

    await page.waitForURL('**/ui/accept-invite**', { timeout: 10000 });
    const landedURL = new URL(page.url());
    expect(landedURL.searchParams.get('token')).toBe(token);
    expect(landedURL.searchParams.get('providerDomain')).toBe(providerDomain);

    const importResponsePromise = page.waitForResponse(
      resp =>
        resp.url().includes('/api/inbox/invites/import') && resp.request().method() === 'POST',
      { timeout: 30000 },
    );
    const acceptResponsePromise = page.waitForResponse(
      resp =>
        resp.url().includes('/api/inbox/invites/') &&
        resp.url().includes('/accept') &&
        resp.request().method() === 'POST',
      { timeout: 30000 },
    );

    await page.click('#accept-btn');

    const importResponse = await importResponsePromise;
    expect(importResponse.status()).not.toBe(401);
    expect(importResponse.ok()).toBeTruthy();

    const acceptResponse = await acceptResponsePromise;
    expect(acceptResponse.status()).not.toBe(401);
    expect(acceptResponse.ok()).toBeTruthy();

    await expect(page.locator('#success-msg')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#success-msg')).toContainText('Invite accepted');
  });
});
