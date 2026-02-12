/**
 * Two-instance WAYF E2E test.
 * A creates invite, B uses A's WAYF to discover B's own accept-invite page,
 * then accepts. Strict mode with signatures enabled.
 *
 * WAYF direction: the WAYF page lives on the INVITER (A). The user enters the
 * RECIPIENT's home provider URL (B) in manual discovery. The redirect goes to
 * B's accept-invite page with providerDomain = A's domain (the inviter). This
 * is correct because the accept-invite page constructs the invite string as
 * base64(token + "@" + providerDomain) where providerDomain must be the
 * inviter's domain for the accept call to succeed.
 */

import { test, expect, Page } from '@playwright/test';
import {
  buildBinary,
  startTwoServers,
  stopServer,
  dumpLogs,
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
 * Asserts that a server's discovery endpoint advertises strict signature
 * support and an inviteAcceptDialog (WAYF enabled).
 */
async function assertStrictDiscovery(page: Page, baseURL: string) {
  const res = await page.request.get(`${baseURL}/.well-known/ocm`);
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.capabilities).toContain('http-sig');
  expect(body.criteria).toContain('http-request-signatures');
  // WAYF requires inviteAcceptDialog in discovery (auto-derived when WAYF is enabled)
  expect(body.inviteAcceptDialog).toBeTruthy();
}

/**
 * Creates an invite via the outgoing UI and returns the invite string.
 */
async function createInviteTokenViaUI(page: Page, baseURL: string): Promise<string> {
  await page.goto(`${baseURL}/ui/outgoing`);
  await page.click('#invite-create-btn');
  await page.waitForSelector('#invite-result', { state: 'visible', timeout: 5000 });
  const inviteString = await page.locator('#invite-string').inputValue();
  expect(inviteString.length).toBeGreaterThan(0);
  return inviteString;
}

/**
 * Parses an invite string (base64 of "token@providerDomain") into its parts.
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

const wayfConfig = '[http.services.ui.wayf]\nenabled = true\n';

test.describe('Two-Instance WAYF Flow', () => {
  let serverA: ServerInstance;
  let serverB: ServerInstance;

  test.beforeEach(async () => {
    [serverA, serverB] = await startTwoServers(binaryPath, {
      mode: 'strict',
      extraConfigA: wayfConfig,
      extraConfigB: wayfConfig,
    });
  });

  test.afterEach(async ({}, testInfo) => {
    if (testInfo.status !== 'passed') {
      if (serverA) dumpLogs(serverA);
      if (serverB) dumpLogs(serverB);
    }
    if (serverA) stopServer(serverA);
    if (serverB) stopServer(serverB);
  });

  test('A creates invite, B accepts via WAYF discovery', async ({ page }) => {
    // Verify both servers advertise strict signature support and WAYF
    await assertStrictDiscovery(page, serverA.baseURL);
    await assertStrictDiscovery(page, serverB.baseURL);

    // Step 1: Login to A and create invite via outgoing UI
    await login(page, serverA.baseURL);
    const inviteString = await createInviteTokenViaUI(page, serverA.baseURL);
    const { token, providerDomain } = parseInviteString(inviteString);

    // The invite string encodes token@providerDomain where providerDomain is
    // A's FQDN. Verify this matches A's actual address.
    expect(providerDomain).toContain(`localhost:${serverA.port}`);

    // Step 2: Login to B (cookies are per-origin, so A's session persists)
    await login(page, serverB.baseURL);

    // Step 3: Navigate to A's WAYF page with the bare token.
    // WAYF is on A (the inviter) so providerDomain in the redirect = A's domain.
    await page.goto(
      `${serverA.baseURL}/ui/wayf?token=${encodeURIComponent(token)}`,
    );

    // Step 4: Enter B's base URL in manual discovery and click Discover.
    // This triggers A's /ocm-aux/discover?base=B_URL which fetches B's discovery.
    await page.fill('#manual-url', serverB.baseURL);
    await page.click('#discover-btn');

    // Step 5: Wait for the discovered provider item to appear
    await page.waitForSelector('#discover-result .provider-item', {
      state: 'visible',
      timeout: 15000,
    });

    // Step 6: Click the discovered provider to trigger redirect to B's accept-invite.
    // The redirect URL: B's inviteAcceptDialog + ?token=T&providerDomain=A_domain
    await page.click('#discover-result .provider-item');

    // Step 7: Wait for redirect to B's accept-invite page
    await page.waitForURL('**/ui/accept-invite**', { timeout: 10000 });

    // Verify we landed on B's server (URL contains B's port)
    expect(page.url()).toContain(`:${serverB.port}/`);

    // Step 8: Verify the accept-invite dialog shows the correct token and
    // provider domain (the inviter's domain) before clicking Accept.
    // This mirrors the ocm-test-suite assertion: the accept dialog must display
    // the inviter's identity so the user knows who they are federating with.
    await expect(page.locator('#invite-form')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('#display-token')).toContainText(token);
    await expect(page.locator('#display-provider')).toContainText(providerDomain);

    // Step 9: Click Accept (we are logged into B via step 2).
    // Set up a listener for the accept API response before clicking.
    const acceptResponsePromise = page.waitForResponse(
      resp => resp.url().includes('/api/inbox/invites/') && resp.url().includes('/accept'),
      { timeout: 30000 },
    );
    await expect(page.locator('#accept-btn')).toBeVisible();
    await page.click('#accept-btn');

    // Wait for the accept API call to complete and assert success
    const acceptResponse = await acceptResponsePromise;
    if (!acceptResponse.ok()) {
      const body = await acceptResponse.text();
      console.error(`Accept API failed with status ${acceptResponse.status()}: ${body}`);
    }
    expect(acceptResponse.ok()).toBeTruthy();

    // Step 10: Wait for success message. The accept-invite page shows
    // "Invite accepted! Redirecting..." then redirects to B's inbox after 1s.
    // Use toBeVisible to confirm the element is rendered (display:block via
    // .visible class) before asserting text, avoiding race with the redirect.
    await expect(page.locator('#success-msg')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#success-msg')).toContainText('Invite accepted');

    // Step 11: Wait for redirect to B's inbox
    await page.waitForURL('**/ui/inbox', { timeout: 10000 });

    // Step 12: Verify via API on B that the invite is accepted
    const listResponse = await page.request.get(
      `${serverB.baseURL}/api/inbox/invites`,
    );
    expect(listResponse.status()).toBe(200);

    const listBody = await listResponse.json();
    const accepted = listBody.invites.find(
      (inv: { status: string }) => inv.status === 'accepted',
    );
    expect(accepted).toBeTruthy();
  });
});
