/**
 * Outgoing UI E2E tests.
 * Tests invite creation via /ui/outgoing and Inbox|Outgoing nav links.
 */

import { test, expect } from '@playwright/test';
import { buildBinary, startServer, stopServer, ServerInstance } from '../harness/server';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Outgoing Invites', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'outgoing-test', mode: 'dev' });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto(`${server.baseURL}/ui/login`);
    await page.fill('#username', 'admin');
    await page.fill('#password', 'testpassword123');
    await page.click('#submit-btn');
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });
  }

  test('create invite returns a base64 invite string', async ({ page }) => {
    await login(page);
    await page.goto(`${server.baseURL}/ui/outgoing`);

    await page.click('#invite-create-btn');
    await page.waitForSelector('#invite-result', { state: 'visible', timeout: 5000 });

    const inviteString = await page.locator('#invite-string').inputValue();
    expect(inviteString.length).toBeGreaterThan(0);
    expect(inviteString).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  test('nav link from Outgoing to Inbox', async ({ page }) => {
    await login(page);
    await page.goto(`${server.baseURL}/ui/outgoing`);

    await page.locator('nav.nav-links a', { hasText: 'Inbox' }).click();
    await page.waitForURL('**/ui/inbox', { timeout: 5000 });

    expect(page.url()).toContain('/ui/inbox');
  });

  test('nav link from Inbox to Outgoing', async ({ page }) => {
    await login(page);
    // login() lands on /ui/inbox already

    await page.locator('nav.nav-links a', { hasText: 'Outgoing' }).click();
    await page.waitForURL('**/ui/outgoing', { timeout: 5000 });

    expect(page.url()).toContain('/ui/outgoing');
  });
});
