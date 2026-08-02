// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * Accept incoming share E2E tests.
 * Tests accepting and declining shares via the inbox UI.
 */

import { test, expect } from '@playwright/test';
import { rmSync } from 'fs';
import {
  buildBinary,
  startServer,
  startTwoServers,
  stopServer,
  ServerInstance,
} from '../harness/server';
import { loginAndNavigateToInbox } from '../harness/auth';
import { establishTrust } from '../harness/invites';
import { sendOutgoingShare } from '../harness/shares';

let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Accept Share Flow', () => {
  let serverA: ServerInstance;
  let serverB: ServerInstance;
  const shareFilePaths: string[] = [];

  test.beforeEach(async () => {
    [serverA, serverB] = await startTwoServers(binaryPath, { mode: 'dev' });
  });

  test.afterEach(async () => {
    if (serverA) stopServer(serverA);
    if (serverB) stopServer(serverB);
    for (const path of shareFilePaths) {
      rmSync(path, { force: true });
    }
    shareFilePaths.length = 0;
  });

  test('inbox loads shares from API', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const { shareFilePath } = await sendOutgoingShare(page, serverA, serverB, {
      name: 'Test Document.pdf',
    });
    shareFilePaths.push(shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Verify share is displayed
    await expect(page.locator('#share-list .share-item')).toHaveCount(1);
    await expect(page.locator('#share-list .share-name')).toContainText('Test Document.pdf');
    await expect(page.locator('#share-list .share-status')).toContainText('pending');
  });

  test('pending share shows accept and decline buttons', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const { shareFilePath } = await sendOutgoingShare(page, serverA, serverB, {
      name: 'Shared File.docx',
    });
    shareFilePaths.push(shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Verify action buttons are present
    await expect(page.locator('#share-list .btn-accept')).toBeVisible();
    await expect(page.locator('#share-list .btn-decline')).toBeVisible();
  });

  test('clicking accept changes share status', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const { shareFilePath } = await sendOutgoingShare(page, serverA, serverB, {
      name: 'Accept Me.txt',
    });
    shareFilePaths.push(shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Click accept
    await page.click('#share-list .btn-accept');

    // Wait for status to change
    await page.waitForSelector('#share-list .status-accepted', { timeout: 5000 });

    // Verify status changed
    await expect(page.locator('#share-list .share-status')).toContainText('accepted');

    // Action buttons should be gone for accepted share
    await expect(page.locator('#share-list .btn-accept')).toHaveCount(0);
    await expect(page.locator('#share-list .btn-decline')).toHaveCount(0);
  });

  test('clicking decline changes share status', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const { shareFilePath } = await sendOutgoingShare(page, serverA, serverB, {
      name: 'Decline Me.txt',
    });
    shareFilePaths.push(shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Click decline
    await page.click('#share-list .btn-decline');

    // Wait for status to change
    await page.waitForSelector('#share-list .status-declined', { timeout: 5000 });

    // Verify status changed
    await expect(page.locator('#share-list .share-status')).toContainText('declined');

    // Action buttons should be gone for declined share
    await expect(page.locator('#share-list .btn-accept')).toHaveCount(0);
    await expect(page.locator('#share-list .btn-decline')).toHaveCount(0);
  });

  test('tab filter shows only pending shares', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const sent1 = await sendOutgoingShare(page, serverA, serverB, {
      name: 'Pending Share.pdf',
    });
    const sent2 = await sendOutgoingShare(page, serverA, serverB, {
      name: 'Also Pending.pdf',
    });
    shareFilePaths.push(sent1.shareFilePath, sent2.shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Accept one share via UI
    await page.locator('#share-list .btn-accept').first().click();
    await page.waitForSelector('#share-list .status-accepted', { timeout: 5000 });

    // Click Pending tab
    await page.click('#share-tabs .tab[data-filter="pending"]');

    // Should show only pending shares
    await expect(page.locator('#share-list .status-pending')).toHaveCount(1);
    // Should NOT show accepted shares
    await expect(page.locator('#share-list .status-accepted')).toHaveCount(0);
  });

  test('tab filter shows only accepted shares', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const { shareFilePath } = await sendOutgoingShare(page, serverA, serverB, {
      name: 'To Be Accepted.pdf',
    });
    shareFilePaths.push(shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Accept via UI
    await page.click('#share-list .btn-accept');
    await page.waitForSelector('#share-list .status-accepted', { timeout: 5000 });

    // Click Accepted tab
    await page.click('#share-tabs .tab[data-filter="accepted"]');

    // Should show only accepted shares
    await expect(page.locator('#share-list .status-accepted')).toHaveCount(1);
    await expect(page.locator('#share-list .status-pending')).toHaveCount(0);
  });

  test('multiple shares can be managed', async ({ page }) => {
    await establishTrust(page, serverA, serverB);
    await loginAndNavigateToInbox(page, serverA.baseURL);
    const sent1 = await sendOutgoingShare(page, serverA, serverB, { name: 'File 1.txt' });
    const sent2 = await sendOutgoingShare(page, serverA, serverB, { name: 'File 2.txt' });
    const sent3 = await sendOutgoingShare(page, serverA, serverB, { name: 'File 3.txt' });
    shareFilePaths.push(sent1.shareFilePath, sent2.shareFilePath, sent3.shareFilePath);
    await loginAndNavigateToInbox(page, serverB.baseURL);
    await page.waitForSelector('#share-list .share-item', { timeout: 10000 });

    // Should show all 3 shares
    await expect(page.locator('#share-list .share-item')).toHaveCount(3);

    // Accept the first one
    await page.locator('#share-list .btn-accept').first().click();
    await page.waitForSelector('#share-list .status-accepted', { timeout: 5000 });

    // Now we should have 1 accepted and 2 pending
    await expect(page.locator('#share-list .status-accepted')).toHaveCount(1);
    await expect(page.locator('#share-list .status-pending')).toHaveCount(2);
  });
});

test.describe('Accept Share Flow (empty inbox)', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'accept-test-empty', mode: 'dev' });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  test('empty state shows when no shares match filter', async ({ page }) => {
    await loginAndNavigateToInbox(page, server.baseURL);

    // With no shares, should show empty state in the share list
    const shareList = page.locator('#share-list');
    await expect(shareList.locator('.empty-state')).toBeVisible();
    await expect(shareList).toContainText('No shares yet');
  });
});
