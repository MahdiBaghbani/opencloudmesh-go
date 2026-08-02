// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * UI login helpers for E2E tests.
 */

import { Page } from '@playwright/test';

export async function loginAndNavigateToInbox(page: Page, baseURL: string): Promise<void> {
  await page.goto(`${baseURL}/ui/login`);
  await page.fill('#username', 'admin');
  await page.fill('#password', 'testpassword123');
  await page.click('#submit-btn');
  await page.waitForURL('**/ui/inbox', { timeout: 5000 });
}
