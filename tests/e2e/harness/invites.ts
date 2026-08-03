// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * Invite/trust helpers for two-instance E2E tests.
 * Establishes bidirectional trust so server A can send shares to server B.
 */

import { Page } from '@playwright/test';
import { loginAndNavigateToInbox } from './auth';
import { ServerInstance } from './server';

// Establishes trust: A creates invite, B imports+accepts. Leaves the page
// logged into B (B's session cookie active). A re-login is required before
// any subsequent A-side API call (cookies are host-scoped on localhost).
export async function establishTrust(
  page: Page,
  serverA: ServerInstance,
  serverB: ServerInstance,
): Promise<void> {
  await loginAndNavigateToInbox(page, serverA.baseURL);
  const createRes = await page.request.post(`${serverA.baseURL}/api/invites/outgoing`, { data: {} });
  if (createRes.status() !== 201) {
    throw new Error(`invite create failed: ${createRes.status()} ${await createRes.text()}`);
  }
  const created = await createRes.json();
  if (!created.inviteString || typeof created.inviteString !== 'string') {
    throw new Error('invite create response missing inviteString');
  }
  const { inviteString } = created;

  await loginAndNavigateToInbox(page, serverB.baseURL);
  const importRes = await page.request.post(`${serverB.baseURL}/api/inbox/invites/import`, {
    data: { inviteString },
  });
  if (importRes.status() !== 201) {
    throw new Error(`invite import failed: ${importRes.status()} ${await importRes.text()}`);
  }
  const imported = await importRes.json();
  if (!imported.id || typeof imported.id !== 'string') {
    throw new Error('invite import response missing id');
  }
  const { id } = imported;

  const acceptRes = await page.request.post(`${serverB.baseURL}/api/inbox/invites/${id}/accept`);
  if (acceptRes.status() !== 200) {
    throw new Error(`invite accept failed: ${acceptRes.status()} ${await acceptRes.text()}`);
  }
}
