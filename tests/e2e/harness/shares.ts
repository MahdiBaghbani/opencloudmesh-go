// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * Outgoing share helpers for two-instance E2E tests.
 * Sends shares via server A's API so the Go signer delivers them to server B.
 */

import { Page } from '@playwright/test';
import { rmSync } from 'fs';
import { createShareableFile, ServerInstance } from './server';

export interface SendOutgoingShareOptions {
  name: string;
  permissions?: string[];
  resourceType?: string;
}

export interface SentShare {
  shareFilePath: string;
}

/** Caller must have logged the page into server A first (localhost cookies are host-scoped). */
export async function sendOutgoingShare(
  page: Page,
  serverA: ServerInstance,
  serverB: ServerInstance,
  options: SendOutgoingShareOptions,
): Promise<SentShare> {
  const shareFilePath = createShareableFile(serverA);
  try {
    const response = await page.request.post(`${serverA.baseURL}/api/shares/outgoing`, {
      data: {
        receiverDomain: `localhost:${serverB.port}`,
        shareWith: `admin@localhost:${serverB.port}`,
        localPath: shareFilePath,
        permissions: options.permissions ?? ['read'],
        name: options.name,
        resourceType: options.resourceType,
      },
    });
    if (response.status() !== 201) {
      const body = await response.text();
      throw new Error(`outgoing share failed: ${response.status()} ${body}`);
    }
  } catch (err) {
    rmSync(shareFilePath, { force: true });
    throw err;
  }
  return { shareFilePath };
}
