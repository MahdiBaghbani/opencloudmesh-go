// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * RFC 9421 / OCM Appendix B request signing for e2e seeders.
 * Loads the per-instance Ed25519 key written at bootstrap (signing.pem).
 */

import {
  createPrivateKey,
  createHash,
  sign as cryptoSign,
  type KeyObject,
} from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import type { APIRequestContext, APIResponse } from '@playwright/test';
import type { ServerInstance } from './server';

export const DEFAULT_KID_FRAGMENT = 'key1';
export const SIGNATURE_LABEL = 'ocm';
export const SIGNING_ALGORITHM = 'ed25519';

export interface SigningKey {
  privateKey: KeyObject;
  keyId: string;
  algorithm: typeof SIGNING_ALGORITHM;
}

export interface SignOcmRequestOptions {
  method: string;
  url: string;
  body?: string | Buffer;
  key: SigningKey;
  contentType?: string;
  now?: Date;
}

/**
 * Derives the host#fragment keyid the Go bootstrap uses for public_origin.
 * Non-default ports stay in the authority (e.g. localhost:9200#key1).
 */
export function keyIdFromPublicOrigin(
  publicOrigin: string,
  fragment: string = DEFAULT_KID_FRAGMENT,
): string {
  const u = new URL(publicOrigin);
  if (!u.host) {
    throw new Error(`public origin has no host: ${publicOrigin}`);
  }
  return `${u.host.toLowerCase()}#${fragment}`;
}

export function instanceSigningKeyPath(instance: ServerInstance): string {
  return join(instance.tempDir, 'signing.pem');
}

/**
 * Loads the PKCS8 Ed25519 private key generated for an e2e server instance.
 */
export function loadInstanceSigningKey(
  keyPath: string,
  publicOrigin: string,
): SigningKey {
  const pem = readFileSync(keyPath, 'utf8');
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error(`expected Ed25519 key at ${keyPath}`);
  }
  return {
    privateKey,
    keyId: keyIdFromPublicOrigin(publicOrigin),
    algorithm: SIGNING_ALGORITHM,
  };
}

export function loadServerSigningKey(instance: ServerInstance): SigningKey {
  return loadInstanceSigningKey(instanceSigningKeyPath(instance), instance.baseURL);
}

function formatHttpDate(date: Date): string {
  // Match Go http.TimeFormat: "Mon, 02 Jan 2006 15:04:05 GMT"
  const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];
  const dayName = weekdays[date.getUTCDay()];
  const day = String(date.getUTCDate()).padStart(2, '0');
  const month = months[date.getUTCMonth()];
  const year = String(date.getUTCFullYear());
  const hour = String(date.getUTCHours()).padStart(2, '0');
  const minute = String(date.getUTCMinutes()).padStart(2, '0');
  const second = String(date.getUTCSeconds()).padStart(2, '0');
  return `${dayName}, ${day} ${month} ${year} ${hour}:${minute}:${second} GMT`;
}

function contentDigestSha256(body: Buffer): string {
  const digest = createHash('sha256').update(body).digest('base64');
  return `sha-256=:${digest}:`;
}

function appendixBComponents(hasBody: boolean): string[] {
  const components = ['@method', '@target-uri'];
  if (hasBody) {
    components.push('content-digest', 'content-length');
  }
  components.push('date');
  return components;
}

function formatSignatureInput(
  components: string[],
  created: number,
  keyId: string,
  algorithm: string,
): string {
  const quoted = components.map((c) => `"${c}"`).join(' ');
  return `${SIGNATURE_LABEL}=(${quoted});created=${created};keyid="${keyId}";alg="${algorithm}"`;
}

function buildSignatureBase(
  method: string,
  targetUri: string,
  headers: Record<string, string>,
  components: string[],
): string {
  const lines: string[] = [];
  for (const comp of components) {
    let value: string;
    switch (comp) {
      case '@method':
        value = method.toUpperCase();
        break;
      case '@target-uri':
        value = targetUri;
        break;
      case 'content-digest':
      case 'content-length':
      case 'date':
        value = headers[comp] ?? headers[headerCanonicalName(comp)] ?? '';
        if (!value) {
          throw new Error(`missing header for covered component ${comp}`);
        }
        break;
      default:
        throw new Error(`unsupported covered component ${comp}`);
    }
    if (value.includes('\r') || value.includes('\n')) {
      throw new Error(`component ${comp} value contains CR/LF`);
    }
    lines.push(`"${comp}": ${value}`);
  }
  return lines.join('\n') + '\n';
}

function headerCanonicalName(comp: string): string {
  return comp
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('-');
}

/**
 * Builds RFC 9421 Signature-Input / Signature headers for an OCM request.
 * Covered components match Go crypto.AppendixBCoveredComponents().
 */
export function signOcmRequest(opts: SignOcmRequestOptions): Record<string, string> {
  const now = opts.now ?? new Date();
  const bodyBuf =
    opts.body === undefined
      ? Buffer.alloc(0)
      : Buffer.isBuffer(opts.body)
        ? opts.body
        : Buffer.from(opts.body, 'utf8');
  const hasBody = bodyBuf.length > 0;

  const targetUrl = new URL(opts.url);
  const targetUri = `${targetUrl.protocol}//${targetUrl.host}${targetUrl.pathname}${targetUrl.search}`;

  const headers: Record<string, string> = {
    Date: formatHttpDate(now),
  };
  if (opts.contentType) {
    headers['Content-Type'] = opts.contentType;
  }
  if (hasBody) {
    headers['Content-Digest'] = contentDigestSha256(bodyBuf);
    headers['Content-Length'] = String(bodyBuf.length);
  }

  // Lowercase lookup keys used while building the signature base.
  const headerLookup: Record<string, string> = {
    date: headers.Date,
  };
  if (hasBody) {
    headerLookup['content-digest'] = headers['Content-Digest'];
    headerLookup['content-length'] = headers['Content-Length'];
  }

  const components = appendixBComponents(hasBody);
  const created = Math.floor(now.getTime() / 1000);
  const signatureInput = formatSignatureInput(
    components,
    created,
    opts.key.keyId,
    opts.key.algorithm,
  );
  const sigParamsValue = signatureInput.slice(`${SIGNATURE_LABEL}=`.length);
  const sigBase = buildSignatureBase(
    opts.method,
    targetUri,
    headerLookup,
    components,
  );
  const fullBase = `${sigBase}"@signature-params": ${sigParamsValue}`;

  const signatureBytes = cryptoSign(null, Buffer.from(fullBase, 'utf8'), opts.key.privateKey);
  const signatureHeader = `${SIGNATURE_LABEL}=:${signatureBytes.toString('base64')}:`;

  return {
    ...headers,
    'Signature-Input': signatureInput,
    Signature: signatureHeader,
  };
}

/**
 * POST /ocm/shares with Appendix B signatures using the instance signing key.
 * Sender/owner provider must match the instance host so declared peer equals keyid.
 */
export async function postSignedIncomingShare(
  request: APIRequestContext,
  instance: ServerInstance,
  payload: Record<string, unknown>,
): Promise<APIResponse> {
  const key = loadServerSigningKey(instance);
  const url = `${instance.baseURL}/ocm/shares`;
  const body = JSON.stringify(payload);
  const headers = signOcmRequest({
    method: 'POST',
    url,
    body,
    key,
    contentType: 'application/json',
  });
  return request.post(url, { headers, data: body });
}

/**
 * Builds a share payload whose sender/owner provider matches the instance
 * public_origin host so the declared peer matches the server/provider
 * authority.
 */
export function localPeerShareFields(instance: ServerInstance): {
  provider: string;
  owner: string;
  sender: string;
} {
  const provider = new URL(instance.baseURL).host;
  return {
    provider,
    owner: `owner@${provider}`,
    sender: `sender@${provider}`,
  };
}
