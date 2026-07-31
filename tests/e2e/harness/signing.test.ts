// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

/**
 * Focused unit tests for the e2e RFC 9421 signing client.
 * Included by `bun run test` (before Playwright); or: bun test harness/signing.test.ts
 */

import { describe, expect, test } from 'bun:test';
import {
  generateKeyPairSync,
  createPublicKey,
  verify as cryptoVerify,
  type KeyObject,
} from 'crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  keyIdFromPublicOrigin,
  loadInstanceSigningKey,
  signOcmRequest,
  SIGNATURE_LABEL,
  SIGNING_ALGORITHM,
} from './signing';

function generatePkcs8Ed25519Pem(): { pem: string; publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { pem, publicKey };
}

describe('keyIdFromPublicOrigin', () => {
  test('keeps non-default port in authority', () => {
    expect(keyIdFromPublicOrigin('https://localhost:9200')).toBe('localhost:9200#key1');
  });

  test('accepts custom fragment', () => {
    expect(keyIdFromPublicOrigin('https://example.com:8443', 'main')).toBe(
      'example.com:8443#main',
    );
  });
});

describe('signOcmRequest', () => {
  test('emits Appendix B covered components and verifies with public key', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ocm-e2e-sign-'));
    try {
      const { pem, publicKey } = generatePkcs8Ed25519Pem();
      const keyPath = join(dir, 'signing.pem');
      writeFileSync(keyPath, pem, { mode: 0o600 });

      const publicOrigin = 'https://localhost:9443';
      const key = loadInstanceSigningKey(keyPath, publicOrigin);
      expect(key.keyId).toBe('localhost:9443#key1');
      expect(key.algorithm).toBe(SIGNING_ALGORITHM);

      const body = JSON.stringify({ sender: 'sender@localhost:9443', name: 'f.txt' });
      const url = `${publicOrigin}/ocm/shares`;
      const now = new Date('2026-01-15T12:00:00.000Z');
      const headers = signOcmRequest({
        method: 'POST',
        url,
        body,
        key,
        contentType: 'application/json',
        now,
      });

      expect(headers.Date).toBe('Thu, 15 Jan 2026 12:00:00 GMT');
      expect(headers['Content-Type']).toBe('application/json');
      expect(headers['Content-Length']).toBe(String(Buffer.byteLength(body)));
      expect(headers['Content-Digest']).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);

      const sigInput = headers['Signature-Input'];
      expect(sigInput.startsWith(`${SIGNATURE_LABEL}=`)).toBe(true);
      for (const want of [
        '"@method"',
        '"@target-uri"',
        '"content-digest"',
        '"content-length"',
        '"date"',
        'created=1768478400',
        'keyid="localhost:9443#key1"',
        `alg="${SIGNING_ALGORITHM}"`,
      ]) {
        expect(sigInput).toContain(want);
      }

      const signature = headers.Signature;
      expect(signature.startsWith(`${SIGNATURE_LABEL}=:`)).toBe(true);
      expect(signature.endsWith(':')).toBe(true);

      const sigParamsValue = sigInput.slice(`${SIGNATURE_LABEL}=`.length);
      const sigB64 = signature.slice(`${SIGNATURE_LABEL}=:`.length, -1);
      const fullBase =
        `"@method": POST\n` +
        `"@target-uri": ${url}\n` +
        `"content-digest": ${headers['Content-Digest']}\n` +
        `"content-length": ${headers['Content-Length']}\n` +
        `"date": ${headers.Date}\n` +
        `"@signature-params": ${sigParamsValue}`;

      const ok = cryptoVerify(
        null,
        Buffer.from(fullBase, 'utf8'),
        publicKey,
        Buffer.from(sigB64, 'base64'),
      );
      expect(ok).toBe(true);

      // Sanity: public key object matches loaded private key
      expect(createPublicKey(key.privateKey).equals(publicKey)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('omits content-digest and content-length for empty body', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ocm-e2e-sign-empty-'));
    try {
      const { pem } = generatePkcs8Ed25519Pem();
      const keyPath = join(dir, 'signing.pem');
      writeFileSync(keyPath, pem, { mode: 0o600 });
      const key = loadInstanceSigningKey(keyPath, 'https://localhost:9555');

      const headers = signOcmRequest({
        method: 'GET',
        url: 'https://localhost:9555/.well-known/jwks.json',
        key,
        now: new Date('2026-01-15T12:00:00.000Z'),
      });

      expect(headers['Content-Digest']).toBeUndefined();
      expect(headers['Content-Length']).toBeUndefined();
      expect(headers['Signature-Input']).toContain('"@method"');
      expect(headers['Signature-Input']).toContain('"@target-uri"');
      expect(headers['Signature-Input']).toContain('"date"');
      expect(headers['Signature-Input']).not.toContain('content-digest');
      expect(headers['Signature-Input']).not.toContain('content-length');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
