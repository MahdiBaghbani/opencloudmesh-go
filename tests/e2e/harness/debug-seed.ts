import { buildBinary, startServer, stopServer } from './server';
import { localPeerShareFields, postSignedIncomingShare, loadServerSigningKey } from './signing';
import { request as playwrightRequest } from '@playwright/test';

async function main(): Promise<void> {
  const binaryPath = buildBinary();
  const server = await startServer(binaryPath, { name: 'debug', mode: 'dev' });
  try {
    const request = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
    try {
      const { provider, owner, sender } = localPeerShareFields(server);
      const key = loadServerSigningKey(server);
      console.log('keyId', key.keyId);
      console.log('owner', owner, 'sender', sender, 'provider', provider);
      const payload = {
        shareWith: `admin@${provider}`,
        name: 'debug.txt',
        providerId: `dbg-${Date.now()}`,
        owner,
        sender,
        shareType: 'user',
        resourceType: 'file',
        protocol: {
          name: 'webdav',
          webdav: {
            uri: `https://remote.example.com/webdav/${Date.now()}`,
            sharedSecret: `secret-${Date.now()}`,
            permissions: ['read'],
            requirements: ['must-exchange-token'],
          },
        },
      };
      const response = await postSignedIncomingShare(request, server, payload);
      const body = await response.text();
      console.log('status', response.status());
      console.log('body', body);
      if (response.status() !== 201) {
        process.exit(1);
      }
    } finally {
      await request.dispose();
    }
  } finally {
    await stopServer(server);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
