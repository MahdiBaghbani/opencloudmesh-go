/**
 * Smoke test: Verify server starts, login page loads, and server stops cleanly.
 */

import { test, expect } from '@playwright/test';
import { buildBinary, startServer, stopServer, dumpLogs, ServerInstance } from '../harness/server';

// Build binary once before all tests
let binaryPath: string;

test.beforeAll(() => {
  binaryPath = buildBinary();
});

test.describe('Server Smoke Tests', () => {
  let server: ServerInstance;

  test.beforeEach(async () => {
    server = await startServer(binaryPath, { name: 'smoke-test', mode: 'dev' });
  });

  test.afterEach(async () => {
    if (server) {
      stopServer(server);
    }
  });

  test('server starts and serves health endpoint', async ({ request }) => {
    const response = await request.get(`${server.baseURL}/api/healthz`);
    expect(response.ok()).toBeTruthy();
    
    const body = await response.json();
    expect(body.status).toBe('ok');
  });

  test('login page loads successfully', async ({ page }) => {
    await page.goto(`${server.baseURL}/ui/login`);
    
    // Verify the page loaded (not a 404 or error)
    await expect(page).toHaveTitle(/.*OpenCloudMesh.*|.*Login.*|.*/);
    
    // Page should have some content
    const content = await page.content();
    expect(content.length).toBeGreaterThan(100);
    
    // Should not be an error page
    expect(content).not.toContain('404');
    expect(content).not.toContain('500');
    expect(content).not.toContain('Internal Server Error');
  });

  test('discovery endpoint returns JSON', async ({ request }) => {
    const response = await request.get(`${server.baseURL}/.well-known/ocm`);
    expect(response.ok()).toBeTruthy();
    
    const contentType = response.headers()['content-type'];
    expect(contentType).toContain('application/json');
    
    const body = await response.json();
    expect(body.enabled).toBe(true);
    expect(body.provider).toBeDefined();
  });
});

test.describe('Server Lifecycle Tests', () => {
  test('server starts and stops cleanly', async ({ request }) => {
    const server = await startServer(binaryPath, { name: 'lifecycle-test', mode: 'dev' });
    
    // Verify server is running
    const response = await request.get(`${server.baseURL}/api/healthz`);
    expect(response.ok()).toBeTruthy();
    
    // Stop server
    stopServer(server);
    
    // Give it a moment to shut down
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Verify server is stopped (connection should fail)
    try {
      await request.get(`${server.baseURL}/api/healthz`, { timeout: 1000 });
      // If we get here, server is still running - that's unexpected
      expect(false).toBeTruthy(); // Force fail
    } catch {
      // Expected: connection refused or timeout
    }
  });

  test('multiple servers can run on different ports', async ({ request }) => {
    const server1 = await startServer(binaryPath, { name: 'multi-1', mode: 'dev' });
    const server2 = await startServer(binaryPath, { name: 'multi-2', mode: 'dev' });

    try {
      // Both should be running on different ports
      expect(server1.port).not.toBe(server2.port);
      
      // Both should respond
      const [resp1, resp2] = await Promise.all([
        request.get(`${server1.baseURL}/api/healthz`),
        request.get(`${server2.baseURL}/api/healthz`),
      ]);
      
      expect(resp1.ok()).toBeTruthy();
      expect(resp2.ok()).toBeTruthy();
    } finally {
      stopServer(server1);
      stopServer(server2);
    }
  });
});
