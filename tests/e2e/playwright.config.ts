// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

import { chromium, defineConfig, devices } from '@playwright/test';
import { existsSync } from 'node:fs';

function firstExistingPath(paths: Array<string | undefined>): string | undefined {
  return paths.find((path): path is string => Boolean(path && existsSync(path)));
}

const bundledChromiumExecutable = chromium.executablePath();
const systemChromiumExecutable = firstExistingPath([
  process.env.OCM_E2E_CHROMIUM_EXECUTABLE,
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium',
  '/snap/bin/chromium',
]);
const chromiumLaunchOptions =
  !existsSync(bundledChromiumExecutable) && systemChromiumExecutable
    ? { executablePath: systemChromiumExecutable }
    : undefined;
const usingSystemChromium = Boolean(chromiumLaunchOptions);
const chromiumUseOptions = {
  ...devices['Desktop Chrome'],
  ...(chromiumLaunchOptions ? { launchOptions: chromiumLaunchOptions } : {}),
};

/**
 * Playwright configuration for OpenCloudMesh E2E tests.
 * Tests start their own server instances with bounded lifecycles.
 */
export default defineConfig({
  testDir: './specs',
  
  // Run tests in sequence to avoid port conflicts with subprocess servers
  fullyParallel: false,
  workers: 1,
  
  // Fail the build on CI if test.only is left in the source code
  forbidOnly: !!process.env.CI,
  
  // Retry on CI only
  retries: process.env.CI ? 2 : 0,
  
  // Reporter configuration
  reporter: process.env.CI ? 'github' : 'list',
  
  // Shared settings for all projects
  use: {
    // Collect trace when retrying failed test
    trace: 'on-first-retry',
    
    // Take screenshot on failure
    screenshot: 'only-on-failure',

    // Record video for every test run (artifacts available for debugging)
    video: usingSystemChromium ? 'off' : 'on',
    
    // Timeout for actions
    actionTimeout: 10000,

    // E2E servers use static TLS with a project CA; this covers page and request fixtures
    ignoreHTTPSErrors: true,
  },

  // Test timeout - bounded to prevent hanging
  timeout: 30000,
  
  // Expect timeout
  expect: {
    timeout: 5000,
  },

  projects: [
    {
      name: 'chromium',
      use: chromiumUseOptions,
    },
  ],

  // Output folder for test artifacts
  outputDir: './test-results',
});
