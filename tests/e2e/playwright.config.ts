import { defineConfig, devices } from '@playwright/test';

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
    video: 'on',
    
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
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Output folder for test artifacts
  outputDir: './test-results',
});
