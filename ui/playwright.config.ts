import { defineConfig, devices } from '@playwright/test';
import { join } from 'node:path';

const suite = process.env.E2E_SUITE ?? 'core';
const output = process.env.E2E_OUTPUT_DIR ?? 'e2e-results/manual';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  failOnFlakyTests: !!process.env.CI,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  outputDir: join(output, 'test-results', suite),
  reporter: [
    ['list'],
    ['html', { outputFolder: join(output, 'report', suite), open: 'never' }],
    ['junit', { outputFile: join(output, `${suite}.xml`) }],
  ],
  use: {
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    ...devices['Desktop Chrome'],
    baseURL: process.env.E2E_UI_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: ['core', 'capabilities', 'oidc'].map(name => ({
    name,
    testMatch: `**/${name}/**/*.spec.ts`,
  })),
});
