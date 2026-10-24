const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/browser',
  workers: 1,
  outputDir: '.data/playwright/test-results',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  use: { browserName: 'chromium' },
});
