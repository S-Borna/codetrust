// @ts-check

/** @type {import('@playwright/test').PlaywrightTestConfig} */
const config = {
    testDir: "./e2e",
    timeout: 30_000,
    retries: 1,
    use: {
        baseURL: process.env.BASE_URL || "http://localhost:3000",
        headless: true,
        screenshot: "only-on-failure",
        trace: "retain-on-failure",
    },
    webServer: {
        command: "npm run dev",
        port: 3000,
        timeout: 120_000,
        reuseExistingServer: !process.env.CI,
    },
    projects: [
        {
            name: "chromium",
            use: { browserName: "chromium" },
        },
    ],
};

module.exports = config;
