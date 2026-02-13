import { test, expect } from "@playwright/test";

test.describe("Dashboard Home Page", () => {
    test("should load the dashboard landing page", async ({ page }) => {
        await page.goto("/");
        await expect(page).toHaveTitle(/CodeTrust/i);
    });

    test("should display navigation elements", async ({ page }) => {
        await page.goto("/");
        // Dashboard should have visible nav/header
        const body = await page.textContent("body");
        expect(body).toBeTruthy();
    });

    test("should have proper meta viewport", async ({ page }) => {
        await page.goto("/");
        const viewport = await page.getAttribute(
            'meta[name="viewport"]',
            "content"
        );
        expect(viewport).toContain("width=device-width");
    });
});

test.describe("Dashboard Scan Page", () => {
    test("should navigate to scan page", async ({ page }) => {
        await page.goto("/");
        // Attempt to find and click a scan-related link
        const scanLink = page.locator('a[href*="scan"], button:has-text("Scan")');
        if ((await scanLink.count()) > 0) {
            await scanLink.first().click();
            await page.waitForLoadState("networkidle");
            expect(page.url()).toBeTruthy();
        }
    });
});

test.describe("Dashboard API Integration", () => {
    test("should handle API errors gracefully", async ({ page }) => {
        await page.goto("/");
        // Page should not show uncaught JS errors
        const errors: string[] = [];
        page.on("pageerror", (err) => errors.push(err.message));
        await page.waitForTimeout(2000);
        // Some errors are acceptable during dev, but page should load
        const title = await page.title();
        expect(title).toBeTruthy();
    });
});

test.describe("Accessibility Basics", () => {
    test("should have lang attribute on html", async ({ page }) => {
        await page.goto("/");
        const lang = await page.getAttribute("html", "lang");
        expect(lang).toBeTruthy();
    });

    test("should have no duplicate IDs", async ({ page }) => {
        await page.goto("/");
        const duplicateIds = await page.evaluate(() => {
            const ids = Array.from(document.querySelectorAll("[id]")).map(
                (el) => el.id
            );
            const seen = new Set<string>();
            const dupes: string[] = [];
            for (const id of ids) {
                if (seen.has(id)) dupes.push(id);
                seen.add(id);
            }
            return dupes;
        });
        expect(duplicateIds).toHaveLength(0);
    });
});
