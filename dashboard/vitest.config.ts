import { defineConfig } from "vitest/config";
import { resolve } from "path";

export default defineConfig({
    esbuild: {
        jsx: "automatic",
    },
    test: {
        environment: "jsdom",
        globals: true,
        setupFiles: ["./src/__tests__/setup.ts"],
        include: ["src/**/*.test.{ts,tsx}"],
        alias: {
            "@/": resolve(__dirname, "./src") + "/",
        },
    },
});
