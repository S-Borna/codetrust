// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Persistent cache for import and Docker verification results.
 *
 * Stores "known good" verification data in VS Code globalState
 * so results survive restarts and are available offline.
 */

import * as vscode from "vscode";
import type { PackageResult, DockerImageResult } from "./types";

/** Cache entry with a timestamp for expiry. */
interface CacheEntry<T> {
    data: T;
    /** ISO-8601 timestamp when the result was cached. */
    cachedAt: string;
}

/** TTL for cached results (7 days in milliseconds). */
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const IMPORT_CACHE_KEY = "codetrust.verifyImportsCache";
const DOCKER_CACHE_KEY = "codetrust.verifyDockerCache";

/** Manages persistent caching of verification results. */
export class VerificationCache {
    constructor(private readonly globalState: vscode.Memento) { }

    // ───────────────────────────────────────────────────
    //  IMPORT VERIFICATION
    // ───────────────────────────────────────────────────

    /** Get a cached import verification result. Returns undefined if not cached or expired. */
    getImportResult(packageName: string, language: string): PackageResult | undefined {
        const cache = this.getImportCache();
        const key = `${language}:${packageName}`;
        const entry = cache[key];
        if (!entry) { return undefined; }
        if (this.isExpired(entry)) {
            this.removeImportEntry(key);
            return undefined;
        }
        return entry.data;
    }

    /** Cache an import verification result. */
    setImportResult(packageName: string, language: string, result: PackageResult): void {
        const cache = this.getImportCache();
        const key = `${language}:${packageName}`;
        cache[key] = { data: result, cachedAt: new Date().toISOString() };
        this.globalState.update(IMPORT_CACHE_KEY, cache);
    }

    /** Cache multiple import results at once. */
    setImportResults(language: string, results: PackageResult[]): void {
        const cache = this.getImportCache();
        const now = new Date().toISOString();
        for (const result of results) {
            const key = `${language}:${result.package}`;
            cache[key] = { data: result, cachedAt: now };
        }
        this.globalState.update(IMPORT_CACHE_KEY, cache);
    }

    /** Get all cached import results for a list of packages. Returns found and missing lists. */
    getImportResults(
        language: string,
        packages: string[],
    ): { cached: PackageResult[]; missing: string[] } {
        const cached: PackageResult[] = [];
        const missing: string[] = [];

        for (const pkg of packages) {
            const result = this.getImportResult(pkg, language);
            if (result) {
                cached.push({ ...result, cached: true });
            } else {
                missing.push(pkg);
            }
        }

        return { cached, missing };
    }

    // ───────────────────────────────────────────────────
    //  DOCKER VERIFICATION
    // ───────────────────────────────────────────────────

    /** Get a cached Docker image verification result. */
    getDockerResult(image: string, tag: string): DockerImageResult | undefined {
        const cache = this.getDockerCache();
        const key = `${image}:${tag}`;
        const entry = cache[key];
        if (!entry) { return undefined; }
        if (this.isExpired(entry)) {
            this.removeDockerEntry(key);
            return undefined;
        }
        return entry.data;
    }

    /** Cache a Docker image verification result. */
    setDockerResult(image: string, tag: string, result: DockerImageResult): void {
        const cache = this.getDockerCache();
        const key = `${image}:${tag}`;
        cache[key] = { data: result, cachedAt: new Date().toISOString() };
        this.globalState.update(DOCKER_CACHE_KEY, cache);
    }

    /** Cache multiple Docker results at once. */
    setDockerResults(results: DockerImageResult[]): void {
        const cache = this.getDockerCache();
        const now = new Date().toISOString();
        for (const result of results) {
            const key = `${result.image}:${result.tag}`;
            cache[key] = { data: result, cachedAt: now };
        }
        this.globalState.update(DOCKER_CACHE_KEY, cache);
    }

    // ───────────────────────────────────────────────────
    //  MANAGEMENT
    // ───────────────────────────────────────────────────

    /** Clear all cached verification results. */
    clearAll(): void {
        this.globalState.update(IMPORT_CACHE_KEY, {});
        this.globalState.update(DOCKER_CACHE_KEY, {});
    }

    /** Get cache statistics. */
    getStats(): { imports: number; docker: number } {
        return {
            imports: Object.keys(this.getImportCache()).length,
            docker: Object.keys(this.getDockerCache()).length,
        };
    }

    // ───────────────────────────────────────────────────
    //  INTERNAL
    // ───────────────────────────────────────────────────

    private getImportCache(): Record<string, CacheEntry<PackageResult>> {
        return this.globalState.get<Record<string, CacheEntry<PackageResult>>>(
            IMPORT_CACHE_KEY, {},
        );
    }

    private getDockerCache(): Record<string, CacheEntry<DockerImageResult>> {
        return this.globalState.get<Record<string, CacheEntry<DockerImageResult>>>(
            DOCKER_CACHE_KEY, {},
        );
    }

    private isExpired<T>(entry: CacheEntry<T>): boolean {
        const age = Date.now() - new Date(entry.cachedAt).getTime();
        return age > CACHE_TTL_MS;
    }

    private removeImportEntry(key: string): void {
        const cache = this.getImportCache();
        delete cache[key];
        this.globalState.update(IMPORT_CACHE_KEY, cache);
    }

    private removeDockerEntry(key: string): void {
        const cache = this.getDockerCache();
        delete cache[key];
        this.globalState.update(DOCKER_CACHE_KEY, cache);
    }
}
