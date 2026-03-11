// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * HTTP client for the CodeTrust API.
 * Handles all communication with the Python backend.
 */

import * as https from "https";
import * as http from "http";
import { URL } from "url";
import type {
    StaticScanResponse,
    DeepScanResponse,
    VerifyImportsResponse,
    VerifyDockerResponse,
    HealthResponse,
    Language,
    ExtensionConfig,
} from "./types";

const HTTPS_DEFAULT_PORT = 443;
const HTTP_DEFAULT_PORT = 80;
const HTTP_SUCCESS_MIN = 200;
const HTTP_SUCCESS_MAX_EXCLUSIVE = 300;

/** Rate limit usage info from API response headers. */
export interface RateLimitInfo {
    limit: number;
    remaining: number;
    used: number;
}

/** Error thrown when the API request fails. */
export class ApiError extends Error {
    constructor(
        message: string,
        public readonly statusCode: number,
        public readonly body: string,
    ) {
        super(message);
        this.name = "ApiError";
    }
}

/** HTTP client for CodeTrust API endpoints. */
export class ApiClient {
    private baseUrl: string;
    private apiKey: string;
    private timeoutMs: number;

    /** Last rate limit info from API response headers. */
    public lastRateLimit: RateLimitInfo | null = null;

    constructor(config: ExtensionConfig) {
        this.baseUrl = config.apiUrl.replace(/\/+$/, "");
        this.apiKey = config.apiKey;
        this.timeoutMs = config.timeout;
    }

    /** Update client configuration when settings change. */
    updateConfig(config: ExtensionConfig): void {
        this.baseUrl = config.apiUrl.replace(/\/+$/, "");
        this.apiKey = config.apiKey;
        this.timeoutMs = config.timeout;
    }

    /** Check API health. */
    async checkHealth(): Promise<HealthResponse> {
        return this.request<HealthResponse>("GET", "/v1/status");
    }

    /** Run static scan on code. */
    async staticScan(
        code: string,
        filename: string,
        language?: Language,
    ): Promise<StaticScanResponse> {
        const body: Record<string, unknown> = { code, filename };
        if (language) {
            body.language = language;
        }
        return this.request<StaticScanResponse>("POST", "/v1/scan/static", body);
    }

    /** Run deep scan on code (all layers). */
    async deepScan(
        code: string,
        filename: string,
        language?: Language,
        verifyImports: boolean = true,
    ): Promise<DeepScanResponse> {
        const body: Record<string, unknown> = {
            code,
            filename,
            verify_imports: verifyImports,
        };
        if (language) {
            body.language = language;
        }
        return this.request<DeepScanResponse>("POST", "/v1/scan/deep", body);
    }

    /** Verify package imports against registries. */
    async verifyImports(
        language: Language,
        imports: string[],
        requirements: string = "",
    ): Promise<VerifyImportsResponse> {
        return this.request<VerifyImportsResponse>("POST", "/v1/verify/imports", {
            language,
            imports,
            requirements,
        });
    }

    /** Verify Docker images and tags. */
    async verifyDockerfile(
        images: Array<{ image: string; tag: string }>,
    ): Promise<VerifyDockerResponse> {
        return this.request<VerifyDockerResponse>("POST", "/v1/verify/dockerfile", {
            images,
        });
    }

    /** Make an HTTP request to the CodeTrust API. */
    private request<T>(
        method: string,
        path: string,
        body?: Record<string, unknown>,
    ): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            const url = new URL(`${this.baseUrl}${path}`);
            const isHttps = url.protocol === "https:";
            const transport = isHttps ? https : http;

            const headers: Record<string, string> = {
                "Content-Type": "application/json",
                Accept: "application/json",
            };

            if (this.apiKey) {
                headers["X-API-Key"] = this.apiKey;
            }

            const payload = body ? JSON.stringify(body) : undefined;
            if (payload) {
                headers["Content-Length"] = Buffer.byteLength(payload).toString();
            }

            const options = {
                hostname: url.hostname,
                port: url.port || (isHttps ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT),
                path: url.pathname + url.search,
                method,
                headers,
                timeout: this.timeoutMs,
            };

            const req = transport.request(options, (res) => {
                const chunks: Buffer[] = [];
                res.on("data", (chunk: Buffer) => chunks.push(chunk));
                res.on("end", () => {
                    const responseBody = Buffer.concat(chunks).toString("utf-8");
                    const statusCode = res.statusCode ?? 0;

                    // Capture rate limit headers
                    const rlLimit = res.headers["x-ratelimit-limit"];
                    const rlRemaining = res.headers["x-ratelimit-remaining"];
                    const rlUsed = res.headers["x-ratelimit-used"];
                    if (rlLimit) {
                        this.lastRateLimit = {
                            limit: parseInt(String(rlLimit), 10) || 0,
                            remaining: parseInt(String(rlRemaining), 10) || 0,
                            used: parseInt(String(rlUsed), 10) || 0,
                        };
                    }

                    if (statusCode >= HTTP_SUCCESS_MIN && statusCode < HTTP_SUCCESS_MAX_EXCLUSIVE) {
                        try {
                            resolve(JSON.parse(responseBody) as T);
                        } catch {
                            reject(new ApiError("Invalid JSON response", statusCode, responseBody));
                        }
                    } else {
                        reject(
                            new ApiError(
                                `API returned ${statusCode}`,
                                statusCode,
                                responseBody,
                            ),
                        );
                    }
                });
            });

            req.on("error", (err: Error) => {
                reject(new ApiError(`Request failed: ${err.message}`, 0, ""));
            });

            req.on("timeout", () => {
                req.destroy();
                reject(new ApiError("Request timed out", 0, ""));
            });

            if (payload) {
                req.write(payload);
            }
            req.end();
        });
    }
}
