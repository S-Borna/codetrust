/**
 * API client for communicating with the CodeTrust Python backend.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://api.codetrust.ai";

interface ScanLog {
    id: string;
    scan_type: string;
    verdict: string;
    findings_count: number;
    language: string;
    filename: string;
    latency_ms: number;
    created_at: string;
}

interface ScanHistoryResponse {
    scans: ScanLog[];
    page: number;
    per_page: number;
    total: number;
}

interface UsageDay {
    date: string;
    scan_count: number;
    findings_total: number;
    avg_latency_ms: number;
}

interface UsageStatsResponse {
    days: UsageDay[];
    total_scans: number;
    period_days: number;
}

interface ApiKeyInfo {
    id: string;
    name: string;
    prefix: string;
    is_revoked: boolean;
    created_at: string;
    last_used_at: string;
}

interface ApiKeyCreated {
    key: string;
    id: string;
    name: string;
    prefix: string;
}

async function apiFetch<T>(
    path: string,
    apiKey: string,
    options: RequestInit = {},
): Promise<T> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
        ...(options.headers as Record<string, string> || {}),
    };

    const res = await fetch(`${API_URL}${path}`, {
        ...options,
        headers,
        cache: "no-store",
    });

    if (!res.ok) {
        throw new Error(`API error: ${res.status} ${res.statusText}`);
    }

    return res.json() as Promise<T>;
}

export const apiClient = {
    async getScanHistory(
        apiKey: string,
        page = 1,
        perPage = 20,
    ): Promise<ScanHistoryResponse> {
        try {
            return await apiFetch<ScanHistoryResponse>(
                `/v1/scans/history?page=${page}&per_page=${perPage}`,
                apiKey,
            );
        } catch {
            return { scans: [], page: 1, per_page: perPage, total: 0 };
        }
    },

    async getUsageStats(apiKey: string, days = 30): Promise<UsageStatsResponse> {
        try {
            return await apiFetch<UsageStatsResponse>(
                `/v1/usage?days=${days}`,
                apiKey,
            );
        } catch {
            return { days: [], total_scans: 0, period_days: days };
        }
    },

    async listApiKeys(apiKey: string): Promise<ApiKeyInfo[]> {
        try {
            return await apiFetch<ApiKeyInfo[]>("/v1/api-keys", apiKey);
        } catch {
            return [];
        }
    },

    async createApiKey(
        apiKey: string,
        name: string,
    ): Promise<ApiKeyCreated | null> {
        try {
            return await apiFetch<ApiKeyCreated>("/v1/api-keys", apiKey, {
                method: "POST",
                body: JSON.stringify({ name }),
            });
        } catch {
            return null;
        }
    },

    async revokeApiKey(apiKey: string, keyId: string): Promise<boolean> {
        try {
            await apiFetch(`/v1/api-keys/${keyId}`, apiKey, { method: "DELETE" });
            return true;
        } catch {
            return false;
        }
    },

    async createCheckout(apiKey: string, plan: string): Promise<string> {
        try {
            const res = await apiFetch<{ url: string }>(
                "/v1/billing/checkout",
                apiKey,
                {
                    method: "POST",
                    body: JSON.stringify({ plan }),
                },
            );
            return res.url;
        } catch {
            return "";
        }
    },

    async createPortal(apiKey: string): Promise<string> {
        try {
            const res = await apiFetch<{ url: string }>(
                "/v1/billing/portal",
                apiKey,
                { method: "POST" },
            );
            return res.url;
        } catch {
            return "";
        }
    },
};

export type { ScanLog, ScanHistoryResponse, UsageDay, UsageStatsResponse, ApiKeyInfo, ApiKeyCreated };
