/**
 * Dashboard API client — fetches governance data from backend.
 * Polls /v1/dashboard/overview every 30 seconds for real-time updates.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://api.codetrust.ai";

interface FetchOptions {
    apiKey?: string;
    revalidate?: number;
}

async function dashboardFetch<T>(
    path: string,
    options: FetchOptions = {},
): Promise<T> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
    };
    if (options.apiKey) {
        headers["X-API-Key"] = options.apiKey;
    }

    const res = await fetch(`${API_BASE}${path}`, {
        headers,
        next: { revalidate: options.revalidate ?? 30 },
    });

    if (!res.ok) {
        throw new Error(`Dashboard API error: ${res.status} ${res.statusText}`);
    }

    return res.json() as Promise<T>;
}

/**
 * Live scan quota state for a single user.
 *
 * Fetched by the settings page server component to render the reduced
 * mode widget. Matches the response shape of GET /v1/user/quota.
 */
export interface UserQuota {
    plan: string;
    used: number;
    limit: number;
    exceeded: boolean;
    resets_at: string;
}

/**
 * Fetch the current user's scan quota from the backend API.
 *
 * Returns null (rather than throwing) on any failure so that the
 * settings page can render a graceful fallback instead of erroring
 * out if the backend is briefly unreachable.
 */
export async function fetchUserQuota(apiKey: string): Promise<UserQuota | null> {
    if (!apiKey) {
        return null;
    }
    try {
        return await dashboardFetch<UserQuota>("/v1/user/quota", {
            apiKey,
            revalidate: 60,
        });
    } catch {
        return null;
    }
}

export interface DashboardOverview {
    enforcement: {
        layers_active: number;
        total_blocks_24h: number;
        total_warns_24h: number;
        top_blocked_rules: Array<{ rule: string; count: number }>;
    };
    compliance: {
        owasp_asi: { status: string; full: number; total: number };
        eu_ai_act: { status: string; full: number; total: number };
        nist_rmf: { status: string; full: number; total: number };
    };
    pii: {
        scans_24h: number;
        findings_24h: number;
        top_categories: Array<[string, number]>;
        blocks_24h: number;
    };
    classification: {
        files_classified: number;
        by_level: Record<string, number>;
        routing_decisions_24h: number;
        routing_blocks_24h: number;
    };
    cost: {
        current_month_usd: number;
        budget_limit_usd: number;
        budget_pct: number;
        top_developer: { name: string; cost: number };
        top_model: { name: string; cost: number };
        anomalies_24h: number;
    };
    integrity: {
        sessions_analyzed: number;
        trustworthy: number;
        questionable: number;
        unreliable: number;
        top_issue: string;
    };
}

export interface TimelineEvent {
    timestamp: number;
    type: string;
    verdict: string;
    rule_id: string;
    message: string;
}

export interface DashboardAlert {
    type: string;
    severity: string;
    message: string;
}

export async function fetchOverview(apiKey?: string): Promise<DashboardOverview> {
    return dashboardFetch<DashboardOverview>("/v1/dashboard/overview", { apiKey, revalidate: 30 });
}

export async function fetchTimeline(hours: number = 24, apiKey?: string): Promise<{ events: TimelineEvent[] }> {
    return dashboardFetch<{ events: TimelineEvent[] }>(`/v1/dashboard/timeline?hours=${hours}`, { apiKey });
}

export async function fetchAlerts(apiKey?: string): Promise<{ alerts: DashboardAlert[] }> {
    return dashboardFetch<{ alerts: DashboardAlert[] }>("/v1/dashboard/alerts", { apiKey });
}
