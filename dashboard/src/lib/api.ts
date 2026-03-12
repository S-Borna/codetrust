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

interface OrganizationInfo {
    id: string;
    name: string;
    slug: string;
    plan: string;
    owner_id: string;
    member_count: number;
    created_at: string;
}

interface OrganizationMember {
    id: string;
    user_id: string;
    email: string;
    name: string;
    role: "owner" | "admin" | "member" | "viewer";
    created_at: string;
}

interface OrganizationPolicy {
    max_severity_allowed: "INFO" | "WARN" | "BLOCK";
    require_license_compliance: boolean;
    blocked_licenses: string[];
    require_vuln_scan: boolean;
    max_critical_vulns: number;
    max_high_vulns: number;
}

type OrganizationRole = "owner" | "admin" | "member" | "viewer";

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

    async listOrganizations(apiKey: string): Promise<OrganizationInfo[]> {
        try {
            return await apiFetch<OrganizationInfo[]>("/v1/orgs", apiKey);
        } catch {
            return [];
        }
    },

    async createOrganization(
        apiKey: string,
        name: string,
    ): Promise<OrganizationInfo | null> {
        try {
            return await apiFetch<OrganizationInfo>("/v1/orgs", apiKey, {
                method: "POST",
                body: JSON.stringify({ name }),
            });
        } catch {
            return null;
        }
    },

    async listOrganizationMembers(
        apiKey: string,
        orgId: string,
    ): Promise<OrganizationMember[]> {
        try {
            return await apiFetch<OrganizationMember[]>(
                `/v1/orgs/${encodeURIComponent(orgId)}/members`,
                apiKey,
            );
        } catch {
            return [];
        }
    },

    async addOrganizationMember(
        apiKey: string,
        orgId: string,
        userId: string,
        role: OrganizationRole,
    ): Promise<OrganizationMember | null> {
        try {
            return await apiFetch<OrganizationMember>(
                `/v1/orgs/${encodeURIComponent(orgId)}/members`,
                apiKey,
                {
                    method: "POST",
                    body: JSON.stringify({ user_id: userId, role }),
                },
            );
        } catch {
            return null;
        }
    },

    async removeOrganizationMember(
        apiKey: string,
        orgId: string,
        userId: string,
    ): Promise<boolean> {
        try {
            await apiFetch(
                `/v1/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}`,
                apiKey,
                { method: "DELETE" },
            );
            return true;
        } catch {
            return false;
        }
    },

    async updateOrganizationMemberRole(
        apiKey: string,
        orgId: string,
        userId: string,
        role: OrganizationRole,
    ): Promise<boolean> {
        try {
            await apiFetch(
                `/v1/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userId)}/role`,
                apiKey,
                {
                    method: "PUT",
                    body: JSON.stringify({ role }),
                },
            );
            return true;
        } catch {
            return false;
        }
    },

    async getOrganizationPolicy(
        apiKey: string,
        orgId: string,
    ): Promise<OrganizationPolicy | null> {
        try {
            return await apiFetch<OrganizationPolicy>(
                `/v1/orgs/${encodeURIComponent(orgId)}/policy`,
                apiKey,
            );
        } catch {
            return null;
        }
    },

    async updateOrganizationPolicy(
        apiKey: string,
        orgId: string,
        policy: OrganizationPolicy,
    ): Promise<boolean> {
        try {
            await apiFetch(
                `/v1/orgs/${encodeURIComponent(orgId)}/policy`,
                apiKey,
                {
                    method: "PUT",
                    body: JSON.stringify(policy),
                },
            );
            return true;
        } catch {
            return false;
        }
    },
};

export type {
    ScanLog,
    ScanHistoryResponse,
    UsageDay,
    UsageStatsResponse,
    ApiKeyInfo,
    ApiKeyCreated,
    OrganizationInfo,
    OrganizationMember,
    OrganizationPolicy,
    OrganizationRole,
};

// --- Governance types ---

interface GovernanceAuditEntry {
    timestamp: number;
    action_type: string;
    verdict: string;
    rule_id: string;
    original_action: string;
    message: string;
    agent_id: string;
    session_id: string;
}

interface GovernanceAuditStats {
    total: number;
    by_verdict: Record<string, number>;
    by_action_type: Record<string, number>;
    top_rules: { rule_id: string; count: number }[];
}

interface GovernanceAuditResponse {
    entries: GovernanceAuditEntry[];
    stats: GovernanceAuditStats;
}

interface GovernancePosture {
    session_id: string;
    agent_id: string;
    mode: string;
    enabled: boolean;
    trusted_execution_mode: boolean;
    deny_native_execution: boolean;
    require_allow_reason: boolean;
    session_binding_enforced: boolean;
    anti_bypass_enabled: boolean;
    control_plane_ready: boolean;
    policy_integrity: {
        verdict: string;
        rule_id: string;
        policy_hash: string;
    };
    pending_approvals: number;
    active_exceptions: number;
}

interface GovernancePendingApproval {
    request_id: string;
    rule_id: string;
    action_type: string;
    original_action: string;
    action_fingerprint: string;
    requested_at: number;
    expires_at: number;
    session_id: string;
    agent_id: string;
}

interface GovernanceException {
    exception_id: string;
    rule_id: string;
    action_type: string;
    action_fingerprint: string;
    reason: string;
    approver: string;
    approver_role: string;
    created_at: number;
    expires_at: number;
    revoked_at: number;
    revoked_by: string;
    session_id: string;
    agent_id: string;
}

interface GovernanceApproveResult {
    approved: boolean;
    exception_id: string;
    expires_at: number;
}

interface GovernancePolicyBundle {
    bundle_id: string;
    name: string;
    target_tier: string;
    description: string;
    policy: Record<string, unknown>;
    signature: string;
    issued_at: string;
    version: string;
}

interface GovernanceSimulationOutcome {
    command: string;
    verdict: string;
    rule_id: string;
    message: string;
}

interface GovernanceSimulationResponse {
    bundle_id: string;
    outcomes: GovernanceSimulationOutcome[];
}

interface GovernanceWorkspacePosture {
    workspace_id: string;
    workspace_name: string;
    agent_id: string;
    enabled: boolean;
    mode: string;
    control_plane_ready: boolean;
    policy_hash: string;
    policy_verdict: string;
    pending_approvals: number;
    active_exceptions: number;
    drift_count: number;
    last_seen_at: number;
}

interface GovernanceWorkspaceAggregate {
    total_workspaces: number;
    healthy_count: number;
    drifted_count: number;
    disabled_count: number;
    total_pending_approvals: number;
    total_active_exceptions: number;
    workspaces: GovernanceWorkspacePosture[];
}

interface GovernanceUnifiedSession {
    session_token: string;
    surfaces: string[];
    issued_at: number;
    expires_at: number;
    agent_id: string;
    workspace_id: string;
    audit_chain_id: string;
}

interface GovernanceSessionStatus {
    valid: boolean;
    session_token: string;
    surfaces: string[];
    issued_at: number;
    expires_at: number;
    remaining_seconds: number;
    agent_id: string;
    workspace_id: string;
    audit_chain_id: string;
}

export const governanceClient = {
    async getAudit(
        apiKey: string,
        hours = 24,
        verdict?: string,
        limit = 100,
    ): Promise<GovernanceAuditResponse> {
        try {
            const params = new URLSearchParams({
                hours: String(hours),
                limit: String(limit),
            });
            if (verdict) params.set("verdict", verdict);
            return await apiFetch<GovernanceAuditResponse>(
                `/v1/governance/audit?${params.toString()}`,
                apiKey,
            );
        } catch {
            return {
                entries: [],
                stats: { total: 0, by_verdict: {}, by_action_type: {}, top_rules: [] },
            };
        }
    },

    async getPosture(apiKey: string): Promise<GovernancePosture | null> {
        try {
            return await apiFetch<GovernancePosture>(
                "/v1/governance/posture",
                apiKey,
            );
        } catch {
            return null;
        }
    },

    async listApprovals(apiKey: string): Promise<GovernancePendingApproval[]> {
        try {
            return await apiFetch<GovernancePendingApproval[]>(
                "/v1/governance/approvals",
                apiKey,
            );
        } catch {
            return [];
        }
    },

    async approveAction(
        apiKey: string,
        requestId: string,
        approver: string,
        reason: string,
        approverRole = "owner",
        ttlMinutes?: number,
    ): Promise<GovernanceApproveResult | null> {
        try {
            const body: Record<string, unknown> = {
                approver,
                approver_role: approverRole,
                reason,
            };
            if (ttlMinutes !== undefined) body.ttl_minutes = ttlMinutes;
            return await apiFetch<GovernanceApproveResult>(
                `/v1/governance/approvals/${requestId}/approve`,
                apiKey,
                { method: "POST", body: JSON.stringify(body) },
            );
        } catch {
            return null;
        }
    },

    async listExceptions(apiKey: string): Promise<GovernanceException[]> {
        try {
            return await apiFetch<GovernanceException[]>(
                "/v1/governance/exceptions",
                apiKey,
            );
        } catch {
            return [];
        }
    },

    async revokeException(
        apiKey: string,
        exceptionId: string,
    ): Promise<boolean> {
        try {
            await apiFetch(
                `/v1/governance/exceptions/${exceptionId}`,
                apiKey,
                { method: "DELETE" },
            );
            return true;
        } catch {
            return false;
        }
    },

    async listPolicyBundles(
        apiKey: string,
    ): Promise<GovernancePolicyBundle[]> {
        try {
            return await apiFetch<GovernancePolicyBundle[]>(
                "/v1/governance/policy-bundles",
                apiKey,
            );
        } catch {
            return [];
        }
    },

    async simulatePolicy(
        apiKey: string,
        bundleId: string,
        commands: string[],
    ): Promise<GovernanceSimulationResponse | null> {
        try {
            return await apiFetch<GovernanceSimulationResponse>(
                "/v1/governance/simulate-policy",
                apiKey,
                {
                    method: "POST",
                    body: JSON.stringify({
                        bundle_id: bundleId,
                        commands,
                    }),
                },
            );
        } catch {
            return null;
        }
    },

    async getWorkspaces(apiKey: string): Promise<GovernanceWorkspaceAggregate> {
        try {
            return await apiFetch<GovernanceWorkspaceAggregate>(
                "/v1/governance/workspaces",
                apiKey,
            );
        } catch {
            return {
                total_workspaces: 0,
                healthy_count: 0,
                drifted_count: 0,
                disabled_count: 0,
                total_pending_approvals: 0,
                total_active_exceptions: 0,
                workspaces: [],
            };
        }
    },

    async registerWorkspace(
        apiKey: string,
        workspaceId: string,
        workspaceName: string,
        agentId = "unknown",
        posture: Record<string, unknown> = {},
    ): Promise<GovernanceWorkspacePosture | null> {
        try {
            return await apiFetch<GovernanceWorkspacePosture>(
                "/v1/governance/workspaces",
                apiKey,
                {
                    method: "POST",
                    body: JSON.stringify({
                        workspace_id: workspaceId,
                        workspace_name: workspaceName,
                        agent_id: agentId,
                        posture,
                    }),
                },
            );
        } catch {
            return null;
        }
    },

    async issueSessionToken(
        apiKey: string,
        surfaces: string[],
        agentId = "unknown",
        workspaceId = "",
        ttlMinutes = 60,
    ): Promise<GovernanceUnifiedSession | null> {
        try {
            return await apiFetch<GovernanceUnifiedSession>(
                "/v1/governance/session-token",
                apiKey,
                {
                    method: "POST",
                    body: JSON.stringify({
                        surfaces,
                        agent_id: agentId,
                        workspace_id: workspaceId,
                        ttl_minutes: ttlMinutes,
                    }),
                },
            );
        } catch {
            return null;
        }
    },

    async validateSessionToken(
        apiKey: string,
        token: string,
    ): Promise<GovernanceSessionStatus | null> {
        try {
            return await apiFetch<GovernanceSessionStatus>(
                `/v1/governance/session-token/${encodeURIComponent(token)}`,
                apiKey,
            );
        } catch {
            return null;
        }
    },
};

export type {
    GovernanceAuditEntry,
    GovernanceAuditStats,
    GovernanceAuditResponse,
    GovernancePosture,
    GovernancePendingApproval,
    GovernanceException,
    GovernanceApproveResult,
    GovernancePolicyBundle,
    GovernanceSimulationOutcome,
    GovernanceSimulationResponse,
    GovernanceWorkspacePosture,
    GovernanceWorkspaceAggregate,
    GovernanceUnifiedSession,
    GovernanceSessionStatus,
};
