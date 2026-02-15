import { GovernanceAuditView } from "@/components/governance-audit";

/**
 * Governance page — displays audit log from .codetrust/audit.jsonl.
 *
 * In production, this would fetch from the API. For now, it shows
 * the structure with placeholder data. The actual data comes from
 * the gateway MCP server's audit_history tool or the CLI's
 * `codetrust audit` command.
 */
export default function GovernancePage() {
    // Placeholder data — in production, fetch from /v1/governance/audit
    const placeholderEntries = [
        {
            timestamp: Date.now() / 1000,
            action_type: "terminal_command",
            verdict: "BLOCK",
            rule_id: "gateway_heredoc",
            original_action: "cat << EOF > README.md",
            message: "Heredoc detected in terminal command.",
            agent_id: "claude",
            session_id: "gateway-1739500000",
        },
        {
            timestamp: Date.now() / 1000 - 60,
            action_type: "terminal_command",
            verdict: "ALLOW",
            rule_id: "",
            original_action: "pytest tests/ -v",
            message: "",
            agent_id: "copilot",
            session_id: "gateway-1739500000",
        },
    ];

    const placeholderStats = {
        total: 2,
        by_verdict: { BLOCK: 1, ALLOW: 1 },
        by_action_type: { terminal_command: 2 },
        top_rules: [{ rule_id: "gateway_heredoc", count: 1 }],
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Governance
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    AI agent action audit log — every terminal command, file write,
                    and package install is logged and validated.
                </p>
            </div>

            <GovernanceAuditView
                entries={placeholderEntries}
                stats={placeholderStats}
            />

            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                    Query Audit Log
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                    Use the CLI or MCP tools to query the full audit log:
                </p>
                <div className="space-y-2 font-mono text-sm text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                    <p>$ codetrust audit --hours 24</p>
                    <p>$ codetrust audit --verdict BLOCK --stats</p>
                    <p className="text-gray-400"># Or via MCP: codetrust_audit_history</p>
                </div>
            </div>
        </div>
    );
}
