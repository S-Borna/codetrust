/**
 * Compliance dashboard page — self-assessed framework mapping.
 * Honest: this maps CT features to framework risks. It does NOT
 * verify code against compliance requirements.
 */

import Link from "next/link";

const FRAMEWORKS = [
    {
        id: "owasp_asi",
        name: "OWASP ASI 2026",
        risks: 10,
        covered: 10,
        description: "Agentic Security Initiative — top 10 risks for AI agent systems.",
    },
    {
        id: "eu_ai_act",
        name: "EU AI Act",
        risks: 7,
        covered: 7,
        description: "High-risk AI system requirements under the EU AI Act.",
    },
    {
        id: "nist_rmf",
        name: "NIST AI RMF 1.0",
        risks: 4,
        covered: 4,
        description: "AI Risk Management Framework — govern, map, measure, manage.",
    },
    {
        id: "nis2",
        name: "NIS2 Directive",
        risks: 7,
        covered: 3,
        description: "EU 2022/2555 Art. 21 — technical measures (supply chain, secure development, effectiveness) mapped; organizational measures (incident reporting, continuity, MFA) are out of scope.",
    },
];

export default function CompliancePage() {
    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Compliance Mapping
            </h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Self-assessed mapping of CodeTrust capabilities to regulatory frameworks.
                This is a feature-to-risk mapping — not a certified compliance audit.
            </p>

            {/* Info banner */}
            <div className="mt-6 flex items-start gap-3 rounded-lg border border-blue-200 dark:border-blue-900 bg-blue-50 dark:bg-blue-950 p-4">
                <span className="text-blue-500 mt-0.5">&#9432;</span>
                <p className="text-sm text-blue-700 dark:text-blue-300">
                    These mappings show which CodeTrust features address each framework risk.
                    They are not third-party audited certifications. Verify via CLI for evidence with file:line references.
                </p>
            </div>

            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
                {FRAMEWORKS.map((fw) => {
                    const partial = fw.covered < fw.risks;
                    return (
                        <div key={fw.id} className="rounded-lg border p-6">
                            <p className="text-sm font-semibold text-gray-900 dark:text-white">{fw.name}</p>
                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{fw.description}</p>
                            <p className="mt-3 text-2xl font-bold text-gray-900 dark:text-white">
                                {fw.covered}/{fw.risks}
                                <span className="ml-2 text-xs font-normal text-gray-400">
                                    {partial ? "measures mapped (partial)" : "risks mapped"}
                                </span>
                            </p>
                        </div>
                    );
                })}
            </div>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Verify with evidence
                </h2>
                <pre className="mt-3 rounded-lg bg-gray-900 p-4 text-sm text-green-400 overflow-x-auto">
{`$ codetrust compliance --framework owasp-asi-2026
# Shows each risk → CT feature → file:line evidence`}
                </pre>
            </div>

            <div className="mt-6">
                <Link
                    href="/dashboard/pricing"
                    className="text-sm text-brand-600 hover:text-brand-500 font-medium"
                >
                    Need certified compliance reports? See Enterprise plan &rarr;
                </Link>
            </div>
        </div>
    );
}
