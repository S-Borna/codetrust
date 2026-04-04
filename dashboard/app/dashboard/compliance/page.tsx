/**
 * Compliance dashboard page — OWASP ASI, EU AI Act, NIST RMF status.
 */

const frameworks = [
    { id: "owasp_asi", name: "OWASP ASI 2026", full: 10, total: 10 },
    { id: "eu_ai_act", name: "EU AI Act", full: 7, total: 7 },
    { id: "nist_rmf", name: "NIST AI RMF 1.0", full: 4, total: 4 },
];

export default function CompliancePage() {
    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Compliance
            </h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Regulatory compliance status across three enterprise frameworks.
            </p>

            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-3">
                {frameworks.map((fw) => (
                    <div key={fw.id} className="rounded-lg border p-6">
                        <p className="text-sm font-medium text-gray-500">{fw.name}</p>
                        <p className="mt-2 text-3xl font-bold text-green-600">
                            {fw.full}/{fw.total}
                        </p>
                        <span className="mt-2 inline-block rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-800 dark:bg-green-900 dark:text-green-200">
                            COMPLIANT
                        </span>
                    </div>
                ))}
            </div>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Verify via CLI
                </h2>
                <pre className="mt-2 rounded-lg bg-gray-900 p-4 text-sm text-green-400 overflow-x-auto">
{`$ codetrust compliance --framework owasp-asi-2026 --strict
COMPLIANT: 10/10 risks at full coverage

$ codetrust compliance --framework eu-ai-act --strict
COMPLIANT: 7/7 risks at full coverage

$ codetrust compliance --framework nist-ai-rmf --strict
COMPLIANT: 4/4 risks at full coverage`}
                </pre>
            </div>
        </div>
    );
}
