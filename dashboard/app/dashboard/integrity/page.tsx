/**
 * Agent Integrity dashboard page — behavioral patterns and CLI reference.
 */

const PATTERNS = [
    {
        name: "Sycophantic Retraction",
        description: "Agent agrees emphatically then reverses position without new evidence.",
        weight: -4,
        color: "red" as const,
    },
    {
        name: "Contradictory Positions",
        description: "Opposite stances within 3 messages without intervening evidence.",
        weight: -5,
        color: "red" as const,
    },
    {
        name: "Unsubstantiated Claims",
        description: "Factual assertions without corresponding verification in session history.",
        weight: -3,
        color: "yellow" as const,
    },
    {
        name: "Unverified References",
        description: "File:line citations without file reads in session.",
        weight: -1,
        color: "yellow" as const,
    },
];

function weightBadge(color: "red" | "yellow"): string {
    if (color === "red") return "text-red-600 bg-red-100 dark:bg-red-900/30 dark:text-red-400";
    return "text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30 dark:text-yellow-400";
}

export default function IntegrityPage() {
    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Agent Integrity
            </h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Detects behavioral patterns that indicate unreliable AI agent output.
            </p>

            {/* Status banner */}
            <div className="mt-6 flex items-center gap-3 rounded-lg border border-green-200 dark:border-green-900 bg-green-50 dark:bg-green-950 p-4">
                <span className="text-green-600 text-lg">&#10003;</span>
                <div>
                    <p className="text-sm font-medium text-green-800 dark:text-green-200">Integrity analysis is active</p>
                    <p className="text-xs text-green-600 dark:text-green-400">Available via CLI, MCP gateway, and API. Calibrated against 20 real session incidents.</p>
                </div>
            </div>

            {/* Detection patterns */}
            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Detection Patterns
                </h2>
                <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                    {PATTERNS.map((p) => (
                        <div key={p.name} className="rounded-lg border p-5">
                            <div className="flex items-center justify-between mb-2">
                                <h3 className="font-semibold text-gray-900 dark:text-white text-sm">{p.name}</h3>
                                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${weightBadge(p.color)}`}>
                                    {p.weight}
                                </span>
                            </div>
                            <p className="text-sm text-gray-500 dark:text-gray-400">{p.description}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* How scoring works */}
            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    How it works
                </h2>
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                    Each session starts at 100. Pattern detections subtract their weight.
                    Final verdict: <strong className="text-green-600">Trustworthy</strong> (80+),{" "}
                    <strong className="text-yellow-600">Questionable</strong> (50-79),{" "}
                    <strong className="text-red-600">Unreliable</strong> (&lt;50).
                </p>
            </div>

            {/* CLI reference */}
            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Check integrity
                </h2>
                <pre className="mt-3 rounded-lg bg-gray-900 p-4 text-sm text-green-400 overflow-x-auto">
{`$ codetrust integrity check --last 3
Session 1: TRUSTWORTHY (score: 96)
Session 2: QUESTIONABLE (score: 62, sycophantic_retraction x2)
Session 3: TRUSTWORTHY (score: 100)`}
                </pre>
            </div>
        </div>
    );
}
