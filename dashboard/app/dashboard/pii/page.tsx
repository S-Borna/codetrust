/**
 * PII Detection dashboard page — policy overview and CLI reference.
 */

const BLOCK_CATEGORIES = [
    "api_key", "password", "private_key", "credit_card",
    "personnummer", "jwt", "ssn", "url_credentials",
];

const WARN_CATEGORIES = [
    "email", "phone", "iban", "ip_address", "passport",
];

const OFF_CATEGORIES = [
    "name", "address", "date_of_birth",
];

export default function PIIPage() {
    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                PII Detection
            </h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Active on every scan. 16 categories with Luhn, IBAN, and personnummer validation.
            </p>

            {/* Status banner */}
            <div className="mt-6 flex items-center gap-3 rounded-lg border border-green-200 dark:border-green-900 bg-green-50 dark:bg-green-950 p-4">
                <span className="text-green-600 text-lg">&#10003;</span>
                <div>
                    <p className="text-sm font-medium text-green-800 dark:text-green-200">PII detection is active</p>
                    <p className="text-xs text-green-600 dark:text-green-400">Enforced via gateway hooks and scan pipeline. Configure in <code className="font-mono">.codetrust/pii-policy.toml</code></p>
                </div>
            </div>

            {/* Policy modes */}
            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Enforcement Policy
                </h2>
                <div className="mt-4 space-y-3">
                    <div className="rounded-lg border border-red-200 dark:border-red-900 p-4">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-500" />
                            <span className="font-semibold text-red-600 dark:text-red-400 text-sm uppercase tracking-wide">Block</span>
                            <span className="text-xs text-gray-400 ml-auto">{BLOCK_CATEGORIES.length} categories</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {BLOCK_CATEGORIES.map((cat) => (
                                <span key={cat} className="rounded bg-red-100 dark:bg-red-900/30 px-2 py-0.5 text-xs font-mono text-red-700 dark:text-red-300">
                                    {cat}
                                </span>
                            ))}
                        </div>
                    </div>
                    <div className="rounded-lg border border-yellow-200 dark:border-yellow-900 p-4">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="inline-block h-2.5 w-2.5 rounded-full bg-yellow-500" />
                            <span className="font-semibold text-yellow-600 dark:text-yellow-400 text-sm uppercase tracking-wide">Warn</span>
                            <span className="text-xs text-gray-400 ml-auto">{WARN_CATEGORIES.length} categories</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {WARN_CATEGORIES.map((cat) => (
                                <span key={cat} className="rounded bg-yellow-100 dark:bg-yellow-900/30 px-2 py-0.5 text-xs font-mono text-yellow-700 dark:text-yellow-300">
                                    {cat}
                                </span>
                            ))}
                        </div>
                    </div>
                    <div className="rounded-lg border p-4">
                        <div className="flex items-center gap-2 mb-2">
                            <span className="inline-block h-2.5 w-2.5 rounded-full bg-gray-400" />
                            <span className="font-semibold text-gray-500 text-sm uppercase tracking-wide">Off</span>
                            <span className="text-xs text-gray-400 ml-auto">{OFF_CATEGORIES.length} categories</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {OFF_CATEGORIES.map((cat) => (
                                <span key={cat} className="rounded bg-gray-100 dark:bg-gray-800 px-2 py-0.5 text-xs font-mono text-gray-500">
                                    {cat}
                                </span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* CLI reference */}
            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Run a PII scan
                </h2>
                <pre className="mt-3 rounded-lg bg-gray-900 p-4 text-sm text-green-400 overflow-x-auto">
{`$ codetrust pii scan src/
Found 2 PII matches:
  src/config.py:14  api_key    BLOCK  confidence=0.95
  src/utils.py:88   email      WARN   confidence=0.70`}
                </pre>
            </div>
        </div>
    );
}
