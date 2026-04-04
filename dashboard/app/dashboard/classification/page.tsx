/**
 * Data Classification dashboard page — sensitivity levels + model routing.
 */

const levels = [
    { name: "PUBLIC", color: "bg-green-500", desc: "Open source, docs, README, examples" },
    { name: "INTERNAL", color: "bg-blue-500", desc: "Business code, internal APIs, tests" },
    { name: "CONFIDENTIAL", color: "bg-yellow-500", desc: "Customer data, financial, HR, email/phone" },
    { name: "RESTRICTED", color: "bg-red-500", desc: "Credentials, PII critical, regulated data" },
];

export default function ClassificationPage() {
    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                Data Classification
            </h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Automatic sensitivity assessment with model routing enforcement.
            </p>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Sensitivity Levels
                </h2>
                <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    {levels.map((level) => (
                        <div key={level.name} className="rounded-lg border p-4">
                            <div className="flex items-center gap-2">
                                <span className={`h-3 w-3 rounded-full ${level.color}`} />
                                <span className="font-medium text-gray-900 dark:text-white">{level.name}</span>
                            </div>
                            <p className="mt-2 text-sm text-gray-500">{level.desc}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Model Routing Policy
                </h2>
                <div className="mt-4 rounded-lg border overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead className="bg-gray-50 dark:bg-gray-800">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Level</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Allowed Models</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                            <tr>
                                <td className="px-6 py-4 text-sm font-medium text-green-600">PUBLIC</td>
                                <td className="px-6 py-4 text-sm text-gray-500">All models (*)</td>
                                <td className="px-6 py-4"><span className="rounded bg-green-100 px-2 py-1 text-xs text-green-800">allow</span></td>
                            </tr>
                            <tr>
                                <td className="px-6 py-4 text-sm font-medium text-blue-600">INTERNAL</td>
                                <td className="px-6 py-4 text-sm text-gray-500">claude-*, gpt-4o, gpt-4o-mini</td>
                                <td className="px-6 py-4"><span className="rounded bg-blue-100 px-2 py-1 text-xs text-blue-800">allow approved</span></td>
                            </tr>
                            <tr>
                                <td className="px-6 py-4 text-sm font-medium text-yellow-600">CONFIDENTIAL</td>
                                <td className="px-6 py-4 text-sm text-gray-500">claude-opus-*, claude-sonnet-*, gpt-4o</td>
                                <td className="px-6 py-4"><span className="rounded bg-yellow-100 px-2 py-1 text-xs text-yellow-800">restricted</span></td>
                            </tr>
                            <tr>
                                <td className="px-6 py-4 text-sm font-medium text-red-600">RESTRICTED</td>
                                <td className="px-6 py-4 text-sm text-gray-500">No models</td>
                                <td className="px-6 py-4"><span className="rounded bg-red-100 px-2 py-1 text-xs text-red-800">block / redact</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    CLI Usage
                </h2>
                <pre className="mt-2 rounded-lg bg-gray-900 p-4 text-sm text-green-400 overflow-x-auto">
{`$ codetrust classify README.md
README.md ... PUBLIC (0.85)

$ codetrust classify src/ --model gpt-4o --report
Summary: 8 restricted, 11 confidential, 71 internal, 10 public
Model routing for gpt-4o: 81 allow, 11 allow, 8 block/redact`}
                </pre>
            </div>
        </div>
    );
}
