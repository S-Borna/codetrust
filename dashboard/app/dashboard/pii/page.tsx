/**
 * PII Detection dashboard page — scans, findings, categories, blocks.
 */

export default function PIIPage() {
    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                PII Detection
            </h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Personally identifiable information detection across 16 categories with policy enforcement.
            </p>

            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-4">
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Scans (24h)</p>
                    <p className="mt-1 text-3xl font-bold text-gray-900 dark:text-white">--</p>
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Findings (24h)</p>
                    <p className="mt-1 text-3xl font-bold text-yellow-600">--</p>
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Blocks (24h)</p>
                    <p className="mt-1 text-3xl font-bold text-red-600">--</p>
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Categories</p>
                    <p className="mt-1 text-3xl font-bold text-blue-600">16</p>
                </div>
            </div>

            <div className="mt-8 grid grid-cols-1 gap-8 lg:grid-cols-2">
                <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Detection Categories
                    </h2>
                    <ul className="mt-4 space-y-2">
                        {["email", "phone", "credit_card", "personnummer", "api_key",
                          "password", "private_key", "jwt", "iban", "ssn", "ip_address",
                          "url_credentials", "passport", "name", "address", "date_of_birth"].map((cat) => (
                            <li key={cat} className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                                <span className="h-2 w-2 rounded-full bg-blue-500" />
                                {cat.replace(/_/g, " ")}
                            </li>
                        ))}
                    </ul>
                </div>
                <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Policy Modes
                    </h2>
                    <div className="mt-4 space-y-3">
                        <div className="rounded border p-3">
                            <span className="font-medium text-red-600">BLOCK</span>
                            <span className="ml-2 text-sm text-gray-500">api_key, password, private_key, credit_card, personnummer, jwt, ssn, url_credentials</span>
                        </div>
                        <div className="rounded border p-3">
                            <span className="font-medium text-yellow-600">WARN</span>
                            <span className="ml-2 text-sm text-gray-500">email, phone, iban, ip_address, passport</span>
                        </div>
                        <div className="rounded border p-3">
                            <span className="font-medium text-gray-400">OFF</span>
                            <span className="ml-2 text-sm text-gray-500">name, address, date_of_birth</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
