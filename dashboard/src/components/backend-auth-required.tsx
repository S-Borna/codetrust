export function BackendAuthRequired() {
    return (
        <div className="rounded-xl border border-amber-200 bg-amber-50/80 p-6 dark:border-amber-800 dark:bg-amber-950/30">
            <h2 className="text-lg font-semibold text-amber-900 dark:text-amber-200">
                Backend Auth Not Configured
            </h2>
            <p className="mt-2 text-sm text-amber-800 dark:text-amber-300">
                The dashboard could not bootstrap a user API key from the backend. Configure
                CODETRUST_API_KEY on the dashboard server and ensure /v1/admin/dashboard/bootstrap-api-key
                is reachable.
            </p>
        </div>
    );
}
