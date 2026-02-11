"use client";

import { apiClient } from "@/lib/api";

interface UserInfo {
  name?: string | null;
  email?: string | null;
  image?: string | null;
  plan?: string;
}

export function SettingsForm({ user }: { user?: UserInfo | null }) {
  const plan = user?.plan || "free";

  async function handleUpgrade() {
    const url = await apiClient.createCheckout("", "pro");
    if (url) {
      window.location.href = url;
    }
  }

  async function handleManageBilling() {
    const url = await apiClient.createPortal("");
    if (url) {
      window.location.href = url;
    }
  }

  return (
    <div className="space-y-6">
      {/* Profile */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
        <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
          Profile
        </h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
              Name
            </label>
            <p className="mt-1 text-gray-900 dark:text-white">
              {user?.name || "—"}
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
              Email
            </label>
            <p className="mt-1 text-gray-900 dark:text-white">
              {user?.email || "—"}
            </p>
          </div>
        </div>
      </div>

      {/* Subscription */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
        <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
          Subscription
        </h3>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-900 dark:text-white">
              Current plan:{" "}
              <span className="font-semibold text-brand-600 capitalize">
                {plan}
              </span>
            </p>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {plan === "free"
                ? "100 scans/day included"
                : plan === "pro"
                  ? "10,000 scans/day included"
                  : "100,000 scans/day included"}
            </p>
          </div>
          <div>
            {plan === "free" ? (
              <button
                onClick={handleUpgrade}
                className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 transition"
              >
                Upgrade to Pro
              </button>
            ) : (
              <button
                onClick={handleManageBilling}
                className="rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
              >
                Manage billing
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Danger zone */}
      <div className="rounded-xl border border-red-200 dark:border-red-800 bg-white dark:bg-gray-900 p-6">
        <h3 className="font-semibold text-red-600 dark:text-red-400 mb-4">
          Danger zone
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Deleting your account will revoke all API keys and remove all scan
          history. This action cannot be undone.
        </p>
        <button className="mt-4 rounded-lg border border-red-300 dark:border-red-700 px-4 py-2 text-sm font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950 transition">
          Delete account
        </button>
      </div>
    </div>
  );
}
