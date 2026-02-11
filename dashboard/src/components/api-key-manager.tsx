"use client";

import { useState } from "react";
import type { ApiKeyInfo } from "@/lib/api";
import { apiClient } from "@/lib/api";

export function ApiKeyManager({
  initialKeys,
}: {
  initialKeys: ApiKeyInfo[];
}) {
  const [keys, setKeys] = useState<ApiKeyInfo[]>(initialKeys);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleCreate() {
    if (!newKeyName.trim()) return;
    setLoading(true);
    const result = await apiClient.createApiKey("", newKeyName);
    if (result) {
      setCreatedKey(result.key);
      setKeys((prev) => [
        {
          id: result.id,
          name: result.name,
          prefix: result.prefix,
          is_revoked: false,
          created_at: new Date().toISOString(),
          last_used_at: "",
        },
        ...prev,
      ]);
      setNewKeyName("");
    }
    setLoading(false);
  }

  async function handleRevoke(keyId: string) {
    const confirmed = window.confirm(
      "Are you sure you want to revoke this API key? This cannot be undone.",
    );
    if (!confirmed) return;

    const success = await apiClient.revokeApiKey("", keyId);
    if (success) {
      setKeys((prev) =>
        prev.map((k) =>
          k.id === keyId ? { ...k, is_revoked: true } : k,
        ),
      );
    }
  }

  return (
    <div className="space-y-6">
      {/* Create form */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
        <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
          Create new API key
        </h3>
        <div className="flex gap-3">
          <input
            type="text"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            placeholder="Key name (e.g. CI Server)"
            className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-white placeholder-gray-400 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
          />
          <button
            onClick={handleCreate}
            disabled={loading || !newKeyName.trim()}
            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-50 transition"
          >
            {loading ? "Creating..." : "Create key"}
          </button>
        </div>

        {createdKey && (
          <div className="mt-4 rounded-lg bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 p-4">
            <p className="text-sm font-semibold text-green-800 dark:text-green-300">
              Key created! Copy it now — it won&apos;t be shown again.
            </p>
            <code className="mt-2 block rounded bg-green-100 dark:bg-green-900 p-2 text-xs font-mono text-green-900 dark:text-green-200 break-all">
              {createdKey}
            </code>
            <button
              onClick={() => {
                navigator.clipboard.writeText(createdKey);
              }}
              className="mt-2 text-xs text-green-700 dark:text-green-400 hover:underline"
            >
              Copy to clipboard
            </button>
          </div>
        )}
      </div>

      {/* Key list */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="font-semibold text-gray-900 dark:text-white">
            Your API keys
          </h3>
        </div>
        {keys.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-500 dark:text-gray-400">
            No API keys yet. Create one above.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-800">
              <tr>
                <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                  Name
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                  Key
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                  Status
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                  Created
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {keys.map((key) => (
                <tr key={key.id}>
                  <td className="px-6 py-4 text-gray-900 dark:text-white">
                    {key.name}
                  </td>
                  <td className="px-6 py-4 font-mono text-gray-600 dark:text-gray-400">
                    {key.prefix}...
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                        key.is_revoked
                          ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
                          : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
                      }`}
                    >
                      {key.is_revoked ? "Revoked" : "Active"}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-600 dark:text-gray-400">
                    {new Date(key.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4">
                    {!key.is_revoked && (
                      <button
                        onClick={() => handleRevoke(key.id)}
                        className="text-sm text-red-600 dark:text-red-400 hover:underline"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
