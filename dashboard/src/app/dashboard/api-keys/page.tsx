import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { ApiKeyManager } from "@/components/api-key-manager";
import { apiClient } from "@/lib/api";

export default async function ApiKeysPage() {
  const session = await getServerSession(authOptions);
  const apiKey = session?.user?.apiKey || "";

  const keys = await apiClient.listApiKeys(apiKey);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          API Keys
        </h1>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
          Create and manage API keys for the CodeTrust API
        </p>
      </div>

      <ApiKeyManager initialKeys={keys} />
    </div>
  );
}
