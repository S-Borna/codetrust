import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { SettingsForm } from "@/components/settings-form";
import { fetchUserQuota } from "@/lib/dashboard-api";

export default async function SettingsPage() {
    const session = await getServerSession(authOptions);
    const apiKey = session?.user?.apiKey || "";
    const quota = await fetchUserQuota(apiKey);

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Settings
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Manage your account and subscription
                </p>
            </div>

            <SettingsForm
                user={session?.user}
                apiKey={apiKey}
                trialEnd={session?.user?.trialEnd || null}
                quota={quota}
            />
        </div>
    );
}
