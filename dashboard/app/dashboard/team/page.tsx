import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { apiClient } from "@/lib/api";
import { TeamDashboard } from "@/components/team-dashboard";

export default async function TeamPage() {
    const session = await getServerSession(authOptions);
    let apiKey = "";
    if (
        session
        && session.user
        && typeof session.user.apiKey === "string"
    ) {
        apiKey = session.user.apiKey;
    }
    const orgs = await apiClient.listOrganizations(apiKey);

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Team Dashboard
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Organization governance workflows: orgs, members, and policy settings.
                </p>
            </div>

            <TeamDashboard apiKey={apiKey} initialOrgs={orgs} />
        </div>
    );
}
