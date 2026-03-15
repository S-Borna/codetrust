import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { apiClient } from "@/lib/api";
import { TeamDashboard } from "@/components/team-dashboard";
import { BackendAuthRequired } from "@/components/backend-auth-required";
import { PlanGate } from "@/components/plan-gate";

export default async function TeamPage() {
    const session = await getServerSession(authOptions);
    let plan = "free";
    if (session && session.user && session.user.plan) {
        plan = session.user.plan.toLowerCase();
    }
    const isEnterprise = plan === "enterprise";
    let apiKey = "";
    if (
        session
        && session.user
        && typeof session.user.apiKey === "string"
    ) {
        apiKey = session.user.apiKey;
    }
    if (!apiKey) {
        return <BackendAuthRequired />;
    }
    const orgs = isEnterprise ? await apiClient.listOrganizations(apiKey) : [];

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

            <PlanGate
                currentPlan={plan}
                requiredPlan="enterprise"
                title="Enterprise Feature"
                description="Team management is available on Enterprise. Upgrade to create organizations and manage team policies."
            >
                <TeamDashboard apiKey={apiKey} initialOrgs={orgs} />
            </PlanGate>
        </div>
    );
}
