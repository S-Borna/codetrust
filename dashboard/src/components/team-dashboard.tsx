"use client";

import { useEffect, useMemo, useState } from "react";
import {
    apiClient,
    type OrganizationInfo,
    type OrganizationMember,
    type OrganizationPolicy,
    type OrganizationRole,
} from "@/lib/api";

const DEFAULT_POLICY: OrganizationPolicy = {
    max_severity_allowed: "BLOCK",
    require_license_compliance: false,
    blocked_licenses: [],
    require_vuln_scan: false,
    max_critical_vulns: 0,
    max_high_vulns: 0,
};

const ROLE_OPTIONS: OrganizationRole[] = ["owner", "admin", "member", "viewer"];
const SEVERITY_OPTIONS: OrganizationPolicy["max_severity_allowed"][] = ["INFO", "WARN", "BLOCK"];

interface TeamDashboardProps {
    apiKey: string;
    initialOrgs: OrganizationInfo[];
}

export function TeamDashboard({ apiKey, initialOrgs }: TeamDashboardProps) {
    const [orgs, setOrgs] = useState<OrganizationInfo[]>(initialOrgs);
    const initialSelectedOrgId = initialOrgs.length > 0 ? initialOrgs[0].id : "";
    const [selectedOrgId, setSelectedOrgId] = useState<string>(initialSelectedOrgId);
    const [members, setMembers] = useState<OrganizationMember[]>([]);
    const [policy, setPolicy] = useState<OrganizationPolicy>(DEFAULT_POLICY);
    const [newOrgName, setNewOrgName] = useState<string>("");
    const [newMemberUserId, setNewMemberUserId] = useState<string>("");
    const [newMemberRole, setNewMemberRole] = useState<OrganizationRole>("member");
    const [isBusy, setIsBusy] = useState<boolean>(false);
    const [statusMessage, setStatusMessage] = useState<string>("");

    const selectedOrg = useMemo(
        () => orgs.find((org) => org.id === selectedOrgId) ?? null,
        [orgs, selectedOrgId],
    );
    const selectedOrgPlan = selectedOrg ? selectedOrg.plan : "-";
    const selectedOrgOwner = selectedOrg ? selectedOrg.owner_id : "-";
    const selectedOrgMembers = selectedOrg ? selectedOrg.member_count : 0;

    useEffect(() => {
        async function loadOrgDetails(): Promise<void> {
            if (!selectedOrgId) {
                setMembers([]);
                setPolicy(DEFAULT_POLICY);
                return;
            }

            setIsBusy(true);
            setStatusMessage("");
            const [loadedMembers, loadedPolicy] = await Promise.all([
                apiClient.listOrganizationMembers(apiKey, selectedOrgId),
                apiClient.getOrganizationPolicy(apiKey, selectedOrgId),
            ]);
            setMembers(loadedMembers);
            setPolicy(loadedPolicy ?? DEFAULT_POLICY);
            setIsBusy(false);
        }

        void loadOrgDetails();
    }, [apiKey, selectedOrgId]);

    async function handleCreateOrg(): Promise<void> {
        const trimmed = newOrgName.trim();
        if (!trimmed) {
            setStatusMessage("Organization name is required.");
            return;
        }

        setIsBusy(true);
        setStatusMessage("");
        const created = await apiClient.createOrganization(apiKey, trimmed);
        if (!created) {
            setStatusMessage("Could not create organization. Check permissions/API key.");
            setIsBusy(false);
            return;
        }

        const updated = [...orgs, created];
        setOrgs(updated);
        setSelectedOrgId(created.id);
        setNewOrgName("");
        setStatusMessage(`Created organization ${created.name}.`);
        setIsBusy(false);
    }

    async function handleAddMember(): Promise<void> {
        if (!selectedOrgId) {
            setStatusMessage("Select an organization first.");
            return;
        }

        const userId = newMemberUserId.trim();
        if (!userId) {
            setStatusMessage("Member user id is required.");
            return;
        }

        setIsBusy(true);
        setStatusMessage("");
        const added = await apiClient.addOrganizationMember(
            apiKey,
            selectedOrgId,
            userId,
            newMemberRole,
        );
        if (!added) {
            setStatusMessage("Could not add member. Validate user id and role permissions.");
            setIsBusy(false);
            return;
        }

        const refreshed = await apiClient.listOrganizationMembers(apiKey, selectedOrgId);
        setMembers(refreshed);
        setNewMemberUserId("");
        setNewMemberRole("member");
        setStatusMessage(`Added member ${added.user_id}.`);
        setIsBusy(false);
    }

    async function handleRoleChange(userId: string, role: OrganizationRole): Promise<void> {
        if (!selectedOrgId) {
            return;
        }
        if (!ROLE_OPTIONS.includes(role)) {
            setStatusMessage("Invalid role selected.");
            return;
        }

        setIsBusy(true);
        setStatusMessage("");
        const ok = await apiClient.updateOrganizationMemberRole(apiKey, selectedOrgId, userId, role);
        if (!ok) {
            setStatusMessage(`Could not update role for ${userId}.`);
            setIsBusy(false);
            return;
        }

        const refreshed = await apiClient.listOrganizationMembers(apiKey, selectedOrgId);
        setMembers(refreshed);
        setStatusMessage(`Updated role for ${userId}.`);
        setIsBusy(false);
    }

    async function handleRemoveMember(userId: string): Promise<void> {
        if (!selectedOrgId) {
            return;
        }

        setIsBusy(true);
        setStatusMessage("");
        const ok = await apiClient.removeOrganizationMember(apiKey, selectedOrgId, userId);
        if (!ok) {
            setStatusMessage(`Could not remove member ${userId}.`);
            setIsBusy(false);
            return;
        }

        const refreshed = await apiClient.listOrganizationMembers(apiKey, selectedOrgId);
        setMembers(refreshed);
        setStatusMessage(`Removed member ${userId}.`);
        setIsBusy(false);
    }

    async function handleSavePolicy(): Promise<void> {
        if (!selectedOrgId) {
            setStatusMessage("Select an organization first.");
            return;
        }

        setIsBusy(true);
        setStatusMessage("");
        const ok = await apiClient.updateOrganizationPolicy(apiKey, selectedOrgId, policy);
        if (!ok) {
            setStatusMessage("Could not update policy. Check role permissions.");
            setIsBusy(false);
            return;
        }

        setStatusMessage("Policy updated.");
        setIsBusy(false);
    }

    return (
        <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4">
                    <h2 className="text-base font-semibold text-gray-900 dark:text-white">Organizations</h2>
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                        Create and switch organizations for team governance.
                    </p>
                    <div className="mt-4 flex gap-2">
                        <input
                            value={newOrgName}
                            onChange={(event) => setNewOrgName(event.target.value)}
                            className="flex-1 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                            placeholder="New organization name"
                        />
                        <button
                            onClick={() => void handleCreateOrg()}
                            disabled={isBusy}
                            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                        >
                            Create
                        </button>
                    </div>
                    <select
                        value={selectedOrgId}
                        onChange={(event) => setSelectedOrgId(event.target.value)}
                        className="mt-3 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                    >
                        {orgs.length === 0 ? <option value="">No organizations</option> : null}
                        {orgs.map((org) => (
                            <option key={org.id} value={org.id}>
                                {org.name} ({org.member_count} members)
                            </option>
                        ))}
                    </select>
                </div>

                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4">
                    <h2 className="text-base font-semibold text-gray-900 dark:text-white">Selected Org</h2>
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                        {selectedOrg ? `${selectedOrg.name} (${selectedOrg.slug})` : "No organization selected"}
                    </p>
                    <div className="mt-3 text-sm text-gray-700 dark:text-gray-300">
                        <p>Plan: <span className="font-medium">{selectedOrgPlan}</span></p>
                        <p>Owner: <span className="font-medium">{selectedOrgOwner}</span></p>
                        <p>Members: <span className="font-medium">{selectedOrgMembers}</span></p>
                    </div>
                </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4">
                    <h2 className="text-base font-semibold text-gray-900 dark:text-white">Members</h2>
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                        Add users and manage roles for the selected organization.
                    </p>

                    <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
                        <input
                            value={newMemberUserId}
                            onChange={(event) => setNewMemberUserId(event.target.value)}
                            className="rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm sm:col-span-2"
                            placeholder="User id"
                        />
                        <select
                            value={newMemberRole}
                            onChange={(event) => setNewMemberRole(event.target.value as OrganizationRole)}
                            className="rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                        >
                            {ROLE_OPTIONS.map((role) => (
                                <option key={role} value={role}>{role}</option>
                            ))}
                        </select>
                        <button
                            onClick={() => void handleAddMember()}
                            disabled={isBusy || !selectedOrgId}
                            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 sm:col-span-3"
                        >
                            Add Member
                        </button>
                    </div>

                    <div className="mt-4 overflow-x-auto">
                        <table className="min-w-full text-sm">
                            <thead>
                                <tr className="text-left text-gray-500 dark:text-gray-400">
                                    <th className="py-2">User</th>
                                    <th className="py-2">Role</th>
                                    <th className="py-2">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {members.map((member) => (
                                    <tr key={member.id} className="border-t border-gray-100 dark:border-gray-800">
                                        <td className="py-2">
                                            <div className="font-medium text-gray-900 dark:text-white">{member.user_id}</div>
                                            <div className="text-xs text-gray-500 dark:text-gray-400">{member.email || member.name || "-"}</div>
                                        </td>
                                        <td className="py-2">
                                            <select
                                                value={member.role}
                                                onChange={(event) => void handleRoleChange(member.user_id, event.target.value as OrganizationRole)}
                                                className="rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-2 py-1 text-xs"
                                            >
                                                {ROLE_OPTIONS.map((role) => (
                                                    <option key={role} value={role}>{role}</option>
                                                ))}
                                            </select>
                                        </td>
                                        <td className="py-2">
                                            <button
                                                onClick={() => void handleRemoveMember(member.user_id)}
                                                className="rounded border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50"
                                            >
                                                Remove
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                                {members.length === 0 ? (
                                    <tr>
                                        <td colSpan={3} className="py-3 text-sm text-gray-500 dark:text-gray-400">
                                            No members loaded.
                                        </td>
                                    </tr>
                                ) : null}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4">
                    <h2 className="text-base font-semibold text-gray-900 dark:text-white">Policy</h2>
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                        Configure severity and license/vulnerability gates for this organization.
                    </p>

                    <div className="mt-4 grid grid-cols-1 gap-3">
                        <label className="text-sm text-gray-700 dark:text-gray-300">
                            Max severity allowed
                            <select
                                value={policy.max_severity_allowed}
                                onChange={(event) => setPolicy({ ...policy, max_severity_allowed: event.target.value as OrganizationPolicy["max_severity_allowed"] })}
                                className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                            >
                                {SEVERITY_OPTIONS.map((severity) => (
                                    <option key={severity} value={severity}>{severity}</option>
                                ))}
                            </select>
                        </label>

                        <label className="text-sm text-gray-700 dark:text-gray-300">
                            Blocked licenses (comma-separated)
                            <input
                                value={policy.blocked_licenses.join(", ")}
                                onChange={(event) => {
                                    const licenses = event.target.value
                                        .split(",")
                                        .map((value) => value.trim())
                                        .filter((value) => value.length > 0);
                                    setPolicy({ ...policy, blocked_licenses: licenses });
                                }}
                                className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                            />
                        </label>

                        <div className="grid grid-cols-2 gap-3">
                            <label className="text-sm text-gray-700 dark:text-gray-300">
                                Max critical vulns
                                <input
                                    type="number"
                                    min={0}
                                    value={policy.max_critical_vulns}
                                    onChange={(event) => setPolicy({ ...policy, max_critical_vulns: Number(event.target.value) })}
                                    className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                                />
                            </label>
                            <label className="text-sm text-gray-700 dark:text-gray-300">
                                Max high vulns
                                <input
                                    type="number"
                                    min={0}
                                    value={policy.max_high_vulns}
                                    onChange={(event) => setPolicy({ ...policy, max_high_vulns: Number(event.target.value) })}
                                    className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                                />
                            </label>
                        </div>

                        <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                            <input
                                type="checkbox"
                                checked={policy.require_license_compliance}
                                onChange={(event) => setPolicy({ ...policy, require_license_compliance: event.target.checked })}
                            />
                            Require license compliance
                        </label>

                        <label className="inline-flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                            <input
                                type="checkbox"
                                checked={policy.require_vuln_scan}
                                onChange={(event) => setPolicy({ ...policy, require_vuln_scan: event.target.checked })}
                            />
                            Require vulnerability scan
                        </label>

                        <button
                            onClick={() => void handleSavePolicy()}
                            disabled={isBusy || !selectedOrgId}
                            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                        >
                            Save Policy
                        </button>
                    </div>
                </div>
            </div>

            <p className="text-sm text-gray-600 dark:text-gray-400" role="status">
                {isBusy ? "Working..." : statusMessage}
            </p>
        </div>
    );
}
