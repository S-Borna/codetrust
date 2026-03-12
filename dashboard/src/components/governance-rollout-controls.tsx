"use client";

import { useEffect, useState } from "react";
import { governanceClient } from "@/lib/api";
import type {
    GovernancePolicyBundle,
    GovernanceSimulationOutcome,
} from "@/lib/api";

const DEFAULT_COMMANDS = [
    "git push",
    "rm -rf /tmp/cache",
    "npm install left-pad",
].join("\n");

interface GovernanceRolloutControlsProps {
    apiKey: string;
}

export function GovernanceRolloutControls({ apiKey }: GovernanceRolloutControlsProps) {
    const [bundles, setBundles] = useState<GovernancePolicyBundle[]>([]);
    const [selectedBundle, setSelectedBundle] = useState<string>("startup");
    const [commands, setCommands] = useState<string>(DEFAULT_COMMANDS);
    const [outcomes, setOutcomes] = useState<GovernanceSimulationOutcome[]>([]);
    const [status, setStatus] = useState<string>("");
    const [isBusy, setIsBusy] = useState<boolean>(false);

    useEffect(() => {
        async function loadBundles(): Promise<void> {
            const loaded = await governanceClient.listPolicyBundles(apiKey);
            setBundles(loaded);
            if (loaded.length > 0) {
                setSelectedBundle(loaded[0].bundle_id);
            }
        }

        void loadBundles();
    }, [apiKey]);

    async function runSimulation(): Promise<void> {
        const commandList = commands
            .split("\n")
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
        if (commandList.length === 0) {
            setStatus("Add at least one command to simulate.");
            return;
        }

        setIsBusy(true);
        setStatus("");
        const result = await governanceClient.simulatePolicy(
            apiKey,
            selectedBundle,
            commandList,
        );

        if (!result) {
            setStatus("Simulation failed. Verify API key and governance service availability.");
            setOutcomes([]);
            setIsBusy(false);
            return;
        }

        setOutcomes(result.outcomes);
        setStatus(`Simulation complete for ${result.bundle_id}.`);
        setIsBusy(false);
    }

    return (
        <section className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
            <div className="mb-4">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Policy Rollout Controls
                </h2>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Simulate bundle behavior before promoting policies across workspaces.
                </p>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
                <div>
                    <label className="text-sm text-gray-700 dark:text-gray-300">
                        Policy bundle
                        <select
                            value={selectedBundle}
                            onChange={(event) => setSelectedBundle(event.target.value)}
                            className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                        >
                            {bundles.map((bundle) => (
                                <option key={bundle.bundle_id} value={bundle.bundle_id}>
                                    {bundle.name} ({bundle.bundle_id})
                                </option>
                            ))}
                        </select>
                    </label>

                    <label className="mt-3 block text-sm text-gray-700 dark:text-gray-300">
                        Commands to simulate
                        <textarea
                            value={commands}
                            onChange={(event) => setCommands(event.target.value)}
                            rows={8}
                            className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm font-mono"
                        />
                    </label>

                    <button
                        onClick={() => void runSimulation()}
                        disabled={isBusy || selectedBundle.length === 0}
                        className="mt-3 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                    >
                        Run Simulation
                    </button>
                    <p className="mt-2 text-sm text-gray-600 dark:text-gray-400" role="status">{status}</p>
                </div>

                <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Simulation Outcomes</h3>
                    <div className="rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                        <table className="min-w-full text-sm">
                            <thead className="bg-gray-50 dark:bg-gray-800">
                                <tr className="text-left text-gray-500 dark:text-gray-400">
                                    <th className="px-3 py-2">Command</th>
                                    <th className="px-3 py-2">Verdict</th>
                                    <th className="px-3 py-2">Rule</th>
                                </tr>
                            </thead>
                            <tbody>
                                {outcomes.map((outcome) => (
                                    <tr key={`${outcome.command}-${outcome.rule_id}`} className="border-t border-gray-100 dark:border-gray-800">
                                        <td className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                                            {outcome.command}
                                        </td>
                                        <td className="px-3 py-2">
                                            <span className={`rounded px-2 py-1 text-xs font-medium ${outcome.verdict === "BLOCK"
                                                ? "bg-red-100 text-red-700"
                                                : outcome.verdict === "WARN"
                                                    ? "bg-amber-100 text-amber-700"
                                                    : "bg-green-100 text-green-700"
                                                }`}
                                            >
                                                {outcome.verdict}
                                            </span>
                                        </td>
                                        <td className="px-3 py-2 text-xs text-gray-500 dark:text-gray-400">
                                            {outcome.rule_id}
                                        </td>
                                    </tr>
                                ))}
                                {outcomes.length === 0 ? (
                                    <tr>
                                        <td className="px-3 py-3 text-sm text-gray-500 dark:text-gray-400" colSpan={3}>
                                            No simulation results yet.
                                        </td>
                                    </tr>
                                ) : null}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>
    );
}
