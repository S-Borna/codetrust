"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "next-auth/react";

interface NavUser {
    name?: string | null;
    email?: string | null;
    image?: string | null;
}

export function DashboardNav({ user }: { user?: NavUser | null }) {
    const pathname = usePathname();
    let displayName = "User";
    if (user && typeof user.name === "string" && user.name.length > 0) {
        displayName = user.name;
    } else if (user && typeof user.email === "string" && user.email.length > 0) {
        displayName = user.email;
    }

    function navClass(href: string): string {
        if (pathname === href) {
            return "rounded-lg px-3 py-2 text-sm font-medium transition bg-brand-50 dark:bg-brand-950 text-brand-700 dark:text-brand-300";
        }
        return "rounded-lg px-3 py-2 text-sm font-medium transition text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800";
    }

    return (
        <header className="border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
                <div className="flex items-center gap-8">
                    <Link
                        href="/dashboard"
                        className="text-lg font-bold text-brand-600"
                    >
                        CodeTrust
                    </Link>
                    <nav className="hidden sm:flex items-center gap-1">
                        <Link href="/dashboard" className={navClass("/dashboard")}>Overview</Link>
                        <Link href="/dashboard/team" className={navClass("/dashboard/team")}>Team</Link>
                        <Link href="/dashboard/api-keys" className={navClass("/dashboard/api-keys")}>API Keys</Link>
                        <Link href="/dashboard/governance" className={navClass("/dashboard/governance")}>Governance</Link>
                        <Link href="/dashboard/settings" className={navClass("/dashboard/settings")}>Settings</Link>
                    </nav>
                </div>

                <div className="flex items-center gap-4">
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                        {displayName}
                    </span>
                    {user?.image && (
                        <img
                            src={user.image}
                            alt=""
                            className="h-8 w-8 rounded-full"
                        />
                    )}
                    <button
                        onClick={() => signOut({ callbackUrl: "/" })}
                        className="text-sm text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition"
                    >
                        Sign out
                    </button>
                </div>
            </div>
        </header>
    );
}
