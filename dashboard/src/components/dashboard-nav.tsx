"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "next-auth/react";

/** Only allow avatar images from trusted HTTPS hosts. */
const TRUSTED_IMAGE_HOSTS = new Set([
    "avatars.githubusercontent.com",
    "lh3.googleusercontent.com",
]);

function isSafeImageUrl(url: string): boolean {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== "https:") return false;
        return TRUSTED_IMAGE_HOSTS.has(parsed.hostname);
    } catch {
        return false;
    }
}

interface NavUser {
    name?: string | null;
    email?: string | null;
    image?: string | null;
}

const CORE_LINKS = [
    { href: "/dashboard", label: "Overview" },
    { href: "/dashboard/enforcement", label: "Enforcement" },
    { href: "/dashboard/pii", label: "PII" },
    { href: "/dashboard/integrity", label: "Integrity" },
    { href: "/dashboard/settings", label: "Settings" },
] as const;

const PRO_LINKS = [
    { href: "/dashboard/cost", label: "Cost" },
    { href: "/dashboard/classification", label: "Classification" },
    { href: "/dashboard/governance", label: "Governance" },
    { href: "/dashboard/team", label: "Team" },
] as const;

export function DashboardNav({ user }: { user?: NavUser | null }) {
    const pathname = usePathname();
    const [mobileOpen, setMobileOpen] = useState(false);
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
                    <nav className="hidden sm:flex items-center gap-1 flex-wrap">
                        {CORE_LINKS.map((link) => (
                            <Link key={link.href} href={link.href} className={navClass(link.href)}>
                                {link.label}
                            </Link>
                        ))}
                        <span className="mx-1 h-4 w-px bg-gray-200 dark:bg-gray-700" />
                        {PRO_LINKS.map((link) => (
                            <Link key={link.href} href={link.href} className={navClass(link.href)}>
                                <span className="opacity-60">{link.label}</span>
                            </Link>
                        ))}
                    </nav>
                </div>

                <div className="flex items-center gap-4">
                    <span className="hidden sm:inline text-sm text-gray-600 dark:text-gray-400">
                        {displayName}
                    </span>
                    {user?.image && isSafeImageUrl(user.image) && (
                        <img
                            src={user.image}
                            alt=""
                            className="h-8 w-8 rounded-full"
                            referrerPolicy="no-referrer"
                        />
                    )}
                    <button
                        onClick={() => signOut({ callbackUrl: "/" })}
                        className="hidden sm:inline text-sm text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition"
                    >
                        Sign out
                    </button>
                    <button
                        onClick={() => setMobileOpen((prev) => !prev)}
                        className="sm:hidden p-2 rounded-lg text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                        aria-label={mobileOpen ? "Close menu" : "Open menu"}
                        aria-expanded={mobileOpen}
                    >
                        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            {mobileOpen ? (
                                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                            ) : (
                                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                            )}
                        </svg>
                    </button>
                </div>
            </div>

            {mobileOpen && (
                <nav className="sm:hidden border-t border-gray-200 dark:border-gray-800 px-6 py-3 flex flex-col gap-1">
                    {CORE_LINKS.map((link) => (
                        <Link
                            key={link.href}
                            href={link.href}
                            onClick={() => setMobileOpen(false)}
                            className={navClass(link.href)}
                        >
                            {link.label}
                        </Link>
                    ))}
                    <div className="my-1 border-t border-gray-200 dark:border-gray-700" />
                    <p className="px-3 py-1 text-xs font-medium text-gray-400 uppercase tracking-wider">Pro</p>
                    {PRO_LINKS.map((link) => (
                        <Link
                            key={link.href}
                            href={link.href}
                            onClick={() => setMobileOpen(false)}
                            className={navClass(link.href)}
                        >
                            {link.label}
                        </Link>
                    ))}
                    <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-800 flex items-center justify-between">
                        <span className="text-sm text-gray-600 dark:text-gray-400">
                            {displayName}
                        </span>
                        <button
                            onClick={() => signOut({ callbackUrl: "/" })}
                            className="text-sm text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition"
                        >
                            Sign out
                        </button>
                    </div>
                </nav>
            )}
        </header>
    );
}
