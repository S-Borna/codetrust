import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";

export const metadata: Metadata = {
    title: "CodeTrust — AI Code Verification Dashboard",
    description:
        "Manage API keys, view scan history, and monitor usage for CodeTrust.",
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body className="min-h-screen bg-gray-50 dark:bg-gray-950">
                <Providers>{children}</Providers>
                <div className="fixed bottom-3 right-3 z-50 opacity-80 hover:opacity-100 transition-opacity">
                    <a href="https://globaldex.ai/domain/codetrust.ai" target="_blank" rel="noopener noreferrer">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img src="https://globaldex.ai/api/v1/badge?domain=codetrust.ai" alt="GlobalDex Score" height={32} width={210} className="h-[28px] w-auto" referrerPolicy="no-referrer" />
                    </a>
                </div>
            </body>
        </html>
    );
}
