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
      </body>
    </html>
  );
}
