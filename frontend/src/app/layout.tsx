/*
Author: Domonick Mack
Date: 2026-11-16
Description: Root application layout for the Doom SIEM Next.js Dark Ops console.
*/

import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DOOM // SOC Command & Telemetry Environment",
  description:
    "Next-generation Security Information & Event Management (SIEM) platform with Syslog/Webhook ingestion, MITRE ATT&CK detection, and AI threat triage.",
};

export const viewport: Viewport = {
  colorScheme: "light dark",
  themeColor: "#060609",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <meta name="color-scheme" content="light dark" />
      </head>
      <body className="min-h-screen bg-doom-obsidian text-zinc-100 antialiased selection:bg-doom-crimson selection:text-white">
        {children}
      </body>
    </html>
  );
}
