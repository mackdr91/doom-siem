/*
Author: Domonick Mack
Date: 2026-11-16
Description: Next.js configuration enabling standalone container output for Doom SIEM.
*/

import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
};

export default nextConfig;
