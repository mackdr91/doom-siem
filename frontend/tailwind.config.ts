/*
Author: Domonick Mack
Date: 2026-11-16
Description: Tailwind CSS configuration defining the Doom SOC Dark Ops design system tokens.
*/

import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        doom: {
          obsidian: "#060609",
          panel: "#0c0c12",
          elevated: "#12121b",
          border: "#1e1e2d",
          crimson: "#e11d48",
          amber: "#f59e0b",
          emerald: "#10b981",
        },
      },
      fontFamily: {
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};

export default config;
