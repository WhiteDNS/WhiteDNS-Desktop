import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";

const packageVersion = JSON.parse(readFileSync(path.resolve(__dirname, "package.json"), "utf8")).version;
const appVersion = process.env.VITE_APP_VERSION?.trim() || process.env.VERSION?.trim() || packageVersion;

export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(appVersion) },
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    strictPort: true,
  },
});
