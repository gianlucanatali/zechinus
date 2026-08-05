import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// datacloak/'s pure-logic tests run on `node --test` (see package.json's "test"
// script); only the React hook bindings (react/useStore.ts and friends) need a DOM,
// so this config exists solely to run tests/**/*.test.tsx under jsdom.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    include: ["tests/**/*.test.tsx"],
  },
});
