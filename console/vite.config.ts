import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
const target = process.env.FORGEFLOW_API_URL || "http://127.0.0.1:8787";
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    watch: { usePolling: true, interval: 700 },
    proxy: {
      "/api": {
        target,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", (req, incoming) => {
            if (incoming.headers.origin) req.setHeader("origin", target);
          });
        },
      },
    },
  },
});
