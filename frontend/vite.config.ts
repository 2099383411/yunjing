import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { port: 3000, proxy: { "/api": "http://backend:8000", "/ws": { target: "ws://backend:8000", ws: true } } },
  build: {
    rollupOptions: {
      treeshake: false,
      output: {
        manualChunks: {
          vendor: ["react", "react-dom", "react-router-dom"],
          antd: ["antd", "@ant-design/icons", "@ant-design/cssinjs"],
          xyflow: ["@xyflow/react"],
        },
      },
    },
    chunkSizeWarningLimit: 600,
  },
});
