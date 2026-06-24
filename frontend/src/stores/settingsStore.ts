import { create } from "zustand";
import client from "../api/request";

interface SettingsState {
  settings: Record<string, string>;
  llmStatus: { configured: boolean; provider?: string } | null;
  loading: boolean;
  loadSettings: () => Promise<void>;
  saveSetting: (key: string, value: string) => Promise<boolean>;
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
  settings: {},
  llmStatus: null,
  loading: false,

  loadSettings: async () => {
    set({ loading: true });
    try {
      const [sRes, stRes] = await Promise.all([
        client.get("/settings/").catch(() => null),
        client.get("/settings/llm-status").catch(() => null),
      ]);
      set({
        settings: sRes?.data || {},
        llmStatus: stRes?.data || { configured: false, provider: "deepseek" },
      });
    } catch {
      // ignore
    } finally {
      set({ loading: false });
    }
  },

  saveSetting: async (key: string, value: string) => {
    try {
      await client.put("/settings/", { settings: { [key]: value } });
      // Refresh
      get().loadSettings();
      return true;
    } catch {
      return false;
    }
  },
}));
