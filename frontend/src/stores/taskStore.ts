import { create } from "zustand";
import client from "../api/client";
import client from "../api/request";

interface TaskState {
  tasks: any[];
  loading: boolean;
  loadTasks: () => Promise<void>;
}

export const useTaskStore = create<TaskState>((set) => ({
  tasks: [],
  loading: false,
  loadTasks: async () => {
    set({ loading: true });
    try {
      const res = await client.get("/tasks/");
      set({ tasks: res.data || [] });
    } catch {
      // ignore
    } finally {
      set({ loading: false });
    }
  },
}));
