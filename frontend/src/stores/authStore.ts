import { create } from "zustand";
import { persist } from "zustand/middleware";
import request from "../api/request";

interface User {
  id: number;
  username: string;
  role?: string;
  avatar?: string;
}

interface AuthState {
  token: string | null;
  user: User | null;
  initialized: boolean;
  loading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      initialized: false,
      loading: false,
      error: null,

      login: async (username: string, password: string) => {
        set({ loading: true, error: null });
        try {
          const res = await request.post("/auth/login", { username, password });
          const { access_token, user } = res.data;
          set({ token: access_token, user, loading: false, initialized: true });
        } catch (err: any) {
          const msg = err.response?.data?.detail || err.response?.data?.message || "登录失败，请检查账号密码";
          set({ loading: false, error: msg });
          throw new Error(msg);
        }
      },

      logout: () => {
        set({ token: null, user: null });
        localStorage.removeItem("auth-storage");
      },

      checkAuth: async () => {
        const { token } = get();
        if (!token) {
          set({ initialized: true });
          return;
        }
        try {
          const res = await request.get("/auth/me");
          set({ user: res.data, initialized: true });
        } catch {
          set({ token: null, user: null, initialized: true });
        }
      },
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({ token: state.token, user: state.user }),
    }
  )
);
