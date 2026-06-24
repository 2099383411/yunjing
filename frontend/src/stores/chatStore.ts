import { create } from "zustand";

interface Message {
  role: "user" | "assistant";
  content: string;
  raw?: any;
}

interface ChatState {
  sessionId: string | null;
  messages: Message[];
  authorized: boolean;
  scanning: boolean;
  setSessionId: (id: string) => void;
  addMessage: (msg: Message) => void;
  setAuthorized: (v: boolean) => void;
  setScanning: (v: boolean) => void;
  clearMessages: () => void;
}

export const useChatStore = create<ChatState>((set) => ({
  sessionId: null,
  messages: [],
  authorized: false,
  scanning: false,
  setSessionId: (id) => set({ sessionId: id }),
  addMessage: (msg) => set((s) => ({ messages: [...s.messages, msg] })),
  setAuthorized: (v) => set({ authorized: v }),
  setScanning: (v) => set({ scanning: v }),
  clearMessages: () => set({ messages: [], sessionId: null }),
}));
