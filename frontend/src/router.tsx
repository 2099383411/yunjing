import { useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { Spin } from "antd";
import { useAuthStore } from "./stores/authStore";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import ChatPage from "./pages/ChatPage";
import TaskListPage from "./pages/TaskListPage";
import ReportsListPage from "./pages/ReportsListPage";
import ReportPage from "./pages/ReportPage";
import ScheduleCenterPage from "./pages/ScheduleCenterPage";
import ReasoningPage from "./pages/ReasoningPage";
import AttackSurfacePage from "./pages/AttackSurfacePage";
import ExperienceBrowserPage from "./pages/ExperienceBrowserPage";
import SessionManagerPage from "./pages/SessionManagerPage";
import PerceptionPage from "./pages/PerceptionPage";
import PhishingPage from "./pages/PhishingPage";
import SettingsPage from "./pages/SettingsPage";
// Removed: AdvancedConfigPage, ToolOverviewPage, OfflineUpdatePage, EngineConfigPage,
// SkillMarketPage, OrchestrationPage, ApprovalWorkbenchPage

function AuthGuard({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token);
  const initialized = useAuthStore((s) => s.initialized);
  if (!initialized) {
    return (
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#F1F5F9" }}>
        <Spin size="large" />
      </div>
    );
  }
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function AuthRedirect() {
  const token = useAuthStore((s) => s.token);
  const initialized = useAuthStore((s) => s.initialized);
  if (!initialized) {
    return (
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#F1F5F9" }}>
        <Spin size="large" />
      </div>
    );
  }
  if (token) return <Navigate to="/" replace />;
  return <LoginPage />;
}

export default function Router() {
  const checkAuth = useAuthStore((s) => s.checkAuth);
  useEffect(() => { checkAuth(); }, []);

  return (
    <Routes>
      <Route path="/login" element={<AuthRedirect />} />
      <Route element={<AuthGuard><Layout /></AuthGuard>}>
        {/* Core pages */}
        <Route path="/" element={<DashboardPage />} />
        <Route path="/chat" element={<ChatPage />} />
        <Route path="/tasks" element={<TaskListPage />} />
        <Route path="/schedules" element={<ScheduleCenterPage />} />
        <Route path="/reports" element={<ReportsListPage />} />
        <Route path="/reports/:id" element={<ReportPage />} />

        {/* Security analysis */}
        <Route path="/perception" element={<PerceptionPage />} />
        <Route path="/reasoning" element={<ReasoningPage />} />

                {/* Knowledge & Assets */}
        <Route path="/attack-surface" element={<AttackSurfacePage />} />
        <Route path="/experience" element={<ExperienceBrowserPage />} />
        <Route path="/sessions" element={<SessionManagerPage />} />

        {/* Social engineering */}
        <Route path="/phishing" element={<PhishingPage />} />

        {/* Settings */}
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/settings/*" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}
