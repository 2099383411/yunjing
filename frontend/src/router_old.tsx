import { useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { Spin } from "antd";
import { useAuthStore } from "./stores/authStore";
import Layout from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import ChatPage from "./pages/ChatPage";
import DashboardPage from "./pages/DashboardPage";
import ToolOverviewPage from "./pages/ToolOverviewPage";
import OfflineUpdatePage from "./pages/OfflineUpdatePage";
import EngineConfigPage from "./pages/EngineConfigPage";
import SkillMarketPage from "./pages/SkillMarketPage";
import ScheduleCenterPage from "./pages/ScheduleCenterPage";
import TaskListPage from "./pages/TaskListPage";
import ReportsListPage from "./pages/ReportsListPage";
import ReportPage from "./pages/ReportPage";
import AdvancedConfigPage from "./pages/AdvancedConfigPage";
import SettingsPage from "./pages/SettingsPage";

function AuthGuard({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token);
  const initialized = useAuthStore((s) => s.initialized);
  if (!initialized) {
    return (
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#f1f5f9" }}>
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
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#f1f5f9" }}>
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
        <Route path="/advanced" element={<AdvancedConfigPage />} />
        <Route path="/tasks" element={<TaskListPage />} />
        <Route path="/reports" element={<ReportsListPage />} />
        <Route path="/reports/:id" element={<ReportPage />} />

        {/* Tools management */}
        <Route path="/tools" element={<ToolOverviewPage />} />
        <Route path="/tools/updates" element={<OfflineUpdatePage />} />
        <Route path="/tools/config" element={<EngineConfigPage />} />

        {/* Skills & Schedules */}
        <Route path="/skills" element={<SkillMarketPage />} />
        <Route path="/schedules" element={<ScheduleCenterPage />} />

        {/* Legacy pages - use existing nextgen files */}
        <Route path="/orchestration" element={<div style={{ padding: 40 }}><h3>大屏编排</h3><p>建设中...</p></div>} />
        <Route path="/reasoning" element={<div style={{ padding: 40 }}><h3>推理链</h3><p>建设中...</p></div>} />
        <Route path="/approval" element={<div style={{ padding: 40 }}><h3>审核工作台</h3><p>建设中...</p></div>} />
        <Route path="/perception" element={<div style={{ padding: 40 }}><h3>资产感知</h3><p>建设中...</p></div>} />
        <Route path="/engine" element={<Navigate to="/tools/config" replace />} />

        {/* Settings */}
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}
