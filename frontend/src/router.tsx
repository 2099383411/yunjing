import { useEffect, lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { Spin } from "antd";
import { useAuthStore } from "./stores/authStore";
import Layout from "./components/Layout";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const ChatPage = lazy(() => import("./pages/ChatPage"));
const TaskListPage = lazy(() => import("./pages/TaskListPage"));
const ReportsListPage = lazy(() => import("./pages/ReportsListPage"));
<<<<<<< Updated upstream

=======
const ReviewPage = lazy(() => import("./pages/ReviewPage"));
>>>>>>> Stashed changes
const ReportPage = lazy(() => import("./pages/ReportPage"));
const ScheduleCenterPage = lazy(() => import("./pages/ScheduleCenterPage"));
const ReasoningPage = lazy(() => import("./pages/ReasoningPage"));
const AttackSurfacePage = lazy(() => import("./pages/AttackSurfacePage"));
const ExperienceBrowserPage = lazy(() => import("./pages/ExperienceBrowserPage"));
const SessionManagerPage = lazy(() => import("./pages/SessionManagerPage"));
const PerceptionPage = lazy(() => import("./pages/PerceptionPage"));
const PhishingPage = lazy(() => import("./pages/PhishingPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

function PageLoader() {
  return <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: 300 }}><Spin size="large" /></div>;
}

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
      <Route element={<AuthGuard><Suspense fallback={<PageLoader />}><Layout /></Suspense></AuthGuard>}>
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
<<<<<<< Updated upstream
        
=======
        <Route path="/review" element={<ReviewPage />} />
>>>>>>> Stashed changes

        {/* Social engineering */}
        <Route path="/phishing" element={<PhishingPage />} />

        {/* Settings */}
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/settings/*" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}
