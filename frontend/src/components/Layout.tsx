import { useState } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  Layout as AntLayout, Menu, Typography, Avatar, Dropdown, Space, Badge, Button, Tooltip,
  theme, Modal, Form, Input, message as antMsg
} from "antd";
import { useAuthStore } from "../stores/authStore";
import request from "../api/request";

// ─── Icons ───
import DashboardOutlined from "@ant-design/icons/es/icons/DashboardOutlined";
import MessageOutlined from "@ant-design/icons/es/icons/MessageOutlined";
import UnorderedListOutlined from "@ant-design/icons/es/icons/UnorderedListOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import UserOutlined from "@ant-design/icons/es/icons/UserOutlined";
import LogoutOutlined from "@ant-design/icons/es/icons/LogoutOutlined";
import BranchesOutlined from "@ant-design/icons/es/icons/BranchesOutlined";
import RadarChartOutlined from "@ant-design/icons/es/icons/RadarChartOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import ScheduleOutlined from "@ant-design/icons/es/icons/ScheduleOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import BellOutlined from "@ant-design/icons/es/icons/BellOutlined";
import MenuFoldOutlined from "@ant-design/icons/es/icons/MenuFoldOutlined";
import MenuUnfoldOutlined from "@ant-design/icons/es/icons/MenuUnfoldOutlined";
import MenuOutlined from "@ant-design/icons/es/icons/MenuOutlined";

const { Sider, Content, Header } = AntLayout;
const { Text } = Typography;

const menuItems = [
  { key: "/", icon: <DashboardOutlined />, label: "系统总览" },
  { key: "/chat", icon: <MessageOutlined />, label: "智能渗透" },
  {
    key: "tasks-group", icon: <UnorderedListOutlined />, label: "扫描任务",
    children: [
      { key: "/tasks", icon: <UnorderedListOutlined />, label: "任务列表" },
      { key: "/schedules", icon: <ScheduleOutlined />, label: "调度中心" },
    ],
  },
  { key: "/reports", icon: <FileTextOutlined />, label: "检测报告" },
  { type: "divider" as const },
  {
    key: "analysis-group", icon: <RadarChartOutlined />, label: "安全分析",
    children: [
      { key: "/perception", icon: <RadarChartOutlined />, label: "资产感知" },
      { key: "/reasoning", icon: <BranchesOutlined />, label: "推理引擎" },
      { key: "/attack-surface", icon: <SafetyOutlined />, label: "攻击面" },
    ],
  },
  { type: "divider" as const },
  {
    key: "knowledge-group", icon: <UnorderedListOutlined />, label: "知识资产",
    children: [
      { key: "/experience", icon: <FileTextOutlined />, label: "经验知识库" },
      { key: "/sessions", icon: <SafetyOutlined />, label: "Session管理" },
      { key: "/review", icon: <FileTextOutlined />, label: "渗透复盘" },
    ],
  },
  { key: "/phishing", icon: <ThunderboltOutlined />, label: "社工钓鱼" },
  { type: "divider" as const },
  { key: "/settings", icon: <SettingOutlined />, label: "系统设置" },
];

export default function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const logout = useAuthStore((s) => s.logout);
  const user = useAuthStore((s) => s.user);
  const checkAuth = useAuthStore((s) => s.checkAuth);
  const [collapsed, setCollapsed] = useState(false);
  const { token } = theme.useToken();

  // ── Profile Modal ──
  const [profileOpen, setProfileOpen] = useState(false);
  const [profileForm] = Form.useForm();
  const [profileSaving, setProfileSaving] = useState(false);

  const handleSaveProfile = async () => {
    const values = profileForm.getFieldsValue();
    setProfileSaving(true);
    try {
      await request.put("/auth/me", values);
      antMsg.success("信息已更新");
      setProfileOpen(false);
      checkAuth(); // refresh user info
    } catch {
      antMsg.error("保存失败");
    } finally {
      setProfileSaving(false);
    }
  };

  const selectedKey = location.pathname;
  const openKeys = ["tasks-group", "analysis-group"];

  const handleMenuClick = (e: { key: string }) => { navigate(e.key); };

  const userMenu = {
    items: [
      { key: "profile", icon: <UserOutlined />, label: "个人信息" },
      { type: "divider" as const },
      { key: "logout", icon: <LogoutOutlined />, label: "退出登录", danger: true },
    ],
    onClick: ({ key }: { key: string }) => {
      if (key === "profile") {
        profileForm.setFieldsValue({ display_name: user?.display_name || user?.username || "" });
        setProfileOpen(true);
      }
      if (key === "logout") { logout(); navigate("/login"); }
    },
  };

  return (
    <AntLayout style={{ minHeight: "100vh" }}>
      <Sider width={220} collapsedWidth={64} collapsible collapsed={collapsed}
        onCollapse={setCollapsed}
        style={{ background: "#0F172A", borderRight: "none", position: "fixed", left: 0, top: 0, bottom: 0, zIndex: 100, overflow: "auto" }}>
        <div style={{ height: 56, display: "flex", alignItems: "center", justifyContent: collapsed ? "center" : "flex-start", padding: collapsed ? 0 : "0 20px", borderBottom: "1px solid rgba(255,255,255,0.06)", cursor: "pointer" }}
          onClick={() => navigate("/")}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: "linear-gradient(135deg, #0284c7, #38bdf8)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <SafetyOutlined style={{ fontSize: 16, color: "#fff" }} />
          </div>
          {!collapsed && <div style={{ marginLeft: 12 }}>
            <Text strong style={{ color: "#fff", fontSize: 14, display: "block", lineHeight: 1.2 }}>云镜</Text>
            <Text style={{ color: "#64748B", fontSize: 11, display: "block" }}>渗透测试平台</Text>
          </div>}
        </div>
        <Menu mode="inline" selectedKeys={[selectedKey]} defaultOpenKeys={openKeys}
          items={menuItems} onClick={handleMenuClick}
          style={{ background: "transparent", borderRight: "none", paddingTop: 4 }} theme="dark" />
      </Sider>

      <AntLayout style={{ marginLeft: collapsed ? 64 : 220, transition: "margin-left 0.2s" }}>
        <Header style={{ background: "#fff", padding: "0 24px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid #E2E8F0", height: 56, position: "sticky", top: 0, zIndex: 99 }}>
          <Space>
            <Button type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => setCollapsed(!collapsed)} style={{ fontSize: 16, color: "#64748B" }} />
          </Space>
          <Space size={16}>
            <Badge count={0} size="small">
              <BellOutlined style={{ fontSize: 18, color: "#64748B", cursor: "pointer" }} />
            </Badge>
            <Dropdown menu={userMenu} placement="bottomRight">
              <Space style={{ cursor: "pointer" }}>
                <Avatar size={32} style={{ background: "#EFF6FF", color: "#2563EB", fontSize: 14 }}
                  icon={<UserOutlined />} />
                <Text style={{ fontSize: 13, color: "#0F172A" }}>
                  {user?.display_name || user?.username || "Admin"}
                </Text>
              </Space>
            </Dropdown>
          </Space>
        </Header>

        <Content style={{ padding: 24, minHeight: "calc(100vh - 56px)" }}>
          <Outlet />
        </Content>
      </AntLayout>

      {/* ── 个人信息弹窗 ── */}
      <Modal title="个人信息" open={profileOpen} onCancel={() => setProfileOpen(false)}
        onOk={handleSaveProfile} confirmLoading={profileSaving}
        okText="保存" cancelText="取消">
        <Form form={profileForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item label="用户名">
            <Input value={user?.username || ""} disabled style={{ color: "#94a3b8" }} />
          </Form.Item>
          <Form.Item name="display_name" label="显示名称">
            <Input placeholder="输入显示名称" />
          </Form.Item>
          <Form.Item name="password" label="新密码">
            <Input.Password placeholder="留空则不修改密码" />
          </Form.Item>
          <Text style={{ fontSize: 11, color: "#94a3b8" }}>仅修改需要更新的信息，不修改的字段留空即可。</Text>
        </Form>
      </Modal>
    </AntLayout>
  );
}
