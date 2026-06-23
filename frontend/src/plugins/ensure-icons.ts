// This file is imported by App.tsx to ensure icons survive tree-shaking
// Directly import all commonly used icons to prevent Rollup from removing them
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import UserOutlined from "@ant-design/icons/es/icons/UserOutlined";
import LockOutlined from "@ant-design/icons/es/icons/LockOutlined";

// Re-export so they are available to other modules
export { SafetyOutlined, UserOutlined, LockOutlined };
