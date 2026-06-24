import {useState} from "react";
import {useNavigate} from "react-router-dom";
import {Form, Input, Button, Typography, message, Space, Divider} from "antd";





import {useAuthStore} from "../stores/authStore";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import UserOutlined from "@ant-design/icons/es/icons/UserOutlined";
import LockOutlined from "@ant-design/icons/es/icons/LockOutlined";
import EyeInvisibleOutlined from "@ant-design/icons/es/icons/EyeInvisibleOutlined";
import EyeTwoTone from "@ant-design/icons/es/icons/EyeTwoTone"

const {Title, Text} = Typography;

export default function LoginPage() {
 const [form] = Form.useForm();
 const navigate = useNavigate();
 const login = useAuthStore((s) => s.login);
 const loading = useAuthStore((s) => s.loading);
 const [error, setError] = useState<string | null>(null);

 const handleSubmit = async (values: {username: string; password: string}) => {
 setError(null);
 try {
 await login(values.username, values.password);
 message.success("欢迎回来！");
 navigate("/");
} catch (err: any) {
 setError(err.message || "登录失败");
}
};

 return (
 <div
 className="login-bg"
 style={{
 minHeight: "100vh",
 display: "flex",
 alignItems: "center",
 justifyContent: "center",
 padding: 24,
}}
 >
 {/* 装饰性网格背景 */}
 <div
 style={{
 position: "absolute",
 inset: 0,
 backgroundImage:
 "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)",
 backgroundSize: "60px 60px",
 pointerEvents: "none",
}}
 />

 {/* 主卡片 */}
 <div
 className="login-card"
 style={{
 width: 420,
 maxWidth: "100%",
 borderRadius: 12,
 padding: 40,
 position: "relative",
 zIndex: 1,
}}
 >
 {/* Logo + 标题 */}
 <div style={{textAlign: "center", marginBottom: 36}}>
 <div
 style={{
 width: 56,
 height: 56,
 borderRadius: 14,
 background: "linear-gradient(135deg, #0284c7, #38bdf8)",
 display: "flex",
 alignItems: "center",
 justifyContent: "center",
 margin: "0 auto 16px",
 boxShadow: "0 4px 12px rgba(2,132,199,0.3)",
}}
 >
 <SafetyOutlined style={{fontSize: 28, color: "#fff"}} />
 </div>
 <Title level={3} style={{margin: 0, color: "#1e293b", fontWeight: 700}}>
 云镜 · 渗透测试平台
 </Title>
 <Text type="secondary" style={{fontSize: 13, marginTop: 6, display: "block"}}>
 企业级安全检测与风险评估系统
 </Text>
 </div>

 {/* 错误提示 */}
 {error && (
 <div
 style={{
 background: "#fef2f2",
 border: "1px solid #fecaca",
 borderRadius: 8,
 padding: "10px 14px",
 marginBottom: 20,
 color: "#b91c1c",
 fontSize: 13,
}}
 >
 {error}
 </div>
 )}

 {/* 登录表单 */}
 <Form
 form={form}
 layout="vertical"
 onFinish={handleSubmit}
 autoComplete="off"
 size="large"
 requiredMark={false}
 >
 <Form.Item
 name="username"
 rules={[{required: true, message: "请输入用户名"}]}
 >
 <Input
 prefix={<UserOutlined style={{color: "#94a3b8"}} />}
 placeholder="用户名"
 style={{height: 44, borderRadius: 8}}
 />
 </Form.Item>

 <Form.Item
 name="password"
 rules={[{required: true, message: "请输入密码"}]}
 >
 <Input.Password
 prefix={<LockOutlined style={{color: "#94a3b8"}} />}
 placeholder="密码"
 iconRender={(visible) =>
 visible ? <EyeTwoTone /> : <EyeInvisibleOutlined />
}
 style={{height: 44, borderRadius: 8}}
 />
 </Form.Item>

 <Form.Item style={{marginBottom: 12}}>
 <Button
 type="primary"
 htmlType="submit"
 loading={loading}
 block
 style={{
 height: 44,
 borderRadius: 8,
 fontSize: 15,
 fontWeight: 600,
 background: "linear-gradient(135deg, #0284c7, #0369a1)",
 border: "none",
 boxShadow: "0 2px 8px rgba(2,132,199,0.3)",
}}
 >
 {loading ? "登录中..." : "登 录"}
 </Button>
 </Form.Item>
 </Form>

 <Divider style={{borderColor: "#e2e8f0", margin: "16px 0"}}>
 <Text style={{color: "#94a3b8", fontSize: 12}}>安全提示</Text>
 </Divider>

 <Text
 style={{
 display: "block",
 textAlign: "center",
 color: "#94a3b8",
 fontSize: 12,
 lineHeight: 1.6,
}}
 >
 本系统仅供授权安全测试使用
 <br />
 请确保您已获得目标系统的明确授权
 </Text>
 </div>
 </div>
 );
}
