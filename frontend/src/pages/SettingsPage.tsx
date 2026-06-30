import { useState, useEffect, useCallback } from "react";
import {
  Card,
  Typography,
  Form,
  Input,
  InputNumber,
  Select,
  Button,
  Checkbox,
  Space,
  Descriptions,
  Tabs,
  message,
  Spin,
} from "antd";
import request from "../api/request";

const { Title } = Typography;

/* ==================== Types ==================== */

interface SystemSettings {
  site_name: string;
  login_timeout: number;
  pw_upper: boolean;
  pw_lower: boolean;
  pw_digit: boolean;
  pw_special: boolean;
}

interface UserInfo {
  username: string;
  role: string;
  email: string;
  [key: string]: any;
}

interface LlmConfig {
  provider: string;
  model?: string;
  api_key?: string;
  base_url?: string;
}

/* ==================== Tab 1: 系统设置 ==================== */

const SystemConfig = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      const res = await request.get("/settings");
      const data = res.data?.data || res.data || {};
      form.setFieldsValue({
        site_name: data.site_name || data.system_name || "",
        login_timeout: data.login_timeout ?? data.session_timeout ?? 30,
        pw_upper: data.pw_upper ?? false,
        pw_lower: data.pw_lower ?? true,
        pw_digit: data.pw_digit ?? true,
        pw_special: data.pw_special ?? false,
      });
    } catch {
      message.error("加载系统配置失败");
    } finally {
      setLoading(false);
    }
  }, [form]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSave = async () => {
    try {
      const values = await form.validateFields();
      setSaving(true);
      await request.put("/settings", {
        site_name: values.site_name,
        login_timeout: values.login_timeout,
        pw_upper: values.pw_upper,
        pw_lower: values.pw_lower,
        pw_digit: values.pw_digit,
        pw_special: values.pw_special,
      });
      message.success("系统配置已保存");
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.response?.data?.detail || "保存失败");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <Spin style={{ display: "block", marginTop: 48 }} />;

  return (
    <Form form={form} layout="vertical" style={{ maxWidth: 500 }}>
      <Form.Item
        label="系统名称"
        name="site_name"
        rules={[{ required: true, message: "请输入系统名称" }]}
      >
        <Input placeholder="例如：云镜" />
      </Form.Item>

      <Form.Item
        label="登录超时（分钟）"
        name="login_timeout"
        rules={[{ required: true, message: "请设置登录超时时间" }]}
      >
        <InputNumber min={5} max={1440} style={{ width: "100%" }} />
      </Form.Item>

      <Form.Item label="密码复杂度">
        <Space>
          <Form.Item name="pw_upper" valuePropName="checked" noStyle>
            <Checkbox>大写字母</Checkbox>
          </Form.Item>
          <Form.Item name="pw_lower" valuePropName="checked" noStyle>
            <Checkbox>小写字母</Checkbox>
          </Form.Item>
          <Form.Item name="pw_digit" valuePropName="checked" noStyle>
            <Checkbox>数字</Checkbox>
          </Form.Item>
          <Form.Item name="pw_special" valuePropName="checked" noStyle>
            <Checkbox>特殊字符</Checkbox>
          </Form.Item>
        </Space>
      </Form.Item>

      <Button type="primary" loading={saving} onClick={handleSave}>
        保存
      </Button>
    </Form>
  );
};

/* ==================== Tab 2: 个人中心 ==================== */

const Profile = () => {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [changingPwd, setChangingPwd] = useState(false);
  const [pwdForm] = Form.useForm();

  const loadUser = useCallback(async () => {
    setLoading(true);
    try {
      const res = await request.get("/auth/me");
      setUser(res.data?.data || res.data || null);
    } catch {
      message.error("获取用户信息失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  const changePassword = async () => {
    try {
      const values = await pwdForm.validateFields();
      if (values.new_password !== values.confirm_password) {
        message.error("两次输入的新密码不一致");
        return;
      }
      setChangingPwd(true);
      await request.put("/users/me/password", {
        old_password: values.old_password,
        new_password: values.new_password,
        confirm_password: values.confirm_password,
      });
      message.success("密码修改成功");
      pwdForm.resetFields();
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.response?.data?.detail || "修改密码失败");
    } finally {
      setChangingPwd(false);
    }
  };

  if (loading) return <Spin style={{ display: "block", marginTop: 48 }} />;

  return (
    <>
      <Card title="个人信息" style={{ maxWidth: 500 }}>
        <Descriptions column={1}>
          <Descriptions.Item label="用户名">
            {user?.username || "-"}
          </Descriptions.Item>
          <Descriptions.Item label="角色">
            {user?.role || "-"}
          </Descriptions.Item>
          <Descriptions.Item label="邮箱">
            {user?.email || "-"}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card title="修改密码" style={{ maxWidth: 500, marginTop: 24 }}>
        <Form form={pwdForm} layout="vertical">
          <Form.Item
            label="旧密码"
            name="old_password"
            rules={[{ required: true, message: "请输入旧密码" }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            label="新密码"
            name="new_password"
            rules={[
              { required: true, message: "请输入新密码" },
              { min: 6, message: "密码长度不能少于6位" },
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            label="确认新密码"
            name="confirm_password"
            rules={[
              { required: true, message: "请再次输入新密码" },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue("new_password") === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error("两次输入的密码不一致"));
                },
              }),
            ]}
          >
            <Input.Password />
          </Form.Item>
          <Button type="primary" loading={changingPwd} onClick={changePassword}>
            修改密码
          </Button>
        </Form>
      </Card>
    </>
  );
};

/* ==================== Tab 3: 大模型配置 ==================== */

const LlmConfig = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [provider, setProvider] = useState<string>("deepseek");

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const res = await request.get("/settings/llm-config");
      const data = res.data?.data || res.data || {};
      const p = data.provider || "deepseek";
      setProvider(p);
      form.setFieldsValue({
        provider: p,
        model: data.model || "",
        api_key: data.api_key || "",
        base_url: data.base_url || "",
      });
    } catch {
      // 首次加载可能没有配置，静默处理
    } finally {
      setLoading(false);
    }
  }, [form]);

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  const handleSave = async () => {
    try {
      const values = await form.validateFields();
      setSaving(true);
      await request.put("/settings/llm-config", {
        provider: values.provider,
        model: values.model || "",
        api_key: values.api_key || "",
        base_url: values.base_url || "",
      });
      message.success("大模型配置已保存");
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.response?.data?.detail || "保存配置失败");
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    try {
      const values = await form.validateFields();
      setTesting(true);
      await request.post("/settings/llm-config/test", {
        provider: values.provider,
        model: values.model || "",
        api_key: values.api_key || "",
        base_url: values.base_url || "",
      });
      message.success("连接测试通过 ✅");
    } catch (err: any) {
      if (err?.errorFields) return;
      message.error(err?.response?.data?.detail || "连接测试失败");
    } finally {
      setTesting(false);
    }
  };

  if (loading) return <Spin style={{ display: "block", marginTop: 48 }} />;

  return (
    <Form
      form={form}
      layout="vertical"
      style={{ maxWidth: 500 }}
      initialValues={{ provider: "deepseek" }}
    >
      <Form.Item
        label="LLM 提供商"
        name="provider"
        rules={[{ required: true, message: "请选择 LLM 提供商" }]}
      >
        <Select onChange={(val) => setProvider(val)}>
          <Select.Option value="deepseek">DeepSeek（云端）</Select.Option>
          <Select.Option value="local">本地模型</Select.Option>
          <Select.Option value="custom">自定义 OpenAI 兼容</Select.Option>
        </Select>
      </Form.Item>

      {provider === "deepseek" && (
        <>
          <Form.Item
            label="模型"
            name="model"
            rules={[{ required: true, message: "请选择模型" }]}
          >
            <Select>
              <Select.Option value="deepseek-chat">
                DeepSeek V3
              </Select.Option>
              <Select.Option value="deepseek-reasoner">
                DeepSeek R1
              </Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            label="API Key"
            name="api_key"
            rules={[{ required: true, message: "请输入 API Key" }]}
          >
            <Input.Password placeholder="sk-..." />
          </Form.Item>
        </>
      )}

      {provider === "local" && (
        <Form.Item
          label="本地模型地址"
          name="base_url"
          rules={[{ required: true, message: "请输入本地模型地址" }]}
        >
          <Input placeholder="http://localhost:11434/v1" />
        </Form.Item>
      )}

      {provider === "custom" && (
        <>
          <Form.Item
            label="Base URL"
            name="base_url"
            rules={[{ required: true, message: "请输入 Base URL" }]}
          >
            <Input placeholder="https://api.openai.com/v1" />
          </Form.Item>
          <Form.Item
            label="模型名"
            name="model"
            rules={[{ required: true, message: "请输入模型名" }]}
          >
            <Input placeholder="gpt-4o" />
          </Form.Item>
          <Form.Item
            label="API Key"
            name="api_key"
            rules={[{ required: true, message: "请输入 API Key" }]}
          >
            <Input.Password />
          </Form.Item>
        </>
      )}

      <Space>
        <Button type="primary" loading={saving} onClick={handleSave}>
          保存配置
        </Button>
        <Button loading={testing} onClick={handleTest}>
          测试连接
        </Button>
      </Space>
    </Form>
  );
};

/* ==================== Main Component ==================== */

export default function SettingsPage() {
  const tabItems = [
    {
      key: "system",
      label: "系统设置",
      children: <SystemConfig />,
    },
    {
      key: "profile",
      label: "个人中心",
      children: <Profile />,
    },
    {
      key: "llm",
      label: "大模型配置",
      children: <LlmConfig />,
    },
  ];

  return (
    <div style={{ padding: 24 }}>
      <Title level={4} style={{ marginBottom: 24 }}>
        设置
      </Title>
      <Tabs defaultActiveKey="system" items={tabItems} />
    </div>
  );
}
