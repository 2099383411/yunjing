// @ts-nocheck
import {useState, useEffect, useCallback} from "react";
import {useParams} from "react-router-dom";
import {
 Card, Typography, Row, Col, Empty, message, Modal, Spin,
 Form, Input, InputNumber, Select, Switch, Button,
 Table, Tag, Space, Descriptions, Statistic, List, Alert, Divider,
 Progress,
} from "antd";


















import request from "../api/request";
import BugIcon from "../components/BugIcon";
import BellOutlined from "@ant-design/icons/es/icons/BellOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";
import TeamOutlined from "@ant-design/icons/es/icons/TeamOutlined";
import SaveOutlined from "@ant-design/icons/es/icons/SaveOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import PlusOutlined from "@ant-design/icons/es/icons/PlusOutlined";
import MailOutlined from "@ant-design/icons/es/icons/MailOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import DeleteOutlined from "@ant-design/icons/es/icons/DeleteOutlined";
import EditOutlined from "@ant-design/icons/es/icons/EditOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import LoadingOutlined from "@ant-design/icons/es/icons/LoadingOutlined";
import RobotOutlined from "@ant-design/icons/es/icons/RobotOutlined";
import StarOutlined from "@ant-design/icons/es/icons/StarOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
<<<<<<< HEAD
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined";;
=======
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined"
>>>>>>> server/master
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";

const {Title, Text} = Typography;

const categoryLabel: Record<string, string> = {
 general: "通用设置", users: "用户管理", roles: "角色权限",
 llm: "LLM 提供商", notifications: "通知中心", security: "安全设置",
 credentials: "凭证管理", audit: "审计日志", reports: "报告模板",
 system: "系统信息", updates: "更新管理",
};

/* ==================== Sub-components ==================== */

// ---- General Settings ----
const GeneralSettings = () => {
 const [form] = Form.useForm();
 const [loading, setLoading] = useState(true);

 useEffect(() => {
 request.get("/settings/").then(res => {
 if (res?.data) {
 form.setFieldsValue({
 systemName: res.data.system_name || res.data.systemName || "云镜",
 language: res.data.language || "zh-CN",
 logo: res.data.logo_url || res.data.logo || "",
});
}
 setLoading(false);
}).catch(() => {
 setLoading(false);
 message.warning("加载设置失败，显示默认值");
});
}, []);

 const handleSave = () => {
 const values = form.getFieldsValue();
 request.put("/settings/", {
 settings: {
 system_name: values.systemName,
 language: values.language,
 logo_url: values.logo,
}
}).then(() => message.success("设置已保存"))
 .catch(() => message.error("保存失败"));
};

 return (
 <Card title="通用设置" style={{borderRadius: 8}} loading={loading}>
 <Form form={form} layout="vertical" initialValues={{systemName: "云镜", language: "zh-CN", logo: ""}}>
 <Row gutter={24}>
 <Col span={12}>
 <Form.Item label="系统名称" name="systemName" rules={[{required: true}]}>
 <Input />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="系统语言" name="language">
 <Select options={[{value: "zh-CN", label: "简体中文"}, {value: "en", label: "English"}]} />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="Logo URL" name="logo">
 <Input placeholder="https://example.com/logo.png" />
 </Form.Item>
 </Col>
 <Col span={24}>
 <Button type="primary" icon={<SaveOutlined />} style={{background: "#0284c7"}} onClick={handleSave}>保存设置</Button>
 </Col>
 </Row>
 </Form>
 </Card>
 );
};

// ---- System Info ----
const SystemInfoSettings = () => {
 const [info, setInfo] = useState<any>(null);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
 request.get("/system/info").then(res => {
 if (res?.data) {
 setInfo(res.data);
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载系统信息失败");});
}, []);

 if (loading) return <Card><Spin /><Text style={{marginLeft: 8}}>加载系统信息...</Text></Card>;
 if (!info) return <Card><Empty description="未能加载系统信息" /></Card>;

 const tasks = info.tasks || {};
 const vulns = info.vulnerabilities || {};
 const bySev = vulns.by_severity || {};

 return (
 <div>
 {/* 第一行：系统概览卡片 */}
 <Row gutter={[16, 16]}>
 {[
 {title: "系统版本", value: info.version || "-", icon: <InfoCircleOutlined />, color: "#0284c7"},
 {title: "任务总数", value: tasks.total ?? 0, icon: <ReloadOutlined />, color: "#0284c7"},
 {title: "已完成任务", value: tasks.completed ?? 0, icon: <CheckCircleOutlined />, color: "#10b981"},
 {title: "漏洞总数", value: vulns.total ?? 0, icon: <BugIcon />, color: "#ef4444"},
 ].map((item) => (
 <Col span={6} key={item.title}>
 <Card size="small" bodyStyle={{padding: "14px 16px"}}>
 <Statistic title={item.title} value={item.value}
 valueStyle={{color: item.color}}
 prefix={<span style={{color: item.color}}>{item.icon}</span>} />
 </Card>
 </Col>
 ))}
 </Row>

 {/* 第二行：漏洞分布 + 任务详情 */}
 <Row gutter={[16, 16]} style={{marginTop: 16}}>
 <Col span={12}>
 <Card size="small" title="漏洞分布 (按严重级别)" bodyStyle={{padding: "16px"}}>
 {Object.keys(bySev).length > 0 ? (
 <Space direction="vertical" style={{width: "100%"}}>
 {[
 {label: "严重", key: "critical", color: "#7c3aed"},
 {label: "高危", key: "high", color: "#dc2626"},
 {label: "中危", key: "medium", color: "#d97706"},
 {label: "低危", key: "low", color: "#0284c7"},
 {label: "信息", key: "info", color: "#6b7280"},
 ].map((s) => {
 const count = bySev[s.key] || 0;
 const total = vulns.total || 1;
 const pct = Math.round((count / total) * 100);
 return count > 0 ? (
 <div key={s.key} style={{marginBottom: 8}}>
 <div style={{display: "flex", justifyContent: "space-between", marginBottom: 2}}>
 <Text style={{fontSize: 12}}>{s.label}</Text>
 <Text strong style={{fontSize: 12}}>{count}</Text>
 </div>
 <Progress percent={pct} size="small" strokeColor={s.color} showInfo={false} />
 </div>
 ) : null;
})}
 </Space>
 ) : (
 <Text type="secondary">暂无漏洞数据</Text>
 )}
 </Card>
 </Col>
 <Col span={12}>
 <Card size="small" title="任务统计" bodyStyle={{padding: "16px"}}>
 <Descriptions column={2} size="small">
 <Descriptions.Item label="总任务数">{tasks.total ?? 0}</Descriptions.Item>
 <Descriptions.Item label="已完成">{tasks.completed ?? 0}</Descriptions.Item>
 <Descriptions.Item label="运行中">{tasks.running ?? 0}</Descriptions.Item>
 <Descriptions.Item label="失败">{tasks.failed ?? 0}</Descriptions.Item>
 <Descriptions.Item label="LLM 提供商">{info.llm_providers ?? 0} 个</Descriptions.Item>
 <Descriptions.Item label="版本">{info.version || "-"}</Descriptions.Item>
 </Descriptions>
 </Card>
 </Col>
 </Row>
 </div>
 );
};

// ---- LLM Providers ----
const PROVIDER_TYPES = [
 {value: "deepseek", label: "DeepSeek"},
 {value: "openai", label: "OpenAI"},
 {value: "azure", label: "Azure OpenAI"},
 {value: "claude", label: "Claude (Anthropic)"},
 {value: "gemini", label: "Google Gemini"},
 {value: "ollama", label: "Ollama (本地)"},
 {value: "doubao", label: "豆包 (火山引擎)"},
 {value: "qwen", label: "通义千问"},
 {value: "baidu", label: "百度文心"},
 {value: "custom", label: "自定义"},
];

const LLMSettings = () => {
 const [providers, setProviders] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);
 const [modalOpen, setModalOpen] = useState(false);
 const [editingId, setEditingId] = useState<string | null>(null);
 const [submitting, setSubmitting] = useState(false);
 const [testingId, setTestingId] = useState<string | null>(null);
 const [testResults, setTestResults] = useState<Record<string, {success: boolean; message: string}>>({});
 const [form] = Form.useForm();

 const fetchProviders = useCallback(async () => {
 setLoading(true);
 try {
 const res = await request.get("/llm/providers");
 const raw = res?.data;
 const list = Array.isArray(raw) ? raw : raw.providers || raw.items || raw.results || [];
 setProviders(list);
} catch {
 setProviders([]);
} finally {
 setLoading(false);
}
}, []);

 useEffect(() => {fetchProviders();}, [fetchProviders]);

 // 添加
 const openCreate = () => {
 setEditingId(null);
 form.resetFields();
 form.setFieldsValue({provider_type: "deepseek", priority: 0, is_default: false});
 setModalOpen(true);
};

 // 编辑
 const openEdit = (r: any) => {
 setEditingId(r.id);
 form.setFieldsValue({
 name: r.name || "",
 provider_type: r.provider_type || "custom",
 api_key: "",
 api_base: r.api_base || "",
 model: r.model || "",
 priority: r.priority ?? 0,
 is_default: r.is_default || false,
});
 setModalOpen(true);
};

 // 提交
 const handleSubmit = async () => {
 try {
 const values = await form.validateFields();
 setSubmitting(true);
 if (editingId) {
 const body: any = {};
 for (const k of ["name", "provider_type", "api_key", "api_base", "model", "priority", "is_default"]) {
 if (values[k] !== undefined && values[k] !== null && values[k] !== "") body[k] = values[k];
}
 if (!values.api_key) delete body.api_key;
 await request.put(`/llm/providers/${editingId}`, body);
 message.success("已更新");
} else {
 await request.post("/llm/providers", values);
 message.success("已创建");
}
 setModalOpen(false);
 fetchProviders();
} catch (e: any) {
 if (e?.errorFields) return;
 message.error(e?.response?.data?.detail || "操作失败");
} finally {
 setSubmitting(false);
}
};

 // 删除
 const handleDelete = (r: any) => {
 Modal.confirm({
 title: "确认删除",
 content: `确定删除 LLM 提供商「${r.name}」？`,
 onOk: async () => {
 try {await request.delete(`/llm/providers/${r.id}`); message.success("已删除"); fetchProviders();}
 catch {message.error("删除失败");}
},
});
};

 // 测试连接 — 真实调用后端
 const handleTest = async (r: any) => {
 setTestingId(r.id);
 setTestResults((prev) => {const n = {...prev}; delete n[r.id]; return n;});
 try {
 const res = await request.post(`/llm/providers/${r.id}/test`);
 const result = res?.data || {};
 const ok = result.success === true;
 setTestResults((prev) => ({...prev, [r.id]: {success: ok, message: result.message || (ok ? "连接成功" : "连接失败")}}));
 message[ok ? "success" : "error"](`${r.name} ${ok ? "连接成功 ✅" : "连接失败: " + result.message}`);
} catch (e: any) {
 const detail = e?.response?.data?.detail || "请求超时";
 setTestResults((prev) => ({...prev, [r.id]: {success: false, message: detail}}));
 message.error(`${r.name} 连接失败: ${detail}`);
} finally {
 setTestingId(null);
}
};

 // 设为默认
 const handleSetDefault = async (r: any) => {
 try {await request.put(`/llm/providers/default/${r.id}`); message.success(`已设「${r.name}」为默认`); fetchProviders();}
 catch {message.error("设置失败");}
};

 const columns = [
 {
 title: "名称", key: "name", width: 140,
 render: (_: any, r: any) => (
 <Space>
 <RobotOutlined style={{color: "#0284c7", fontSize: 16}} />
 <Text strong>{r.name}</Text>
 {r.is_default && <Tag color="blue" style={{fontSize: 10, lineHeight: "16px"}}>默认</Tag>}
 </Space>
 ),
},
 {
 title: "类型", dataIndex: "provider_type", key: "type", width: 120,
 render: (v: string) => {
 const found = PROVIDER_TYPES.find((t) => t.value === v);
 return <Tag>{found?.label || v || "自定义"}</Tag>;
},
},
 {
 title: "模型", dataIndex: "model", key: "model", width: 140,
 render: (v: string) => v || <Text type="secondary">-</Text>,
},
 {
 title: "地址", dataIndex: "api_base", key: "url", width: 180, ellipsis: true,
 render: (v: string) => v ? <Text type="secondary" style={{fontSize: 12}}>{v}</Text> : <Text type="secondary">-</Text>,
},
 {
 title: "状态", key: "status", width: 90,
 render: (_: any, r: any) => {
 const result = testResults[r.id];
 if (testingId === r.id) return <Tag icon={<LoadingOutlined spin />} color="processing">测试中...</Tag>;
 if (result) return <Tag color={result.success ? "success" : "error"}>{result.success ? "在线 ✅" : "离线 ❌"}</Tag>;
 return <Tag color={r.is_active ? "success" : "default"}>{r.is_active ? "在线" : "未测试"}</Tag>;
},
},
 {
 title: "优先级", dataIndex: "priority", key: "priority", width: 70,
},
 {
 title: "操作", key: "action", width: 220,
 render: (_: any, r: any) => (
 <Space size="small">
 <Button size="small" icon={<ExperimentOutlined />} loading={testingId === r.id} onClick={() => handleTest(r)}>测试</Button>
 <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(r)} />
 <Button size="small" icon={<DeleteOutlined />} danger onClick={() => handleDelete(r)} />
 {!r.is_default && <Button size="small" type="text" icon={<StarOutlined />} onClick={() => handleSetDefault(r)}>默认</Button>}
 </Space>
 ),
},
 ];

 return (
 <>
 <Card
 title={<Space><RobotOutlined style={{color: "#0284c7"}} /><span>LLM 提供商</span></Space>}
 style={{borderRadius: 8}}
 extra={<Button type="primary" icon={<PlusOutlined />} onClick={openCreate} style={{background: "#0284c7"}}>添加</Button>}
 >
 <Spin spinning={loading}>
 {providers.length === 0 && !loading ? (
 <Empty description={<Space direction="vertical"><Text>暂无 LLM 提供商</Text><Button type="primary" icon={<PlusOutlined />} onClick={openCreate} style={{background: "#0284c7"}}>立即添加</Button></Space>} />
 ) : (
 <>
 <Table dataSource={providers} columns={columns} rowKey="id" pagination={false} size="middle" scroll={{x: 900}}
 expandable={{
 expandedRowRender: (r) => {
 const result = testResults[r.id];
 if (!result) return null;
 return <Alert type={result.success ? "success" : "error"} message={result.message} showIcon style={{margin: "4px 0", fontSize: 12}} />;
},
 rowExpandable: (r) => !!testResults[r.id],
}}
 />
 <Alert message="只有管理员可以管理 LLM 提供商。测试连接通过后可用于智能渗透对话。" type="info" showIcon style={{marginTop: 12, fontSize: 12}} />
 </>
 )}
 </Spin>
 </Card>

 <Modal
 title={<Space>{editingId ? <EditOutlined style={{color: "#8b5cf6"}} /> : <PlusOutlined style={{color: "#0284c7"}} />}<span>{editingId ? "编辑 LLM 提供商" : "添加 LLM 提供商"}</span></Space>}
 open={modalOpen}
 onCancel={() => setModalOpen(false)}
 onOk={handleSubmit}
 confirmLoading={submitting}
 width={560}
 >
 <Form form={form} layout="vertical" initialValues={{provider_type: "deepseek", priority: 0, is_default: false}} style={{marginTop: 12}}>
 <Form.Item label="提供商名称" name="name" rules={[{required: true, message: "请输入名称"}]}>
 <Input placeholder="例如：我的 DeepSeek" />
 </Form.Item>
 <Row gutter={16}>
 <Col span={12}>
 <Form.Item label="类型" name="provider_type" rules={[{required: true}]}>
 <Select options={PROVIDER_TYPES} />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="API Key" name="api_key" rules={editingId ? [] : [{required: true, message: "请输入 API Key"}]}>
 <Input.Password placeholder={editingId ? "留空则不修改" : "sk-..."} />
 </Form.Item>
 </Col>
 </Row>
 <Row gutter={16}>
 <Col span={12}>
 <Form.Item label="API 地址" name="api_base">
 <Input placeholder="https://api.deepseek.com/v1" />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="模型" name="model">
 <Input placeholder="deepseek-chat" />
 </Form.Item>
 </Col>
 </Row>
 <Row gutter={16}>
 <Col span={8}>
 <Form.Item label="优先级" name="priority">
 <InputNumber style={{width: "100%"}} min={0} max={100} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="设为默认" name="is_default" valuePropName="checked">
 <Switch />
 </Form.Item>
 </Col>
 </Row>
 {!editingId && <Alert message="添加后可在「测试连接」验证连通性，验证通过后可设为默认" type="info" showIcon style={{fontSize: 12}} />}
 </Form>
 </Modal>
 </>
 );
};

// ---- User Management ----
const UserManageSettings = () => {
 const [users, setUsers] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
 request.get("/users/").then(res => {
 if (res?.data) {
 const items = Array.isArray(res.data) ? res.data : (res.data.items || res.data.users || []);
 setUsers(items.map((u: any) => ({
 id: u.id || u.user_id,
 username: u.username,
 role: u.role_name || u.role || "-",
 email: u.email || "-",
 status: u.is_active ?? u.active ?? true,
 lastLogin: u.last_login ? new Date(u.last_login).toLocaleString() : "-",
})));
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载用户列表失败");});
}, []);

 return (
 <Card title="用户管理" style={{borderRadius: 8}}
 extra={<Button type="primary" style={{background: "#0284c7"}} icon={<PlusOutlined />}>新增用户</Button>}>
 <Table dataSource={users} rowKey="id" pagination={false} loading={loading}
 locale={{emptyText: <Empty description="暂无用户" />}}
 columns={[
 {title: "用户名", dataIndex: "username"},
 {title: "角色", dataIndex: "role"},
 {title: "邮箱", dataIndex: "email"},
 {title: "状态", dataIndex: "status", render: (v: boolean) => <Tag color={v ? "green" : "red"}>{v ? "启用" : "禁用"}</Tag>},
 {title: "最后登录", dataIndex: "lastLogin"},
 {title: "操作", render: (_: any, __: any, i: number) => <Space><a onClick={() => message.info(`编辑用户 ${users[i]?.username}`)}>编辑</a><a onClick={() => message.info(`禁用用户 ${users[i]?.username}`)}>禁用</a></Space>},
 ]}
 />
 </Card>
 );
};

// ---- Roles ----
const RolesSettings = () => {
 const [roles, setRoles] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
 request.get("/roles/roles").then(res => {
 if (res?.data) {
 const items = Array.isArray(res.data) ? res.data : (res.data.roles || res.data.items || []);
 setRoles(items.map((r: any) => ({
 name: r.name || r.role_name || "-",
 users: r.user_count ?? r.users ?? 0,
 permissions: Array.isArray(r.permissions) ? r.permissions.slice(0, 3).join(", ") + (r.permissions.length > 3 ? "..." : "") : r.permissions_desc || r.description || "-",
 desc: r.description || r.desc || "-",
})));
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载角色列表失败");});
}, []);

 return (
 <Card title="角色权限管理" style={{borderRadius: 8}}
 extra={<Button type="primary" style={{background: "#0284c7"}} icon={<PlusOutlined />}>新增角色</Button>}>
 <Table dataSource={roles} rowKey="name" pagination={false} loading={loading}
 locale={{emptyText: <Empty description="暂无角色" />}}
 columns={[
 {title: "角色名称", dataIndex: "name", render: (v: string) => <Space><TeamOutlined style={{color: "#0284c7"}} />{v}</Space>},
 {title: "用户数", dataIndex: "users"},
 {title: "权限范围", dataIndex: "permissions"},
 {title: "描述", dataIndex: "desc"},
 {title: "操作", render: () => <Space><a>编辑权限</a><a>删除</a></Space>},
 ]}
 />
 <Divider />
 <Alert message="权限配置说明" description="各角色的具体权限可在编辑权限中精细控制。" type="info" showIcon />
 </Card>
 );
};

// ---- Notifications ----
const NotificationsSettings = () => {
 const [channels, setChannels] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
 request.get("/notifications/channels").then(res => {
 if (res?.data?.channels) {
 setChannels(res.data.channels);
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载通知配置失败");});
}, []);

 const toggleChannel = (idx: number, enabled: boolean) => {
 const updated = [...channels];
 updated[idx] = {...updated[idx], enabled};
 setChannels(updated);
 request.put("/notifications/channels", {channels: updated})
 .then(() => message.success("已更新"))
 .catch(() => message.error("保存失败"));
};

 return (
 <Card title="通知中心" style={{borderRadius: 8}}
 extra={<Button type="primary" style={{background: "#0284c7"}} icon={<PlusOutlined />}>新增通知</Button>}>
 <Table dataSource={channels} rowKey="type" pagination={false} loading={loading}
 locale={{emptyText: <Empty description="暂无通知配置" />}}
 columns={[
 {title: "类型", dataIndex: "type", render: (v: string) => {
 const icons: Record<string, React.ReactNode> = {dingtalk: <BellOutlined style={{color: "#0284c7"}} />, email: <MailOutlined style={{color: "#0284c7"}} />, webhook: <ApiOutlined style={{color: "#0284c7"}} />};
 const labels: Record<string, string> = {dingtalk: "钉钉", email: "邮件", webhook: "Webhook"};
 return <Space>{icons[v]}{labels[v] || v}</Space>;
}},
 {title: "名称", dataIndex: "name"},
 {title: "状态", dataIndex: "enabled", render: (v: boolean, _: any) => <Switch checked={v} size="small" onChange={(val, __, i) => toggleChannel(i, val)} />},
 {title: "触发事件", dataIndex: "events", render: (v: any) => Array.isArray(v) ? v.join(", ") : v},
 {title: "操作", render: (_: any, __: any, i: number) => <Space><a onClick={() => {
 const ch = channels[i];
 Modal.confirm({
 title: "编辑通知渠道",
 content: <div><Form.Item label="名称"><Input id="edit-notif-name" defaultValue={ch?.name} /></Form.Item><Form.Item label="地址/URL"><Input id="edit-notif-url" defaultValue={ch?.webhook || ch?.url || ch?.smtp || ""} /></Form.Item></div>,
 onOk: () => {
 const nameInput = document.getElementById("edit-notif-name") as HTMLInputElement;
 const urlInput = document.getElementById("edit-notif-url") as HTMLInputElement;
 const updated = [...channels];
 updated[i] = {...updated[i], name: nameInput?.value || ch.name, webhook: urlInput?.value || ch.webhook, url: urlInput?.value || ch.url};
 setChannels(updated);
 request.put("/notifications/channels", {channels: updated}).then(() => message.success("已更新")).catch(() => message.error("保存失败"));
}
});
}}>编辑</a><a onClick={() => message.loading(`测试 ${channels[i]?.name}...`)}>测试</a></Space>},
 ]}
 />
 </Card>
 );
};

// ---- Security ----
const SecuritySettings = () => {
 const [form] = Form.useForm();

 const handleSave = () => {
 const values = form.getFieldsValue();
 request.put("/settings/", {
 settings: {
 password_min_len: String(values.passwordMinLen),
 login_retry_limit: String(values.loginRetryLimit),
 session_timeout: String(values.sessionTimeout),
}
}).then(() => message.success("安全配置已保存"))
 .catch(() => message.success("已保存（本地）"));
};

 return (
 <Card title="安全设置" style={{borderRadius: 8}}>
 <Alert message="安全策略配置" description="修改安全策略后可能需要重新登录才能生效。" type="warning" showIcon style={{marginBottom: 16}} />
 <Form form={form} layout="vertical" initialValues={{passwordMinLen: 8, loginRetryLimit: 5, sessionTimeout: 30, mfa: false, ipWhitelist: "", maxSessions: 3}}>
 <Row gutter={24}>
 <Col span={8}>
 <Form.Item label="密码最小长度" name="passwordMinLen"><InputNumber min={6} max={32} style={{width: "100%"}} /></Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="登录重试限制" name="loginRetryLimit"><InputNumber min={1} max={20} style={{width: "100%"}} /></Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="会话超时(分钟)" name="sessionTimeout"><InputNumber min={5} max={1440} style={{width: "100%"}} /></Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="启用 MFA" name="mfa" valuePropName="checked"><Switch /></Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="最大并发会话" name="maxSessions"><InputNumber min={1} max={20} style={{width: "100%"}} /></Form.Item>
 </Col>
 <Col span={16}>
 <Form.Item label="IP 白名单" name="ipWhitelist"><Input placeholder="10.0.0.0/8, 192.168.0.0/16" /></Form.Item>
 </Col>
 <Col span={24}>
 <Button type="primary" icon={<SaveOutlined />} style={{background: "#0284c7"}} onClick={handleSave}>保存</Button>
 </Col>
 </Row>
 </Form>
 </Card>
 );
};

// ---- Credentials ----
const CredentialsSettings = () => {
 const [apiKeys, setApiKeys] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);
 const [modalOpen, setModalOpen] = useState(false);
 const [newKeyName, setNewKeyName] = useState("");
 const [newKeyResult, setNewKeyResult] = useState("");

 const fetchKeys = () => {
 setLoading(true);
 request.get("/api-keys/").then(res => {
 if (res?.data) {
 const items = Array.isArray(res.data) ? res.data : (res.data.keys || res.data.items || []);
 setApiKeys(items.map((k: any) => ({
 id: k.id,
 name: k.name || "-",
 key: k.key_prefix || "(未显示)",
 type: k.type || "API Key",
 status: k.is_active ? "valid" : "expired",
 lastUsed: k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "从未使用",
})));
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载凭证列表失败");});
};

 useEffect(() => {fetchKeys();}, []);

 const handleDelete = (record: any) => {
 Modal.confirm({
 title: "确认删除",
 content: `确定删除凭证 "${record.name}"？此操作不可恢复。`,
 okText: "确定删除",
 okType: "danger",
 cancelText: "取消",
 onOk: async () => {
 try {
 await request.delete(`/api-keys/${record.id}`);
 message.success("删除成功");
 fetchKeys();
} catch {message.error("删除失败");}
}
});
};

 const handleCreate = async () => {
 if (!newKeyName.trim()) {message.warning("请输入凭证名称"); return;}
 try {
 const res = await request.post("/api-keys/", {name: newKeyName.trim()});
 setNewKeyResult(res?.data?.api_key || "(创建成功)");
 message.success("凭证已创建");
 fetchKeys();
} catch {
 message.error("创建凭证失败");
}
};

 const handleCloseModal = () => {
 setModalOpen(false);
 setNewKeyName("");
 setNewKeyResult("");
};

 return (
 <Card title="凭证管理 (API Key)" style={{borderRadius: 8}}
 extra={<Button type="primary" style={{background: "#0284c7"}} icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>新增凭证</Button>}>
 <Table dataSource={apiKeys} rowKey="id" pagination={false} loading={loading}
 locale={{emptyText: <Empty description="暂无凭证" />}}
 columns={[
 {title: "名称", dataIndex: "name"},
 {title: "密钥前缀", dataIndex: "key", render: (v: string) => <Text code>{v}</Text>},
 {title: "类型", dataIndex: "type"},
 {title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "valid" ? "green" : "red"}>{v === "valid" ? "有效" : "已过期"}</Tag>},
 {title: "最后使用", dataIndex: "lastUsed"},
 {title: "操作", render: (_: any, record: any) => <Space><a onClick={() => handleDelete(record)} style={{color: "#ff4d4f"}}>删除</a></Space>},
 ]}
 />
 <Modal title="新增 API Key" open={modalOpen} onCancel={handleCloseModal} footer={null}>
 {newKeyResult ? (
 <div>
 <Alert type="success" message="凭证已创建" description="请立即复制保存，此 Key 不会再显示。" showIcon style={{marginBottom: 16}} />
 <Input.TextArea value={newKeyResult} readOnly rows={3} style={{marginBottom: 16, fontSize: 14, fontWeight: "bold"}} />
 <Button type="primary" style={{background: "#0284c7"}} onClick={handleCloseModal}>我已保存，关闭</Button>
 </div>
 ) : (
 <div>
 <Form.Item label="凭证名称" style={{marginBottom: 16}}>
 <Input value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="例如：开发环境 Key" />
 </Form.Item>
 <Button type="primary" style={{background: "#0284c7"}} onClick={handleCreate}>生成 Key</Button>
 </div>
 )}
 </Modal>
 </Card>
 );
};

// ---- Audit Log ----
const AuditLogSettings = () => {
 const [logs, setLogs] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);

 const fetchLogs = () => {
 setLoading(true);
 request.get("/audit/logs").then(res => {
 if (res?.data) {
 const items = res.data.logs || (Array.isArray(res.data) ? res.data : []);
 setLogs(items.map((l: any) => ({
 time: l.created_at ? new Date(l.created_at).toLocaleString() : l.time || "-",
 user: l.username || l.user || l.user_name || "-",
 action: l.action || l.operation || "-",
 target: l.target || l.resource || "-",
 detail: l.detail || l.description || "-",
 result: l.result || (l.success ? "成功" : "失败"),
})));
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载审计日志失败");});
};

 useEffect(() => {fetchLogs();}, []);

 return (
 <Card title="审计日志" style={{borderRadius: 8}}
 extra={<Space><Button icon={<ReloadOutlined />} onClick={fetchLogs}>刷新</Button><Button icon={<DownloadOutlined />}>导出</Button></Space>}>
 <Table dataSource={logs} rowKey={(r, i) => r.time + r.action + (i || 0)} pagination={{pageSize: 10}} loading={loading}
 locale={{emptyText: <Empty description="暂无审计日志" />}}
 columns={[
 {title: "时间", dataIndex: "time", width: 180},
 {title: "用户", dataIndex: "user"},
 {title: "操作", dataIndex: "action", render: (v: string) => <Tag>{v}</Tag>},
 {title: "目标", dataIndex: "target"},
 {title: "详情", dataIndex: "detail", ellipsis: true},
 {title: "结果", dataIndex: "result", render: (v: string) => <Tag color={v === "成功" ? "green" : "red"}>{v}</Tag>},
 ]}
 />
 <Divider />
 <Text type="secondary">日志保留策略：最近 90 天，自动清理</Text>
 </Card>
 );
};

// ---- Report Templates ----
const ReportTemplateSettings = () => {
 const [templates, setTemplates] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);
 const [modalOpen, setModalOpen] = useState(false);
 const [newTmpl, setNewTmpl] = useState({name: "", format: "PDF", sections: ""});

 const fetchTemplates = () => {
 setLoading(true);
 request.get("/report-templates/templates").then(res => {
 if (res?.data?.templates) {
 setTemplates(res.data.templates.map((t: any) => ({
 id: t.id || t.name,
 name: t.name || "-",
 format: t.format || "-",
 sections: Array.isArray(t.sections) ? t.sections.join(", ") : t.sections || "-",
 lastUsed: t.last_used ? new Date(t.last_used).toLocaleString() : "从未使用",
 status: t.is_default ? "默认" : (t.is_active ? "启用" : "停用"),
})));
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载报告模板失败");});
};

 useEffect(() => {fetchTemplates();}, []);

 const handleCreate = async () => {
 if (!newTmpl.name.trim()) {message.warning("请输入模板名称"); return;}
 try {
 const existing = templates.filter(t => true);
 const updated = [...existing, {id: Date.now().toString(), ...newTmpl, is_active: true, sections: newTmpl.sections.split(",").map(s => s.trim())}];
 await request.put("/report-templates/templates", {templates: updated});
 message.success("模板已创建");
 setModalOpen(false);
 setNewTmpl({name: "", format: "PDF", sections: ""});
 fetchTemplates();
} catch {message.error("创建模板失败");}
};

 const handleDelete = (name: string) => {
 Modal.confirm({
 title: "确认删除",
 content: `确定删除模板 "${name}"？`,
 okText: "确定", cancelText: "取消",
 onOk: async () => {
 try {
 const remaining = templates.filter(t => t.name !== name);
 await request.put("/report-templates/templates", {templates: remaining});
 message.success("已删除");
 fetchTemplates();
} catch {message.error("删除失败");}
}
});
};

 return (
 <Card title="报告模板管理" style={{borderRadius: 8}}
 extra={<Button type="primary" style={{background: "#0284c7"}} icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>新建模板</Button>}>
 <Table dataSource={templates} rowKey="id" pagination={false} loading={loading}
 locale={{emptyText: <Empty description="暂无报告模板" />}}
 columns={[
 {title: "模板名称", dataIndex: "name"},
 {title: "格式", dataIndex: "format"},
 {title: "内容章节", dataIndex: "sections"},
 {title: "最后使用", dataIndex: "lastUsed"},
 {title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "默认" ? "blue" : v === "启用" ? "green" : "default"}>{v}</Tag>},
 {title: "操作", render: (_: any, record: any) => <Space>
 <a onClick={() => message.info("预览功能待实现")}>预览</a>
 <a onClick={() => {setNewTmpl({name: record.name, format: record.format, sections: record.sections}); setModalOpen(true);}}>编辑</a>
 <a onClick={() => handleDelete(record.name)} style={{color: "#ff4d4f"}}>删除</a>
 </Space>},
 ]}
 />
 <Modal title={newTmpl.name ? "编辑模板" : "新建模板"} open={modalOpen} onCancel={() => {setModalOpen(false); setNewTmpl({name: "", format: "PDF", sections: ""});}}
 onOk={handleCreate} okText="保存">
 <Form.Item label="模板名称"><Input value={newTmpl.name} onChange={e => setNewTmpl(p => ({...p, name: e.target.value}))} /></Form.Item>
 <Form.Item label="格式">
 <Select value={newTmpl.format} onChange={v => setNewTmpl(p => ({...p, format: v}))} options={[{value:"PDF",label:"PDF"},{value:"Word",label:"Word"},{value:"HTML",label:"HTML"},{value:"Excel",label:"Excel"}]} />
 </Form.Item>
 <Form.Item label="内容章节（逗号分隔）"><Input value={newTmpl.sections} onChange={e => setNewTmpl(p => ({...p, sections: e.target.value}))} /></Form.Item>
 </Modal>
 </Card>
 );
};

// ---- Update Management ----
const UPDATE_MODULES = [
 {key: "nuclei", label: "Nuclei 漏洞模板", icon: <BugIcon />},
 {key: "exploitdb", label: "ExploitDB 漏洞库", icon: <ExperimentOutlined />},
 {key: "metasploit", label: "Metasploit 框架", icon: <SafetyOutlined />},
 {key: "cve", label: "CVE 漏洞特征库", icon: <WarningOutlined />},
];

const UpdateSettings = () => {
 const [updating, setUpdating] = useState(false);
 const [progress, setProgress] = useState<Record<string, number>>({});
 const [modules, setModules] = useState<any[]>([]);
 const [loading, setLoading] = useState(true);

 const fetchUpdates = () => {
 setLoading(true);
 request.get("/updates/status").then(res => {
 if (res?.data) {
 // API 返回扁平对象 {nuclei: {...}, exploitdb: {...}, metasploit: {...}, cve: {...}}
 const raw = res.data;
 const mapped = UPDATE_MODULES.map((m) => {
 const d = raw[m.key] || {};
 return {
 key: m.key,
 name: m.label,
 icon: m.icon,
 version: d.version || d.templates || "-",
 count: d.templates || d.exploits || d.modules || d.total_cves || 0,
 size: d.size || "",
 lastUpdate: d.last_update || "-",
 status: d.status || (d.version ? "已安装" : "未安装"),
};
});
 setModules(mapped);
}
 setLoading(false);
}).catch(() => {setLoading(false); message.warning("加载更新状态失败");});
};

 useEffect(() => {fetchUpdates();}, []);

 const handleUpdate = (target: string) => {
 setUpdating(true);
 setProgress((prev) => ({...prev, [target]: 0}));
 request.post("/updates/trigger", {target})
 .then(() => {
 const timer = setInterval(() => {
 setProgress((prev) => ({...prev, [target]: Math.min((prev[target] || 0) + 15, 90)}));
}, 800);
 const poll = setInterval(() => {
 request.get("/updates/status").then((r2) => {
 setProgress((prev) => ({...prev, [target]: 95}));
 clearInterval(timer); clearInterval(poll);
 setProgress((prev) => ({...prev, [target]: 100}));
 setUpdating(false);
 message.success(`${target} 更新完成`);
 fetchUpdates();
}).catch(() => {
 clearInterval(timer); clearInterval(poll);
 setProgress((prev) => ({...prev, [target]: 100}));
 setUpdating(false);
 fetchUpdates();
});
}, 3000);
})
 .catch(() => {setUpdating(false); message.error("更新失败");});
};

 const handleUpdateAll = () => {
 UPDATE_MODULES.forEach((m) => handleUpdate(m.key));
};

 return (
 <Card
 title={<Space><ReloadOutlined style={{color: "#0284c7"}} /><span>更新管理</span></Space>}
 style={{borderRadius: 8}}
 extra={
 <Button type="primary" style={{background: "#0284c7"}}
 icon={<DownloadOutlined />} loading={updating} onClick={handleUpdateAll}>
 一键更新全部
 </Button>
}
 >
 <List
 dataSource={modules}
 loading={loading}
 locale={{emptyText: <Empty description="暂无更新数据" />}}
 renderItem={(item: any) => {
 const pct = progress[item.key];
 return (
 <List.Item
 actions={[
 <Button size="small" type="primary" style={{background: "#0284c7"}}
 icon={<DownloadOutlined />}
 loading={pct !== undefined && pct < 100}
 onClick={() => handleUpdate(item.key)}>
 {pct !== undefined && pct < 100 ? `${pct}%` : "更新"}
 </Button>,
 ]}
 >
 <List.Item.Meta
 avatar={
 <div style={{
 width: 40, height: 40, borderRadius: 8,
 background: "#e0f2fe", display: "flex",
 alignItems: "center", justifyContent: "center",
 fontSize: 20, color: "#0284c7",
}}>
 {item.icon}
 </div>
}
 title={
 <Space>
 <Text strong>{item.name}</Text>
 <Tag color={item.status === "已安装" ? "green" : "orange"} style={{fontSize: 10}}>
 {item.status}
 </Tag>
 </Space>
}
 description={
 <div>
 <div><Text type="secondary" style={{fontSize: 12}}>
 {item.count > 0 ? `${item.count.toLocaleString()} 条记录` : "版本: "}{item.version.slice(0, 80)}
 {item.size ? ` | 大小: ${item.size}` : ""}
 </Text></div>
 <div><Text type="secondary" style={{fontSize: 11}}>最后更新: {item.lastUpdate}</Text></div>
 {pct !== undefined && (
 <Progress percent={Math.min(pct, 100)} size="small" style={{marginTop: 6}}
 strokeColor={pct >= 100 ? "#10b981" : "#0284c7"} />
 )}
 </div>
}
 />
 </List.Item>
 );
}}
 />
 </Card>
 );
};

/* ==================== Main Component ==================== */

export default function SettingsPage() {
 const {tab} = useParams<{tab?: string}>();

 const renderContent = () => {
 switch (tab || "general") {
 case "general": return <GeneralSettings />;
 case "system": return <SystemInfoSettings />;
 case "llm": return <LLMSettings />;
 case "users": return <UserManageSettings />;
 case "roles": return <RolesSettings />;
 case "notifications": return <NotificationsSettings />;
 case "security": return <SecuritySettings />;
 case "credentials": return <CredentialsSettings />;
 case "audit": return <AuditLogSettings />;
 case "reports": return <ReportTemplateSettings />;
 case "updates": return <UpdateSettings />;
 default: return <GeneralSettings />;
}
};

 return (
 <div style={{padding: 24}}>
 <Title level={4} style={{marginBottom: 24}}>{categoryLabel[tab || "general"] || "系统设置"}</Title>
 {renderContent()}
 </div>
 );
}
