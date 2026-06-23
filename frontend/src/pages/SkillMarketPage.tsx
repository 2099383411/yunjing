// @ts-nocheck
import {useState, useEffect, useCallback} from "react";
import {
 Table, Card, Tag, Button, Input, Typography, Space, Switch,
 message, Modal, Upload, Row, Col, Spin, Empty, Tooltip, Badge,
 Alert, Divider, Form, Select,
} from "antd";

















import request from "../api/request";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import UploadOutlined from "@ant-design/icons/es/icons/UploadOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import ExclamationCircleOutlined from "@ant-design/icons/es/icons/ExclamationCircleOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import DeleteOutlined from "@ant-design/icons/es/icons/DeleteOutlined";
import PlusOutlined from "@ant-design/icons/es/icons/PlusOutlined";
import EditOutlined from "@ant-design/icons/es/icons/EditOutlined";
import CodeOutlined from "@ant-design/icons/es/icons/CodeOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import CloudServerOutlined from "@ant-design/icons/es/icons/CloudServerOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import FolderOpenOutlined from "@ant-design/icons/es/icons/FolderOpenOutlined";;

const {Title, Text, Paragraph} = Typography;
const {TextArea} = Input;

const SEVERITY_COLORS: Record<string, string> = {
 critical: "red", high: "orange", medium: "blue", low: "default",
};
const CAT_COLORS: Record<string, string> = {
 "扫描": "blue", "漏洞扫描": "red", "注入检测": "purple",
 "暴力破解": "orange", "目录发现": "cyan", "渗透框架": "geekblue",
 "信息收集": "green", "AD测试": "volcano", "中继攻击": "magenta",
 "逆向": "lime", "云安全": "geekblue", "Web": "purple",
 "内网": "red", "后渗透": "orange", "工具": "cyan",
 "开发": "blue", "架构": "gold", "综合": "default",
};
const CATEGORY_OPTIONS = [
 "综合", "扫描", "漏洞扫描", "信息收集", "Web", "内网",
 "AD测试", "API测试", "后渗透", "工具", "云安全", "开发",
 "架构", "逆向", "自定义",
];
const SEVERITY_OPTIONS = [
 {value: "critical", label: "严重"},
 {value: "high", label: "高危"},
 {value: "medium", label: "中危"},
 {value: "low", label: "低危"},
];

export default function SkillMarketPage() {
 const [skills, setSkills] = useState<any[]>([]);
 const [loading, setLoading] = useState(false);
 const [search, setSearch] = useState("");
 const [activeTab, setActiveTab] = useState("installed");
 const [modalOpen, setModalOpen] = useState(false);
 const [editingSkill, setEditingSkill] = useState<any>(null);
 const [formLoading, setFormLoading] = useState(false);
 const [importing, setImporting] = useState(false);

 // 加载技能列表
 const fetchSkills = useCallback(async () => {
 setLoading(true);
 try {
 const res = await request.get("/skills/");
 const raw = res?.data;
 const list = Array.isArray(raw) ? raw : raw.skills || raw.items || raw.results || [];
 setSkills(list);
} catch {
 setSkills([]);
} finally {
 setLoading(false);
}
}, []);

 useEffect(() => {fetchSkills();}, [fetchSkills]);

 // 启用/禁用
 const toggleEnabled = async (skill: any, enabled: boolean) => {
 try {
 await request.put(`/skills/${skill.id}/`, {enabled});
 message.success(enabled ? "已启用" : "已禁用");
 setSkills((prev) => prev.map((s) => (s.id === skill.id ? {...s, enabled} : s)));
} catch {
 message.error("操作失败");
}
};

 // 删除自定义技能
 const deleteCustomSkill = async (skill: any) => {
 try {
 await request.delete(`/skills/${skill.id}/`);
 message.success("已删除");
 setSkills((prev) => prev.filter((s) => s.id !== skill.id));
} catch {
 message.error("删除失败");
}
};

 // 编辑/新建弹窗
 const openEditModal = (skill: any = null) => {
 setEditingSkill(skill);
 setModalOpen(true);
};

 const handleFormSubmit = async (values: any) => {
 setFormLoading(true);
 try {
 if (editingSkill) {
 await request.put(`/skills/${editingSkill.id}/`, values);
 message.success("已更新");
} else {
 await request.post("/skills/", values);
 message.success("已创建");
}
 setModalOpen(false);
 setEditingSkill(null);
 fetchSkills();
} catch (e: any) {
 message.error(e?.response?.data?.detail || "操作失败");
} finally {
 setFormLoading(false);
}
};

 // ZIP导入
 const handleImport = async (file: File) => {
 setImporting(true);
 const formData = new FormData();
 formData.append("file", file);
 try {
 await request.post("/skills/import", formData, {
 headers: {"Content-Type": "multipart/form-data"},
});
 message.success("技能导入成功");
 fetchSkills();
} catch {
 message.error("导入失败，请检查 ZIP 格式");
} finally {
 setImporting(false);
}
 return false;
};

 // 筛选
 const filteredSkills = skills.filter((s) => {
 if (!search) return true;
 const q = search.toLowerCase();
 return (
 (s.name || "").toLowerCase().includes(q) ||
 (s.id || "").toLowerCase().includes(q) ||
 (s.category || "").includes(q) ||
 (s.description || "").toLowerCase().includes(q)
 );
});

 const customSkills = filteredSkills.filter((s) => s.is_custom);
 const builtinSkills = filteredSkills.filter((s) => !s.is_custom);

 // 已安装技能 - 列
 const columnsBuiltin = [
 {
 title: "技能名称", key: "name", width: 180,
 render: (_: any, r: any) => (
 <Space>
 <SettingOutlined style={{color: "#0284c7"}} />
 <div>
 <Text strong style={{fontSize: 13}}>{r.name}</Text>
 <div><Text type="secondary" style={{fontSize: 11}}>{r.id}</Text></div>
 </div>
 </Space>
 ),
},
 {
 title: "分类", dataIndex: "category", key: "category", width: 90,
 render: (v: string) => <Tag color={CAT_COLORS[v] || "default"}>{v}</Tag>,
},
 {
 title: "严重级别", dataIndex: "severity", key: "severity", width: 80,
 render: (v: string) => (
 <Tag color={SEVERITY_COLORS[v] || "default"}>
 {SEVERITY_OPTIONS.find((o) => o.value === v)?.label || v}
 </Tag>
 ),
},
 {
 title: "描述", dataIndex: "description", key: "description", ellipsis: true,
},
 {
 title: "状态", key: "enabled", width: 70,
 render: (_: any, r: any) => (
 <Badge status={r.enabled ? "success" : "default"} text={r.enabled ? "启用" : "禁用"} />
 ),
},
 {
 title: "启用", key: "action", width: 60,
 render: (_: any, r: any) => (
 <Switch size="small" checked={r.enabled} onChange={(v) => toggleEnabled(r, v)} />
 ),
},
 ];

 // 自定义技能 - 列
 const columnsCustom = [
 {
 title: "技能名称", key: "name", width: 180,
 render: (_: any, r: any) => (
 <Space>
 <CodeOutlined style={{color: "#8b5cf6", fontSize: 16}} />
 <div>
 <Text strong style={{fontSize: 13}}>{r.name}</Text>
 <div><Text type="secondary" style={{fontSize: 11}}>{r.id}</Text></div>
 </div>
 </Space>
 ),
},
 {
 title: "分类", dataIndex: "category", key: "category", width: 90,
 render: (v: string) => <Tag color={CAT_COLORS[v] || "default"}>{v || "-"}</Tag>,
},
 {
 title: "严重级别", dataIndex: "severity", key: "severity", width: 80,
 render: (v: string) => (
 <Tag color={SEVERITY_COLORS[v] || "default"}>
 {SEVERITY_OPTIONS.find((o) => o.value === v)?.label || v || "中危"}
 </Tag>
 ),
},
 {
 title: "描述", dataIndex: "description", key: "description", ellipsis: true,
},
 {
 title: "创建时间", dataIndex: "created_at", key: "created_at", width: 150,
 render: (v: string) => {
 if (!v) return "-";
 const d = new Date(v);
 return <Text type="secondary">{isNaN(d.getTime()) ? v.slice(0, 10) : d.toLocaleDateString("zh-CN")}</Text>;
},
},
 {
 title: "状态", key: "enabled", width: 70,
 render: (_: any, r: any) => (
 <Badge status={r.enabled ? "success" : "default"} text={r.enabled ? "启用" : "禁用"} />
 ),
},
 {
 title: "操作", key: "action", width: 120,
 render: (_: any, r: any) => (
 <Space>
 <Switch size="small" checked={r.enabled} onChange={(v) => toggleEnabled(r, v)} />
 <Tooltip title="编辑">
 <Button size="small" icon={<EditOutlined />} onClick={() => openEditModal(r)} />
 </Tooltip>
 <Tooltip title="删除">
 <Button size="small" danger icon={<DeleteOutlined />}
 onClick={() => {
 Modal.confirm({
 title: "确认删除",
 content: `确定删除自定义技能「${r.name}」？`,
 onOk: () => deleteCustomSkill(r),
});
}}
 />
 </Tooltip>
 </Space>
 ),
},
 ];

 // 编辑/新建弹窗
 const renderFormModal = () => (
 <Modal
 title={
 <Space>
 {editingSkill
 ? <EditOutlined style={{color: "#8b5cf6"}} />
 : <PlusOutlined style={{color: "#0284c7"}} />}
 <span>{editingSkill ? "编辑自定义技能" : "新建自定义技能"}</span>
 </Space>
}
 open={modalOpen}
 onCancel={() => {setModalOpen(false); setEditingSkill(null);}}
 footer={null}
 width={520}
 >
 <Form
 layout="vertical"
 initialValues={editingSkill || {category: "自定义", severity: "medium", enabled: true}}
 onFinish={handleFormSubmit}
 style={{marginTop: 16}}
 >
 <Form.Item label="技能名称" name="name" rules={[{required: true, message: "请输入技能名称"}]}>
 <Input placeholder="例如：自定义端口扫描器" />
 </Form.Item>

 <Row gutter={16}>
 <Col span={12}>
 <Form.Item label="分类" name="category">
 <Select
 mode="tags"
 maxCount={1}
 placeholder="选择或输入"
 options={CATEGORY_OPTIONS.map((c) => ({value: c, label: c}))}
 />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="严重级别" name="severity">
 <Select options={SEVERITY_OPTIONS} />
 </Form.Item>
 </Col>
 </Row>

 <Form.Item label="描述说明" name="description">
 <TextArea rows={3} placeholder="对这个自定义技能的用途说明（可选）" />
 </Form.Item>

 {!editingSkill && (
 <Alert
 message="创建后该技能将出现在扫描任务的可选技能列表中，你可以随时编辑描述或启用/禁用"
 type="info" showIcon style={{marginBottom: 16}}
 />
 )}

 <div style={{textAlign: "right"}}>
 <Button style={{marginRight: 8}} onClick={() => {setModalOpen(false); setEditingSkill(null);}}>
 取消
 </Button>
 <Button type="primary" htmlType="submit" loading={formLoading} style={{background: "#0284c7"}}>
 {editingSkill ? "保存修改" : "创建技能"}
 </Button>
 </div>
 </Form>
 </Modal>
 );

 return (
 <div style={{padding: 0}}>
 {/* 头部 */}
 <div style={{
 marginBottom: 16, display: "flex", justifyContent: "space-between",
 alignItems: "center", background: "#fff", padding: "16px 24px",
 borderRadius: 8, border: "1px solid #e2e8f0",
}}>
 <Space>
 <CodeOutlined style={{fontSize: 22, color: "#0284c7"}} />
 <Title level={4} style={{margin: 0, color: "#0284c7"}}>技能管理</Title>
 </Space>
 <Space>
 <Input
 placeholder="搜索技能..."
 prefix={<SearchOutlined />}
 style={{width: 200}}
 value={search}
 onChange={(e) => setSearch(e.target.value)}
 allowClear
 />
 <Button icon={<ReloadOutlined />} onClick={fetchSkills}>刷新</Button>
 </Space>
 </div>

 {/* Tab 切换 */}
 <Card bodyStyle={{padding: 0}}>
 <div style={{
 display: "flex", borderBottom: "1px solid #e2e8f0",
 background: "#f8fafc", borderRadius: "8px 8px 0 0",
}}>
 {[
 {key: "installed", icon: <SettingOutlined />, label: "已安装技能", count: builtinSkills.length},
 {key: "custom", icon: <CodeOutlined />, label: "自定义技能", count: customSkills.length},
 ].map((tab) => (
 <div
 key={tab.key}
 onClick={() => setActiveTab(tab.key)}
 style={{
 flex: 1, textAlign: "center", padding: "14px 20px",
 cursor: "pointer", fontWeight: activeTab === tab.key ? 600 : 400,
 color: activeTab === tab.key ? "#0284c7" : "#64748b",
 borderBottom: activeTab === tab.key ? "2px solid #0284c7" : "2px solid transparent",
 transition: "all 0.2s", display: "flex", alignItems: "center",
 justifyContent: "center", gap: 8,
}}
 >
 {tab.icon}
 <span>{tab.label}</span>
 <Tag color={activeTab === tab.key ? "blue" : "default"} style={{margin: 0, fontSize: 11}}>
 {tab.count}
 </Tag>
 </div>
 ))}
 </div>

 {/* 已安装技能 Tab */}
 {activeTab === "installed" && (
 <div style={{padding: 16}}>
 <div style={{marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center"}}>
 <Text type="secondary">内置的技能库，可按需启用/禁用</Text>
 <Upload
 accept=".zip,.tar.gz"
 showUploadList={false}
 beforeUpload={handleImport}
 disabled={importing}
 >
 <Button icon={<UploadOutlined />} loading={importing} size="small">
 导入技能包 (ZIP)
 </Button>
 </Upload>
 </div>
 <Spin spinning={loading}>
 {builtinSkills.length === 0 && !loading ? (
 <Empty description="暂无技能数据" style={{padding: 40}} />
 ) : (
 <Table
 dataSource={builtinSkills}
 columns={columnsBuiltin}
 rowKey="id"
 pagination={{pageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 个内置技能`}}
 size="middle"
 scroll={{x: 700}}
 />
 )}
 </Spin>
 </div>
 )}

 {/* 自定义技能 Tab */}
 {activeTab === "custom" && (
 <div style={{padding: 16}}>
 <div style={{marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center"}}>
 <Text type="secondary">自定义扫描技能，可在渗透测试中选用</Text>
 <Button
 type="primary"
 icon={<PlusOutlined />}
 onClick={() => openEditModal(null)}
 style={{background: "#0284c7"}}
 >
 新建自定义技能
 </Button>
 </div>
 <Spin spinning={loading}>
 {customSkills.length === 0 && !loading ? (
 <Empty
 description={
 <Space direction="vertical" style={{textAlign: "center"}}>
 <Text>暂无自定义技能</Text>
 <Button type="primary" icon={<PlusOutlined />} onClick={() => openEditModal(null)}
 style={{background: "#0284c7"}}>
 立即创建
 </Button>
 </Space>
}
 style={{padding: 60}}
 />
 ) : (
 <Table
 dataSource={customSkills}
 columns={columnsCustom}
 rowKey="id"
 pagination={{pageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 个自定义技能`}}
 size="middle"
 scroll={{x: 800}}
 />
 )}
 </Spin>
 </div>
 )}
 </Card>

 {/* 编辑/新建弹窗 */}
 {renderFormModal()}
 </div>
 );
}
