// @ts-nocheck
import {useState, useEffect, useMemo} from "react";
import {
 Table, Card, Tag, Button, Input, Select, Typography, Space,
 Progress, Badge, Drawer, Statistic, Row, Col, Spin, Empty,
 Tooltip, message, Descriptions, Tabs, Collapse, List, Divider,
} from "antd";




















import request from "../api/request";
import {useNavigate} from "react-router-dom";
import BugIcon from "../components/BugIcon";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import EyeOutlined from "@ant-design/icons/es/icons/EyeOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import SyncOutlined from "@ant-design/icons/es/icons/SyncOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import ArrowLeftOutlined from "@ant-design/icons/es/icons/ArrowLeftOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import CloudServerOutlined from "@ant-design/icons/es/icons/CloudServerOutlined";
import LockOutlined from "@ant-design/icons/es/icons/LockOutlined";
import FolderOpenOutlined from "@ant-design/icons/es/icons/FolderOpenOutlined";
import CodeOutlined from "@ant-design/icons/es/icons/CodeOutlined";
<<<<<<< HEAD
import LinkOutlined from "@ant-design/icons/es/icons/LinkOutlined";;
=======
import LinkOutlined from "@ant-design/icons/es/icons/LinkOutlined"
>>>>>>> server/master

const {Title, Text} = Typography;

// ====== 常量配置 ======
const STATUS_MAP: Record<string, {color: string; label: string}> = {
 completed: {color: "green", label: "已完成"},
 running: {color: "blue", label: "运行中"},
 queued: {color: "default", label: "排队中"},
 pending: {color: "default", label: "排队中"},
 failed: {color: "red", label: "失败"},
 paused: {color: "orange", label: "已暂停"},
 cancelled: {color: "default", label: "已取消"},
};

const TYPE_LABELS: Record<string, string> = {
 quick: "快速扫描",
 full: "全面扫描",
 port: "端口扫描",
 api: "API测试",
 password: "弱口令检测",
 vuln: "漏洞扫描",
};

const PHASE_LABELS: Record<string, {label: string; icon: React.ReactNode; color: string}> = {
 asset_discovery: {label: "资产发现", icon: <SearchOutlined />, color: "#6366f1"},
 port_scan: {label: "端口扫描", icon: <ApiOutlined />, color: "#0284c7"},
 service_detect: {label: "服务识别", icon: <CloudServerOutlined />, color: "#0ea5e9"},
 vuln_scan: {label: "漏洞扫描", icon: <BugIcon />, color: "#f59e0b"},
 web_scan: {label: "Web扫描", icon: <ExperimentOutlined />, color: "#8b5cf6"},
 dir_scan: {label: "目录扫描", icon: <FolderOpenOutlined />, color: "#ec4899"},
 web_fuzz: {label: "Fuzz测试", icon: <ExperimentOutlined />, color: "#f43f5e"},
 api_scan: {label: "API测试", icon: <CodeOutlined />, color: "#14b8a6"},
 auth_test: {label: "认证测试", icon: <LockOutlined />, color: "#f97316"},
 exploit: {label: "漏洞利用", icon: <ThunderboltOutlined />, color: "#ef4444"},
 post_exploit: {label: "后渗透", icon: <LinkOutlined />, color: "#10b981"},
 reporting: {label: "报告生成", icon: <FileTextOutlined />, color: "#6b7280"},
};

function phaseConfig(name: string) {
 return PHASE_LABELS[name] || {label: name, icon: <SafetyOutlined />, color: "#6b7280"};
}

function fmtTime(ts: string): string {
 if (!ts) return "-";
 const d = new Date(ts);
 return isNaN(d.getTime()) ? ts.slice(0, 16).replace("T", " ") : d.toLocaleString("zh-CN");
}

// ====== 页面组件 ======
export default function TaskListPage() {
 const [tasks, setTasks] = useState<any[]>([]);
 const [loading, setLoading] = useState(false);
 const [search, setSearch] = useState("");
 const [statusFilter, setStatusFilter] = useState<string>("");
 const [selectedTask, setSelectedTask] = useState<any>(null);
 const [drawerOpen, setDrawerOpen] = useState(false);
 const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
 const [vulnLoading, setVulnLoading] = useState(false);
 const [cancelling, setCancelling] = useState(false);

 useEffect(() => {
 setLoading(true);
 request.get("/tasks/")
 .then((res: any) => {
 const raw = res?.data;
 if (raw) {
 const list = Array.isArray(raw) ? raw : raw.tasks || raw.items || raw.results || [];
 setTasks(list);
}
})
 .catch(() => message.error("加载任务列表失败"))
 .finally(() => setLoading(false));
}, []);

 // 搜索/筛选
 const filtered = useMemo(() => {
 return tasks.filter((t) => {
 if (search && !(t.target || "").toLowerCase().includes(search.toLowerCase())) return false;
 if (statusFilter && t.status !== statusFilter) return false;
 return true;
});
}, [tasks, search, statusFilter]);

 // 打开抽屉
 const openDrawer = (task: any) => {
 // 解析 result（可能是字符串）
 if (typeof task.result === "string") {
 try {task.result = JSON.parse(task.result);} catch {}
}
 setSelectedTask(task);
 setDrawerOpen(true);
 fetchVulnerabilities(task.id);
};


 const fetchVulnerabilities = async (taskId: string) => {
 setVulnLoading(true);
 try {
 const res = await request.get("/tasks/" + taskId + "/vulnerabilities");
 const data = res?.data;
 setVulnerabilities(Array.isArray(data) ? data : []);
 } catch {
 setVulnerabilities([]);
 } finally {
 setVulnLoading(false);
 }
 };

 const handleCancel = async (taskId: string) => {
 setCancelling(true);
 try {
 await request.post("/tasks/" + taskId + "/cancel");
 message.success("任务已取消");
 const res = await request.get("/tasks/");
 const raw = res?.data;
 setTasks(Array.isArray(raw) ? raw : raw.tasks || raw.items || raw.results || []);
 setDrawerOpen(false);
 } catch (err: any) {
 message.error(err?.response?.data?.detail || "取消失败");
 } finally {
 setCancelling(false);
 }
 };
 // ====== 列定义 ======
 const columns = [
 {
 title: "目标", dataIndex: "target", key: "target", width: 200,
 render: (v: string, r: any) => (
 <a onClick={() => openDrawer(r)} style={{fontWeight: 500}}>
 <SafetyOutlined style={{marginRight: 6, color: "#0284c7"}} />
 {v || "未知"}
 </a>
 ),
},
 {
 title: "扫描类型", dataIndex: "scan_type", key: "scan_type", width: 100,
 render: (v: string) => {
 const label = TYPE_LABELS[v?.toLowerCase()] || v || "未知";
 return <Tag color={v === "full" ? "purple" : "blue"}>{label}</Tag>;
},
},
 {
 title: "状态", dataIndex: "status", key: "status", width: 90,
 render: (v: string) => {
 const key = v?.toLowerCase();
 const cfg = STATUS_MAP[key] || {color: "default", label: v || "未知"};
 return <Badge status={cfg.color as any} text={cfg.label} />;
},
},
 {
 title: "进度", dataIndex: "progress", key: "progress", width: 150,
 render: (v: number, r: any) => {
 const pct = v ?? 0;
 const done = r.status?.toLowerCase() === "completed";
 return <Progress percent={done ? 100 : pct} size="small" status={done ? "success" : "active"} />;
},
},
 {
 title: "漏洞数", key: "vulns", width: 80,
 render: (_: any, r: any) => {
 const total = r.result?.total ?? 0;
 const critical = r.result?.critical ?? 0;
 if (total > 0) {
 return (
 <Tooltip title={`严重${critical} 总计${total}`}>
 <Tag color="red">{total}</Tag>
 </Tooltip>
 );
}
 return <Text type="secondary">0</Text>;
},
},
 {
 title: "端口", key: "ports", width: 60,
 render: (_: any, r: any) => {
 const ports = r.result?.ports;
 if (ports && ports.length > 0) return <Text strong>{ports.length}</Text>;
 const portsFound = r.result?.ports_found;
 return portsFound ? <Text>{portsFound}</Text> : "-";
},
},
 {
 title: "创建时间", dataIndex: "created_at", key: "created_at", width: 160,
 render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text>,
},
 {
 title: "操作", key: "action", width: 50,
 render: (_: any, r: any) => (
 <Tooltip title="查看详情">
 <Button size="small" icon={<EyeOutlined />} onClick={() => openDrawer(r)} />
 </Tooltip>
 ),
},
 ];

 // ====== 统计信息 ======
 const stats = useMemo(() => {
 const s = {total: 0, completed: 0, running: 0, failed: 0, pending: 0, vulns: 0};
 tasks.forEach((t) => {
 s.total++;
 const st = (t.status || "").toLowerCase();
 if (st === "completed") s.completed++;
 else if (st === "running") s.running++;
 else if (st === "failed") s.failed++;
 else s.pending++;
 s.vulns += (t.result?.total || 0);
});
 return s;
}, [tasks]);

 // ====== 抽屉：任务详情 ======
 const renderDrawer = () => {
 if (!selectedTask) return null;
 const t = selectedTask;
 const r = t.result || {};
 const phases = r.phases_log || [];

 return (
 <Drawer
 title={
 <Space>
 <SafetyOutlined style={{color: "#0284c7"}} />
 <span>{t.target || "未知目标"}</span>
 <Tag color={t.scan_type === "full" ? "purple" : "blue"}>
 {TYPE_LABELS[t.scan_type] || t.scan_type || "未知"}
 </Tag>
 </Space>
}
 placement="right"
 width={560}
 open={drawerOpen}
 onClose={() => {setDrawerOpen(false); setSelectedTask(null);}}
 extra={
 <Space>
 {(t.status || "").toLowerCase() === "running" && (
 <Button
 danger
 icon={<CloseCircleOutlined />}
 loading={cancelling}
 onClick={() => handleCancel(t.id)}
 >
 取消任务
 </Button>
 )}
 <Button icon={<ArrowLeftOutlined />} onClick={() => {setDrawerOpen(false); setSelectedTask(null);}}>
 返回
 </Button>
 </Space>
}
 >
 {/* 基本信息 */}
 <Card size="small" style={{marginBottom: 16}} bodyStyle={{padding: "12px 16px"}}>
 <Descriptions column={2} size="small">
 <Descriptions.Item label="目标">{t.target}</Descriptions.Item>
 <Descriptions.Item label="扫描类型">{TYPE_LABELS[t.scan_type] || t.scan_type || "未知"}</Descriptions.Item>
 <Descriptions.Item label="状态">
 {(() => {
 const key = (t.status || "").toLowerCase();
 const cfg = STATUS_MAP[key];
 return <Badge status={cfg?.color as any} text={cfg?.label || t.status} />;
})()}
 </Descriptions.Item>
 <Descriptions.Item label="进度">{t.progress ?? 0}%</Descriptions.Item>
 <Descriptions.Item label="漏洞总数">{r.total || 0}</Descriptions.Item>
 <Descriptions.Item label="开放端口">{r.ports?.length || r.ports_found || 0} 个</Descriptions.Item>
 <Descriptions.Item label="任务ID" span={2}>
 <Text copyable style={{fontSize: 12}}>{t.id}</Text>
 </Descriptions.Item>
 <Descriptions.Item label="创建时间">{fmtTime(t.created_at)}</Descriptions.Item>
 <Descriptions.Item label="完成时间">{fmtTime(t.completed_at)}</Descriptions.Item>
 </Descriptions>
 </Card>

 {/* 漏洞统计 */}
 {(r.total || r.critical || r.high || r.medium) > 0 && (
 <Card size="small" style={{marginBottom: 16}} title="漏洞统计" bodyStyle={{padding: "12px 16px"}}>
 <Row gutter={8}>
 {[
 {label: "严重", value: r.critical || 0, color: "#7c3aed"},
 {label: "高危", value: r.high || 0, color: "#dc2626"},
 {label: "中危", value: r.medium || 0, color: "#d97706"},
 {label: "低危", value: r.low || 0, color: "#0284c7"},
 ].map((item) => (
 <Col span={6} key={item.label}>
 <div style={{textAlign: "center"}}>
 <div style={{fontSize: 20, fontWeight: 700, color: item.color}}>{item.value}</div>
 <Text type="secondary" style={{fontSize: 12}}>{item.label}</Text>
 </div>
 </Col>
 ))}
 </Row>
 {r.vulnerability_names && r.vulnerability_names.length > 0 && (
 <div style={{marginTop: 8}}>
 <Divider style={{margin: "8px 0"}} />
 <Text type="secondary" style={{fontSize: 12}}>漏洞名称：</Text>
 <Space wrap size={[4, 4]} style={{marginTop: 4}}>
 {r.vulnerability_names.map((v: string, i: number) => (
 <Tag key={i} color="red">{v}</Tag>
 ))}
 </Space>
 </div>
 )}
 </Card>
 )}

 {/* 端口信息 */}
 {r.ports && r.ports.length > 0 && (
 <Card size="small" style={{marginBottom: 16}} title={`开放端口 (${r.ports.length})`} bodyStyle={{padding: "12px 16px"}}>
 <Space wrap size={[4, 4]}>
 {r.ports.map((p: number, i: number) => (
 <Tag key={i} color="blue" style={{margin: 0, fontSize: 12, padding: "2px 10px"}}>
 {p}/tcp <span style={{color: "#52c41a"}}>OPEN</span>
 </Tag>
 ))}
 </Space>
 {r.services_detailed && r.services_detailed.length > 0 && (
 <div style={{marginTop: 8}}>
 {r.services_detailed.map((s: any, i: number) => (
 <Tag key={i} color="geekblue" style={{marginBottom: 2}}>
 {s.port}/tcp: {s.service}{s.version ? ` (${s.version})` : ""}
 </Tag>
 ))}
 </div>
 )}
 </Card>
 )}

 {/* 漏洞详情列表 */}
 {(vulnerabilities.length > 0 || vulnLoading) && (
 <Card size="small" style={{marginBottom: 16}} title="漏洞详情" bodyStyle={{padding: "12px 16px"}}>
 {vulnLoading ? (
 <Spin />
 ) : (
 <List
 size="small"
 dataSource={vulnerabilities}
 renderItem={(v: any) => (
 <List.Item>
 <List.Item.Meta
 avatar={
 <BugIcon style={{fontSize: 18, color: v.severity === "critical" ? "#7c3aed" : v.severity === "high" ? "#dc2626" : v.severity === "medium" ? "#d97706" : "#0284c7"}} />
 }
 title={
 <Space size={4}>
 <Text strong>{v.name || v.title || "未知漏洞"}</Text>
 {v.severity && (
 <Tag color={v.severity === "critical" ? "purple" : v.severity === "high" ? "red" : v.severity === "medium" ? "orange" : "blue"}>
 {v.severity.toUpperCase()}
 </Tag>
 )}
 {v.cve_id && <Tag>{v.cve_id}</Tag>}
 </Space>
 }
 description={
 <div>
 <Text type="secondary" style={{fontSize: 12}}>{v.description || v.detail || ""}</Text>
 {v.target && <div><Text type="secondary" style={{fontSize: 11}}>目标: {v.target}</Text></div>}
 {v.remediation && <div><Text type="secondary" style={{fontSize: 11}}>修复建议: {v.remediation}</Text></div>}
 </div>
 }
 />
 </List.Item>
 )}
 />
 )}
 </Card>
 )}

 {/* 执行阶段 */}
 <Card size="small" title={`执行阶段 (${(r.phases_executed || phases).length})`} bodyStyle={{padding: "12px 16px"}}>
 {phases.length > 0 ? (
 <Collapse
 size="small"
 expandIconPosition="end"
 items={phases.map((p: any, i: number) => {
 const name = p.name || "";
 const cfg = phaseConfig(name);
 const data = p.data || {};
 const done = p.status === "done";
 return {
 key: String(i),
 label: (
 <Space>
 <span style={{color: cfg.color, fontSize: 14}}>{cfg.icon}</span>
 <Text strong>{cfg.label}</Text>
 {!done && <Badge status="processing" />}
 <Tag color={done ? "green" : "orange"} style={{fontSize: 10, lineHeight: "16px"}}>
 {done ? "已完成" : p.status || "进行中"}
 </Tag>
 </Space>
 ),
 children: (
 <div style={{padding: "4px 0"}}>
 {Object.entries(data).map(([k, v]) => {
 if (!v || (Array.isArray(v) && v.length === 0)) return null;
 return (
 <div key={k} style={{marginBottom: 4}}>
 <Text type="secondary" style={{fontSize: 12}}>{k}: </Text>
 <Text style={{fontSize: 12}}>
 {typeof v === "object" ? JSON.stringify(v).slice(0, 200) : String(v)}
 </Text>
 </div>
 );
})}
 </div>
 ),
};
})}
 />
 ) : (
 /* 备选：从 phases_executed 显示简要列表 */
 <List
 size="small"
 dataSource={r.phases_executed || []}
 renderItem={(name: string, i: number) => {
 const cfg = phaseConfig(name);
 const done = true; // 已完成的任务所有阶段都已执行
 return (
 <List.Item style={{padding: "4px 0"}}>
 <Space>
 <span style={{color: cfg.color}}>{cfg.icon}</span>
 <Text>{cfg.label}</Text>
 {done && <CheckCircleOutlined style={{color: "#10b981"}} />}
 </Space>
 </List.Item>
 );
}}
 />
 )}
 </Card>
 </Drawer>
 );
};

 return (
 <div style={{padding: 0}}>
 {/* 头部 */}
 <div style={{
 marginBottom: 16, display: "flex", justifyContent: "space-between",
 alignItems: "center", background: "#fff", padding: "16px 24px",
 borderRadius: 8, border: "1px solid #e2e8f0",
}}>
 <Space>
 <SyncOutlined style={{fontSize: 22, color: "#0284c7"}} />
 <Title level={4} style={{margin: 0, color: "#0284c7"}}>扫描任务</Title>
 </Space>
 <Space>
 <Select
 style={{width: 120}}
 placeholder="状态筛选"
 allowClear
 value={statusFilter || undefined}
 onChange={(v) => setStatusFilter(v || "")}
 options={[
 {value: "COMPLETED", label: "已完成"},
 {value: "RUNNING", label: "运行中"},
 {value: "PENDING", label: "排队中"},
 {value: "FAILED", label: "失败"},
 ]}
 />
 <Input
 placeholder="搜索目标..."
 prefix={<SearchOutlined />}
 style={{width: 200}}
 value={search}
 onChange={(e) => setSearch(e.target.value)}
 allowClear
 />
 <Button icon={<ReloadOutlined />} onClick={() => window.location.reload()}>刷新</Button>
 </Space>
 </div>

 {/* 统计行 */}
 <Row gutter={[16, 16]} style={{marginBottom: 16}}>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="任务总数" value={stats.total} prefix={<SyncOutlined />} />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="已完成" value={stats.completed} valueStyle={{color: "#10b981"}} prefix={<CheckCircleOutlined />} />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="运行中" value={stats.running} valueStyle={{color: "#0284c7"}} prefix={<SyncOutlined />} />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="失败" value={stats.failed} valueStyle={{color: "#dc2626"}} prefix={<CloseCircleOutlined />} />
 </Card>
 </Col>
 </Row>

 {/* 表格 */}
 <Card bodyStyle={{padding: 0}}>
 <Spin spinning={loading}>
 {filtered.length === 0 && !loading ? (
 <Empty description="暂无任务数据" style={{padding: 48}} />
 ) : (
 <Table
 dataSource={filtered}
 columns={columns}
 rowKey="id"
 pagination={{pageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 条`}}
 scroll={{x: 900}}
 size="middle"
 />
 )}
 </Spin>
 </Card>

 {/* 详情抽屉 */}
 {renderDrawer()}
 </div>
 );
}
