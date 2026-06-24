// @ts-nocheck
// 重新理解用户需求：
// 1. 选择一个已完成扫描任务 → 展示该任务的可视化攻击链
// 2. 树形结构展示每个阶段的真实数据（扫描到的端口、服务、漏洞等）
// 3. 动态展示，让客户看到真实渗透状态

import request from "../api/request";
import {useState, useEffect, useMemo, useCallback} from "react";
import {
 Card,
 Row,
 Col,
 Tag,
 Typography,
 Space,
 Button,
 Tooltip,
 message,
 Select,
 Empty,
 Spin,
 Descriptions,
 Statistic,
 Table,
 Progress,
 Alert,
 Tree,
} from "antd";
import BugIcon from "../components/BugIcon";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import AimOutlined from "@ant-design/icons/es/icons/AimOutlined";
import LinkOutlined from "@ant-design/icons/es/icons/LinkOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import DatabaseOutlined from "@ant-design/icons/es/icons/DatabaseOutlined";
import CloudServerOutlined from "@ant-design/icons/es/icons/CloudServerOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import FileProtectOutlined from "@ant-design/icons/es/icons/FileProtectOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import ApartmentOutlined from "@ant-design/icons/es/icons/ApartmentOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
















const {Text, Title} = Typography;

// ---------- 阶段配置 ----------
interface PhaseConfig {
 icon: React.ReactNode;
 color: string;
 label: string;
}

const PHASE_MAP: Record<string, PhaseConfig> = {
 asset_discovery: {
 icon: <SearchOutlined />,
 color: "#6366f1",
 label: "资产发现",
},
 port_scan: {
 icon: <ApiOutlined />,
 color: "#0284c7",
 label: "端口扫描",
},
 service_detect: {
 icon: <CloudServerOutlined />,
 color: "#0ea5e9",
 label: "服务识别",
},
 vuln_scan: {
 icon: <WarningOutlined />,
 color: "#f59e0b",
 label: "漏洞扫描",
},
 web_scan: {
 icon: <ExperimentOutlined />,
 color: "#8b5cf6",
 label: "Web应用扫描",
},
 exploit: {
 icon: <ThunderboltOutlined />,
 color: "#ef4444",
 label: "漏洞利用",
},
 reporting: {
 icon: <FileProtectOutlined />,
 color: "#10b981",
 label: "报告生成",
},
};

function getPhaseConfig(name: string): PhaseConfig {
 for (const [key, cfg] of Object.entries(PHASE_MAP)) {
 if (name.includes(key)) return cfg;
}
 return {
 icon: <SafetyOutlined />,
 color: "#6b7280",
 label: name,
};
}

// ---------- 阶段详情组件 ----------
function PhaseDetails({phase}: {phase: any}) {
 const name = phase.name || phase.phase || "";
 const data = phase.data || {};

 if (name.includes("port_scan") || name.includes("asset")) {
 const ports = data.ports || [];
 if (ports.length === 0) return <Text type="secondary">未发现开放端口</Text>;
 return (
 <Space wrap size={[4, 4]}>
 {ports.map((p: number) => (
 <Tag key={p} color="blue" style={{margin: 0}}>
 {p}/tcp
 </Tag>
 ))}
 <Text type="secondary" style={{fontSize: 12}}>
 共 {ports.length} 个端口
 </Text>
 </Space>
 );
}

 if (name.includes("service")) {
 const services = data.services || [];
 if (services.length === 0)
 return <Text type="secondary">未识别到服务</Text>;
 return (
 <div>
 {services.map((s: any, i: number) => (
 <Tag key={i} color="geekblue" style={{marginBottom: 2}}>
 {s.port}/tcp: {s.service || "未知"}{" "}
 {s.version ? `(${s.version})` : ""}
 </Tag>
 ))}
 </div>
 );
}

 if (name.includes("vuln_scan")) {
 const count = data.count || 0;
 const findings = data.findings || [];
 if (count === 0 && findings.length === 0)
 return <Text type="secondary">未发现漏洞</Text>;
 return (
 <div>
 <Text strong style={{color: count > 0 ? "#ef4444" : undefined}}>
 发现 {count} 个漏洞
 </Text>
 {findings.length > 0 && (
 <Table
 dataSource={findings}
 rowKey={(_, i) => String(i)}
 size="small"
 pagination={false}
 columns={[
 {
 title: "漏洞",
 dataIndex: "name",
 key: "name",
 render: (v: string) => <Text code>{v}</Text>,
},
 {
 title: "风险",
 dataIndex: "severity",
 key: "severity",
 width: 80,
 render: (v: string) => {
 const color: Record<string, string> = {
 critical: "#ef4444",
 high: "#f59e0b",
 medium: "#0284c7",
 low: "#6b7280",
};
 return <Tag color={color[v] || "default"}>{v}</Tag>;
},
},
 ]}
 />
 )}
 </div>
 );
}

 if (name.includes("web_scan")) {
 const techs = data.techs || [];
 const nikto = data.nikto || 0;
 return (
 <div>
 {nikto > 0 && <Text>Nikto 检查: {nikto} 项发现</Text>}
 {techs.length > 0 && (
 <div style={{marginTop: 4}}>
 {techs.map((t: any, i: number) => (
 <Tag key={i} color="purple" style={{marginBottom: 2}}>
 {t.url || t.name || "Web"}
 </Tag>
 ))}
 </div>
 )}
 {nikto === 0 && techs.length === 0 && (
 <Text type="secondary">Web扫描完成，未发现异常</Text>
 )}
 </div>
 );
}

 if (name.includes("exploit")) {
 const attempted = data.attempted || 0;
 const success = data.success || false;
 return (
 <Space>
 <Statistic
 title="尝试次数"
 value={attempted}
 valueStyle={{fontSize: 16}}
 suffix={
 success ? (
 <CheckCircleOutlined style={{color: "#10b981"}} />
 ) : (
 <CloseCircleOutlined style={{color: "#6b7280"}} />
 )
}
 />
 <Tag color={success ? "green" : "default"}>
 {success ? "利用成功" : "未成功利用"}
 </Tag>
 </Space>
 );
}

 // Fallback: show raw data keys
 const otherKeys = Object.keys(data).filter(
 (k) => !["ports", "services", "findings", "count", "attempted", "success", "techs", "nikto"].includes(k)
 );
 if (otherKeys.length > 0) {
 return (
 <Descriptions size="small" column={1}>
 {otherKeys.map((k) => (
 <Descriptions.Item key={k} label={k}>
 {typeof data[k] === "object"
 ? JSON.stringify(data[k], null, 2).slice(0, 200)
 : String(data[k])}
 </Descriptions.Item>
 ))}
 </Descriptions>
 );
}

 return <Text type="secondary">阶段已完成</Text>;
}

// ---------- 构建树数据 ----------
function buildTreeData(task: any) {
 const result = task.result || {};
 if (typeof result === "string") {
 try {
 return JSON.parse(result);
} catch {
 return {};
}
}

 const phasesLog = result.phases_log || result.phasesExecuted || [];
 const target = task.target || "未知目标";
 const ports = result.ports || [];
 const vulnNames = result.vulnerability_names || [];
 const vulnTotal = task.vuln_total || result.total || 0;

 // 根节点
 const root: any = {
 title: (
 <Space>
 <SafetyOutlined style={{color: "#0284c7"}} />
 <Text strong style={{fontSize: 15}}>
 {target}
 </Text>
 <Tag color="blue">{task.scan_type || "unknown"}</Tag>
 <Tag color={task.status === "COMPLETED" ? "green" : "default"}>
 {task.status}
 </Tag>
 </Space>
 ),
 key: "root",
 selectable: false,
 children: [],
};

 // 遍历 phases_log 构建子节点
 for (const phase of phasesLog) {
 const name = phase.name || phase.phase || "";
 const pc = getPhaseConfig(name);
 const data = phase.data || {};

 // 构建叶子节点（具体数据）
 const leafChildren: any[] = [];

 if (name.includes("port_scan") || name.includes("asset")) {
 const ports_in_phase = data.ports || [];
 if (ports_in_phase.length > 0) {
 leafChildren.push({
 title: (
 <Space wrap size={[4, 4]}>
 {ports_in_phase.map((p: number) => (
 <Tag key={p} color="blue" style={{margin: 0, fontSize: 12}}>
 {p}/tcp <span style={{color: "#52c41a"}}>OPEN</span>
 </Tag>
 ))}
 <Text type="secondary" style={{fontSize: 12}}>
 共 {ports_in_phase.length} 个开放端口
 </Text>
 </Space>
 ),
 key: `phase-${name}-ports`,
 selectable: false,
 isLeaf: true,
});
} else {
 leafChildren.push({
 title: <Text type="secondary">未发现开放端口</Text>,
 key: `phase-${name}-none`,
 selectable: false,
 isLeaf: true,
});
}
}

 if (name.includes("service")) {
 const services = data.services || [];
 if (services.length > 0) {
 services.forEach((s: any, i: number) => {
 leafChildren.push({
 title: (
 <div style={{display: "flex", alignItems: "center", gap: 8}}>
 <Tag color="geekblue" style={{margin: 0}}>
 {s.port}/tcp
 </Tag>
 <Text>
 {s.service || "未知服务"}
 {s.version ? (
 <Text type="secondary" style={{fontSize: 12}}>
 {" "}
 ({s.version})
 </Text>
 ) : null}
 </Text>
 </div>
 ),
 key: `phase-${name}-svc-${i}`,
 selectable: false,
 isLeaf: true,
});
});
}
}

 if (name.includes("vuln_scan")) {
 const findings = data.findings || [];
 const count = data.count || vulnTotal || 0;
 if (count > 0 || findings.length > 0) {
 leafChildren.push({
 title: (
 <Space>
 <WarningOutlined style={{color: "#ef4444"}} />
 <Text strong style={{color: "#ef4444"}}>
 发现 {count} 个漏洞（{vulnNames.length} 项）
 </Text>
 </Space>
 ),
 key: `phase-${name}-count`,
 selectable: false,
 isLeaf: true,
});
 vulnNames.forEach((v: string, i: number) => {
 leafChildren.push({
 title: (
 <Space>
 <BugIcon style={{color: "#ef4444"}} />
 <Text code style={{fontSize: 13}}>
 {v}
 </Text>
 </Space>
 ),
 key: `phase-${name}-vuln-${i}`,
 selectable: false,
 isLeaf: true,
});
});
} else {
 leafChildren.push({
 title: <Text type="secondary">未发现漏洞</Text>,
 key: `phase-${name}-safe`,
 selectable: false,
 isLeaf: true,
});
}
}

 if (name.includes("web_scan")) {
 const techs = data.techs || [];
 if (techs.length > 0) {
 techs.forEach((t: any, i: number) => {
 leafChildren.push({
 title: (
 <Text>
 🌐 {t.url || t.name || `技术 ${i + 1}`}
 {t.info ? (
 <Text type="secondary" style={{fontSize: 11}}>
 {" "}
 — {String(t.info).slice(0, 80)}
 </Text>
 ) : null}
 </Text>
 ),
 key: `phase-${name}-tech-${i}`,
 selectable: false,
 isLeaf: true,
});
});
}
}

 if (name.includes("exploit")) {
 const attempted = data.attempted || 0;
 const success = data.success || false;
 leafChildren.push({
 title: (
 <Space>
 {success ? (
 <CheckCircleOutlined style={{color: "#10b981"}} />
 ) : (
 <CloseCircleOutlined style={{color: "#6b7280"}} />
 )}
 <Text>
 尝试 <Text strong>{attempted}</Text> 次，
 {success ? (
 <Text strong style={{color: "#10b981"}}>
 利用成功
 </Text>
 ) : (
 <Text type="secondary">未成功利用</Text>
 )}
 </Text>
 </Space>
 ),
 key: `phase-${name}-result`,
 selectable: false,
 isLeaf: true,
});
}

 // 阶段主节点
 root.children.push({
 title: (
 <Space>
 <span
 style={{
 display: "inline-flex",
 alignItems: "center",
 justifyContent: "center",
 width: 24,
 height: 24,
 borderRadius: 12,
 background: pc.color,
 color: "#fff",
 fontSize: 12,
}}
 >
 {pc.icon}
 </span>
 <Text strong>{pc.label}</Text>
 <Tag
 color={
 data.count > 0 || data.ports?.length > 0
 ? "orange"
 : "default"
}
 style={{fontSize: 11, lineHeight: "18px"}}
 >
 {data.ports?.length > 0
 ? `${data.ports.length} 端口`
 : data.count > 0
 ? `${data.count} 漏洞`
 : data.attempted !== undefined
 ? `${data.attempted} 次`
 : "已完成"}
 </Tag>
 </Space>
 ),
 key: `phase-${name}`,
 selectable: false,
 children: leafChildren.length > 0 ? leafChildren : undefined,
});
}

 return root;
}

// ---------- 页面主组件 ----------
const OrchestrationPage: React.FC = () => {
 const [tasks, setTasks] = useState<any[]>([]);
 const [selectedId, setSelectedId] = useState<string | undefined>();
 const [selectedTask, setSelectedTask] = useState<any | null>(null);
 const [loading, setLoading] = useState(false);
 const [treeLoading, setTreeLoading] = useState(false);

 // 获取已完成的扫描任务
 const fetchTasks = useCallback(async () => {
 setLoading(true);
 try {
 const res = await request.get("/tasks/", {
 params: {limit: 50},
});
 let raw = res.data;
 if (!Array.isArray(raw)) raw = raw?.tasks || raw?.items || raw?.results || [];
 const completed = raw
 .filter((t: any) => t.status === "COMPLETED")
 .sort(
 (a: any, b: any) =>
 new Date(b.updated_at || 0).getTime() -
 new Date(a.updated_at || 0).getTime()
 );
 setTasks(completed);
 // 默认选中第一个
 if (completed.length > 0 && !selectedId) {
 setSelectedId(completed[0].id);
 setSelectedTask(completed[0]);
}
} catch (e: any) {
 message.error("获取任务列表失败");
} finally {
 setLoading(false);
}
}, [selectedId]);

 useEffect(() => {
 fetchTasks();
}, []);

 // 选择任务
 const handleSelect = (id: string) => {
 setSelectedId(id);
 const task = tasks.find((t) => t.id === id);
 setSelectedTask(task || null);
};

 // 构建树数据
 const treeData = useMemo(() => {
 if (!selectedTask) return [];
 const root = buildTreeData(selectedTask);
 return [root];
}, [selectedTask]);

 // 统计数据
 const stats = useMemo(() => {
 if (!selectedTask) return null;
 const r = selectedTask.result || {};
 if (typeof r === "string") {
 try {
 return JSON.parse(r);
} catch {
 return {};
}
}
 return r;
}, [selectedTask]);

 return (
 <div style={{padding: 24, background: "#f1f5f9", minHeight: "100vh"}}>
 {/* 头部 */}
 <Card
 style={{marginBottom: 16}}
 bodyStyle={{padding: "16px 24px"}}
 >
 <Row align="middle" justify="space-between">
 <Col>
 <Space>
 <ApartmentOutlined
 style={{fontSize: 22, color: "#0284c7"}}
 />
 <Title level={4} style={{margin: 0}}>
 攻击链可视化
 </Title>
 <Tag color="blue" style={{marginLeft: 8}}>
 任务级渗透路径
 </Tag>
 </Space>
 </Col>
 <Col>
 <Space>
 <Select
 style={{width: 320}}
 placeholder="选择一个已完成任务..."
 loading={loading}
 value={selectedId}
 onChange={handleSelect}
 showSearch
 filterOption={(input, option) =>
 (option?.label as string)
 ?.toLowerCase()
 .includes(input.toLowerCase()) ?? false
}
 options={tasks.map((t) => ({
 value: t.id,
 label: (() => {
 const d = new Date(t.updated_at);
 const ts = isNaN(d.getTime()) ? "刚刚" : d.toLocaleString("zh-CN", {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"});
 return `${t.target || "?"} [${t.scan_type || "?"}] ${ts}`;
})(),
}))}
 />
 <Tooltip title="刷新任务列表">
 <Button
 icon={<ReloadOutlined />}
 onClick={fetchTasks}
 loading={loading}
 />
 </Tooltip>
 </Space>
 </Col>
 </Row>
 </Card>

 {/* 统计概要 */}
 {selectedTask && stats && (
 <Row gutter={16} style={{marginBottom: 16}}>
 <Col span={4}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="端口"
 value={
 (stats.ports || selectedTask.ports || []).length
}
 prefix={<ApiOutlined />}
 valueStyle={{color: "#0284c7"}}
 />
 </Card>
 </Col>
 <Col span={4}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="漏洞"
 value={stats.total || selectedTask.vuln_total || 0}
 prefix={<BugIcon />}
 valueStyle={{
 color:
 (stats.total || 0) > 0 ? "#ef4444" : "#10b981",
}}
 />
 </Card>
 </Col>
 <Col span={4}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="严重"
 value={stats.critical || 0}
 prefix={<WarningOutlined />}
 valueStyle={{
 color:
 (stats.critical || 0) > 0 ? "#ef4444" : undefined,
}}
 />
 </Card>
 </Col>
 <Col span={4}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="高危"
 value={stats.high || 0}
 prefix={<WarningOutlined />}
 valueStyle={{color: "#f59e0b"}}
 />
 </Card>
 </Col>
 <Col span={4}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="阶段"
 value={
 (selectedTask.result?.phases_log || []).length
}
 prefix={<ApartmentOutlined />}
 />
 </Card>
 </Col>
 <Col span={4}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="状态"
 value={selectedTask.status || "?"}
 prefix={
 selectedTask.status === "COMPLETED" ? (
 <CheckCircleOutlined style={{color: "#10b981"}} />
 ) : (
 <CloseCircleOutlined style={{color: "#ef4444"}} />
 )
}
 valueStyle={{
 color:
 selectedTask.status === "COMPLETED"
 ? "#10b981"
 : "#ef4444",
 fontSize: 14,
}}
 />
 </Card>
 </Col>
 </Row>
 )}

 {/* 主内容区：攻击链树形展示 */}
 <Card
 style={{minHeight: 400}}
 bodyStyle={{padding: "24px"}}
 >
 {!selectedTask ? (
 <Empty description="请选择一个已完成的任务查看攻击链" />
 ) : treeData.length > 0 ? (
 <Tree
 showLine={{showLeafIcon: false}}
 defaultExpandedKeys={treeData[0]?.children?.map(
 (c: any) => c.key
 )}
 treeData={treeData}
 style={{
 fontSize: 14,
 lineHeight: "32px",
}}
 />
 ) : (
 <Empty description="该任务暂无阶段日志数据" />
 )}
 </Card>
 </div>
 );
};

export default OrchestrationPage;
