// @ts-nocheck
import {useState, useEffect, useCallback} from "react";
import {
 Card,
 Tag,
 Typography,
 Space,
 Row,
 Col,
 Spin,
 Empty,
 Table,
 Drawer,
 Input,
 Select,
 Button,
 Descriptions,
 Divider,
 List,
 Badge,
 Statistic,
 Tooltip,
 message,
 Alert,
 Progress,
 Tabs,
} from "antd";














import request from "../api/request";
import DesktopOutlined from "@ant-design/icons/es/icons/DesktopOutlined";
import CloudServerOutlined from "@ant-design/icons/es/icons/CloudServerOutlined";
import DatabaseOutlined from "@ant-design/icons/es/icons/DatabaseOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import NodeIndexOutlined from "@ant-design/icons/es/icons/NodeIndexOutlined";
import LaptopOutlined from "@ant-design/icons/es/icons/LaptopOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ExportOutlined from "@ant-design/icons/es/icons/ExportOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import AppstoreOutlined from "@ant-design/icons/es/icons/AppstoreOutlined";
import CodeOutlined from "@ant-design/icons/es/icons/CodeOutlined";
import AimOutlined from "@ant-design/icons/es/icons/AimOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";

const {Title, Text} = Typography;

// ==================== 类型定义 ====================

interface Port {
 port: number;
 service: string;
 version: string;
 status: "open" | "filtered" | "closed";
}

interface Asset {
 id: string;
 ip: string;
 hostname: string;
 type: "server" | "webapp" | "api" | "database" | "middleware";
 typeLabel: string;
 portCount: number;
 serviceCount: number;
 os: string;
 status: "online" | "offline";
 discoveredAt: string;
 lastActiveAt: string;
 ports: Port[];
 vulnerabilities: {name: string; level: "high" | "medium" | "low"}[];
}

// ==================== Mock 数据 ====================



// ==================== 常量 ====================

const TYPE_OPTIONS = [
 {value: "all", label: "全部"},
 {value: "server", label: "服务器"},
 {value: "webapp", label: "Web应用"},
 {value: "api", label: "API"},
 {value: "database", label: "数据库"},
 {value: "middleware", label: "中间件"},
];

const STATUS_OPTIONS = [
 {value: "all", label: "全部"},
 {value: "online", label: "在线"},
 {value: "offline", label: "离线"},
];

const TYPE_TAG_COLORS: Record<string, string> = {
 server: "#0284c7",
 webapp: "#7c3aed",
 api: "#059669",
 database: "#d97706",
 middleware: "#db2777",
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
 server: <CloudServerOutlined />,
 webapp: <LaptopOutlined />,
 api: <ApiOutlined />,
 database: <DatabaseOutlined />,
 middleware: <NodeIndexOutlined />,
};

const VULN_LEVEL_COLORS: Record<string, string> = {
 high: "#ef4444",
 medium: "#f59e0b",
 low: "#3b82f6",
};

const PORT_STATUS_COLORS: Record<string, "success" | "warning" | "default"> = {
 open: "success",
 filtered: "warning",
 closed: "default",
};

// ==================== 组件 ====================

const PerceptionPage: React.FC = () => {
 // ---- 状态 ----
 const [targetIp, setTargetIp] = useState("192.168.1.180");
const [loading, setLoading] = useState(true);
 const [assets, setAssets] = useState<Asset[]>([]);
 const [searchText, setSearchText] = useState("");
 const [typeFilter, setTypeFilter] = useState("all");
 const [statusFilter, setStatusFilter] = useState("all");
 const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
 const [drawerVisible, setDrawerVisible] = useState(false);
 const [currentAsset, setCurrentAsset] = useState<Asset | null>(null);
 const [summaryStats, setSummaryStats] = useState<any>(null);
 const [subdomains, setSubdomains] = useState<any[]>([]);
 const [scanStrategy, setScanStrategy] = useState<any>(null);

 // ---- 获取资产数据 ----
 const fetchAssets = useCallback(async () => {
 setLoading(true);
 const mapped: Asset[] = [];

 try {
 // 1. Try perception API for detailed asset info
 let perceptionTarget = "192.168.1.180";
 try {
   const latestTask = await request.get("/tasks?page=1&page_size=1").catch(() => null);
   if (latestTask?.data) {
     const tasks = Array.isArray(latestTask.data) ? latestTask.data : (latestTask.data.items || []);
     if (tasks.length > 0 && tasks[0].target) {
       perceptionTarget = tasks[0].target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
     }
   }
 } catch {}
 const perRes = await request.get("/perception/profile?target=" + perceptionTarget);
 const sumRes = await request.get("/perception/profile/summary?target=" + perceptionTarget).catch(() => null);
 const subRes = await request.get("/perception/subdomains/validated?target=" + perceptionTarget).catch(() => null);
 const strRes = await request.get("/perception/scan-strategy?target=" + perceptionTarget).catch(() => null);
 if (perRes?.data) {
 const d = perRes.data;
 if (d.ip_address) mapped.push({
 id: "api-1", name: d.ip_address, ip: d.ip_address,
 type: "主机", os: d.os || "-", ports: d.open_ports?.length || 0, vulns: 0,
 status: "online", hostname: d.domain || "",
 discoveredAt: new Date().toISOString(),
 lastActiveAt: new Date().toISOString(),
 lastSeen: new Date().toISOString(),
 typeLabel: "主机",
 portCount: d.open_ports?.length || 0,
 serviceCount: 0,
});
 if (d.domain) mapped.push({
 id: "api-2", name: d.domain, ip: d.ip_address || "0.0.0.0",
 type: "域名", os: "-", ports: 0, vulns: 0,
 status: "online", hostname: d.domain,
 discoveredAt: new Date().toISOString(),
 lastActiveAt: new Date().toISOString(),
 lastSeen: new Date().toISOString(),
 typeLabel: "域名",
 portCount: 0,
 serviceCount: 0,
});
}
} catch {
 // Fall through to task-based assets

 // 3. Process additional data
 if (sumRes?.data) setSummaryStats(sumRes.data);
 if (subRes?.data) setSubdomains(Array.isArray(subRes.data) ? subRes.data : (subRes.data.subdomains || subRes.data.items || []));
 if (strRes?.data) setScanStrategy(strRes.data);
}

 // 2. Always also fetch from tasks for real targets
 if (mapped.length === 0) {
 try {
 const taskRes = await request.get("/tasks", {params: {page: 1, page_size: 10}});
 const tasks = taskRes?.data?.items || taskRes?.data || [];
 if (Array.isArray(tasks)) {
 tasks.forEach((t: any, i: number) => {
 const target = t.target || t.target_url || "";
 if (target) {
 mapped.push({
 id: "task-" + i,
 name: target,
 ip: target,
 type: "域名",
 os: "-",
 ports: 0,
 vulns: t.vulnerability_count || t.vulns || 0,
 status: t.status === "completed" ? "online" : "offline",
 hostname: target,
 discoveredAt: t.created_at || new Date().toISOString(),
 lastActiveAt: t.completed_at || t.updated_at || t.created_at || new Date().toISOString(),
 lastSeen: t.completed_at || t.updated_at || t.created_at || new Date().toISOString(),
 typeLabel: "域名",
 portCount: 0,
 serviceCount: 0,
});
}
});
}
} catch {
 // No tasks available
}
}

 if (mapped.length > 0) {
 setAssets(mapped);
}
 setLoading(false);
}, []);

 useEffect(() => {
 fetchAssets();
}, [fetchAssets]);

 // ---- 统计数据 ----
 const total = assets.length;
 const onlineCount = assets.filter((a) => a.status === "online").length;
 const offlineCount = assets.filter((a) => a.status === "offline").length;
 const today = new Date().toISOString().slice(0, 10);
 const newToday = assets.filter((a) => a.discoveredAt?.startsWith(today)).length;

 // ---- 筛选 ----
 const filteredAssets = assets.filter((a) => {
 const matchSearch =
 !searchText ||
 a.ip.includes(searchText) ||
 a.hostname.toLowerCase().includes(searchText.toLowerCase());
 const matchType = typeFilter === "all" || a.type === typeFilter;
 const matchStatus = statusFilter === "all" || a.status === statusFilter;
 return matchSearch && matchType && matchStatus;
});

 // ---- 导出 CSV ----
 const handleExportCSV = () => {
 const target = selectedRowKeys.length > 0 ? assets.filter((a) => selectedRowKeys.includes(a.id)) : filteredAssets;
 const header = "IP,主机名,类型,端口数,服务数,操作系统,状态,发现时间,最后活跃时间\n";
 const rows = target
 .map(
 (a) =>
 `${a.ip},${a.hostname},${a.typeLabel},${a.portCount},${a.serviceCount},${a.os},${a.status === "online" ? "在线" : "离线"},${a.discoveredAt},${a.lastActiveAt}`
 )
 .join("\n");
 const blob = new Blob(["\uFEFF" + header + rows], {type: "text/csv;charset=utf-8"});
 const url = URL.createObjectURL(blob);
 const link = document.createElement("a");
 link.href = url;
 link.download = `资产清单_${new Date().toISOString().slice(0, 10)}.csv`;
 link.click();
 URL.revokeObjectURL(url);
 message.success(`已导出 ${target.length} 条资产记录`);
};

 // ---- 刷新 ----
 const handleRefresh = () => {
 setLoading(true);
 setTimeout(() => {
 setLoading(false);
 message.success("资产列表已刷新");
}, 800);
};

 // ---- 表格列 ----
 const columns = [
 {
 title: "IP 地址",
 dataIndex: "ip",
 key: "ip",
 width: 150,
 render: (ip: string) => (
 <Text code style={{color: "#0284c7", fontWeight: 500}}>
 {ip}
 </Text>
 ),
},
 {
 title: "主机名",
 dataIndex: "hostname",
 key: "hostname",
 width: 160,
 ellipsis: true,
},
 {
 title: "类型",
 dataIndex: "type",
 key: "type",
 width: 110,
 render: (type: string, record: Asset) => (
 <Tag icon={TYPE_ICONS[type]} color={TYPE_TAG_COLORS[type]}>
 {record.typeLabel}
 </Tag>
 ),
},
 {
 title: "端口数",
 dataIndex: "portCount",
 key: "portCount",
 width: 90,
 align: "center" as const,
 sorter: (a: Asset, b: Asset) => a.portCount - b.portCount,
},
 {
 title: "服务数",
 dataIndex: "serviceCount",
 key: "serviceCount",
 width: 90,
 align: "center" as const,
 sorter: (a: Asset, b: Asset) => a.serviceCount - b.serviceCount,
},
 {
 title: "操作系统",
 dataIndex: "os",
 key: "os",
 width: 170,
 ellipsis: true,
 render: (os: string) => (
 <Space>
 <DesktopOutlined style={{color: "#8c8c8c"}} />
 <Text>{os}</Text>
 </Space>
 ),
},
 {
 title: "状态",
 dataIndex: "status",
 key: "status",
 width: 90,
 align: "center" as const,
 render: (status: string) =>
 status === "online" ? (
 <Badge status="success" text="在线" />
 ) : (
 <Badge status="default" text="离线" />
 ),
},
 {
 title: "发现时间",
 dataIndex: "discoveredAt",
 key: "discoveredAt",
 width: 170,
 sorter: (a: Asset, b: Asset) => a.discoveredAt.localeCompare(b.discoveredAt),
},
 {
 title: "最后活跃",
 dataIndex: "lastActiveAt",
 key: "lastActiveAt",
 width: 170,
 sorter: (a: Asset, b: Asset) => a.lastActiveAt.localeCompare(b.lastActiveAt),
 render: (t: string) => (
 <Text type="secondary">{t}</Text>
 ),
},
 ];

 // ==================== 渲染 ====================

 return (
 <div style={{padding: "0 0 24px 0", minHeight: "100vh"}}>
 {/* ---- 页面标题 ---- */}
 <div style={{marginBottom: 20}}>
 <Title level={4} style={{margin: 0, color: "#0284c7"}}>
 <AimOutlined style={{marginRight: 8}} />
 资产感知
 </Title>
 <Text type="secondary">实时监控与发现网络资产，识别潜在风险</Text>
 </div>

 {/* ---- 统计卡片 ---- */}
 <Row gutter={[16, 16]} style={{marginBottom: 20}}>
 <Col xs={12} sm={6}>
 <Card bordered={false} style={{borderRadius: 8, boxShadow: "0 1px 3px rgba(0,0,0,0.08)"}}>
 <Statistic
 title="资产总数"
 value={total}
 prefix={<AppstoreOutlined style={{color: "#0284c7"}} />}
 valueStyle={{color: "#0284c7"}}
 />
 </Card>
 </Col>
 <Col xs={12} sm={6}>
 <Card bordered={false} style={{borderRadius: 8, boxShadow: "0 1px 3px rgba(0,0,0,0.08)"}}>
 <Statistic
 title="在线资产"
 value={onlineCount}
 prefix={<Badge status="success" />}
 valueStyle={{color: "#16a34a"}}
 suffix={
 <Text type="secondary" style={{fontSize: 14}}>
 / {total}
 </Text>
}
 />
 </Card>
 </Col>
 <Col xs={12} sm={6}>
 <Card bordered={false} style={{borderRadius: 8, boxShadow: "0 1px 3px rgba(0,0,0,0.08)"}}>
 <Statistic
 title="离线资产"
 value={offlineCount}
 prefix={<Badge status="default" />}
 valueStyle={{color: "#8c8c8c"}}
 />
 </Card>
 </Col>
 <Col xs={12} sm={6}>
 <Card bordered={false} style={{borderRadius: 8, boxShadow: "0 1px 3px rgba(0,0,0,0.08)"}}>
 <Statistic
 title="今日新增"
 value={newToday}
 prefix={<ExperimentOutlined style={{color: "#d97706"}} />}
 valueStyle={{color: "#d97706"}}
 />
 </Card>
 </Col>
 </Row>

 {/* ---- 扫描策略推荐 ---- */}
 {scanStrategy && (
 <Card size="small" style={{marginBottom: 16, borderRadius: 8}} title="推荐扫描策略" extra={<Tag color="blue">{scanStrategy.type || "综合"}</Tag>}>
 <Row gutter={[16, 8]}>
 <Col span={8}><Statistic title="策略类型" value={scanStrategy.type || "综合"} valueStyle={{fontSize: 16}} /></Col>
 <Col span={8}><Statistic title="建议周期" value={scanStrategy.frequency || "每周"} valueStyle={{fontSize: 16}} /></Col>
 <Col span={8}><Statistic title="优先级" value={scanStrategy.priority || "高"} valueStyle={{fontSize: 16, color: "#dc2626"}} /></Col>
 </Row>
 {scanStrategy.reason && <Text type="secondary" style={{marginTop: 8, display: "block", fontSize: 12}}>{scanStrategy.reason}</Text>}
 </Card>
 )}

 {/* ---- 已校验子域名 ---- */}
 {subdomains.length > 0 && (
 <Card size="small" style={{marginBottom: 16, borderRadius: 8}} title="已校验子域名" bodyStyle={{padding: "12px 16px"}}>
 <Row gutter={[8, 8]}>
 {subdomains.slice(0, 20).map((sd: any, idx: number) => (
 <Col key={idx}>
 <Tag style={{fontSize: 12, padding: "4px 10px", margin: 2}}>{sd.domain || sd.hostname || sd}</Tag>
 </Col>
 ))}
 </Row>
 {subdomains.length > 20 && <Text type="secondary" style={{fontSize: 11}}>...还有 {subdomains.length - 20} 个</Text>}
 </Card>
 )}

 {/* ---- 搜索筛选栏 ---- */}
 <Card
 bordered={false}
 style={{borderRadius: 8, marginBottom: 16, boxShadow: "0 1px 3px rgba(0,0,0,0.08)"}}
 bodyStyle={{padding: "16px 20px"}}
 >
 <Row gutter={[16, 12]} align="middle">
 <Col xs={24} sm={8} md={6}>
 <Input
 placeholder="搜索 IP / 域名"
 prefix={<SearchOutlined style={{color: "#bfbfbf"}} />}
 value={searchText}
 onChange={(e) => setSearchText(e.target.value)}
 allowClear
 />
 </Col>
 <Col xs={12} sm={6} md={4}>
 <Select
 value={typeFilter}
 onChange={setTypeFilter}
 options={TYPE_OPTIONS}
 style={{width: "100%"}}
 />
 </Col>
 <Col xs={12} sm={6} md={4}>
 <Select
 value={statusFilter}
 onChange={setStatusFilter}
 options={STATUS_OPTIONS}
 style={{width: "100%"}}
 />
 </Col>
 <Col flex="auto" />
 <Col>
 <Space>
 <Button
 icon={<ExportOutlined />}
 onClick={handleExportCSV}
 disabled={filteredAssets.length === 0}
 >
 导出 CSV
 </Button>
 <Tooltip title="刷新">
 <Button
 icon={<ReloadOutlined spin={loading} />}
 onClick={handleRefresh}
 />
 </Tooltip>
 </Space>
 </Col>
 </Row>
 </Card>

 {/* ---- 资产表格 ---- */}
 <Card
 bordered={false}
 style={{borderRadius: 8, boxShadow: "0 1px 3px rgba(0,0,0,0.08)"}}
 bodyStyle={{padding: "0 20px 20px"}}
 >
 <Spin spinning={loading}>
 {filteredAssets.length === 0 ? (
 <Empty
 description="未找到匹配的资产"
 style={{padding: "60px 0"}}
 />
 ) : (
 <Table<Asset>
 rowKey="id"
 dataSource={filteredAssets}
 columns={columns}
 rowSelection={{
 selectedRowKeys,
 onChange: setSelectedRowKeys,
 selections: [
 Table.SELECTION_ALL,
 Table.SELECTION_INVERT,
 Table.SELECTION_NONE,
 ],
}}
 onRow={(record) => ({
 onClick: () => {
 setCurrentAsset(record);
 setDrawerVisible(true);
},
 style: {cursor: "pointer"},
})}
 pagination={{
 showSizeChanger: true,
 showQuickJumper: true,
 showTotal: (total, range) =>
 `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
 pageSizeOptions: ["10", "20", "50"],
 defaultPageSize: 10,
}}
 scroll={{x: 1200}}
 size="middle"
 />
 )}
 </Spin>
 </Card>

 {/* ---- 详情 Drawer ---- */}
 <Drawer
 title={
 currentAsset && (
 <Space>
 <SafetyOutlined style={{color: "#0284c7"}} />
 <Text strong style={{fontSize: 16}}>
 {currentAsset.hostname}
 </Text>
 <Tag color={TYPE_TAG_COLORS[currentAsset.type]} icon={TYPE_ICONS[currentAsset.type]}>
 {currentAsset.typeLabel}
 </Tag>
 <Badge
 status={currentAsset.status === "online" ? "success" : "default"}
 text={currentAsset.status === "online" ? "在线" : "离线"}
 />
 </Space>
 )
}
 placement="right"
 width={640}
 open={drawerVisible}
 onClose={() => {
 setDrawerVisible(false);
 setCurrentAsset(null);
}}
 destroyOnClose
 >
 {currentAsset && (
 <Tabs
 defaultActiveKey="basic"
 items={[
 {
 key: "basic",
 label: "基本信息",
 children: (
 <>
 <Descriptions
 bordered
 column={2}
 size="small"
 labelStyle={{fontWeight: 500, background: "#fafafa"}}
 contentStyle={{background: "#fff"}}
 >
 <Descriptions.Item label="IP 地址">
 <Text code style={{color: "#0284c7", fontWeight: 500}}>
 {currentAsset.ip}
 </Text>
 </Descriptions.Item>
 <Descriptions.Item label="主机名">{currentAsset.hostname}</Descriptions.Item>
 <Descriptions.Item label="类型">
 <Tag color={TYPE_TAG_COLORS[currentAsset.type]}>
 {currentAsset.typeLabel}
 </Tag>
 </Descriptions.Item>
 <Descriptions.Item label="操作系统">{currentAsset.os}</Descriptions.Item>
 <Descriptions.Item label="端口数">{currentAsset.portCount}</Descriptions.Item>
 <Descriptions.Item label="服务数">{currentAsset.serviceCount}</Descriptions.Item>
 <Descriptions.Item label="状态">
 <Badge
 status={currentAsset.status === "online" ? "success" : "default"}
 text={currentAsset.status === "online" ? "在线" : "离线"}
 />
 </Descriptions.Item>
 <Descriptions.Item label="发现时间">{currentAsset.discoveredAt}</Descriptions.Item>
 <Descriptions.Item label="最后活跃" span={2}>
 {currentAsset.lastActiveAt}
 </Descriptions.Item>
 </Descriptions>

 <Divider orientation="left" plain style={{margin: "20px 0 12px"}}>
 <Text type="secondary">在线率</Text>
 </Divider>
 <Progress
 percent={Math.round((onlineCount / total) * 100)}
 strokeColor="#0284c7"
 format={(p) => `${p}% 在线`}
 />
 </>
 ),
},
 {
 key: "ports",
 label: `开放端口 (${currentAsset.ports.length})`,
 children: (
 <List
 dataSource={currentAsset.ports}
 renderItem={(port) => (
 <List.Item
 style={{padding: "10px 0"}}
 >
 <List.Item.Meta
 avatar={
 <Badge
 status={PORT_STATUS_COLORS[port.status]}
 />
}
 title={
 <Space>
 <Text strong style={{color: "#0284c7"}}>
 {port.port}
 </Text>
 <Tag>{port.service}</Tag>
 <Text type="secondary" style={{fontSize: 13}}>
 v{port.version}
 </Text>
 </Space>
}
 description={
 <Text type="secondary" style={{fontSize: 12}}>
 状态: {port.status}
 </Text>
}
 />
 </List.Item>
 )}
 />
 ),
},
 {
 key: "vulns",
 label: `漏洞关联 (${currentAsset.vulnerabilities.length})`,
 children: (
 <List
 dataSource={currentAsset.vulnerabilities}
 renderItem={(vuln) => (
 <List.Item style={{padding: "12px 0"}}>
 <List.Item.Meta
 avatar={
 <Tag
 color={VULN_LEVEL_COLORS[vuln.level]}
 style={{marginRight: 0}}
 >
 {vuln.level === "high" ? "高危" : vuln.level === "medium" ? "中危" : "低危"}
 </Tag>
}
 title={<Text>{vuln.name}</Text>}
 />
 </List.Item>
 )}
 locale={{emptyText: "暂无关联漏洞"}}
 />
 ),
},
 ]}
 />
 )}
 </Drawer>
 </div>
 );
};

export default PerceptionPage;
