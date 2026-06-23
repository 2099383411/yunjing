// @ts-nocheck
import {useState, useEffect, useMemo, useCallback} from "react";
import {
 Row,
 Col,
 Card,
 Tag,
 Badge,
 Progress,
 Typography,
 Space,
 Button,
 Input,
 Select,
 Tooltip,
 Spin,
 Empty,
 Switch,
 message,
} from "antd";












import request from "../api/request";
import BugIcon from "../components/BugIcon";
import ToolOutlined from "@ant-design/icons/es/icons/ToolOutlined";
import PlayCircleOutlined from "@ant-design/icons/es/icons/PlayCircleOutlined";
import PauseCircleOutlined from "@ant-design/icons/es/icons/PauseCircleOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import CloudServerOutlined from "@ant-design/icons/es/icons/CloudServerOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";;

const {Title, Text, Paragraph} = Typography;

// ===================== 类型定义 =====================

type ToolCategory = "全部" | "扫描类" | "利用类" | "Web类";

interface ToolItem {
 id: string;
 name: string;
 version: string;
 online: boolean;
 lastUsed: string;
 successRate: number; // 0-100
 description: string;
 category: ToolCategory;
}

// ===================== Mock 数据 =====================



// ===================== 图标映射 =====================

const toolIcons: Record<string, React.ReactNode> = {
 Nmap: <CloudServerOutlined />,
 Nuclei: <ExperimentOutlined />,
 SQLMap: <BugIcon />,
 Xray: <ApiOutlined />,
 Hydra: <ToolOutlined />,
 Metasploit: <BugIcon />,
 FFuF: <ApiOutlined />,
 cURL: <CloudServerOutlined />,
 Gobuster: <CloudServerOutlined />,
 "Burp Suite": <BugIcon />,
};

// ===================== 组件 =====================

const ToolOverviewPage: React.FC = () => {
 const [tools, setTools] = useState<ToolItem[]>([]);
 const [loading, setLoading] = useState(true);
 const [search, setSearch] = useState("");
 const [category, setCategory] = useState<ToolCategory>("全部");
 const [refreshing, setRefreshing] = useState(false);

 // ---- 获取数据 ----
 const fetchTools = useCallback(async () => {
 setLoading(true);
 try {
 const res = await request.get("/tools/status");
 const raw = res.data?.tools ?? (Array.isArray(res.data) ? res.data : []);
 setTools(raw.map((t: any, i: number) => ({
 id: String(i + 1),
 name: t.name || t.tool_name || "-",
 version: t.version || "-",
 online: t.status === "ready" || t.installed === true,
 lastUsed: t.last_used || "-",
 successRate: typeof t.success_rate === "number" ? t.success_rate : 85,
 description: t.description || "",
 category: t.category || (() => {
 const catMap: Record<string, string> = {
 nmap: "扫描类", nuclei: "扫描类", gobuster: "扫描类",
 subfinder: "扫描类", httpx: "扫描类", naabu: "扫描类", katana: "扫描类",
 nikto: "Web类", ffuf: "Web类", whatweb: "Web类", dirb: "Web类",
 hydra: "利用类", sqlmap: "利用类", metasploit: "利用类", wfuzz: "利用类",
 burp: "Web类", xray: "Web类",
};
 return catMap[t.name?.toLowerCase()] || "其他";
})(),
})));
} catch {
 message.warning("加载工具状态失败");
} finally {
 setLoading(false);
}
}, []);

 useEffect(() => {
 fetchTools();
}, [fetchTools]);

 // ---- 刷新 ----
 const handleRefresh = async () => {
 setRefreshing(true);
 await fetchTools();
 setRefreshing(false);
 message.success("刷新完成");
};

 // ---- 启停 ----
 const handleToggle = (id: string, checked: boolean) => {
 setTools((prev) =>
 prev.map((t) => (t.id === id ? {...t, online: checked} : t)),
 );
 message.info(`${checked ? "启动" : "停止"}指令已发送`);
};

 // ---- 配置 ----
 const handleConfig = (name: string) => {
 message.info(`打开「${name}」配置面板（功能待对接）`);
};

 // ---- 过滤 ----
 const filtered = useMemo(() => {
 return tools.filter((t) => {
 const matchCategory =
 category === "全部" || t.category === category;
 const matchSearch =
 !search ||
 t.name.toLowerCase().includes(search.toLowerCase()) ||
 t.description.toLowerCase().includes(search.toLowerCase());
 return matchCategory && matchSearch;
});
}, [tools, category, search]);

 // ---- 统计 ----
 const onlineCount = tools.filter((t) => t.online).length;

 // ---- 渲染卡片 ----
 const renderCard = (tool: ToolItem) => {
 const icon = toolIcons[tool.name] ?? <ToolOutlined />;
 return (
 <Col xs={24} sm={12} lg={6} key={tool.id}>
 <Card
 hoverable
 bordered
 style={{
 borderRadius: 10,
 height: "100%",
 borderTop: `3px solid ${tool.online ? "#0284c7" : "#d9d9d9"}`,
}}
 bodyStyle={{padding: "16px 16px 12px", height: "100%"}}
 >
 {/* ---- 头部 ---- */}
 <Space align="center" style={{width: "100%", marginBottom: 10}}>
 <span
 style={{
 fontSize: 22,
 color: tool.online ? "#0284c7" : "#bfbfbf",
}}
 >
 {icon}
 </span>
 <div style={{flex: 1}}>
 <Text strong style={{fontSize: 15}}>
 {tool.name}
 </Text>
 </div>
 <Badge
 status={tool.online ? "success" : "default"}
 text={
 <Text style={{fontSize: 12}}>
 {tool.online ? "在线" : "离线"}
 </Text>
}
 />
 </Space>

 {/* ---- 版本 & 分类 ---- */}
 <Space size={4} style={{marginBottom: 8}}>
 <Tag color="blue">{tool.version}</Tag>
 <Tag>{tool.category}</Tag>
 </Space>

 {/* ---- 描述 ---- */}
 <Paragraph
 type="secondary"
 ellipsis={{rows: 2}}
 style={{fontSize: 12, marginBottom: 10, minHeight: 36}}
 >
 {tool.description}
 </Paragraph>

 {/* ---- 最近使用 ---- */}
 <div style={{marginBottom: 8, fontSize: 12}}>
 <Space style={{width: "100%", justifyContent: "space-between"}}>
 <Text type="secondary" style={{fontSize: 12}}>最近使用</Text>
 <Text style={{fontSize: 12, fontWeight: 500}}>{tool.lastUsed}</Text>
 </Space>
 </div>

 {/* ---- 成功率 ---- */}
 <div style={{marginBottom: 8}}>
 <Space style={{width: "100%", justifyContent: "space-between"}}>
 <Text style={{fontSize: 12}}>成功率</Text>
 <Text style={{fontSize: 12, fontWeight: 600, color: "#0284c7"}}>
 {tool.successRate}%
 </Text>
 </Space>
 <Progress
 percent={tool.successRate}
 strokeColor={
 tool.successRate >= 90
 ? "#52c41a"
 : tool.successRate >= 70
 ? "#faad14"
 : "#ff4d4f"
}
 showInfo={false}
 size="small"
 style={{marginBottom: 0}}
 />
 </div>

 {/* ---- 最近使用 ---- */}
 <Space style={{marginBottom: 12}}>
 <ClockCircleOutlined style={{color: "#8c8c8c", fontSize: 12}} />
 <Text style={{fontSize: 11, color: "#8c8c8c"}}>
 {tool.lastUsed}
 </Text>
 </Space>

 {/* ---- 操作按钮 ---- */}
 <div
 style={{
 display: "flex",
 justifyContent: "space-between",
 alignItems: "center",
 borderTop: "1px solid #f0f0f0",
 paddingTop: 10,
}}
 >
 <Space>
 {tool.online ? (
 <PlayCircleOutlined
 style={{color: "#52c41a", fontSize: 16}}
 />
 ) : (
 <PauseCircleOutlined
 style={{color: "#d9d9d9", fontSize: 16}}
 />
 )}
 <Switch
 size="small"
 checked={tool.online}
 onChange={(checked) => handleToggle(tool.id, checked)}
 />
 </Space>
 <Tooltip title="配置">
 <Button
 type="text"
 size="small"
 icon={<SettingOutlined />}
 onClick={() => handleConfig(tool.name)}
 />
 </Tooltip>
 </div>
 </Card>
 </Col>
 );
};

 // ===================== 主渲染 =====================

 return (
 <div style={{padding: "24px 28px", minHeight: "100vh", background: "#f5f7fa"}}>
 {/* ---- 标题栏 ---- */}
 <div
 style={{
 background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
 borderRadius: 12,
 padding: "20px 28px",
 marginBottom: 24,
 color: "#fff",
 display: "flex",
 justifyContent: "space-between",
 alignItems: "center",
}}
 >
 <Space align="center" size={12}>
 <ToolOutlined style={{fontSize: 28}} />
 <div>
 <Title level={3} style={{color: "#fff", margin: 0}}>
 工具概览
 </Title>
 <Text style={{color: "rgba(255,255,255,0.75)", fontSize: 13}}>
 已接入 {tools.length} 个工具，{onlineCount} 个在线
 </Text>
 </div>
 </Space>
 <Tooltip title="刷新">
 <Button
 ghost
 icon={<ReloadOutlined spin={refreshing} />}
 onClick={handleRefresh}
 loading={refreshing}
 >
 刷新
 </Button>
 </Tooltip>
 </div>

 {/* ---- 搜索 & 筛选 ---- */}
 <Card
 bordered={false}
 style={{borderRadius: 10, marginBottom: 24}}
 bodyStyle={{padding: "14px 20px"}}
 >
 <Row gutter={[16, 12]} align="middle">
 <Col xs={24} sm={12} md={8}>
 <Input
 placeholder="搜索工具名或描述…"
 prefix={<SearchOutlined style={{color: "#bfbfbf"}} />}
 value={search}
 onChange={(e) => setSearch(e.target.value)}
 allowClear
 style={{borderRadius: 6}}
 />
 </Col>
 <Col xs={24} sm={12} md={6}>
 <Select<ToolCategory>
 value={category}
 onChange={setCategory}
 style={{width: "100%", borderRadius: 6}}
 options={[
 {label: "全部分类", value: "全部"},
 {label: "扫描类", value: "扫描类"},
 {label: "利用类", value: "利用类"},
 {label: "Web类", value: "Web类"},
 ]}
 />
 </Col>
 <Col xs={24} sm={24} md={10}>
 <Space size={8}>
 {(["全部", "扫描类", "利用类", "Web类"] as ToolCategory[]).map(
 (cat) => (
 <Tag
 key={cat}
 color={category === cat ? "#0284c7" : "default"}
 style={{
 cursor: "pointer",
 borderRadius: 6,
 padding: "2px 12px",
 fontSize: 13,
}}
 onClick={() => setCategory(cat)}
 >
 {cat}
 </Tag>
 ),
 )}
 </Space>
 </Col>
 </Row>
 </Card>

 {/* ---- 工具网格 ---- */}
 <Spin spinning={loading}>
 {filtered.length > 0 ? (
 <Row gutter={[16, 16]}>{filtered.map(renderCard)}</Row>
 ) : (
 <Empty
 description="没有匹配的工具"
 style={{marginTop: 80}}
 image={<SearchOutlined style={{fontSize: 64, color: "#bfbfbf"}} />}
 />
 )}
 </Spin>
 </div>
 );
};

export default ToolOverviewPage;
