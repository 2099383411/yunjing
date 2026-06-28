import {useState} from "react";
import {
 Card,
 Input,
 Typography,
 Space,
 Button,
 Radio,
 Switch,
 InputNumber,
 Tag,
 Divider,
 message,
 Row,
 Col,
 Alert,
 Tooltip,
 Select,
 Slider,
 Collapse,
 Checkbox,
} from "antd";












import request from "../api/request";
import {useNavigate} from "react-router-dom";
import BugIcon from "../components/BugIcon";
import ControlOutlined from "@ant-design/icons/es/icons/ControlOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import PlayCircleOutlined from "@ant-design/icons/es/icons/PlayCircleOutlined";
import AimOutlined from "@ant-design/icons/es/icons/AimOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import ToolOutlined from "@ant-design/icons/es/icons/ToolOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import RocketOutlined from "@ant-design/icons/es/icons/RocketOutlined";
import QuestionCircleOutlined from "@ant-design/icons/es/icons/QuestionCircleOutlined";
import ClearOutlined from "@ant-design/icons/es/icons/ClearOutlined";
import HistoryOutlined from "@ant-design/icons/es/icons/HistoryOutlined";;

const {Title, Text, Paragraph} = Typography;
const {TextArea} = Input;

const PRIMARY_COLOR = "#0284c7";

const TOOLS = [
 {key: "nmap", label: "Nmap", icon: <ToolOutlined />, desc: "端口扫描与服务发现"},
 {key: "nuclei", label: "Nuclei", icon: <BugIcon />, desc: "模板化漏洞检测"},
 {key: "sqlmap", label: "SQLMap", icon: <ExperimentOutlined />, desc: "SQL 注入自动化检测"},
 {key: "xray", label: "Xray", icon: <SafetyOutlined />, desc: "被动代理漏洞扫描"},
 {key: "ffuf", label: "Ffuf", icon: <ThunderboltOutlined />, desc: "Web 路径 / 子域爆破"},
 {key: "hydra", label: "Hydra", icon: <ControlOutlined />, desc: "弱口令暴力破解"},
];

const QUICK_TARGETS: {label: string; targets: string}[] = [
 {
 label: "OWASP Top 10 靶场",
 targets: "testphp.vulnweb.com\njuice-shop.herokuapp.com\n127.0.0.1:3000",
},
 {
 label: "内网资产示例",
 targets: "192.168.1.0/24\n10.0.0.1-10.0.0.254",
},
 {
 label: "Web 应用示例",
 targets: "demo.testfire.net\nexample.com/admin\napi.example.com/v2",
},
];

const AdvancedConfigPage: React.FC = () => {
 const navigate = useNavigate();

 // ---- 状态 ----
 const [targets, setTargets] = useState("");
 const [scanType, setScanType] = useState<"quick" | "full" | "custom">("quick");
 const [loading, setLoading] = useState(false);

 // 自定义高级选项
 const [tools, setTools] = useState<Record<string, boolean>>({
 nmap: true,
 nuclei: true,
 sqlmap: false,
 xray: false,
 ffuf: false,
 hydra: false,
});
 const [portRange, setPortRange] = useState("1-10000");
 const [rateLimit, setRateLimit] = useState(50);
 const [timeout, setTimeoutVal] = useState(300);
 const [verifyMode, setVerifyMode] = useState(true);
 const [threads, setThreads] = useState(10);

 // ---- 辅助 ----
 const toggleTool = (key: string) => {
 setTools((prev) => ({...prev, [key]: !prev[key]}));
};

 const fillQuickTargets = (item: (typeof QUICK_TARGETS)[number]) => {
 setTargets(item.targets);
 message.success(`已填充「${item.label}」`);
};

 const clearTargets = () => {
 setTargets("");
 message.info("已清空目标");
};

 const buildPayload = () => {
 const targetList = targets
 .split("\n")
 .map((t) => t.trim())
 .filter(Boolean);

 if (targetList.length === 0) {
 message.warning("请输入至少一个扫描目标");
 return null;
}

 const payload: Record<string, unknown> = {
 targets: targetList,
 scan_type: scanType,
};

 if (scanType === "custom") {
 payload.tools = Object.entries(tools)
 .filter(([, v]) => v)
 .map(([k]) => k);
 payload.port_range = portRange;
 payload.rate_limit = rateLimit;
 payload.timeout = timeout;
 payload.verify = verifyMode;
 payload.threads = threads;
}

 return payload;
};

 const handleSubmit = async () => {
 const payload = buildPayload();
 if (!payload) return;

 setLoading(true);
 try {
 await request.post("/tasks/", payload);
 message.success("扫描任务已提交，即将跳转任务列表");
 setTimeout(() => navigate("/tasks"), 1200);
} catch {
 message.error("提交失败，请检查网络后重试");
} finally {
 setLoading(false);
}
};

 // 是否自定义模式
 const isCustom = scanType === "custom";

 // ---- 样式常量 ----
 const sectionIconStyle: React.CSSProperties = {
 color: PRIMARY_COLOR,
 marginRight: 6,
 fontSize: 16,
};

 // ==================== JSX ====================
 return (
 <div
 style={{
 minHeight: "100vh",
 background: "#f0f2f5",
 padding: "24px 32px",
}}
 >
 {/* ---- 页面头部 ---- */}
 <div style={{marginBottom: 24}}>
 <Title level={3} style={{margin: 0, color: "#1a1a2e"}}>
 <SettingOutlined style={{color: PRIMARY_COLOR, marginRight: 8}} />
 高级扫描配置
 </Title>
 <Text type="secondary">
 配置目标资产、扫描策略与工具链，一键启动深度安全扫描
 </Text>
 </div>

 <Row gutter={[24, 24]}>
 {/* ========== 左栏：目标 + 扫描类型 ========== */}
 <Col xs={24} lg={14}>
 <Card
 bordered={false}
 style={{borderRadius: 12, boxShadow: "0 2px 12px rgba(0,0,0,0.06)"}}
 >
 {/* ---- 目标输入 ---- */}
 <div style={{marginBottom: 20}}>
 <Space align="center" style={{marginBottom: 8}}>
 <AimOutlined style={sectionIconStyle} />
 <Text strong style={{fontSize: 15}}>
 扫描目标
 </Text>
 <Tag color={PRIMARY_COLOR}>
 {targets
 .split("\n")
 .filter((t) => t.trim())
 .length.toLocaleString()}{" "}
 个目标
 </Tag>
 </Space>

 <TextArea
 rows={6}
 placeholder={"每行输入一个目标，支持 IP / 域名 / URL\n\n示例：\n192.168.1.1\n10.0.0.0/24\nexample.com\napi.example.com/v1/login"}
 value={targets}
 onChange={(e) => setTargets(e.target.value)}
 style={{
 borderRadius: 8,
 fontFamily: "'SF Mono', 'Fira Code', monospace",
 fontSize: 13,
 resize: "vertical",
}}
 />

 {/* 操作按钮行 */}
 <Row justify="space-between" align="middle" style={{marginTop: 10}}>
 <Space size={4} wrap>
 <Tooltip title="一键清空">
 <Button
 size="small"
 icon={<ClearOutlined />}
 onClick={clearTargets}
 disabled={!targets.trim()}
 >
 清空
 </Button>
 </Tooltip>
 <Tooltip title="从剪贴板导入">
 <Button
 size="small"
 icon={<HistoryOutlined />}
 onClick={async () => {
 try {
 const text = await navigator.clipboard.readText();
 if (text.trim()) {
 setTargets((prev) =>
 prev ? prev + "\n" + text : text,
 );
 message.success("已从剪贴板导入");
}
} catch {
 message.warning("无法读取剪贴板");
}
}}
 >
 剪贴板导入
 </Button>
 </Tooltip>
 </Space>
 </Row>
 </div>

 <Divider style={{margin: "16px 0"}} />

 {/* ---- 扫描类型 ---- */}
 <div>
 <Space align="center" style={{marginBottom: 12}}>
 <ThunderboltOutlined style={sectionIconStyle} />
 <Text strong style={{fontSize: 15}}>
 扫描类型
 </Text>
 </Space>

 <Radio.Group
 value={scanType}
 onChange={(e) => setScanType(e.target.value)}
 optionType="button"
 buttonStyle="solid"
 size="large"
 style={{width: "100%"}}
 >
 <Row gutter={[12, 12]}>
 <Col xs={24} sm={8}>
 <Radio.Button
 value="full"
 style={{
 width: "100%",
 height: 58,
 borderRadius: 8,
 display: "flex",
 flexDirection: "column",
 alignItems: "center",
 justifyContent: "center",
 border: scanType === "quick" ? `2px solid ${PRIMARY_COLOR}` : undefined,
}}
 >
 <ThunderboltOutlined
 style={{
 color: scanType === "quick" ? PRIMARY_COLOR : "#999",
 fontSize: 18,
}}
 />
 <div style={{marginTop: 2, fontWeight: 600}}>全面渗透</div>
 <div style={{fontSize: 11, color: "#999"}}>全端口 + 漏洞利用 + 后渗透</div>
 </Radio.Button>
 </Col>
 <Col xs={24} sm={8}>
 <Radio.Button
 value="full"
 style={{
 width: "100%",
 height: 58,
 borderRadius: 8,
 display: "flex",
 flexDirection: "column",
 alignItems: "center",
 justifyContent: "center",
 border: scanType === "full" ? `2px solid ${PRIMARY_COLOR}` : undefined,
}}
 >
 <RocketOutlined
 style={{
 color: scanType === "full" ? PRIMARY_COLOR : "#999",
 fontSize: 18,
}}
 />
 <div style={{marginTop: 2, fontWeight: 600}}>全面渗透</div>
 <div style={{fontSize: 11, color: "#999"}}>全端口 + 漏洞利用 + 后渗透</div>
 </Radio.Button>
 </Col>
 <Col xs={24} sm={8}>
 <Radio.Button
 value="custom"
 style={{
 width: "100%",
 height: 58,
 borderRadius: 8,
 display: "flex",
 flexDirection: "column",
 alignItems: "center",
 justifyContent: "center",
 border: scanType === "custom" ? `2px solid ${PRIMARY_COLOR}` : undefined,
}}
 >
 <ControlOutlined
 style={{
 color: scanType === "custom" ? PRIMARY_COLOR : "#999",
 fontSize: 18,
}}
 />
 <div style={{marginTop: 2, fontWeight: 600}}>自定义</div>
 <div style={{fontSize: 11, color: "#999"}}>精细控制每个参数</div>
 </Radio.Button>
 </Col>
 </Row>
 </Radio.Group>
 </div>
 </Card>

 {/* ========== 自定义高级选项 ========== */}
 {isCustom && (
 <Card
 bordered={false}
 style={{
 borderRadius: 12,
 marginTop: 16,
 boxShadow: "0 2px 12px rgba(0,0,0,0.06)",
 borderLeft: `4px solid ${PRIMARY_COLOR}`,
}}
 title={
 <Space>
 <ToolOutlined style={{color: PRIMARY_COLOR}} />
 <span>高级自定义参数</span>
 <Tag color={PRIMARY_COLOR} style={{marginLeft: 4}}>
 自定义模式
 </Tag>
 </Space>
}
 >
 {/* ===== 工具选择 ===== */}
 <div style={{marginBottom: 20}}>
 <Text strong style={{display: "block", marginBottom: 10, fontSize: 14}}>
 <ExperimentOutlined style={sectionIconStyle} />
 扫描工具
 </Text>
 <Row gutter={[12, 12]}>
 {TOOLS.map((tool) => (
 <Col xs={12} sm={8} md={4} key={tool.key}>
 <Card
 size="small"
 hoverable
 onClick={() => toggleTool(tool.key)}
 style={{
 borderRadius: 10,
 textAlign: "center",
 cursor: "pointer",
 border: tools[tool.key]
 ? `2px solid ${PRIMARY_COLOR}`
 : "1px solid #e8e8e8",
 background: tools[tool.key] ? "#e6f4ff" : "#fff",
 transition: "all 0.25s",
}}
 bodyStyle={{padding: "12px 8px"}}
 >
 <div
 style={{
 fontSize: 22,
 color: tools[tool.key] ? PRIMARY_COLOR : "#999",
}}
 >
 {tool.icon}
 </div>
 <div
 style={{
 fontWeight: 600,
 marginTop: 4,
 color: tools[tool.key] ? PRIMARY_COLOR : "#333",
}}
 >
 {tool.label}
 </div>
 <div style={{fontSize: 11, color: "#999", marginTop: 2}}>
 {tool.desc}
 </div>
 <Checkbox
 checked={tools[tool.key]}
 style={{marginTop: 6, pointerEvents: "none"}}
 />
 </Card>
 </Col>
 ))}
 </Row>
 </div>

 <Divider style={{margin: "8px 0 16px"}} />

 {/* ===== 端口 / 速率 / 超时 / 验证 ===== */}
 <Row gutter={[24, 16]}>
 <Col xs={24} sm={12} md={8}>
 <Text strong style={{display: "block", marginBottom: 6, fontSize: 13}}>
 <AimOutlined style={sectionIconStyle} />
 端口范围
 <Tooltip title="支持格式：1-65535, 80,443, 或 1-10000">
 <QuestionCircleOutlined style={{marginLeft: 4, color: "#999", fontSize: 12}} />
 </Tooltip>
 </Text>
 <Input
 placeholder="1-65535"
 value={portRange}
 onChange={(e) => setPortRange(e.target.value)}
 style={{borderRadius: 6}}
 />
 </Col>

 <Col xs={24} sm={12} md={8}>
 <Text strong style={{display: "block", marginBottom: 6, fontSize: 13}}>
 <ThunderboltOutlined style={sectionIconStyle} />
 速率限制 (req/s)
 </Text>
 <Row align="middle" gutter={12}>
 <Col flex="auto">
 <Slider
 min={1}
 max={200}
 value={rateLimit}
 onChange={setRateLimit}
 trackStyle={{background: PRIMARY_COLOR}}
 handleStyle={{borderColor: PRIMARY_COLOR}}
 />
 </Col>
 <Col>
 <InputNumber
 min={1}
 max={200}
 value={rateLimit}
 onChange={(v) => setRateLimit(v ?? 50)}
 style={{width: 72, borderRadius: 6}}
 />
 </Col>
 </Row>
 </Col>

 <Col xs={24} sm={12} md={8}>
 <Text strong style={{display: "block", marginBottom: 6, fontSize: 13}}>
 <ControlOutlined style={sectionIconStyle} />
 超时时间 (秒)
 </Text>
 <InputNumber
 min={10}
 max={3600}
 value={timeout}
 onChange={(v) => setTimeoutVal(v ?? 300)}
 style={{width: "100%", borderRadius: 6}}
 addonAfter="s"
 />
 </Col>

 <Col xs={24} sm={12} md={8}>
 <Text strong style={{display: "block", marginBottom: 6, fontSize: 13}}>
 <SettingOutlined style={sectionIconStyle} />
 并发线程
 </Text>
 <InputNumber
 min={1}
 max={100}
 value={threads}
 onChange={(v) => setThreads(v ?? 10)}
 style={{width: "100%", borderRadius: 6}}
 />
 </Col>

 <Col xs={24} sm={12} md={8}>
 <Text strong style={{display: "block", marginBottom: 6, fontSize: 13}}>
 <SafetyOutlined style={sectionIconStyle} />
 漏洞验证
 <Tooltip title="开启后将对发现的漏洞进行无害化验证，确认其真实性">
 <QuestionCircleOutlined style={{marginLeft: 4, color: "#999", fontSize: 12}} />
 </Tooltip>
 </Text>
 <Switch
 checked={verifyMode}
 onChange={setVerifyMode}
 style={{
 background: verifyMode ? PRIMARY_COLOR : undefined,
}}
 />
 <Text
 type="secondary"
 style={{marginLeft: 8, fontSize: 12}}
 >
 {verifyMode ? "已启用 — 自动验证漏洞真伪" : "已关闭 — 仅输出检测结果"}
 </Text>
 </Col>
 </Row>
 </Card>
 )}
 </Col>

 {/* ========== 右栏：示例 + 汇总 + 启动 ========== */}
 <Col xs={24} lg={10}>
 {/* 快速示例 */}
 <Card
 bordered={false}
 style={{borderRadius: 12, boxShadow: "0 2px 12px rgba(0,0,0,0.06)"}}
 title={
 <Space>
 <RocketOutlined style={{color: PRIMARY_COLOR}} />
 <span>快速示例</span>
 </Space>
}
 >
 <Space direction="vertical" style={{width: "100%"}} size={8}>
 {QUICK_TARGETS.map((item) => (
 <Button
 key={item.label}
 block
 onClick={() => fillQuickTargets(item)}
 style={{
 borderRadius: 8,
 textAlign: "left",
 height: "auto",
 padding: "10px 14px",
}}
 >
 <div>
 <Text strong style={{fontSize: 13}}>
 {item.label}
 </Text>
 <Paragraph
 style={{
 margin: 0,
 fontSize: 11,
 color: "#999",
 whiteSpace: "pre-line",
 lineHeight: "18px",
}}
 ellipsis={{rows: 2}}
 >
 {item.targets}
 </Paragraph>
 </div>
 </Button>
 ))}
 </Space>
 </Card>

 {/* 扫描策略提示 */}
 <Card
 bordered={false}
 style={{
 borderRadius: 12,
 marginTop: 16,
 boxShadow: "0 2px 12px rgba(0,0,0,0.06)",
}}
 >
 <Alert
 type="info"
 showIcon
 icon={<ThunderboltOutlined />}
 message={
 <span style={{color: PRIMARY_COLOR, fontWeight: 600}}>
 当前策略：{scanType === "quick" ? "全面渗透" : scanType === "full" ? "全面渗透" : "自定义扫描"}
 </span>
}
 description={
 scanType === "quick"
 ? "仅扫描常见端口 (Top 100)，执行 Nmap 端口扫描 + Nuclei 基础检测，预计 5-15 分钟。"
 : scanType === "full"
 ? "全端口扫描 (1-65535)，启用全部工具链，执行深度漏洞检测与弱口令爆破，预计 30-120 分钟。"
 : `已选 ${Object.values(tools).filter(Boolean).length} 个工具，端口 ${portRange}，速率 ${rateLimit} req/s。`
}
 style={{
 borderRadius: 8,
 border: `1px solid ${PRIMARY_COLOR}22`,
 background: `${PRIMARY_COLOR}08`,
}}
 />
 </Card>

 {/* 一键启动 */}
 <Button
 type="primary"
 block
 size="large"
 icon={<PlayCircleOutlined />}
 loading={loading}
 onClick={handleSubmit}
 disabled={!targets.trim()}
 style={{
 marginTop: 20,
 height: 56,
 borderRadius: 12,
 fontSize: 18,
 fontWeight: 700,
 border: "none",
 background: `linear-gradient(135deg, ${PRIMARY_COLOR} 0%, #0369a1 100%)`,
 boxShadow: `0 6px 20px ${PRIMARY_COLOR}44`,
 transition: "all 0.3s",
}}
 onMouseEnter={(e) => {
 (e.currentTarget as HTMLButtonElement).style.transform = "translateY(-2px)";
 (e.currentTarget as HTMLButtonElement).style.boxShadow = `0 8px 28px ${PRIMARY_COLOR}66`;
}}
 onMouseLeave={(e) => {
 (e.currentTarget as HTMLButtonElement).style.transform = "translateY(0)";
 (e.currentTarget as HTMLButtonElement).style.boxShadow = `0 6px 20px ${PRIMARY_COLOR}44`;
}}
 >
 {loading ? "提交中…" : "一键启动扫描"}
 </Button>

 <Text
 type="secondary"
 style={{display: "block", textAlign: "center", marginTop: 10, fontSize: 12}}
 >
 提交后将自动跳转至任务列表，可实时查看扫描进度
 </Text>
 </Col>
 </Row>
 </div>
 );
};

export default AdvancedConfigPage;
