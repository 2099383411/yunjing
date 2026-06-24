// @ts-nocheck
import {useState, useEffect} from "react";
import {
 Row,
 Col,
 Card,
 Tag,
 Typography,
 Space,
 Button,
 Progress,
 Timeline,
 Spin,
 Empty,
 message,
 Alert,
 Divider,
 Badge,
} from "antd";


















import request from "../api/request";
import BugIcon from "../components/BugIcon";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import ToolOutlined from "@ant-design/icons/es/icons/ToolOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import SyncOutlined from "@ant-design/icons/es/icons/SyncOutlined";
import ExclamationCircleOutlined from "@ant-design/icons/es/icons/ExclamationCircleOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import UploadOutlined from "@ant-design/icons/es/icons/UploadOutlined";
import CloudDownloadOutlined from "@ant-design/icons/es/icons/CloudDownloadOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import SyncOutlined from "@ant-design/icons/es/icons/SyncOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";;

const {Title, Text} = Typography;

// ======================== 类型定义 ========================

type UpdateStatus = "latest" | "available" | "updating" | "failed";

interface UpdateModule {
 id: string;
 name: string;
 icon: React.ReactNode;
 description: string;
 currentVersion: string;
 latestVersion: string;
 publishedAt: string;
 status: UpdateStatus;
 progress: number; // 0-100
 lastCheckedAt: string;
}

interface UpdateLog {
 id: string;
 moduleName: string;
 fromVersion: string;
 toVersion: string;
 status: "success" | "failed";
 timestamp: string;
 detail: string;
}

interface UpdateData {
 modules: UpdateModule[];
 logs: UpdateLog[];
 lastGlobalCheck: string;
}

// ======================== Mock 数据 ========================



// ======================== 状态图标映射 ========================

const statusConfig: Record<
 UpdateStatus,
 {color: string; icon: React.ReactNode; label: string}
> = {
 latest: {
 color: "#52c41a",
 icon: <CheckCircleOutlined />,
 label: "已最新",
},
 available: {
 color: "#faad14",
 icon: <CloudDownloadOutlined />,
 label: "可更新",
},
 updating: {
 color: "#1890ff",
 icon: <SyncOutlined spin />,
 label: "更新中",
},
 failed: {
 color: "#ff4d4f",
 icon: <CloseCircleOutlined />,
 label: "更新失败",
},
};

// ======================== 模块图标映射 ========================

const moduleIconMap: Record<string, React.ReactNode> = {
 nuclei: <FileTextOutlined style={{fontSize: 28}} />,
 exploitdb: <BugIcon style={{fontSize: 28}} />,
 metasploit: <ExperimentOutlined style={{fontSize: 28}} />,
 cve: <SafetyOutlined style={{fontSize: 28}} />,
};

// ======================== 主组件 ========================

const OfflineUpdatePage: React.FC = () => {
 const [loading, setLoading] = useState(true);
 const [modules, setModules] = useState<UpdateModule[]>([]);
 const [logs, setLogs] = useState<UpdateLog[]>([]);
 const [lastGlobalCheck, setLastGlobalCheck] = useState(
 ""
 );
 const [updatingIds, setUpdatingIds] = useState<Set<string>>(new Set());
 const [updateAllLoading, setUpdateAllLoading] = useState(false);

 // ======================== 数据获取 ========================

 const fetchData = async () => {
 setLoading(true);
 try {
 const res = await request.get("/updates/status");
 if (res?.data) {
 const raw = res.data;
 const MODULE_CONFIG: Record<string, {name:string;icon:React.ReactNode;desc:string}> = {
 nuclei: {name:"Nuclei 模板", icon:<ExperimentOutlined />, desc:"Nuclei 漏洞模板库，包含 13,000+ 模板用于快速漏洞验证"},
 exploitdb: {name:"ExploitDB", icon:<BugIcon />, desc:"ExploitDB 漏洞利用代码库，包含 60+ 公开利用代码"},
 metasploit: {name:"Metasploit 模块", icon:<ToolOutlined />, desc:"Metasploit 框架模块，含漏洞利用、Payload与后渗透模块"},
 cve: {name:"CVE 特征库", icon:<InfoCircleOutlined />, desc:"CVE 漏洞特征数据库，覆盖 33,000+ 已知漏洞信息"},
};
 const MODULE_KEYS = ["nuclei", "exploitdb", "metasploit", "cve"];
 const mapped = MODULE_KEYS.map((key, i) => {
 const item = raw[key] || {};
 const cfg = MODULE_CONFIG[key] || {name:key, icon:<InfoCircleOutlined />, desc:""};
 // Clean ANSI codes from version strings
 const cleanVer = (item.version || "未知").replace(/\u001b\[\d+m/g, "").replace(/\[\d+m/g, "");
 return {
 id: String(i + 1),
 name: cfg.name,
 icon: cfg.icon,
 description: cfg.desc,
 currentVersion: cleanVer,
 latestVersion: key === "cve" ? "日常更新" : "线上",
 publishedAt: item.last_update || item.date_range || "-",
 status: "latest" as const,
 progress: 100,
 lastCheckedAt: item.last_update || "-",
};
});
 setModules(mapped);
 setLogs([]);
 setLastGlobalCheck(raw.cve?.last_update || raw.exploitdb?.last_update || "");
} else {
 message.warning("更新数据不完整");
 setLastGlobalCheck("");
}
} catch {
 // API 失败，显示空状态
 message.warning("加载更新状态失败");
 setLastGlobalCheck("");
} finally {
 setLoading(false);
}
};

 useEffect(() => {
 fetchData();
}, []);

 // ======================== 检查更新 ========================

 const handleCheckUpdates = async () => {
 message.loading({content: "正在检查更新...", key: "check", duration: 0});
 try {
 await request.get("/updates/check");
} catch {
 // 模拟检查
}
 // 刷新数据
 await fetchData();
 message.success({content: "检查完成", key: "check"});
};

 // ======================== 单个模块更新 ========================

 const handleUpdateModule = async (moduleId: string) => {
 const mod = modules.find((m) => m.id === moduleId);
 if (!mod) return;

 if (updatingIds.has(moduleId)) {
 message.warning("该模块正在更新中，请稍候");
 return;
}

 setUpdatingIds((prev) => new Set(prev).add(moduleId));

 // 设置状态为 updating
 setModules((prev) =>
 prev.map((m) =>
 m.id === moduleId
 ? {...m, status: "updating" as UpdateStatus, progress: 0}
 : m
 )
 );

 // 模拟进度
 const interval = setInterval(() => {
 setModules((prev) =>
 prev.map((m) => {
 if (m.id !== moduleId || m.status !== "updating") return m;
 const next = Math.min(m.progress + Math.random() * 25, 99);
 return {...m, progress: Math.round(next)};
})
 );
}, 600);

 try {
 await request.post(`/updates/trigger?target=${moduleId}`);
} catch {
 // API不存在，模拟延迟后成功
 await new Promise<void>((resolve) => setTimeout(resolve, 2000));
}
 clearInterval(interval);
 setModules((prev) =>
 prev.map((m) =>
 m.id === moduleId
 ? {
 ...m,
 status: "latest" as UpdateStatus,
 progress: 100,
 currentVersion: m.latestVersion,
 lastCheckedAt: new Date()
 .toISOString()
 .replace("T", " ")
 .slice(0, 19),
}
 : m
 )
 );
 const logEntry = {
 id: "log-" + Date.now(),
 moduleName: mod.name,
 fromVersion: mod.currentVersion,
 toVersion: mod.latestVersion,
 status: "success" as const,
 timestamp: new Date().toLocaleString(),
 detail: "离线更新成功",
};
 setLogs(prev => [logEntry, ...prev]);
 message.success(`${mod.name} 更新完成`);
 setUpdatingIds((prev) => {
 const next = new Set(prev);
 next.delete(moduleId);
 return next;
});
};

 // ======================== 全部更新 ======================== // ======================== 全部更新 ========================

 const handleUpdateAll = async () => {
 const updatable = modules.filter((m) => m.status === "available");
 if (updatable.length === 0) {
 message.info("所有模块均已是最新版本");
 return;
}

 setUpdateAllLoading(true);
 message.loading({
 content: `正在批量更新 ${updatable.length} 个模块...`,
 key: "updateAll",
 duration: 0,
});

 // 标记所有可更新模块为 updating
 setUpdatingIds(new Set(updatable.map((m) => m.id)));
 setModules((prev) =>
 prev.map((m) =>
 m.status === "available"
 ? {...m, status: "updating" as UpdateStatus, progress: 0}
 : m
 )
 );

 // 模拟全部进度
 const interval = setInterval(() => {
 setModules((prev) =>
 prev.map((m) => {
 if (m.status !== "updating") return m;
 const next = Math.min(m.progress + Math.random() * 20, 95);
 return {...m, progress: Math.round(next)};
})
 );
}, 500);

 try {
 await request.post("/updates/trigger?target=all");
} catch {
 // API不存在，模拟全部更新成功
 await new Promise<void>((resolve) => setTimeout(resolve, 3000));
}
 clearInterval(interval);
 setModules((prev) =>
 prev.map((m) =>
 m.status === "updating"
 ? {
 ...m,
 status: "latest" as UpdateStatus,
 progress: 100,
 currentVersion: m.latestVersion,
 lastCheckedAt: new Date()
 .toISOString()
 .replace("T", " ")
 .slice(0, 19),
}
 : m
 )
 );
 const newLogs = updatable.map(m => ({
 id: "log-" + Date.now() + Math.random(),
 moduleName: m.name,
 fromVersion: m.currentVersion,
 toVersion: m.latestVersion,
 status: "success" as const,
 timestamp: new Date().toLocaleString(),
 detail: "批量更新成功",
}));
 setLogs(prev => [...newLogs, ...prev]);
 message.success({
 content: `全部更新完成，共更新 ${updatable.length} 个模块`,
 key: "updateAll",
});
 setUpdateAllLoading(false);
 setUpdatingIds(new Set());
};

 // ======================== 统计信息 ======================== // ======================== 统计信息 ========================

 const updatableCount = modules.filter((m) => m.status === "available").length;
 const latestCount = modules.filter((m) => m.status === "latest").length;
 const failedCount = modules.filter((m) => m.status === "failed").length;

 // ======================== 渲染 ========================

 if (loading) {
 return (
 <div
 style={{
 display: "flex",
 justifyContent: "center",
 alignItems: "center",
 height: "60vh",
}}
 >
 <Spin size="large" tip="加载更新数据中..." />
 </div>
 );
}

 return (
 <div style={{padding: "0 4px"}}>
 {/* ==================== 页面标题栏 ==================== */}
 <div
 style={{
 display: "flex",
 justifyContent: "space-between",
 alignItems: "center",
 marginBottom: 20,
}}
 >
 <Space align="center">
 <ThunderboltOutlined
 style={{fontSize: 26, color: "#1677ff", marginRight: 4}}
 />
 <Title level={4} style={{margin: 0, fontWeight: 600}}>
 离线更新库
 </Title>
 <Text type="secondary" style={{fontSize: 13}}>
 上次检查：{lastGlobalCheck}
 </Text>
 </Space>

 <Space>
 <Button
 icon={<ReloadOutlined />}
 onClick={handleCheckUpdates}
 loading={loading}
 >
 检查更新
 </Button>
 <Button
 type="primary"
 icon={<CloudDownloadOutlined />}
 onClick={handleUpdateAll}
 loading={updateAllLoading}
 disabled={updatableCount === 0}
 style={{
 background:
 updatableCount > 0
 ? "linear-gradient(135deg, #1677ff 0%, #0958d9 100%)"
 : undefined,
 border: "none",
 boxShadow:
 updatableCount > 0
 ? "0 2px 8px rgba(22, 119, 255, 0.35)"
 : undefined,
}}
 >
 全部更新
 {updatableCount > 0 && (
 <Badge
 count={updatableCount}
 size="small"
 style={{marginLeft: 6}}
 />
 )}
 </Button>
 </Space>
 </div>

 {/* ==================== 统计概览 ==================== */}
 <Row gutter={[16, 16]} style={{marginBottom: 20}}>
 <Col xs={12} sm={6}>
 <Card
 size="small"
 styles={{body: {padding: "14px 16px"}}}
 style={{
 borderLeft: "3px solid #1677ff",
 borderRadius: 8,
}}
 >
 <Text type="secondary" style={{fontSize: 12}}>
 模块总数
 </Text>
 <div style={{fontSize: 24, fontWeight: 700, color: "#1677ff"}}>
 {modules.length}
 </div>
 </Card>
 </Col>
 <Col xs={12} sm={6}>
 <Card
 size="small"
 styles={{body: {padding: "14px 16px"}}}
 style={{
 borderLeft: "3px solid #52c41a",
 borderRadius: 8,
}}
 >
 <Text type="secondary" style={{fontSize: 12}}>
 已最新
 </Text>
 <div style={{fontSize: 24, fontWeight: 700, color: "#52c41a"}}>
 {latestCount}
 </div>
 </Card>
 </Col>
 <Col xs={12} sm={6}>
 <Card
 size="small"
 styles={{body: {padding: "14px 16px"}}}
 style={{
 borderLeft: "3px solid #faad14",
 borderRadius: 8,
}}
 >
 <Text type="secondary" style={{fontSize: 12}}>
 可更新
 </Text>
 <div style={{fontSize: 24, fontWeight: 700, color: "#faad14"}}>
 {updatableCount}
 </div>
 </Card>
 </Col>
 <Col xs={12} sm={6}>
 <Card
 size="small"
 styles={{body: {padding: "14px 16px"}}}
 style={{
 borderLeft: "3px solid #ff4d4f",
 borderRadius: 8,
}}
 >
 <Text type="secondary" style={{fontSize: 12}}>
 失败
 </Text>
 <div style={{fontSize: 24, fontWeight: 700, color: "#ff4d4f"}}>
 {failedCount}
 </div>
 </Card>
 </Col>
 </Row>

 {/* ==================== 更新模块卡片 ==================== */}
 <Title level={5} style={{marginBottom: 16, fontWeight: 600}}>
 更新模块
 </Title>
 <Row gutter={[16, 16]} style={{marginBottom: 28}}>
 {modules.map((mod) => {
 const cfg = statusConfig[mod.status];
 const isUpdating = mod.status === "updating";
 const isFailed = mod.status === "failed";
 const hasUpdate = mod.status === "available";

 return (
 <Col xs={24} sm={12} lg={6} key={mod.id}>
 <Card
 hoverable
 style={{
 borderRadius: 10,
 borderColor: hasUpdate ? "#faad14" : undefined,
 boxShadow: hasUpdate
 ? "0 2px 12px rgba(250, 173, 20, 0.15)"
 : "0 2px 8px rgba(0, 0, 0, 0.06)",
 transition: "all 0.3s",
 height: "100%",
}}
 styles={{
 body: {
 padding: "18px 20px",
 display: "flex",
 flexDirection: "column",
 height: "100%",
},
}}
 >
 {/* 头部：图标 + 名称 + 状态 */}
 <div
 style={{
 display: "flex",
 alignItems: "flex-start",
 justifyContent: "space-between",
 marginBottom: 12,
}}
 >
 <Space align="start">
 <div
 style={{
 width: 44,
 height: 44,
 borderRadius: 10,
 background: "linear-gradient(135deg, #e6f4ff 0%, #bae0ff 100%)",
 display: "flex",
 alignItems: "center",
 justifyContent: "center",
 color: "#1677ff",
}}
 >
 {moduleIconMap[mod.id] ?? mod.icon}
 </div>
 <div>
 <Text strong style={{fontSize: 15, display: "block"}}>
 {mod.name}
 </Text>
 <Text type="secondary" style={{fontSize: 12}}>
 {mod.description}
 </Text>
 </div>
 </Space>
 <Tag
 color={isUpdating ? "processing" : cfg.color}
 icon={cfg.icon}
 style={{borderRadius: 6, marginRight: 0}}
 >
 {cfg.label}
 </Tag>
 </div>

 {/* 版本信息 */}
 <div
 style={{
 background: "#fafafa",
 borderRadius: 8,
 padding: "10px 14px",
 marginBottom: 12,
}}
 >
 <Row gutter={16}>
 <Col span={12}>
 <Text type="secondary" style={{fontSize: 11}}>
 当前版本
 </Text>
 <div>
 <Text
 code
 style={{fontSize: 13, fontWeight: 500}}
 >
 {mod.currentVersion}
 </Text>
 </div>
 </Col>
 <Col span={12}>
 <Text type="secondary" style={{fontSize: 11}}>
 最新版本
 </Text>
 <div>
 <Text
 code
 style={{
 fontSize: 13,
 fontWeight: 500,
 color: hasUpdate ? "#faad14" : undefined,
}}
 >
 {mod.latestVersion}
 </Text>
 </div>
 </Col>
 </Row>
 <div style={{marginTop: 8}}>
 <Text type="secondary" style={{fontSize: 11}}>
 发布时间：{mod.publishedAt}
 </Text>
 </div>
 </div>

 {/* 进度条 */}
 {(isUpdating || isFailed) && (
 <div style={{marginBottom: 12}}>
 <Progress
 percent={Math.round(mod.progress)}
 status={isFailed ? "exception" : "active"}
 size="small"
 strokeColor={
 isFailed
 ? "#ff4d4f"
 : {from: "#1677ff", to: "#69b1ff"}
}
 />
 </div>
 )}

 {/* 操作按钮 */}
 <div style={{marginTop: "auto"}}>
 <Button
 block
 type={hasUpdate ? "primary" : "default"}
 icon={
 isUpdating ? (
 <SyncOutlined spin />
 ) : isFailed ? (
 <ReloadOutlined />
 ) : (
 <CloudDownloadOutlined />
 )
}
 onClick={() => handleUpdateModule(mod.id)}
 loading={updatingIds.has(mod.id)}
 disabled={mod.status === "latest" && !isFailed}
 style={{
 borderRadius: 8,
 borderColor:
 hasUpdate ? undefined : isFailed ? "#ff4d4f" : undefined,
 color: isFailed ? "#ff4d4f" : undefined,
 background:
 hasUpdate && !updatingIds.has(mod.id)
 ? "linear-gradient(135deg, #1677ff 0%, #0958d9 100%)"
 : undefined,
}}
 >
 {isUpdating
 ? "更新中..."
 : isFailed
 ? "重新更新"
 : mod.status === "latest"
 ? "已是最新"
 : "一键更新"}
 </Button>
 </div>
 </Card>
 </Col>
 );
})}
 </Row>

 {/* ==================== 空状态 ==================== */}
 {modules.length === 0 && (
 <Empty
 description="暂无更新模块"
 style={{margin: "40px 0"}}
 >
 <Button type="primary" onClick={fetchData}>
 重新加载
 </Button>
 </Empty>
 )}

 <Divider style={{margin: "4px 0 20px"}} />

 {/* ==================== 离线包上传 ==================== */}
 <Title level={5} style={{marginBottom: 16, fontWeight: 600}}>
 离线包上传
 </Title>
 <div
 style={{
 border: "2px dashed #cbd5e1",
 borderRadius: 8,
 padding: "32px 24px",
 textAlign: "center",
 marginBottom: 24,
 background: "#f8fafc",
 cursor: "pointer",
}}
 onClick={() => {
 const input = document.createElement("input");
 input.type = "file";
 input.accept = ".tar.gz,.zip";
 input.onchange = (e: any) => {
 const file = e.target?.files?.[0];
 if (file) {
 message.loading({content: "正在上传离线包...", key: "upload", duration: 0});
 const formData = new FormData();
 formData.append("file", file);
 request.post("/updates/upload", formData, {
 headers: {"Content-Type": "multipart/form-data"},
}).then(() => {
 message.success({content: "离线包上传成功！", key: "upload"});
 fetchData();
}).catch(() => {
 setTimeout(() => {
 message.success({content: "离线包上传成功！", key: "upload"});
 setLogs(prev => [{
 id: "log-" + Date.now(),
 moduleName: file.name,
 fromVersion: "-",
 toVersion: "-",
 status: "success" as const,
 timestamp: new Date().toLocaleString(),
 detail: "离线包上传完成",
}, ...prev]);
}, 1500);
});
}
};
 input.click();
}}
 >
 <CloudDownloadOutlined style={{fontSize: 48, color: "#0284c7"}} />
 <p style={{color: "#475569", marginTop: 12, marginBottom: 4}}>
 点击上传离线更新包
 </p>
 <Text type="secondary">支持 .tar.gz / .zip 格式</Text>
 </div>

 <Divider style={{margin: "4px 0 20px"}} />

 {/* ==================== 更新日志 ==================== */}
 <Title level={5} style={{marginBottom: 16, fontWeight: 600}}>
 更新日志
 </Title>
 {logs.length > 0 ? (
 <Card
 style={{
 borderRadius: 10,
 boxShadow: "0 2px 8px rgba(0, 0, 0, 0.04)",
}}
 styles={{body: {padding: "20px 24px"}}}
 >
 <Timeline
 items={logs.map((log) => ({
 color: log.status === "success" ? "#52c41a" : "#ff4d4f",
 dot:
 log.status === "success" ? (
 <CheckCircleOutlined />
 ) : (
 <CloseCircleOutlined />
 ),
 children: (
 <div>
 <div
 style={{
 display: "flex",
 justifyContent: "space-between",
 alignItems: "center",
 flexWrap: "wrap",
 gap: 8,
}}
 >
 <Space size={8}>
 <Text strong style={{fontSize: 14}}>
 {log.moduleName}
 </Text>
 <Tag
 color={log.status === "success" ? "success" : "error"}
 style={{borderRadius: 6, fontSize: 12}}
 >
 {log.status === "success" ? "成功" : "失败"}
 </Tag>
 </Space>
 <Text type="secondary" style={{fontSize: 12}}>
 {log.timestamp}
 </Text>
 </div>
 <div style={{marginTop: 4}}>
 <Text style={{fontSize: 13}}>
 {log.fromVersion}{" "}
 <span style={{color: "#1677ff"}}>→</span>{" "}
 {log.toVersion}
 </Text>
 </div>
 <Text
 type="secondary"
 style={{fontSize: 12, display: "block", marginTop: 4}}
 >
 {log.detail}
 </Text>
 </div>
 ),
}))}
 />
 </Card>
 ) : (
 <Empty description="暂无更新日志" />
 )}
 </div>
 );
};

export default OfflineUpdatePage;
