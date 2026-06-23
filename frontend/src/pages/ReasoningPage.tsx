// @ts-nocheck
import {useState, useEffect, useMemo} from "react";
import {
 Card,
 Tag,
 Typography,
 Space,
 Row,
 Col,
 Spin,
 Empty,
 Timeline,
 Drawer,
 Statistic,
 List,
 Descriptions,
 Progress,
 Tooltip,
 message,
 Alert,
 Table,
 Input,
 Select,
 Button,
 Divider,
 Badge,
} from "antd";






























import request from "../api/request";
import BulbOutlined from "@ant-design/icons/es/icons/BulbOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import QuestionCircleOutlined from "@ant-design/icons/es/icons/QuestionCircleOutlined";
import NodeIndexOutlined from "@ant-design/icons/es/icons/NodeIndexOutlined";
import FileSearchOutlined from "@ant-design/icons/es/icons/FileSearchOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import AimOutlined from "@ant-design/icons/es/icons/AimOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import CodeOutlined from "@ant-design/icons/es/icons/CodeOutlined";
import BranchesOutlined from "@ant-design/icons/es/icons/BranchesOutlined";
import DatabaseOutlined from "@ant-design/icons/es/icons/DatabaseOutlined";
import BarChartOutlined from "@ant-design/icons/es/icons/BarChartOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import PlayCircleOutlined from "@ant-design/icons/es/icons/PlayCircleOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ArrowUpOutlined from "@ant-design/icons/es/icons/ArrowUpOutlined";
import ArrowDownOutlined from "@ant-design/icons/es/icons/ArrowDownOutlined";
import MinusOutlined from "@ant-design/icons/es/icons/MinusOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";
import EyeOutlined from "@ant-design/icons/es/icons/EyeOutlined";
import FieldTimeOutlined from "@ant-design/icons/es/icons/FieldTimeOutlined";
import AlertOutlined from "@ant-design/icons/es/icons/AlertOutlined";
import RobotOutlined from "@ant-design/icons/es/icons/RobotOutlined";
import BookOutlined from "@ant-design/icons/es/icons/BookOutlined";
import ProfileOutlined from "@ant-design/icons/es/icons/ProfileOutlined";
import ApartmentOutlined from "@ant-design/icons/es/icons/ApartmentOutlined";

const {Title, Text, Paragraph} = Typography;

const STATUS_MAP = {
 confirmed: {color: "success", icon: <CheckCircleOutlined />, label: "已确认"},
 refuted: {color: "error", icon: <CloseCircleOutlined />, label: "已排除"},
 testing: {color: "processing", icon: <ClockCircleOutlined />, label: "测试中"},
 pending: {color: "warning", icon: <QuestionCircleOutlined />, label: "待验证"},
 generated: {color: "default", icon: <BulbOutlined />, label: "已生成"},
};

const PHASE_MAP = {
 perception: {label: "信息感知", color: "#6366f1", icon: <EyeOutlined />},
 hypothesis: {label: "假设生成", color: "#0284c7", icon: <BulbOutlined />},
 scanning: {label: "扫描验证", color: "#d97706", icon: <FieldTimeOutlined />},
 exploitation: {label: "漏洞利用", color: "#dc2626", icon: <ThunderboltOutlined />},
 reporting: {label: "报告汇总", color: "#16a34a", icon: <ProfileOutlined />},
};

// ─────────────────── end types ───────────────────

const EngineDashboard: React.FC = () => {
 // ── state ──
 const [loading, setLoading] = useState(true);
 const [refreshing, setRefreshing] = useState(false);
 const [pipelineRunning, setPipelineRunning] = useState(false);

 // 引擎数据
 const [engineState, setEngineState] = useState<any>(null);
 const [kbStats, setKbStats] = useState<any>(null);
 const [learningStats, setLearningStats] = useState<any>(null);
 const [hypotheses, setHypotheses] = useState<any[]>([]);
 const [steps, setSteps] = useState<any[]>([]);
 const [targetIp, setTargetIp] = useState("192.168.1.180");

 // 筛选
 const [statusFilter, setStatusFilter] = useState<string>("all");
 const [searchText, setSearchText] = useState("");

 // 抽屉
 const [drawerOpen, setDrawerOpen] = useState(false);
 const [detailHyp, setDetailHyp] = useState<any>(null);
 const [chainDrawer, setChainDrawer] = useState(false);
 const [chainSteps, setChainSteps] = useState<any[]>([]);
 const [chainLoading, setChainLoading] = useState(false);
 const [experienceResults, setExperienceResults] = useState<any[]>([]);

 const [experienceStats, setExperienceStats] = useState<any>(null);

 const [deductionResult, setDeductionResult] = useState<any>(null);

 const [exploitResult, setExploitResult] = useState<any>(null);

 const [negativeResults, setNegativeResults] = useState<any[]>([]);

 const [negativeStats, setNegativeStats] = useState<any>(null);


 // ── 数据加载 ──
 const loadAllData = async (silent = false) => {
 if (!silent) setLoading(true);
 try {
 // 并行加载主数据
 const [engRes, kbRes, learnRes, hypRes, statsRes, negRes, negStatsRes] = await Promise.allSettled([
 request.get("/engine/state", {params: {target: targetIp}}).catch(() => null),
 request.get("/engine/kb-stats").catch(() => null),
 request.get("/engine/learning-stats").catch(() => null),
 request.get("/engine/hypotheses", {params: {target: targetIp}}).catch(() => null),
 request.get("/reasoning/stats").catch(() => null),
 request.get("/negative/list").catch(() => null),
 request.get("/negative/stats").catch(() => null),
 ]);

 if (engRes.status === "fulfilled" && engRes.value?.data) {
 setEngineState(engRes.value.data);
 }
 if (kbRes.status === "fulfilled" && kbRes.value?.data) {
 setKbStats(kbRes.value.data);
 }
 if (learnRes.status === "fulfilled" && learnRes.value?.data) {
 setLearningStats(learnRes.value.data);
 }
 if (hypRes.status === "fulfilled" && hypRes.value?.data) {
 const hyps = hypRes.value.data.hypotheses || [];
 setHypotheses(hyps);
 }
 if (statsRes.status === "fulfilled" && statsRes.value?.data) {
 const d = statsRes.value.data;
 setSteps(d.top_evidence_types || []);
 }
 if (negRes.status === "fulfilled" && negRes.value?.data) {
 const negData = negRes.value.data;
 setNegativeResults(Array.isArray(negData) ? negData : (negData.items || negData.results || []));
 }
 if (negStatsRes.status === "fulfilled" && negStatsRes.value?.data) {
 setNegativeStats(negStatsRes.value.data);
 }

 // 额外请求：经验搜索（POST）
 try {
 const expRes = await request.post("/engine/experience/search", {query: "latest", limit: 10}).catch(() => null);
 if (expRes?.data) {
 const expData = expRes.data;
 setExperienceResults(Array.isArray(expData) ? expData : (expData.results || []));
 setExperienceStats(expData.stats || expData.total || null);
 }
 } catch {}

 // 额外请求：演绎推理
 try {
 const dedRes = await request.get("/deduction/deduce?target=" + targetIp).catch(() => null);
 if (dedRes?.data) {
 setDeductionResult(dedRes.data);
 }
 } catch {}

 // 加载最近推理链
 const tasksRes = await request.get("/tasks?limit=3").catch(() => null);
 if (tasksRes?.data) {
 const tasks = Array.isArray(tasksRes.data) ? tasksRes.data : [];
 if (tasks.length > 0) {
 const chainRes = await request.get("/reasoning/chain/" + tasks[0].id).catch(() => null);
 if (chainRes?.data?.steps) {
 setSteps(chainRes.data.steps.slice(0, 20));
 }
 }
 }
 } catch (e) {
 console.error("loadAllData error:", e);
 } finally {
 setLoading(false);
 }
 };
 // ── 操作 ──
 const handleRefresh = async () => {
 setRefreshing(true);
 await loadAllData(true);
 setRefreshing(false);
 message.success("数据已刷新");
};

 const handleRunPipeline = async () => {
 setPipelineRunning(true);
 try {
 await request.post("/engine/run-pipeline", {target: targetIp});
 message.success("流水线已触发");
 await loadAllData(true);
} catch (e) {
 message.error("触发失败: " + (e.message || "未知错误"));
} finally {
 setPipelineRunning(false);
}
};

 const openDetail = (hyp: any) => {
 setDetailHyp(hyp);
 setDrawerOpen(true);
};

 const openChain = async (taskId: string) => {
 setChainLoading(true);
 setChainDrawer(true);
 try {
 const res = await request.get(`/reasoning/chain/${taskId}`);
 setChainSteps(res.data?.steps || []);
} catch {
 setChainSteps([]);
} finally {
 setChainLoading(false);
}
};

 // ── 筛选 ──
 const filteredHyps = useMemo(() => {
 let list = [...hypotheses];
 if (statusFilter !== "all") {
 list = list.filter((h) => h.status === statusFilter);
}
 if (searchText) {
 const q = searchText.toLowerCase();
 list = list.filter(
 (h) =>
 h.name.toLowerCase().includes(q) ||
 h.description.toLowerCase().includes(q) ||
 h.source_principle.toLowerCase().includes(q)
 );
}
 return list.sort((a, b) => b.priority_score - a.priority_score);
}, [hypotheses, statusFilter, searchText]);

 // ── 统计汇总 ──
 const hypStats = useMemo(() => {
 return {
 total: hypotheses.length,
 confirmed: hypotheses.filter((h) => h.status === "confirmed").length,
 testing: hypotheses.filter((h) => h.status === "testing").length,
 pending: hypotheses.filter((h) => h.status === "pending" || h.status === "generated").length,
 refuted: hypotheses.filter((h) => h.status === "refuted").length,
};
}, [hypotheses]);

 // ── 获取置信度颜色 ──
 const getConfColor = (v: number) => {
 if (v >= 0.7) return "#16a34a";
 if (v >= 0.4) return "#d97706";
 return "#dc2626";
};

 const getPriorityLabel = (p: number) => {
 if (p >= 7) return {label: "高优先级", color: "#dc2626"};
 if (p >= 4) return {label: "中优先级", color: "#d97706"};
 return {label: "低优先级", color: "#94a3b8"};
};

 // ── 优先级列 ──
 const statusBadge = (status: string) => {
 const m = STATUS_MAP[status] || STATUS_MAP.generated;
 return <Tag color={m.color} icon={m.icon}>{m.label}</Tag>;
};

 const confBar = (v: number) => (
 <Tooltip title={`置信度: ${(v * 100).toFixed(0)}%`}>
 <Progress
 percent={Math.round(v * 100)}
 size="small"
 strokeColor={getConfColor(v)}
 style={{width: 120}}
 />
 </Tooltip>
 );

 const priorityTag = (p: number) => {
 const m = getPriorityLabel(p);
 return (
 <Tag color={m.color} style={{fontWeight: 600}}>
 {p.toFixed(1)} · {m.label}
 </Tag>
 );
};

 // ── 表格列 ──
 const hypColumns = [
 {
 title: "假设名称",
 dataIndex: "name",
 key: "name",
 width: 200,
 render: (name: string, record: any) => (
 <Space>
 <BulbOutlined style={{color: "#0284c7"}} />
 <a onClick={() => openDetail(record)} style={{fontWeight: 500}}>
 {name}
 </a>
 </Space>
 ),
},
 {
 title: "置信度",
 dataIndex: "confidence",
 key: "confidence",
 width: 160,
 sorter: (a: any, b: any) => a.confidence - b.confidence,
 render: (v: number) => confBar(v),
},
 {
 title: "优先级",
 dataIndex: "priority_score",
 key: "priority_score",
 width: 140,
 sorter: (a: any, b: any) => a.priority_score - b.priority_score,
 render: (v: number) => priorityTag(v),
},
 {
 title: "状态",
 dataIndex: "status",
 key: "status",
 width: 110,
 filters: [
 {text: "已确认", value: "confirmed"},
 {text: "已排除", value: "refuted"},
 {text: "测试中", value: "testing"},
 {text: "待验证", value: "pending"},
 ],
 onFilter: (value: string, record: any) => record.status === value,
 render: (s: string) => statusBadge(s),
},
 {
 title: "影响",
 dataIndex: "impact",
 key: "impact",
 width: 100,
 render: (v: string) => (
 <Tag>{v || "未知"}</Tag>
 ),
},
 {
 title: "底层原理",
 dataIndex: "source_principle",
 key: "source_principle",
 ellipsis: true,
 render: (t: string) => (
 <Tooltip title={t}>
 <Text type="secondary" ellipsis style={{maxWidth: 200}}>
 {t || "-"}
 </Text>
 </Tooltip>
 ),
},
 {
 title: "方法",
 dataIndex: "verification_method",
 key: "verification_method",
 width: 120,
 render: (v: string) => (
 <Text code style={{fontSize: 12}}>{v || "-"}</Text>
 ),
},
 ];

 // ── 渲染 ──
 if (loading) {
 return (
 <div style={{display: "flex", justifyContent: "center", alignItems: "center", height: "80vh"}}>
 <Spin size="large" tip="加载引擎数据..." />
 </div>
 );
}

 return (
 <div style={{padding: 24}}>
 {/* ─── 头部 ─── */}
 <Row justify="space-between" align="middle" style={{marginBottom: 24}}>
 <Col>
 <Title level={3} style={{margin: 0}}>
 <AimOutlined style={{color: "#0284c7", marginRight: 10}} />
 引擎推理中心
 </Title>
 <Text type="secondary" style={{fontSize: 13}}>
 AI 驱动渗透推理引擎 · 知识库驱动假设生成 · 自学习不断进化
 </Text>
 </Col>
 <Col>
 <Space>
 <Input
 placeholder="目标 IP / 域名"
 value={targetIp}
 onChange={(e) => setTargetIp(e.target.value)}
 style={{width: 180}}
 prefix={<ApiOutlined />}
 onPressEnter={handleRefresh}
 />
 <Button icon={<ReloadOutlined />} loading={refreshing} onClick={handleRefresh}>
 刷新
 </Button>
 <Button
 type="primary"
 icon={<PlayCircleOutlined />}
 loading={pipelineRunning}
 onClick={handleRunPipeline}
 >
 运行流水线
 </Button>
 </Space>
 </Col>
 </Row>

 {/* ─── 统计卡片 ─── */}
 <Row gutter={[16, 16]} style={{marginBottom: 24}}>
 {/* 引擎状态 */}
 <Col xs={24} sm={12} lg={6}>
 <Card hoverable>
 <Space align="start" style={{width: "100%", justifyContent: "space-between"}}>
 <div>
 <Text type="secondary" style={{fontSize: 13}}>引擎状态</Text>
 <Title level={4} style={{margin: "4px 0"}}>
 {engineState?.engine?.total_hypotheses || 0} 个假设
 </Title>
 <div style={{marginTop: 4}}>
 {engineState?.engine?.current_phase && (
 <Tag icon={PHASE_MAP[engineState.engine.current_phase]?.icon} color={PHASE_MAP[engineState.engine.current_phase]?.color}>
 {PHASE_MAP[engineState.engine.current_phase]?.label || engineState.engine.current_phase}
 </Tag>
 )}
 <Text type="secondary" style={{marginLeft: 8, fontSize: 12}}>
 目标: {engineState?.engine?.target || "-"}
 </Text>
 </div>
 </div>
 <RobotOutlined style={{fontSize: 32, color: "#0284c7", opacity: 0.3}} />
 </Space>
 <Divider style={{margin: "12px 0"}} />
 <Row gutter={8}>
 <Col span={6}>
 <Statistic
 value={hypStats.confirmed}
 suffix={`/ ${hypStats.total}`}
 valueStyle={{fontSize: 16, color: "#16a34a"}}
 prefix={<CheckCircleOutlined />}
 />
 <Text style={{fontSize: 11, color: "#94a3b8"}}>已确认</Text>
 </Col>
 <Col span={6}>
 <Statistic
 value={hypStats.testing}
 valueStyle={{fontSize: 16, color: "#d97706"}}
 prefix={<ClockCircleOutlined />}
 />
 <Text style={{fontSize: 11, color: "#94a3b8"}}>测试中</Text>
 </Col>
 <Col span={6}>
 <Statistic
 value={hypStats.pending}
 valueStyle={{fontSize: 16, color: "#6366f1"}}
 prefix={<QuestionCircleOutlined />}
 />
 <Text style={{fontSize: 11, color: "#94a3b8"}}>待验证</Text>
 </Col>
 <Col span={6}>
 <Statistic
 value={hypStats.refuted}
 valueStyle={{fontSize: 16, color: "#94a3b8"}}
 prefix={<CloseCircleOutlined />}
 />
 <Text style={{fontSize: 11, color: "#94a3b8"}}>已排除</Text>
 </Col>
 </Row>
 </Card>
 </Col>

 {/* 知识库 */}
 <Col xs={24} sm={12} lg={6}>
 <Card hoverable>
 <Space align="start" style={{width: "100%", justifyContent: "space-between"}}>
 <div>
 <Text type="secondary" style={{fontSize: 13}}>知识库</Text>
 <Title level={4} style={{margin: "4px 0"}}>
 {(kbStats?.documents || kbStats?.sections || 0)} 文档
 </Title>
 <Space style={{marginTop: 4}} size={4} wrap>
 <Tag icon={<FileSearchOutlined />}>
 攻击面: {kbStats?.attack_surfaces || kbStats?.attack_surface_entries || 0}
 </Tag>
 <Tag icon={<SearchOutlined />}>
 关键词: {kbStats?.keywords || 0}
 </Tag>
 </Space>
 </div>
 <BookOutlined style={{fontSize: 32, color: "#6366f1", opacity: 0.3}} />
 </Space>
 <Divider style={{margin: "12px 0"}} />
 <div style={{maxHeight: 60, overflow: "hidden"}}>
 {kbStats?.domain_distribution && Object.keys(kbStats.domain_distribution).length > 0 ? (
 <Space size={4} wrap>
 {Object.entries(kbStats.domain_distribution).slice(0, 8).map(([k, v]) => (
 <Tag key={k} color="default" style={{fontSize: 11}}>
 {k.replace(/\.md$/, "")}: {v}
 </Tag>
 ))}
 </Space>
 ) : (
 <Text type="secondary" style={{fontSize: 12}}>领域分布加载中...</Text>
 )}
 </div>
 </Card>
 </Col>

 {/* 自学习 */}
 <Col xs={24} sm={12} lg={6}>
 <Card hoverable>
 <Space align="start" style={{width: "100%", justifyContent: "space-between"}}>
 <div>
 <Text type="secondary" style={{fontSize: 13}}>自学习引擎</Text>
 <Title level={4} style={{margin: "4px 0"}}>
 {(learningStats?.total_experiments || 0) + (learningStats?.experiments || 0)} 实验
 </Title>
 <Space style={{marginTop: 4}} size={4} wrap>
 <Tag icon={<ExperimentOutlined />}>
 模式: {learningStats?.total_patterns || learningStats?.patterns || 0}
 </Tag>
 <Tag icon={<BranchesOutlined />}>
 链: {learningStats?.total_chains || learningStats?.chains || 0}
 </Tag>
 <Tag icon={<BarChartOutlined />} color="green">
 成功率: {((learningStats?.overall_success_rate || learningStats?.success_rate || 0) * 100).toFixed(1)}%
 </Tag>
 </Space>
 </div>
 <ExperimentOutlined style={{fontSize: 32, color: "#d97706", opacity: 0.3}} />
 </Space>
 <Divider style={{margin: "12px 0"}} />
 <Text type="secondary" style={{fontSize: 11}}>链类型覆盖: </Text>
 <div style={{marginTop: 4}}>
 {(learningStats?.chain_types_covered || []).slice(0, 3).map((ct: string) => (
 <Tag key={ct} style={{fontSize: 11, margin: "2px 0"}}>{ct}</Tag>
 ))}
 </div>
 </Card>
 </Col>

 {/* 攻击路径 */}
 <Col xs={24} sm={12} lg={6}>
 <Card hoverable>
 <Space align="start" style={{width: "100%", justifyContent: "space-between"}}>
 <div>
 <Text type="secondary" style={{fontSize: 13}}>攻击路径</Text>
 <Title level={4} style={{margin: "4px 0"}}>
 {engineState?.knowledge_base?.attack_surfaces || 0} 面
 </Title>
 <Space style={{marginTop: 4}} size={4} wrap>
 <Tag icon={<ApartmentOutlined />}>
 路径: {engineState?.engine?.attack_paths || 0}
 </Tag>
 <Tag icon={<SafetyOutlined />}>
 活跃假设: {engineState?.engine?.active || 0}
 </Tag>
 </Space>
 </div>
 <ApartmentOutlined style={{fontSize: 32, color: "#16a34a", opacity: 0.3}} />
 </Space>
 <Divider style={{margin: "12px 0"}} />
 <Progress
 percent={Math.round(((engineState?.engine?.confirmed || 0) / Math.max(engineState?.engine?.total_hypotheses || 1, 1)) * 100)}
 size="small"
 strokeColor="#16a34a"
 format={(pct) => `${(engineState?.engine?.confirmed || 0)}/${engineState?.engine?.total_hypotheses || 0} 已确认`}
 />
 </Card>
 </Col>
 </Row>

 {/* ─── 假设列表 ─── */}
 <Card
 title={
 <Space>
 <BulbOutlined style={{color: "#0284c7"}} />
 <span>攻击假设</span>
 <Tag>{hypotheses.length}</Tag>
 </Space>
}
 style={{marginBottom: 24}}
 extra={
 <Space>
 <Select
 value={statusFilter}
 onChange={setStatusFilter}
 size="small"
 style={{width: 120}}
 options={[
 {value: "all", label: "全部状态"},
 {value: "pending", label: "待验证"},
 {value: "testing", label: "测试中"},
 {value: "confirmed", label: "已确认"},
 {value: "refuted", label: "已排除"},
 ]}
 />
 <Input
 prefix={<SearchOutlined />}
 placeholder="搜索假设..."
 value={searchText}
 onChange={(e) => setSearchText(e.target.value)}
 size="small"
 style={{width: 200}}
 allowClear
 />
 </Space>
}
 >
 {filteredHyps.length === 0 ? (
 <Empty
 description={
 <span>
 暂无攻击假设
 <br />
 <Text type="secondary" style={{fontSize: 12}}>
 选择目标后运行流水线生成假设
 </Text>
 </span>
}
 />
 ) : (
 <Table
 dataSource={filteredHyps}
 columns={hypColumns}
 rowKey="id"
 size="middle"
 pagination={{pageSize: 10, showTotal: (t) => `共 ${t} 个假设`}}
 onRow={(record) => ({
 onClick: () => openDetail(record),
 style: {cursor: "pointer"},
})}
 />
 )}
 </Card>

 {/* ─── 推理链最近记录 ─── */}
 <Card
 title={
 <Space>
 <BranchesOutlined style={{color: "#0284c7"}} />
 <span>推理记录</span>
 <Tag>{steps.length}</Tag>
 </Space>
}
 >
 {steps.length === 0 ? (
 <Empty description="暂无推理记录" />
 ) : (
 <Timeline
 items={steps.map((step: any, i: number) => {
 const confDelta =
 step.confidence_after != null && step.confidence_before != null
 ? (step.confidence_after - step.confidence_before).toFixed(2)
 : null;
 return {
 color: step.status === "success" ? "green" : step.status === "failed" ? "red" : "gray",
 dot:
 step.status === "success" ? (
 <CheckCircleOutlined style={{color: "#16a34a"}} />
 ) : step.status === "failed" ? (
 <CloseCircleOutlined style={{color: "#dc2626"}} />
 ) : (
 <ClockCircleOutlined style={{color: "#d97706"}} />
 ),
 children: (
 <div
 style={{cursor: "pointer"}}
 onClick={() => {
 if (step.turn_id) openChain(step.turn_id);
}}
 >
 <Space>
 <Text strong style={{fontSize: 13}}>
 {step.phase || step.evidence_type || step.tool || "步骤"}
 </Text>
 <Tag>{step.tool || "-"}</Tag>
 {confDelta && (
 <Tag
 color={parseFloat(confDelta) > 0 ? "green" : "red"}
 style={{fontSize: 11}}
 >
 {parseFloat(confDelta) > 0 ? "+" : ""}
 {confDelta}
 </Tag>
 )}
 </Space>
 <div>
 <Text type="secondary" style={{fontSize: 12}}>
 {step.llm_reasoning || step.result_summary || "-"}
 </Text>
 </div>
 {step.created_at && (
 <Text type="secondary" style={{fontSize: 11}}>
 {step.created_at}
 </Text>
 )}
 </div>
 ),
};
})}
 />
 )}
 </Card>

 {/* ─── 假设详情抽屉 ─── */}

 {/* ---- 经验搜索结果 ---- */}
 {experienceResults.length > 0 && (
 <Card size="small" style={{marginBottom: 16}} title={"经验搜索 (" + experienceResults.length + "条)"}>
 <List
 size="small"
 dataSource={experienceResults.slice(0, 10)}
 renderItem={(item: any, idx: number) => (
 <List.Item>
 <List.Item.Meta
 title={<Text strong>{item.title || item.hypothesis || "经验#" + (idx+1)}</Text>}
 description={
 <Text type="secondary" style={{fontSize: 12}}>
 {item.summary || item.description || ""}
 {item.target_type && <Tag style={{marginLeft: 8}}>{item.target_type}</Tag>}
 </Text>
 }
 />
 </List.Item>
 )}
 />
 </Card>
 )}

 {/* ---- 负面结果统计 ---- */}
 {negativeResults.length > 0 && (
 <Card size="small" style={{marginBottom: 16}} title={"负面结果 (" + negativeResults.length + "条)"}>
 <Table
 dataSource={negativeResults.slice(0, 10)}
 rowKey={(r:any) => r.id || Math.random()}
 size="small"
 pagination={false}
 columns={[
 {title: "假设", dataIndex: "hypothesis", key: "h", ellipsis: true},
 {title: "目标", dataIndex: "target", key: "t", width: 120},
 {title: "原因", dataIndex: "reason", key: "r", ellipsis: true},
 ]}
 />
 </Card>
 )}

 {/* ---- 演绎推理结果 ---- */}
 {deductionResult && (
 <Card size="small" style={{marginBottom: 16}} title="演绎推理">
 <Descriptions size="small" column={2}>
 <Descriptions.Item label="结论">{deductionResult.conclusion || deductionResult.result || "无"}</Descriptions.Item>
 <Descriptions.Item label="可信度">{(deductionResult.confidence || 0) + "%"}</Descriptions.Item>
 </Descriptions>
 {deductionResult.steps && deductionResult.steps.length > 0 && (
 <Timeline
 items={deductionResult.steps.map((s: any, si: number) => ({
 color: s.status === "confirmed" ? "green" : s.status === "rejected" ? "red" : "gray",
 children: <Text key={si} style={{fontSize: 12}}>{s.description || s.step || s}</Text>,
 }))}
 />
 )}
 </Card>
 )}
 <Drawer
 title={
 <Space>
 <BulbOutlined style={{color: "#0284c7"}} />
 {detailHyp?.name || "假设详情"}
 </Space>
}
 open={drawerOpen}
 onClose={() => setDrawerOpen(false)}
 width={560}
 >
 {detailHyp && (
 <Space direction="vertical" size="middle" style={{width: "100%"}}>
 {/* 状态标签行 */}
 <Space>
 {statusBadge(detailHyp.status)}
 {priorityTag(detailHyp.priority_score)}
 {detailHyp.confidence && confBar(detailHyp.confidence)}
 </Space>

 {/* 描述 */}
 <Descriptions column={1} size="small" bordered>
 <Descriptions.Item label="ID">{detailHyp.id}</Descriptions.Item>
 <Descriptions.Item label="描述">{detailHyp.description || "-"}</Descriptions.Item>
 <Descriptions.Item label="影响级别">
 <Tag color={detailHyp.impact === "高" ? "red" : detailHyp.impact === "中" ? "orange" : "default"}>
 {detailHyp.impact || "未知"}
 </Tag>
 </Descriptions.Item>
 <Descriptions.Item label="利用难度">
 <Tag>{detailHyp.effort || "未知"}</Tag>
 </Descriptions.Item>
 <Descriptions.Item label="验证方法">
 <Text code>{detailHyp.verification_method || "-"}</Text>
 </Descriptions.Item>
 <Descriptions.Item label="环境提示">
 <Text>{detailHyp.env_hint || "-"}</Text>
 </Descriptions.Item>
 </Descriptions>

 {/* 底层原理 */}
 <Card size="small" title="底层原理" type="inner">
 <Paragraph style={{fontSize: 13, whiteSpace: "pre-wrap"}}>
 {detailHyp.source_principle || "暂无"}
 </Paragraph>
 </Card>

 {/* 攻击面来源 */}
 {detailHyp.source_attack_surface && (
 <Card size="small" title="攻击面来源" type="inner">
 <Text style={{fontSize: 13, whiteSpace: "pre-wrap"}}>
 {detailHyp.source_attack_surface}
 </Text>
 </Card>
 )}
 </Space>
 )}
 </Drawer>

 {/* ─── 推理链详情抽屉 ─── */}
 <Drawer
 title="推理详情"
 open={chainDrawer}
 onClose={() => setChainDrawer(false)}
 width={600}
 >
 {chainLoading ? (
 <Spin style={{display: "block", margin: "40px auto"}} />
 ) : chainSteps.length === 0 ? (
 <Empty description="无推理步骤" />
 ) : (
 <Timeline
 items={chainSteps.map((s: any, i: number) => {
 const confDelta =
 s.confidence_after != null && s.confidence_before != null
 ? (s.confidence_after - s.confidence_before).toFixed(2)
 : null;
 return {
 color: s.status === "success" ? "green" : s.status === "failed" ? "red" : "gray",
 children: (
 <div>
 <Space>
 <Text strong>{s.evidence_type || s.tool || `Step ${i + 1}`}</Text>
 {confDelta && (
 <Tag color={parseFloat(confDelta) > 0 ? "green" : "red"}>
 {parseFloat(confDelta) > 0 ? "+" : ""}
 {confDelta}
 </Tag>
 )}
 {s.risk_level && <Tag color={s.risk_level === "高" ? "red" : s.risk_level === "中" ? "orange" : "blue"}>{s.risk_level}</Tag>}
 </Space>
 {s.llm_reasoning && (
 <Paragraph
 style={{
 fontSize: 12,
 color: "#475569",
 background: "#f8fafc",
 padding: "8px 12px",
 borderRadius: 6,
 margin: "4px 0",
}}
 ellipsis={{rows: 3, expandable: true}}
 >
 {s.llm_reasoning}
 </Paragraph>
 )}
 {s.result_summary && (
 <Text
 type="secondary"
 style={{
 fontSize: 12,
 background: s.status === "success" ? "#f0fdf4" : "#fef2f2",
 padding: "4px 8px",
 borderRadius: 4,
 display: "inline-block",
}}
 >
 {s.result_summary}
 </Text>
 )}
 {s.duration_ms && (
 <Text type="secondary" style={{fontSize: 11, marginLeft: 8}}>
 {s.duration_ms}ms
 </Text>
 )}
 </div>
 ),
};
})}
 />
 )}
 </Drawer>
 </div>
 );
};

export default EngineDashboard;
