// @ts-nocheck
import {useState, useEffect, useMemo} from "react";
import {
 Table, Card, Tag, Button, Input, Select, Typography, Space,
 Progress, Row, Col, Spin, Empty, Tooltip, message, Statistic,
} from "antd";










import request from "../api/request";
import {useNavigate} from "react-router-dom";
import BugIcon from "../components/BugIcon";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import EyeOutlined from "@ant-design/icons/es/icons/EyeOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import FilePdfOutlined from "@ant-design/icons/es/icons/FilePdfOutlined";
import FileWordOutlined from "@ant-design/icons/es/icons/FileWordOutlined";
import FileExcelOutlined from "@ant-design/icons/es/icons/FileExcelOutlined";
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";;
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined"

const {Title, Text} = Typography;

// 安全评分（0-100）：基于漏洞分布计算
function calcScore(summary: any): number {
 const total = summary?.total || 0;
 if (total === 0) return 95;
 const critical = summary?.critical || 0;
 const high = summary?.high || 0;
 const medium = summary?.medium || 0;
 const deduct = critical * 25 + high * 15 + medium * 8 + (summary?.low || 0) * 3;
 return Math.max(10, Math.min(100, 100 - deduct));
}

function scoreColor(s: number) {
 return s >= 80 ? "#16a34a" : s >= 60 ? "#d97706" : "#dc2626";
}

function formatType(fmt: string): string {
 const m: Record<string, string> = {pdf: "PDF", docx: "Word", xlsx: "Excel", html: "在线预览"};
 return m[fmt?.toLowerCase()] || fmt || "未知";
}

function formatStatus(s: string): {text: string; color: string} {
 switch (s?.toLowerCase()) {
 case "completed": return {text: "已完成", color: "green"};
 case "generating": case "pending": return {text: "生成中", color: "orange"};
 case "failed": return {text: "失败", color: "red"};
 default: return {text: s || "未知", color: "default"};
}
}

function formatTime(ts: string): string {
 if (!ts) return "-";
 const d = new Date(ts);
 if (isNaN(d.getTime())) return ts.slice(0, 16).replace("T", " ");
 return d.toLocaleString("zh-CN", {
 year: "numeric", month: "2-digit", day: "2-digit",
 hour: "2-digit", minute: "2-digit",
});
}

// 展平 report 数据
function flattenReport(r: any) {
 const s = r.summary || {};
 return {
 ...r,
 _target: s.target || r.target || "未知",
 _scan_type: s.scan_type || r.scan_type || "",
 _format: r.format || "pdf",
 _total: s.total || 0,
 _critical: s.critical || 0,
 _high: s.high || 0,
 _medium: s.medium || 0,
 _low: s.low || 0,
 _info: s.info || 0,
 _ports: s.ports_found || 0,
 _status: s.status || "",
 _score: calcScore(s),
 _name: s.target ? `${s.target}${s.scan_type ? ` [${s.scan_type}]` : ""}` : r.id?.slice(0, 8) || "报告",
};
}

export default function ReportsListPage() {
 const navigate = useNavigate();
 const [raw, setRaw] = useState<any[]>([]);
 const [loading, setLoading] = useState(false);
 const [search, setSearch] = useState("");

 useEffect(() => {
 setLoading(true);
 request.get("/reports/")
 .then((res: any) => {
 const list = res?.data;
 if (list) {
 const items = Array.isArray(list) ? list : list.reports || list.items || list.results || [];
 setRaw(items);
}
})
 .catch((e: any) => {
 console.error("Failed to load reports:", e);
 message.error("加载报告列表失败");
})
 .finally(() => setLoading(false));
}, []);

 const data = useMemo(() => raw.map(flattenReport), [raw]);

 const filtered = useMemo(() => {
 if (!search) return data;
 const q = search.toLowerCase();
 return data.filter((r) =>
 r._target.toLowerCase().includes(q) ||
 r._scan_type.toLowerCase().includes(q) ||
 r._format.toLowerCase().includes(q)
 );
}, [data, search]);

 // 统计：加入 critical（严重）
 const totals = useMemo(() => ({
 critical: data.reduce((s, r) => s + r._critical, 0),
 high: data.reduce((s, r) => s + r._high, 0),
 medium: data.reduce((s, r) => s + r._medium, 0),
 low: data.reduce((s, r) => s + r._low, 0),
}), [data]);

 const columns = [
 {
 title: "报告名称", key: "name", width: 280,
 render: (_: any, r: any) => (
 <a onClick={() => navigate(`/reports/${r.id}`)} style={{fontWeight: 500}}>
 {r._name}
 </a>
 ),
},
 {
 title: "目标", dataIndex: "_target", key: "target", width: 160,
},
 {
 title: "类型", dataIndex: "_format", key: "type", width: 80,
 render: (v: string) => <Tag color="blue">{formatType(v)}</Tag>,
},
 {
 title: "扫描模式", dataIndex: "_scan_type", key: "scan_type", width: 70,
 render: (v: string) => v ? <Tag>{v}</Tag> : null,
},
 {
 title: "漏洞分布", key: "vulns", width: 220,
 render: (_: any, r: any) => (
 <Space size={4} wrap>
 {r._critical > 0 && <Tag color="#ef4444">严重 {r._critical}</Tag>}
 {r._high > 0 && <Tag color="#f59e0b">高危 {r._high}</Tag>}
 {r._medium > 0 && <Tag color="#0284c7">中危 {r._medium}</Tag>}
 {r._low > 0 && <Tag color="#6b7280">低危 {r._low}</Tag>}
 {r._total === 0 && <Text type="secondary" style={{fontSize: 12}}>无漏洞</Text>}
 </Space>
 ),
},
 {
 title: "端口", dataIndex: "_ports", key: "ports", width: 50,
 render: (v: number) => v > 0 ? <Text strong>{v}</Text> : "-",
},
 {
 title: "安全评分", key: "score", width: 100,
 render: (_: any, r: any) => (
 <Tooltip title={`严重${r._critical} 高危${r._high} 中危${r._medium} 低危${r._low}`}>
 <Progress
 percent={r._score}
 size="small"
 strokeColor={scoreColor(r._score)}
 format={(pct) => <Text strong style={{color: scoreColor(r._score)}}>{pct}</Text>}
 style={{width: 72}}
 />
 </Tooltip>
 ),
},
 {
 title: "状态", dataIndex: "_status", key: "status", width: 70,
 render: (v: string) => {
 const {text, color} = formatStatus(v);
 return <Tag color={color}>{text}</Tag>;
},
},
 {
 title: "生成时间", dataIndex: "created_at", key: "time", width: 130,
 render: (v: string) => <Text type="secondary">{formatTime(v)}</Text>,
},
 {
 title: "操作", key: "action", width: 80,
 render: (_: any, r: any) => (
 <Space>
 <Tooltip title="预览">
 <Button size="small" icon={<EyeOutlined />}
 onClick={() => navigate(`/reports/${r.id}`)} />
 </Tooltip>
 <Tooltip title="下载 PDF">
 <Button size="small" icon={<DownloadOutlined />}
 onClick={() => window.open(`/api/reports/${r.id}/download`, "_blank")} />
 </Tooltip>
 </Space>
 ),
},
 ];

 return (
 <div style={{padding: 0}}>
 {/* 头部 */}
 <div style={{
 marginBottom: 16, display: "flex", justifyContent: "space-between",
 alignItems: "center", background: "#fff", padding: "16px 24px",
 borderRadius: 8, border: "1px solid #e2e8f0",
}}>
 <Space>
 <FileTextOutlined style={{fontSize: 22, color: "#0284c7"}} />
 <Title level={4} style={{margin: 0, color: "#0284c7"}}>检测报告</Title>
 </Space>
 <Space>
 <Input
 placeholder="搜索目标 / 类型..."
 prefix={<SearchOutlined />}
 style={{width: 220}}
 value={search}
 onChange={(e) => setSearch(e.target.value)}
 allowClear
 />
 <Button icon={<ReloadOutlined />} onClick={() => window.location.reload()}>
 刷新
 </Button>
 </Space>
 </div>

 {/* 统计行：严重 + 高危 + 中危 + 低危 */}
 <Row gutter={[16, 16]} style={{marginBottom: 16}}>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="报告总数" value={data.length} prefix={<FileTextOutlined />} />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="严重漏洞"
 value={totals.critical}
 valueStyle={{color: totals.critical > 0 ? "#ef4444" : undefined}}
 prefix={<BugIcon />}
 />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic
 title="高危漏洞"
 value={totals.high}
 valueStyle={{color: totals.high > 0 ? "#f59e0b" : undefined}}
 prefix={<WarningOutlined />}
 />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="中危漏洞" value={totals.medium} valueStyle={{color: "#0284c7"}} />
 </Card>
 </Col>
 <Col span={6}>
 <Card size="small" bodyStyle={{padding: "12px 16px"}}>
 <Statistic title="低危漏洞" value={totals.low} valueStyle={{color: "#6b7280"}} />
 </Card>
 </Col>
 </Row>

 {/* 表格 */}
 <Card bodyStyle={{padding: 0}}>
 <Spin spinning={loading}>
 {filtered.length === 0 && !loading ? (
 <Empty description="暂无报告数据" style={{padding: 48}} />
 ) : (
 <Table
 dataSource={filtered}
 columns={columns}
 rowKey="id"
 pagination={{pageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 条`}}
 scroll={{x: 1400}}
 size="middle"
 />
 )}
 </Spin>
 </Card>
 </div>
 );
}
