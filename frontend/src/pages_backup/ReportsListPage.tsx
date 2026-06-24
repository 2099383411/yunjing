import { useState, useEffect } from "react";
import {
  Table, Card, Tag, Button, Input, Select, Typography, Space,
  Progress, Row, Col, Spin, Empty, Tooltip, message, Statistic,
  Dropdown, DatePicker,
} from "antd";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import EyeOutlined from "@ant-design/icons/es/icons/EyeOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import FilePdfOutlined from "@ant-design/icons/es/icons/FilePdfOutlined";
import FileWordOutlined from "@ant-design/icons/es/icons/FileWordOutlined";
import FileExcelOutlined from "@ant-design/icons/es/icons/FileExcelOutlined";;
import request from "../api/request";
import { useNavigate } from "react-router-dom";

const { Title, Text } = Typography;

const MOCK_REPORTS = [
  { id: "R-001", name: "192.168.1.100 渗透测试报告", task: "T-001", target: "192.168.1.100", type: "快速扫描", high: 3, medium: 5, low: 4, score: 72, status: "completed", created_at: "2026-06-01" },
  { id: "R-002", name: "example.com 全面安全评估", task: "T-002", target: "example.com", type: "全面扫描", high: 7, medium: 9, low: 8, score: 45, status: "completed", created_at: "2026-06-01" },
  { id: "R-003", name: "API安全检测报告", task: "T-004", target: "api.example.com", type: "API测试", high: 2, medium: 3, low: 6, score: 78, status: "completed", created_at: "2026-06-01" },
  { id: "R-004", name: "内网资产安全评估", task: "T-003", target: "10.0.0.0/24", type: "端口扫描", high: 0, medium: 2, low: 10, score: 88, status: "completed", created_at: "2026-05-31" },
  { id: "R-005", name: "弱口令检测报告", task: "T-005", target: "192.168.1.200", type: "弱口令检测", high: 5, medium: 2, low: 1, score: 55, status: "completed", created_at: "2026-05-31" },
  { id: "R-006", name: "VPN网关安全评估", task: "T-007", target: "vpn.company.com", type: "快速扫描", high: 1, medium: 4, low: 0, score: 82, status: "generating", created_at: "2026-06-01" },
];

const SCORE_COLOR = (s: number) => s >= 80 ? "#16a34a" : s >= 60 ? "#d97706" : "#dc2626";

export default function ReportsListPage() {
  const navigate = useNavigate();
  const [data, setData] = useState(MOCK_REPORTS);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    setLoading(true);
    request.get("/reports").then((res) => { if (res.data) setData(res.data.items || res.data); })
      .catch(() => setData(MOCK_REPORTS))
      .finally(() => setLoading(false));
  }, []);

  const filtered = data.filter((r) => !search || r.name.includes(search) || r.target.includes(search));

  const columns = [
    { title: "报告名称", dataIndex: "name", key: "name", render: (v: string, r: any) => <a onClick={() => navigate(`/reports/${r.id}`)}>{v}</a> },
    { title: "目标", dataIndex: "target", key: "target" },
    { title: "类型", dataIndex: "type", key: "type", render: (v: string) => <Tag color="blue">{v}</Tag> },
    { title: "漏洞分布", key: "vulns", render: (_: any, r: any) => <Space size={4}>{r.high > 0 && <Tag color="red">{r.high}高</Tag>}{r.medium > 0 && <Tag color="orange">{r.medium}中</Tag>}{r.low > 0 && <Tag color="blue">{r.low}低</Tag>}</Space> },
    { title: "评分", dataIndex: "score", key: "score", render: (v: number) => <Progress percent={v} size="small" strokeColor={SCORE_COLOR(v)} format={() => `${v}`} style={{ width: 80 }} /> },
    { title: "状态", dataIndex: "status", key: "status", render: (v: string) => <Tag color={v === "completed" ? "green" : "orange"}>{v === "completed" ? "已完成" : "生成中"}</Tag> },
    { title: "时间", dataIndex: "created_at", key: "created_at" },
    {
      title: "操作", key: "action",
      render: (_: any, r: any) => (
        <Space>
          <Tooltip title="预览"><Button size="small" icon={<EyeOutlined />} onClick={() => navigate(`/reports/${r.id}`)} /></Tooltip>
          <Dropdown menu={{ items: [
            { key: "pdf", icon: <FilePdfOutlined />, label: "PDF" },
            { key: "word", icon: <FileWordOutlined />, label: "Word" },
            { key: "excel", icon: <FileExcelOutlined />, label: "Excel" },
          ]}}>
            <Button size="small" icon={<DownloadOutlined />}>下载</Button>
          </Dropdown>
        </Space>
      ),
    },
  ];

  const totals = { high: data.reduce((s, r) => s + r.high, 0), medium: data.reduce((s, r) => s + r.medium, 0), low: data.reduce((s, r) => s + r.low, 0) };

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Title level={4} style={{ margin: 0, color: "#0284c7" }}>检测报告</Title>
        <Space>
          <Input placeholder="搜索报告..." prefix={<SearchOutlined />} style={{ width: 200 }} value={search} onChange={(e) => setSearch(e.target.value)} allowClear />
          <Button icon={<ReloadOutlined />} onClick={() => window.location.reload()}>刷新</Button>
        </Space>
      </div>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col span={6}><Card><Statistic title="报告总数" value={data.length} prefix={<FileTextOutlined />} /></Card></Col>
        <Col span={6}><Card><Statistic title="高危漏洞" value={totals.high} valueStyle={{ color: "#dc2626" }} prefix={<FileTextOutlined />} /></Card></Col>
        <Col span={6}><Card><Statistic title="中危漏洞" value={totals.medium} valueStyle={{ color: "#d97706" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="低危漏洞" value={totals.low} valueStyle={{ color: "#0284c7" }} /></Card></Col>
      </Row>
      <Card><Spin spinning={loading}><Table dataSource={filtered} columns={columns} rowKey="id" pagination={{ pageSize: 10 }} /></Spin></Card>
    </div>
  );
}
