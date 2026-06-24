import { useState, useEffect } from "react";
import {
  Card, Tag, Button, Typography, Space, Row, Col, Spin, Empty,
  Tabs, Table, Statistic, Descriptions, Divider, Progress, Alert, Collapse, Result,
} from "antd";
import ArrowLeftOutlined from "@ant-design/icons/es/icons/ArrowLeftOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import ShareAltOutlined from "@ant-design/icons/es/icons/ShareAltOutlined";
import PrinterOutlined from "@ant-design/icons/es/icons/PrinterOutlined";
import BugOutlined from "@ant-design/icons/es/icons/BugOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloudDownloadOutlined from "@ant-design/icons/es/icons/CloudDownloadOutlined";
import FilePdfOutlined from "@ant-design/icons/es/icons/FilePdfOutlined";
import FileWordOutlined from "@ant-design/icons/es/icons/FileWordOutlined";;
import { useParams, useNavigate } from "react-router-dom";
import request from "../api/request";

const { Title, Text } = Typography;

const MOCK_FINDINGS = [
  { id: "F-001", name: "Apache Struts2 RCE (CVE-2023-34359)", severity: "critical", category: "RCE", status: "confirmed", cvss: 9.8, host: "192.168.1.100:8080" },
  { id: "F-002", name: "MySQL 弱口令 (root/123456)", severity: "high", category: "弱口令", status: "confirmed", cvss: 8.5, host: "192.168.1.100:3306" },
  { id: "F-003", name: "Redis 未授权访问", severity: "high", category: "未授权", status: "confirmed", cvss: 8.0, host: "192.168.1.100:6379" },
  { id: "F-004", name: "OpenSSH 版本信息泄露", severity: "medium", category: "信息泄露", status: "confirmed", cvss: 5.3, host: "192.168.1.100:22" },
  { id: "F-005", name: "Nginx 版本号泄露", severity: "low", category: "信息泄露", status: "confirmed", cvss: 2.1, host: "192.168.1.100:80" },
  { id: "F-006", name: "TLS 1.0 协议支持", severity: "medium", category: "加密弱点", status: "suspected", cvss: 4.8, host: "192.168.1.100:443" },
];

const MOCK_REPORT = {
  id: "R-001", name: "192.168.1.100 渗透测试报告", task: "T-001",
  target: "192.168.1.100", type: "快速扫描", score: 72,
  summary: "本次渗透测试发现 12 个安全漏洞，其中高危 3 个、中危 5 个、低危 4 个。重点风险包括 Apache Struts2 RCE 漏洞（CVSS 9.8）、MySQL 弱口令（CVSS 8.5）和 Redis 未授权访问（CVSS 8.0）。",
  created_at: "2026-06-01 10:30",
};

const SEV_COLORS: Record<string, string> = {
  critical: "#7c3aed", high: "#dc2626", medium: "#d97706", low: "#0284c7", info: "#94a3b8",
};

export default function ReportPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const findingsColumns = [
    { title: "漏洞名称", dataIndex: "name", key: "name", render: (v: string) => <a>{v}</a> },
    { title: "严重程度", dataIndex: "severity", key: "severity", render: (v: string) => <Tag color={SEV_COLORS[v]}>{v.toUpperCase()}</Tag> },
    { title: "分类", dataIndex: "category", key: "category", render: (v: string) => <Tag>{v}</Tag> },
    { title: "状态", dataIndex: "status", key: "status", render: (v: string) => <Tag color={v === "confirmed" ? "red" : "orange"}>{v === "confirmed" ? "已确认" : "疑似"}</Tag> },
    { title: "CVSS", dataIndex: "cvss", key: "cvss", render: (v: number) => <Text strong style={{ color: v >= 7 ? "#dc2626" : v >= 4 ? "#d97706" : "#0284c7" }}>{v}</Text> },
    { title: "主机", dataIndex: "host", key: "host" },
  ];

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/reports")}>返回</Button>
        <Title level={4} style={{ margin: 0, color: "#0284c7" }}>{MOCK_REPORT.name}</Title>
        <div style={{ flex: 1 }} />
        <Button icon={<FilePdfOutlined />}>PDF</Button>
        <Button icon={<FileWordOutlined />}>Word</Button>
        <Button icon={<ShareAltOutlined />}>分享</Button>
      </div>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col span={6}><Card><Statistic title="安全评分" value={MOCK_REPORT.score} suffix="/100" valueStyle={{ color: MOCK_REPORT.score >= 80 ? "#16a34a" : MOCK_REPORT.score >= 60 ? "#d97706" : "#dc2626" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="高危漏洞" value={3} valueStyle={{ color: "#dc2626" }} prefix={<BugOutlined />} /></Card></Col>
        <Col span={6}><Card><Statistic title="中危漏洞" value={5} valueStyle={{ color: "#d97706" }} prefix={<WarningOutlined />} /></Card></Col>
        <Col span={6}><Card><Statistic title="低危漏洞" value={4} valueStyle={{ color: "#0284c7" }} prefix={<CheckCircleOutlined />} /></Card></Col>
      </Row>

      <Card>
        <Tabs defaultActiveKey="findings" items={[
          {
            key: "summary", label: "报告摘要",
            children: (
              <div>
                <Alert type="info" message="执行概述" description={MOCK_REPORT.summary} showIcon style={{ marginBottom: 16 }} />
                <Descriptions column={2} bordered size="small">
                  <Descriptions.Item label="目标资产">{MOCK_REPORT.target}</Descriptions.Item>
                  <Descriptions.Item label="扫描类型">{MOCK_REPORT.type}</Descriptions.Item>
                  <Descriptions.Item label="任务ID">{MOCK_REPORT.task}</Descriptions.Item>
                  <Descriptions.Item label="生成时间">{MOCK_REPORT.created_at}</Descriptions.Item>
                </Descriptions>
              </div>
            ),
          },
          {
            key: "findings", label: "漏洞列表",
            children: <Table dataSource={MOCK_FINDINGS} columns={findingsColumns} rowKey="id" pagination={false} />,
          },
          {
            key: "remediation", label: "修复建议",
            children: (
              <Collapse items={MOCK_FINDINGS.map((f) => ({
                key: f.id, label: <Space><Tag color={SEV_COLORS[f.severity]}>{f.severity.toUpperCase()}</Tag>{f.name}</Space>,
                children: (
                  <div>
                    <p><Text strong>漏洞描述：</Text>{f.name}</p>
                    <p><Text strong>影响主机：</Text>{f.host}</p>
                    <p><Text strong>修复建议：</Text>及时安装安全补丁，升级到最新版本，配置访问控制策略。</p>
                  </div>
                ),
              }))} />),
          },
          {
            key: "evidence", label: "证据附件",
            children: <Empty description="暂无证据附件" />,
          },
        ]} />
      </Card>
    </div>
  );
}
