import { useState, useEffect } from "react";
import {
  Card, Row, Col, Statistic, Table, Tag, Button, Space, Spin, Alert, Empty, Typography
} from "antd";
import {
  SendOutlined, EyeOutlined, LinkOutlined, KeyOutlined,
  ThunderboltOutlined, PlusOutlined, ReloadOutlined
} from "@ant-design/icons/es/icons";

const { Title } = Typography;
const API_BASE = "/api/phishing";

interface CampaignStats {
  total_campaigns: number;
  total_sent: number;
  total_opened: number;
  total_clicked: number;
  total_submitted: number;
  open_rate: number;
  click_rate: number;
  submit_rate: number;
}

interface Campaign {
  id: number;
  name: string;
  status: string;
  created_date: string;
  launch_date: string;
  send_by_date: string;
  completed_date: string;
  template?: { name: string };
  smtp?: { name: string };
  groups?: { name: string }[];
  results?: { email: string; status: string; ip: string; reported: boolean }[];
  status_details?: { total: number; sent: number; opened: number; clicked: number; submitted_data: number; error: number };
}

export default function PhishingPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [stats, setStats] = useState<CampaignStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [campRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/campaigns`),
        fetch(`${API_BASE}/stats`),
      ]);
      if (!campRes.ok || !statsRes.ok) throw new Error("获取数据失败");
      const camps = await campRes.json();
      const st = await statsRes.json();
      setCampaigns(camps);
      setStats(st);
    } catch (e: any) {
      setError(e.message || "未知错误");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const columns = [
    {
      title: "活动名称",
      dataIndex: "name",
      key: "name",
      render: (name: string) => <strong>{name}</strong>,
    },
    {
      title: "状态",
      dataIndex: "status",
      key: "status",
      render: (s: string) => {
        const colors: Record<string, string> = {
          EmailSent: "blue", Clicked: "orange", SubmittedData: "red",
          Error: "red", Completed: "green", Queued: "default",
        };
        return <Tag color={colors[s] || "default"}>{s}</Tag>;
      },
    },
    {
      title: "发送数",
      key: "sent",
      render: (_: any, r: Campaign) => r.status_details?.total || 0,
    },
    {
      title: "已打开",
      key: "opened",
      render: (_: any, r: Campaign) => (
        <span>
          {r.status_details?.opened || 0}
          {r.status_details?.total ? (
            <span style={{ color: "#999", marginLeft: 4 }}>
              ({Math.round((r.status_details.opened / r.status_details.total) * 100)}%)
            </span>
          ) : null}
        </span>
      ),
    },
    {
      title: "已点击",
      key: "clicked",
      render: (_: any, r: Campaign) => (
        <span>
          {r.status_details?.clicked || 0}
          {r.status_details?.total ? (
            <span style={{ color: "#999", marginLeft: 4 }}>
              ({Math.round((r.status_details.clicked / r.status_details.total) * 100)}%)
            </span>
          ) : null}
        </span>
      ),
    },
    {
      title: "已提交",
      key: "submitted",
      render: (_: any, r: Campaign) => {
        const v = r.status_details?.submitted_data || 0;
        return v > 0 ? <span style={{ color: "#cf1322", fontWeight: "bold" }}>{v}</span> : v;
      },
    },
    {
      title: "邮件模板",
      key: "template",
      render: (_: any, r: Campaign) => r.template?.name || "-",
    },
    {
      title: "发信配置",
      key: "smtp",
      render: (_: any, r: Campaign) => r.smtp?.name || "-",
    },
    {
      title: "创建时间",
      dataIndex: "created_date",
      key: "created_date",
      render: (d: string) => d ? new Date(d).toLocaleString("zh-CN") : "-",
    },
  ];

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
        <Spin size="large" tip="加载中..." />
      </div>
    );
  }

  return (
    <div style={{ padding: 24 }}>
      {/* 顶部操作栏 */}
      <Row justify="space-between" align="middle" style={{ marginBottom: 24 }}>
        <Col>
          <Title level={4} style={{ margin: 0 }}>
            <ThunderboltOutlined style={{ marginRight: 8 }} />
            社工钓鱼平台
          </Title>
        </Col>
        <Col>
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchData}>刷新</Button>
            <Button
              type="primary"
              icon={<LinkOutlined />}
              onClick={() => window.open("https://192.168.1.180:3333", "_blank")}
            >
              跳转社工钓鱼平台
            </Button>
          </Space>
        </Col>
      </Row>

      {error && <Alert type="error" message={error} banner style={{ marginBottom: 16 }} />}

      {/* 数据统计卡片 */}
      {stats && (
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={12} sm={6}>
            <Card><Statistic title="钓鱼活动" value={stats.total_campaigns} prefix={<ThunderboltOutlined />} /></Card>
          </Col>
          <Col xs={12} sm={6}>
            <Card><Statistic title="已发送邮件" value={stats.total_sent} prefix={<SendOutlined />} /></Card>
          </Col>
          <Col xs={12} sm={6}>
            <Card>
              <Statistic
                title="打开率"
                value={stats.open_rate}
                precision={1}
                suffix="%"
                prefix={<EyeOutlined />}
                valueStyle={{ color: stats.open_rate > 30 ? "#cf1322" : "#3f8600" }}
              />
            </Card>
          </Col>
          <Col xs={12} sm={6}>
            <Card>
              <Statistic
                title="提交率"
                value={stats.submit_rate}
                precision={1}
                suffix="%"
                prefix={<KeyOutlined />}
                valueStyle={{ color: stats.submit_rate > 10 ? "#cf1322" : "#3f8600" }}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* 活动列表 */}
      <Card title="钓鱼活动列表" style={{ borderRadius: 8 }}>
        {campaigns.length === 0 ? (
          <Empty description="暂无钓鱼活动，请跳转社工钓鱼平台创建" />
        ) : (
          <Table
            dataSource={campaigns}
            columns={columns}
            rowKey="id"
            pagination={{ pageSize: 10 }}
            scroll={{ x: 1200 }}
          />
        )}
      </Card>
    </div>
  );
}
