// @ts-nocheck
import { useState, useEffect, useMemo } from "react";
import { Card, Typography, Row, Col, Spin, Empty, Tag, Table, Input, Select, Space, message } from "antd";
import request from "../api/request";

const { Title } = Typography;
const { Search } = Input;

const ExperienceBrowserPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<any>(null);
  const [experiences, setExperiences] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 20;

  useEffect(() => {
    (async () => {
      try {
        const statsRes = await request.post("/engine/experience/search", {
          query: "__stats__",
          limit: 1,
        }).catch(() => null);
        if (statsRes?.data) setStats(statsRes.data);

        const expRes = await request.post("/engine/experience/search", {
          query: "渗透测试 漏洞利用",
          limit: 20,
        });
        const items = expRes?.data?.results || expRes?.data?.experiences || [];
        setExperiences(Array.isArray(items) ? items : []);
      } catch (e) {
        console.error("Failed to load experiences:", e);
        message.error("加载经验库失败");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const searchExperiences = async (query: string) => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await request.post("/engine/experience/search", { query, limit: 20 });
      const items = res?.data?.results || res?.data?.experiences || [];
      setExperiences(Array.isArray(items) ? items : []);
    } catch (e) {
      console.error("Search failed:", e);
    } finally {
      setLoading(false);
    }
  };

  const filtered = useMemo(() => {
    let list = experiences;
    if (typeFilter !== "all") {
      list = list.filter(e => (e.target_type || e.type || "").toLowerCase() === typeFilter);
    }
    return list;
  }, [experiences, typeFilter]);

  const columns = [
    { title: "方法", dataIndex: "method", key: "method", width: 180, ellipsis: true },
    { title: "目标类型", dataIndex: "target_type", key: "target_type", width: 120, render: (v: string) => <Tag>{v || "-"}</Tag> },
    { title: "漏洞类型", dataIndex: "vuln_type", key: "vuln_type", width: 150, render: (v: string) => <Tag color="red">{v || "-"}</Tag> },
    { title: "命令", dataIndex: "command", key: "command", ellipsis: true, render: (v: string) => <code style={{ fontSize: 12, background: "#f1f5f9", padding: "2px 6px", borderRadius: 3 }}>{v?.slice(0, 80) || "-"}</code> },
    { title: "成功率", dataIndex: "success_rate", key: "success_rate", width: 80, render: (v: number) => v != null ? `${(v * 100).toFixed(0)}%` : "-" },
    { title: "使用次数", dataIndex: "usage_count", key: "usage_count", width: 80 },
  ];

  if (loading && experiences.length === 0) return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
      <Spin size="large" tip="加载经验知识库..." />
    </div>
  );

  return (
    <div style={{ padding: 24 }}>
      <Title level={4} style={{ marginBottom: 24, color: "#0F172A" }}>经验知识库</Title>

      {stats && (
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col span={6}><Card size="small"><div style={{ textAlign: "center" }}><div style={{ fontSize: 28, fontWeight: 700, color: "#2563EB" }}>{stats.total_experiences || stats.total || 0}</div><div style={{ fontSize: 12, color: "#64748b" }}>总经验数</div></div></Card></Col>
          <Col span={6}><Card size="small"><div style={{ textAlign: "center" }}><div style={{ fontSize: 28, fontWeight: 700, color: "#16a34a" }}>{stats.methods_count || Object.keys(stats.by_method || {}).length || 0}</div><div style={{ fontSize: 12, color: "#64748b" }}>方法类型</div></div></Card></Col>
          <Col span={6}><Card size="small"><div style={{ textAlign: "center" }}><div style={{ fontSize: 28, fontWeight: 700, color: "#dc2626" }}>{stats.vuln_types_count || Object.keys(stats.by_vuln_type || {}).length || 0}</div><div style={{ fontSize: 12, color: "#64748b" }}>漏洞类型</div></div></Card></Col>
          <Col span={6}><Card size="small"><div style={{ textAlign: "center" }}><div style={{ fontSize: 28, fontWeight: 700, color: "#d97706" }}>{stats.target_types_count || Object.keys(stats.by_target_type || {}).length || 0}</div><div style={{ fontSize: 12, color: "#64748b" }}>目标类型</div></div></Card></Col>
        </Row>
      )}

      <Card style={{ marginBottom: 16, boxShadow: "0 1px 3px rgba(0,0,0,0.08)" }}>
        <Space style={{ width: "100%" }}>
          <Search placeholder="搜索经验... SQL注入、SSH爆破、文件上传..." allowClear enterButton="搜索" onSearch={searchExperiences} style={{ width: 400 }} />
          <Select value={typeFilter} onChange={setTypeFilter} style={{ width: 150 }}>
            <Select.Option value="all">全类型</Select.Option>
            <Select.Option value="web">Web</Select.Option>
            <Select.Option value="network">网络</Select.Option>
            <Select.Option value="host">主机</Select.Option>
            <Select.Option value="ad">AD域</Select.Option>
            <Select.Option value="cloud">云服务</Select.Option>
          </Select>
        </Space>
      </Card>

      <Card title={`经验列表 (${filtered.length})`} style={{ boxShadow: "0 1px 3px rgba(0,0,0,0.08)" }}>
        {filtered.length === 0 ? (
          <Empty description="暂无经验数据，请先执行渗透测试" />
        ) : (
          <Table dataSource={filtered} columns={columns} rowKey={(r) => r.exp_id || r.id || Math.random().toString()} size="small" pagination={{ pageSize: PAGE_SIZE, current: page, onChange: setPage }} />
        )}
      </Card>
    </div>
  );
};

export default ExperienceBrowserPage;
