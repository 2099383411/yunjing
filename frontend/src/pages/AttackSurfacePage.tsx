// @ts-nocheck
import { useState, useEffect, useMemo } from "react";
import { Card, Typography, Row, Col, Spin, Empty, Tag, Table, Statistic, Space } from "antd";
import request from "../api/request";

const { Title } = Typography;

const SEV_COLORS = { critical: "#7c3aed", high: "#dc2626", medium: "#d97706", low: "#0284c7", info: "#94a3b8" };

interface AttackPath {
  id: string;
  source: string;
  target: string;
  type: string;
  severity: string;
  status: string;
  steps: number;
}

const AttackSurfacePage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [tasks, setTasks] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [sessions, setSessions] = useState<any[]>([]);

  useEffect(() => {
    (async () => {
      try {
        // Get latest scan tasks
<<<<<<< HEAD
        const taskRes = await request.get("/tasks", { params: { page: 1, page_size: 20 } });
=======
        const taskRes = await request.get("/tasks", { params: { offset: 0, limit: 20 } });
>>>>>>> server/master
        const items = taskRes?.data?.items || taskRes?.data || [];
        setTasks(Array.isArray(items) ? items : []);

        // Get all vulnerabilities across tasks
        const tasksArr = Array.isArray(items) ? items : [];
        const allVulns: any[] = [];
        for (const t of tasksArr.slice(0, 5)) {
          try {
            const vRes = await request.get(`/tasks/${t.id}/vulnerabilities`);
            const vData = vRes?.data;
            if (Array.isArray(vData)) allVulns.push(...vData.map(v => ({ ...v, task_id: t.id, target: t.target })));
          } catch {}
        }
        setVulns(allVulns);

        // Sessions from the latest task
        if (tasksArr.length > 0) {
          const latest = tasksArr[0];
          if (latest.result?.sessions) {
            setSessions(Array.isArray(latest.result.sessions) ? latest.result.sessions : []);
          }
        }
      } catch (e) {
        console.error("Failed to load attack surface:", e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const severityCount = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of vulns) {
      const s = (v.severity || v.risk_level || "info").toLowerCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [vulns]);

  const attackPaths: AttackPath[] = useMemo(() => {
    const paths: AttackPath[] = [];
    const grouped: Record<string, any> = {};
    for (const v of vulns) {
      const key = `${v.target || "?"}-${v.type || v.title || "unknown"}`;
      if (!grouped[key]) {
        grouped[key] = {
          id: `path-${Object.keys(grouped).length + 1}`,
          source: "外网",
          target: v.target || "?",
          type: v.type || v.title || "unknown",
          severity: (v.severity || v.risk_level || "info").toLowerCase(),
          status: "已发现",
          steps: 1,
        };
      }
    }
    for (const s of sessions) {
      const target = s.url || s.host || s.target || "?";
      const key = `session-${target}`;
      if (!grouped[key]) {
        grouped[key] = {
          id: `session-${Object.keys(grouped).length + 1}`,
          source: "已渗透",
          target: target,
          type: "session",
          severity: "high",
          status: "活跃",
          steps: 1,
        };
      }
    }
    return Object.values(grouped);
  }, [vulns, sessions]);

  const columns = [
    { title: "攻击路径", dataIndex: "id", key: "id", width: 100, render: (v: string) => <Tag color="blue">{v}</Tag> },
    { title: "入口", dataIndex: "source", key: "source", width: 80 },
    { title: "目标", dataIndex: "target", key: "target", width: 200, ellipsis: true },
    { title: "类型", dataIndex: "type", key: "type", width: 150 },
    { title: "风险", dataIndex: "severity", key: "severity", width: 80, render: (s: string) => <Tag color={SEV_COLORS[s] || "default"}>{s.toUpperCase()}</Tag> },
    { title: "状态", dataIndex: "status", key: "status", width: 80, render: (s: string) => <Tag color={s === "活跃" ? "red" : "orange"}>{s}</Tag> },
  ];

  if (loading) return <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}><Spin size="large" tip="加载攻击面数据..." /></div>;

  return (
    <div style={{ padding: 24 }}>
      <Title level={4} style={{ marginBottom: 24, color: "#0F172A" }}>攻击面总览</Title>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={6}><Card><Statistic title="目标数量" value={tasks.length} suffix="个" valueStyle={{ color: "#2563EB" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="漏洞总数" value={vulns.length} suffix="个" valueStyle={{ color: "#dc2626" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="活跃 Session" value={sessions.length} suffix="个" valueStyle={{ color: "#d97706" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="攻击路径" value={attackPaths.length} suffix="条" valueStyle={{ color: "#7c3aed" }} /></Card></Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        {Object.entries(severityCount).map(([sev, count]) => (
          <Col span={3} key={sev}>
            <Card size="small">
              <Statistic title={sev.toUpperCase()} value={count} valueStyle={{ color: SEV_COLORS[sev] || "#000" }} />
            </Card>
          </Col>
        ))}
      </Row>

      <Card title="攻击路径矩阵" style={{ boxShadow: "0 1px 3px rgba(0,0,0,0.08)" }}>
        {attackPaths.length === 0 ? (
          <Empty description="暂无攻击路径数据，请先执行渗透测试" />
        ) : (
          <Table dataSource={attackPaths} columns={columns} rowKey="id" pagination={false} size="small" />
        )}
      </Card>
    </div>
  );
};

export default AttackSurfacePage;
