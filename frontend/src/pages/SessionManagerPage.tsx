// @ts-nocheck
import { useState, useEffect, useMemo } from "react";
import { Card, Typography, Row, Col, Spin, Empty, Tag, Table, Space, Button, Modal, Descriptions, message, Statistic } from "antd";
import request from "../api/request";

const { Title, Text } = Typography;

const SESSION_TYPE_COLORS: Record<string, string> = {
  ssh: "blue",
  webshell: "orange",
  php_webshell: "orange",
  meterpreter: "purple",
  shell: "cyan",
  reverse_shell: "cyan",
  bind_shell: "geekblue",
};

const SessionManagerPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedSession, setSelectedSession] = useState<any>(null);
  const [detailVisible, setDetailVisible] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        // Try to fetch sessions from the backend
        const res = await request.get("/engine/sessions/list", { params: { page: 1, page_size: 100 } }).catch(() => null);
        if (res?.data?.sessions) {
          setSessions(Array.isArray(res.data.sessions) ? res.data.sessions : []);
        } else {
          // Fall back to extracting from latest task
<<<<<<< HEAD
          const taskRes = await request.get("/tasks", { params: { page: 1, page_size: 5 } });
=======
          const taskRes = await request.get("/tasks", { params: { offset: 0, limit: 5 } });
>>>>>>> server/master
          const tasks = taskRes?.data?.items || taskRes?.data || [];
          const tasksArr = Array.isArray(tasks) ? tasks : [];
          const allSessions: any[] = [];
          for (const t of tasksArr) {
            const result = typeof t.result === "string" ? JSON.parse(t.result) : (t.result || {});
            const sess = result.sessions || result.sessions_created || [];
            if (Array.isArray(sess)) {
              for (const s of sess) {
                allSessions.push({ ...s, task_id: t.id, task_target: t.target });
              }
            }
          }
          setSessions(allSessions);
        }
      } catch (e) {
        console.error("Failed to load sessions:", e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const showDetail = (s: any) => {
    setSelectedSession(s);
    setDetailVisible(true);
  };

  const handleKillSession = async (sessionId: string) => {
    try {
      await request.post(`/engine/sessions/${sessionId}/kill`).catch(() => null);
      message.success("Session 已标记为失效");
      setSessions(prev => prev.map(s => s.session_id === sessionId ? { ...s, alive: false, status: "killed" } : s));
    } catch {
      message.error("操作失败");
    }
    setDetailVisible(false);
  };

  const columns = [
    { title: "ID", dataIndex: "session_id", key: "session_id", width: 90, render: (v: string) => <Text code style={{ fontSize: 11 }}>{v?.slice(0, 8)}</Text> },
    { title: "类型", dataIndex: "type", key: "type", width: 110, render: (v: string) => <Tag color={SESSION_TYPE_COLORS[v?.toLowerCase()] || "default"}>{v || "-"}</Tag> },
    { title: "目标", dataIndex: "url", key: "url", width: 250, ellipsis: true, render: (v: string, r: any) => v || r.host || r.target || r.task_target || "-" },
    { title: "用户", dataIndex: "username", key: "username", width: 120, render: (v: string) => v || r?.user || "-" },
    { title: "状态", dataIndex: "alive", key: "alive", width: 80, render: (v: boolean, r: any) => {
      const status = r.status || (v ? "alive" : "dead");
      return <Tag color={status === "alive" ? "green" : status === "killed" ? "red" : "default"}>{status}</Tag>;
    }},
    { title: "创建时间", dataIndex: "created_at", key: "created_at", width: 150, render: (v: string) => v ? v.slice(0, 19).replace("T", " ") : "-" },
    { title: "操作", key: "actions", width: 80, render: (_: any, r: any) => (
      <Button size="small" onClick={() => showDetail(r)}>详情</Button>
    )},
  ];

  if (loading) return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
      <Spin size="large" tip="加载 Session 数据..." />
    </div>
  );

  return (
    <div style={{ padding: 24 }}>
      <Title level={4} style={{ marginBottom: 24, color: "#0F172A" }}>Session 管理中心</Title>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col span={6}><Card><Statistic title="Session 总数" value={sessions.length} suffix="个" valueStyle={{ color: "#2563EB" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="活跃" value={sessions.filter(s => s.alive !== false && s.status !== "killed").length} suffix="个" valueStyle={{ color: "#16a34a" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="WebShell" value={sessions.filter(s => (s.type || "").toLowerCase().includes("web") || (s.type || "").toLowerCase().includes("php")).length} suffix="个" valueStyle={{ color: "#d97706" }} /></Card></Col>
        <Col span={6}><Card><Statistic title="SSH" value={sessions.filter(s => (s.type || "").toLowerCase() === "ssh").length} suffix="个" valueStyle={{ color: "#0284c7" }} /></Card></Col>
      </Row>

      <Card title="Session 列表" style={{ boxShadow: "0 1px 3px rgba(0,0,0,0.08)" }}>
        {sessions.length === 0 ? (
          <Empty description="暂无 Session 数据，请先执行渗透测试并创建利用会话" />
        ) : (
          <Table dataSource={sessions} columns={columns} rowKey={(r) => r.session_id || r.id || Math.random().toString()} size="small" pagination={{ pageSize: 20 }} />
        )}
      </Card>

      <Modal title="Session 详情" open={detailVisible} onCancel={() => setDetailVisible(false)} footer={
        selectedSession?.alive !== false ? [
          <Button key="close" onClick={() => setDetailVisible(false)}>关闭</Button>,
          <Button key="kill" danger onClick={() => handleKillSession(selectedSession?.session_id)}>结束 Session</Button>,
        ] : [
          <Button key="close" onClick={() => setDetailVisible(false)}>关闭</Button>,
        ]
      } width={600}>
        {selectedSession && (
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="Session ID" span={2}><Text code>{selectedSession.session_id}</Text></Descriptions.Item>
            <Descriptions.Item label="类型">{selectedSession.type || "-"}</Descriptions.Item>
            <Descriptions.Item label="状态">{(selectedSession.status || (selectedSession.alive ? "alive" : "dead"))}</Descriptions.Item>
            <Descriptions.Item label="目标 URL">{selectedSession.url || "-"}</Descriptions.Item>
            <Descriptions.Item label="主机">{selectedSession.host || "-"}</Descriptions.Item>
            <Descriptions.Item label="端口">{selectedSession.port || "-"}</Descriptions.Item>
            <Descriptions.Item label="用户名">{selectedSession.username || selectedSession.user || "-"}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{selectedSession.created_at ? selectedSession.created_at.slice(0, 19).replace("T", " ") : "-"}</Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
};

export default SessionManagerPage;
