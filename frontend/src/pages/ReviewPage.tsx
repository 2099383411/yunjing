import { useState } from "react";
import { Button, Card, Typography, Space, Tag, List, message, Spin, Empty } from "antd";
import request from "../api/request";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";

const { Text, Title, Paragraph } = Typography;

export default function ReviewPage() {
  const [taskId, setTaskId] = useState("");
  const [draft, setDraft] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [notes, setNotes] = useState("");

  const handleGenerate = async () => {
    if (!taskId.trim()) return;
    setLoading(true);
    try {
      const r = await request.post("/review/generate", { task_id: taskId.trim() });
      setDraft(r.data?.draft || r.data);
    } catch (e: any) {
      message.error(e?.response?.data?.message || "生成失败");
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async () => {
    if (!draft) return;
    setConfirming(true);
    try {
      await request.post("/review/confirm", {
        task_id: draft.task_id,
        notes,
        successes: draft.successes || [],
        failures: draft.failures || [],
      });
      message.success("复盘已确认，经验已回流");
      setDraft(null);
      setTaskId("");
      setNotes("");
    } catch (e: any) {
      message.error(e?.response?.data?.message || "确认失败");
    } finally {
      setConfirming(false);
    }
  };

  return (
    <div style={{ maxWidth: 700, margin: "0 auto", padding: 20 }}>
      <Title level={4} style={{ marginBottom: 20 }}>
        <FileTextOutlined style={{ marginRight: 8, color: "#0284c7" }} />
        渗透复盘
      </Title>

      <Card size="small" style={{ marginBottom: 16 }}>
        <Space>
          <Text strong style={{ fontSize: 12 }}>任务ID:</Text>
          <input
            value={taskId}
            onChange={(e) => setTaskId(e.target.value)}
            placeholder="输入扫描任务ID"
            style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #d9d9d9", width: 280, fontSize: 12 }}
          />
          <Button type="primary" size="small" loading={loading} onClick={handleGenerate} icon={<ThunderboltOutlined />}>
            生成复盘
          </Button>
        </Space>
      </Card>

      {draft && (
        <Card title={<Space><Text strong>复盘草稿</Text><Tag color={draft.status === "completed" ? "green" : "red"}>{draft.status}</Tag></Space>}>
          <Paragraph style={{ fontSize: 12 }}><b>目标:</b> {draft.target} | <b>类型:</b> {draft.scan_type}</Paragraph>

          {draft.successes?.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <Text strong style={{ color: "#16a34a", fontSize: 12 }}>
                <CheckCircleOutlined /> 成功经验 ({draft.successes.length})
              </Text>
              <List size="small" dataSource={draft.successes} renderItem={(s: any) => (
                <List.Item style={{ padding: "4px 0", fontSize: 11 }}>
                  <Text style={{ fontSize: 11 }}>[{s.severity}] {s.vuln}: {s.detail}</Text>
                </List.Item>
              )} />
            </div>
          )}

          {draft.failures?.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <Text strong style={{ color: "#dc2626", fontSize: 12 }}>
                <CloseCircleOutlined /> 失败教训 ({draft.failures.length})
              </Text>
              <List size="small" dataSource={draft.failures} renderItem={(f: any) => (
                <List.Item style={{ padding: "4px 0", fontSize: 11 }}>
                  <Text style={{ fontSize: 11, color: "#64748b" }}>{f.reason}</Text>
                </List.Item>
              )} />
            </div>
          )}

          {draft.knowledge_gaps?.length > 0 && (
            <div style={{ marginBottom: 12, padding: 8, background: "#fef3c7", borderRadius: 4 }}>
              <Text strong style={{ color: "#92400e", fontSize: 11 }}>📚 知识缺口: {draft.knowledge_gaps.join(", ")}</Text>
            </div>
          )}

          <div style={{ marginTop: 12 }}>
            <Text strong style={{ fontSize: 11, display: "block", marginBottom: 4 }}>复盘备注:</Text>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)}
              placeholder="补充你的分析..."
              style={{ width: "100%", minHeight: 60, padding: 8, borderRadius: 4, border: "1px solid #d9d9d9", fontSize: 11 }} />
          </div>

          <div style={{ marginTop: 12, textAlign: "right" }}>
            <Button type="primary" loading={confirming} onClick={handleConfirm} icon={<CheckCircleOutlined />}>
              确认复盘 — 回流经验库
            </Button>
          </div>
        </Card>
      )}

      {!draft && !loading && (
        <Empty description="输入任务ID，生成复盘草稿" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      )}
    </div>
  );
}
