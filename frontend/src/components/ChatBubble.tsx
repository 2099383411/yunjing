import { Avatar, Typography, Tag, Space, Spin } from "antd";
import UserOutlined from "@ant-design/icons/es/icons/UserOutlined";
import RobotOutlined from "@ant-design/icons/es/icons/RobotOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import LinkOutlined from "@ant-design/icons/es/icons/LinkOutlined";;
import LinkOutlined from "@ant-design/icons/es/icons/LinkOutlined"

const { Text } = Typography;

// Parse task info from assistant reply
function parseTaskInfo(content: string): { id?: string; status?: string; target?: string } | null {
  const idMatch = content.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  const statusMatch = content.match(/状态[：:]\s*([^\n]+)/);
  const targetMatch = content.match(/目标[：:]\s*`?([^`\n]+)`?/);
  if (idMatch) {
    return {
      id: idMatch[0],
      status: statusMatch?.[1]?.trim(),
      target: targetMatch?.[1]?.trim(),
    };
  }
  return null;
}

export default function ChatBubble({
  role,
  content,
  raw,
}: {
  role: "user" | "assistant";
  content: string;
  raw?: any;
}) {
  const isUser = role === "user";
  const taskInfo = !isUser ? parseTaskInfo(content) : null;

  return (
    <div
      style={{
        display: "flex",
        gap: 12,
        padding: "10px 0",
        justifyContent: isUser ? "flex-end" : "flex-start",
      }}
    >
      {/* Assistant avatar */}
      {!isUser && (
        <Avatar
          icon={<RobotOutlined />}
          style={{
            background: "linear-gradient(135deg, #3b82f6, #1d4ed8)",
            boxShadow: "0 0 12px rgba(0,229,255,0.3)",
            flexShrink: 0,
          }}
        />
      )}

      <div style={{ maxWidth: "78%" }}>
        {/* Bubble */}
        <div
          className={!isUser ? "glow-border" : ""}
          style={{
            padding: "12px 18px",
            borderRadius: 12,
            background: isUser
              ? "linear-gradient(135deg, #3b82f6, #2563eb)"
              : "rgba(19, 24, 55, 0.85)",
            color: isUser ? "#fff" : "#e2e8f0",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            lineHeight: 1.7,
            fontSize: 14,
            border: isUser ? "none" : "1px solid rgba(59, 130, 246, 0.1)",
            boxShadow: isUser
              ? "0 2px 8px rgba(59, 130, 246, 0.2)"
              : "0 2px 8px rgba(0,0,0,0.3)",
          }}
        >
          {content}
        </div>

        {/* Task status card (if detected) */}
        {taskInfo && (
          <div
            style={{
              marginTop: 8,
              padding: "10px 14px",
              borderRadius: 8,
              background: "rgba(59, 130, 246, 0.06)",
              border: "1px solid rgba(59, 130, 246, 0.12)",
              fontSize: 12,
            }}
          >
            <Space size={4} style={{ marginBottom: 4 }}>
              <ThunderboltOutlined style={{ color: "#3b82f6" }} />
              <Text style={{ color: "#94a3b8", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
                {taskInfo.id?.slice(0, 8)}...
              </Text>
            </Space>
            {taskInfo.target && (
              <div>
                <Text style={{ color: "#64748b", fontSize: 11 }}>目标: </Text>
                <Text style={{ color: "#e2e8f0", fontSize: 11 }}>{taskInfo.target}</Text>
              </div>
            )}
            {taskInfo.status && (
              <Space size={4}>
                <ClockCircleOutlined style={{ color: "#ffa500", fontSize: 11 }} />
                <Text style={{ color: "#ffa500", fontSize: 11 }}>{taskInfo.status}</Text>
              </Space>
            )}
          </div>
        )}
      </div>

      {/* User avatar */}
      {isUser && (
        <Avatar
          icon={<UserOutlined />}
          style={{
            background: "#1d4ed8",
            boxShadow: "0 0 8px rgba(124,58,237,0.3)",
            flexShrink: 0,
          }}
        />
      )}
    </div>
  );
}
