import { useEffect, useRef, useState } from "react";
import {
  Typography, Spin
} from "antd";
import RobotOutlined from "@ant-design/icons/es/icons/RobotOutlined";
import AimOutlined from "@ant-design/icons/es/icons/AimOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import LoadingOutlined from "@ant-design/icons/es/icons/LoadingOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import ApiOutlined from "@ant-design/icons/es/icons/ApiOutlined";
import GlobalOutlined from "@ant-design/icons/es/icons/GlobalOutlined";
import BranchesOutlined from "@ant-design/icons/es/icons/BranchesOutlined";
import BugOutlined from "@ant-design/icons/es/icons/BugOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import FileSearchOutlined from "@ant-design/icons/es/icons/FileSearchOutlined";
<<<<<<< HEAD
import KeyOutlined from "@ant-design/icons/es/icons/KeyOutlined";;
=======
import KeyOutlined from "@ant-design/icons/es/icons/KeyOutlined"
>>>>>>> server/master

const { Text } = Typography;

export interface ChainEvent {
  id: string;
  type: "reasoning" | "tool_call" | "tool_result" | "phase" | "text";
  timestamp: string;
  content?: string;
  name?: string;
  arguments?: any;
  result?: any;
  status?: string;
  phase?: string;
  data?: any;
}

interface Props {
  events: ChainEvent[];
  scanning: boolean;
  target: string;
}

const PHASE_ICONS: Record<string, React.ReactNode> = {
  asset_discovery: <SearchOutlined />,
  port_scan: <BranchesOutlined />,
  service_detect: <FileSearchOutlined />,
  vuln_scan: <BugOutlined />,
  web_scan: <GlobalOutlined />,
  dir_scan: <ApiOutlined />,
  exploit: <ExperimentOutlined />,
  post_exploit: <KeyOutlined />,
  report: <SafetyOutlined />,
};

const PHASE_LABELS: Record<string, string> = {
  asset_discovery: "资产发现",
  port_scan: "端口扫描",
  service_detect: "服务识别",
  vuln_scan: "漏洞扫描",
  web_scan: "Web 扫描",
  dir_scan: "目录扫描",
  exploit: "漏洞利用验证",
  post_exploit: "后渗透分析",
  report: "报告生成",
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  pending: <span style={{ color: "#64748b", fontSize: 11 }}>&#9208;</span>,
  running: <LoadingOutlined style={{ color: "#3b82f6", fontSize: 11 }} />,
  done: <CheckCircleOutlined style={{ color: "#00ff88", fontSize: 11 }} />,
  completed: <CheckCircleOutlined style={{ color: "#00ff88", fontSize: 11 }} />,
  error: <CloseCircleOutlined style={{ color: "#ff3355", fontSize: 11 }} />,
  failed: <CloseCircleOutlined style={{ color: "#ff3355", fontSize: 11 }} />,
};

function fmtTime() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function EventCard({ event }: { event: ChainEvent }) {
  const [expanded, setExpanded] = useState(false);

  const iconMap: Record<string, React.ReactNode> = {
    reasoning: <RobotOutlined style={{ color: "#8b5cf6", fontSize: 13 }} />,
    tool_call: <AimOutlined style={{ color: "#f59e0b", fontSize: 13 }} />,
    tool_result: <CheckCircleOutlined style={{ color: "#22c55e", fontSize: 13 }} />,
    phase: <ThunderboltOutlined style={{ color: "#3b82f6", fontSize: 13 }} />,
    text: <span style={{ color: "#94a3b8", fontSize: 11 }}>T</span>,
  };

  const typeLabel: Record<string, string> = {
    reasoning: "思考",
    tool_call: "决策",
    tool_result: "执行结果",
    phase: "阶段",
    text: "消息",
  };

  const bgMap: Record<string, string> = {
    reasoning: "rgba(139,92,246,0.06)",
    tool_call: "rgba(245,158,11,0.06)",
    tool_result: "rgba(34,197,94,0.06)",
    phase: "rgba(59,130,246,0.06)",
    text: "transparent",
  };

  const borderMap: Record<string, string> = {
    reasoning: "1px solid rgba(139,92,246,0.15)",
    tool_call: "1px solid rgba(245,158,11,0.15)",
    tool_result: "1px solid rgba(34,197,94,0.15)",
    phase: "1px solid rgba(59,130,246,0.15)",
    text: "none",
  };

  const isPhaseExec = event.type === "phase" && event.name;
  const isToolCall = event.type === "tool_call" && event.name;
  const isToolResult = event.type === "tool_result";
  const isReasoning = event.type === "reasoning";
  const isEmpty = !event.content && !event.name && !event.result;

  if (isEmpty && event.type !== "phase") {
    return null;
  }

  return (
    <div
      style={{
        marginBottom: 6,
        padding: "8px 10px",
        borderRadius: 6,
        background: bgMap[event.type] || "rgba(30,41,59,0.3)",
        border: borderMap[event.type] || "1px solid rgba(51,65,85,0.3)",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 6 }}>
        <div style={{ marginTop: 1, flexShrink: 0 }}>
          {iconMap[event.type] || null}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 2 }}>
            <span style={{ color: "#64748b", fontSize: 10, fontWeight: 500, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              {typeLabel[event.type] || "事件"}
              {isPhaseExec && event.name && " \u00b7 " + (PHASE_LABELS[event.name || ""] || event.name)}
              {isToolCall && event.name && " \u00b7 " + event.name}
            </span>
            <span style={{ color: "#475569", fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }}>
              {event.timestamp}
            </span>
          </div>

          {isReasoning && event.content && (
            <Text style={{ color: "#a78bfa", fontSize: 12, fontStyle: "italic", display: "block", lineHeight: 1.6 }}>
              {event.content}
            </Text>
          )}

          {isPhaseExec && event.status && (
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              {PHASE_ICONS[event.name || ""] || <ThunderboltOutlined style={{ fontSize: 12, color: "#64748b" }} />}
              {STATUS_ICONS[event.status || ""] || null}
              <Text style={{ color: "#e2e8f0", fontSize: 12, fontWeight: 500 }}>
                {PHASE_LABELS[event.name || ""] || event.name}
              </Text>
              {event.status === "running" && <Spin size="small" style={{ marginLeft: 4 }} />}
            </div>
          )}

          {isToolCall && event.name && (
            <div>
              <Text style={{ color: "#fbbf24", fontSize: 12, display: "block", lineHeight: 1.5 }}>
                {"\uD83C\uDFAF"} 执行 {event.name}
                {event.arguments?.target && (
                  <span style={{ color: "#94a3b8" }}> {"\u2014\u2014"} 目标: {event.arguments.target}</span>
                )}
              </Text>
              {event.arguments && Object.keys(event.arguments).length > 0 && (
                <div
                  style={{
                    marginTop: 4, padding: "4px 8px", borderRadius: 4,
                    background: "rgba(0,0,0,0.2)", fontSize: 11,
                    color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace",
                    maxHeight: expanded ? "none" : 60, overflow: "hidden",
                    cursor: "pointer",
                  }}
                  onClick={() => setExpanded(!expanded)}
                >
                  {JSON.stringify(event.arguments, null, 2)}
                  {expanded ? <span style={{ color: "#64748b", display: "block" }}>收起</span> : <span style={{ color: "#64748b", display: "block" }}>点击展开</span>}
                </div>
              )}
            </div>
          )}

          {isToolResult && event.result && (
            <div>
              {typeof event.result === "string" ? (
                <Text style={{ color: "#86efac", fontSize: 11, display: "block", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5 }}>
                  {event.result}
                </Text>
              ) : (
                <div
                  style={{
                    marginTop: 4, padding: "4px 8px", borderRadius: 4,
                    background: "rgba(0,0,0,0.2)", fontSize: 11,
                    color: "#86efac", fontFamily: "'JetBrains Mono', monospace",
                    whiteSpace: "pre-wrap", wordBreak: "break-all",
                    maxHeight: expanded ? "none" : 100, overflow: "hidden",
                    cursor: "pointer",
                  }}
                  onClick={() => setExpanded(!expanded)}
                >
                  {JSON.stringify(event.result, null, 2)}
                  {!expanded && event.result && Object.keys(event.result).length > 0 && (
                    <span style={{ color: "#64748b", display: "block" }}>点击展开更多...</span>
                  )}
                </div>
              )}
            </div>
          )}

          {event.type === "phase" && event.data && (
            <div style={{ marginTop: 4, display: "flex", gap: 6, flexWrap: "wrap" }}>
              {event.data.ports != null && (
                <Text style={{ color: "#60a5fa", fontSize: 10, background: "rgba(96,165,250,0.1)", padding: "1px 6px", borderRadius: 3 }}>
                  {"\uD83D\uDCE1"} {event.data.ports} 端口
                </Text>
              )}
              {event.data.services != null && (
                <Text style={{ color: "#34d399", fontSize: 10, background: "rgba(52,211,153,0.1)", padding: "1px 6px", borderRadius: 3 }}>
                  {"\u2699"} {event.data.services} 服务
                </Text>
              )}
              {event.data.count != null && (
                <Text style={{ color: event.data.count > 0 ? "#fb923c" : "#94a3b8", fontSize: 10, background: event.data.count > 0 ? "rgba(251,146,60,0.1)" : "rgba(148,163,184,0.1)", padding: "1px 6px", borderRadius: 3 }}>
                  {"\uD83D\uDC1B"} {event.data.count} 漏洞
                </Text>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ChainOfThought({ events, scanning, target }: Props) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  return (
    <div
      style={{
        display: "flex", flexDirection: "column", height: "100%",
        padding: "12px 8px",
      }}
    >
      <div
        style={{
          padding: "0 4px 10px 4px",
          borderBottom: "1px solid rgba(51,65,85,0.5)",
          marginBottom: 10,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 2 }}>
          <BranchesOutlined style={{ color: "#8b5cf6", fontSize: 14 }} />
          <Text style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 600 }}>
            渗透测试执行链
          </Text>
          {scanning && (
            <Spin size="small" style={{ marginLeft: "auto" }} />
          )}
        </div>
        {target && (
          <Text style={{ color: "#64748b", fontSize: 11, display: "block", marginTop: 2 }}>
            目标: <span style={{ color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace" }}>{target}</span>
          </Text>
        )}
      </div>

      <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden" }}>
        {events.length === 0 && !scanning && (
          <div style={{ textAlign: "center", padding: "40px 16px" }}>
            <RobotOutlined style={{ fontSize: 32, color: "#334155", display: "block", marginBottom: 8 }} />
            <Text style={{ color: "#475569", fontSize: 12, display: "block", lineHeight: 1.8 }}>
              发送消息后，AI 智能体的<br />思考过程、决策和执行步骤<br />将实时显示在这里
            </Text>
          </div>
        )}

        {events.length === 0 && scanning && (
          <div style={{ textAlign: "center", padding: "30px 16px" }}>
            <Spin />
            <Text style={{ color: "#64748b", fontSize: 12, display: "block", marginTop: 8 }}>
              渗透测试进行中...
            </Text>
          </div>
        )}

        {events.map((event) => (
          <EventCard key={event.id} event={event} />
        ))}
        <div ref={endRef} />
      </div>

      {scanning && (
        <div
          style={{
            marginTop: 8, paddingTop: 8,
            borderTop: "1px solid rgba(51,65,85,0.3)",
            display: "flex", alignItems: "center", gap: 6,
          }}
        >
          <div
            style={{
              width: 6, height: 6, borderRadius: "50%",
              background: "#22c55e",
            }}
          />
          <Text style={{ color: "#22c55e", fontSize: 10 }}>
            {scanning ? "执行中..." : "就绪"}
          </Text>
        </div>
      )}
    </div>
  );
}
