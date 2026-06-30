import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Input, Button, Typography, Space, Card, Tag, Timeline, Badge,
  Spin, Progress, Tooltip, Empty, Dropdown, Modal, message as antMsg,
  List, Divider, Row, Col, Statistic, Descriptions, Select
} from "antd";
import request from "../api/request";

// ─── Icons ───
import SendOutlined from "@ant-design/icons/es/icons/SendOutlined";
import PlusOutlined from "@ant-design/icons/es/icons/PlusOutlined";
import DeleteOutlined from "@ant-design/icons/es/icons/DeleteOutlined";
import RobotOutlined from "@ant-design/icons/es/icons/RobotOutlined";
import UserOutlined from "@ant-design/icons/es/icons/UserOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import BranchesOutlined from "@ant-design/icons/es/icons/BranchesOutlined";
import HistoryOutlined from "@ant-design/icons/es/icons/HistoryOutlined";
import SyncOutlined from "@ant-design/icons/es/icons/SyncOutlined";
import AimOutlined from "@ant-design/icons/es/icons/AimOutlined";
import BugOutlined from "@ant-design/icons/es/icons/BugOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import EditOutlined from "@ant-design/icons/es/icons/EditOutlined";
import DownOutlined from "@ant-design/icons/es/icons/DownOutlined";

const { Text, Paragraph, Title } = Typography;
const { TextArea } = Input;

// ─── 专家角色定义 ───
const EXPERT_ROLES = [
  { emoji: "🛡️", name: "云鉴", desc: "安全顾问 · 知识问答/漏洞咨询", mode: "expert", color: "#0284c7" },
  { emoji: "🔍", name: "云证", desc: "漏洞验证师 · 漏洞复现/验证", mode: "verify", color: "#22c55e" },
  { emoji: "⚡", name: "云探", desc: "渗透测试师 · 自动化渗透", mode: "scanner", color: "#f97316" },
  { emoji: "💥", name: "云破", desc: "红队指挥官 · 全面攻击模拟", mode: "assault", color: "#ef4444" },
];

// ─── 渗透阶段定义 ───
const PHASES = [
  { key: "recon", label: "信息收集", icon: "\uD83D\uDD0D", color: "#3b82f6" },
  { key: "scan", label: "扫描检测", icon: "\uD83D\uDCE1", color: "#22c55e" },
  { key: "vuln", label: "漏洞分析", icon: "\uD83D\uDD2C", color: "#eab308" },
  { key: "exploit", label: "漏洞利用", icon: "\uD83D\uDCA5", color: "#ef4444" },
  { key: "post", label: "后渗透", icon: "\uD83C\uDFAF", color: "#a855f7" },
  { key: "report", label: "报告生成", icon: "\uD83D\uDCCB", color: "#06b6d4" },
];

// ─── 任务状态映射 ───
const STATUS_MAP = {
  PENDING: { color: "default" as const, text: "等待中" },
  RUNNING: { color: "processing" as const, text: "运行中" },
  COMPLETED: { color: "success" as const, text: "已完成" },
  FAILED: { color: "error" as const, text: "失败" },
  CANCELLED: { color: "warning" as const, text: "已取消" },
};

interface Message {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  created_at?: string;
}
interface Conversation {
  id: string; title: string; message_count: number; updated_at: string;
}
interface VulnItem {
  id: string; name: string; type: string; severity: string;
  url: string; description: string; evidence: string;
}
interface ExecStep {
  id: string; turn_id: number; phase: string; tool: string;
  llm_decision: string; result_summary: string;
  status: string; risk_level: string; created_at: string;
}

// ─── 建议接口 ───
interface Suggestion {
  tool_call_id: string;
  tool: string;
  params: Record<string, any>;
  reasoning: string;
  status: "pending" | "confirmed" | "rejected";
}

const LS_CONV_ID = "yunjing_chat_convId";
const LS_TASK_ID = "yunjing_chat_taskId";
const LS_EXPERT = "yunjing_chat_expert";

export default function ChatPage() {
  const navigate = useNavigate();

  // 会话
  const [convs, setConvs] = useState<Conversation[]>([]);
  const [convId, setConvId] = useState<string | null>(() => localStorage.getItem(LS_CONV_ID));
  const [messages, setMessages] = useState<Message[]>([]);
  const [convLoading, setConvLoading] = useState(false);

  // 输入
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [streamingContent, setStreamingContent] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // 专家选择
  const [currentExpert, setCurrentExpert] = useState<string>(() => {
    return localStorage.getItem(LS_EXPERT) || EXPERT_ROLES[0].mode;
  });

  // LLM 建议
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [modifyModalVisible, setModifyModalVisible] = useState(false);
  const [modifyTarget, setModifyTarget] = useState<Suggestion | null>(null);
  const [modifyParamsText, setModifyParamsText] = useState("");

  // 任务
  const [activeTask, setActiveTask] = useState<any>(null);
  const [vulns, setVulns] = useState<VulnItem[]>([]);
  const [steps, setSteps] = useState<ExecStep[]>([]);
  const wsRef = useRef<any>(null);
  const pollTimerRef = useRef<any>(null);
  const currentPhaseRef = useRef<string | null>(null);

  // 当前专家对象
  const currentExpertObj = EXPERT_ROLES.find((e) => e.mode === currentExpert) || EXPERT_ROLES[0];

  // ─── 切换专家 ───
  const handleExpertChange = (mode: string) => {
    setCurrentExpert(mode);
    localStorage.setItem(LS_EXPERT, mode);
  };

  // ─── 自动滚动 ───
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamingContent, suggestions]);

  // ─── 初始化 ───
  useEffect(() => { initPage(); return () => cleanup(); }, []);

  async function initPage() {
    await loadConvs();
    const cid = localStorage.getItem(LS_CONV_ID);
    if (cid) { setConvId(cid); await loadMessages(cid); }
    const tid = localStorage.getItem(LS_TASK_ID);
    if (tid) { await loadTaskState(tid); connectWs(tid); }
  }

  function cleanup() {
    if (wsRef.current) wsRef.current.close();
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);
  }

  // ─── 加载会话列表 ───
  async function loadConvs() {
    try { const r = await request.get("/chat/conversations"); setConvs(r.data || []); } catch {}
  }

  // ─── 新对话 ───
  async function createNewConv() {
    setSending(false); setStreamingContent(""); setMessages([]);
    setActiveTask(null); setVulns([]); setSteps([]); setSuggestions([]);
    currentPhaseRef.current = null;
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    localStorage.removeItem(LS_TASK_ID);
    try {
      const r = await request.post("/chat/conversations", { title: "新对话" });
      setConvId(r.data.id); localStorage.setItem(LS_CONV_ID, r.data.id);
      await loadConvs();
    } catch { antMsg.error("创建对话失败"); }
  }

  // ─── 切换对话 ───
  async function switchConv(id: string) {
    if (id === convId) return;
    setSending(false); setStreamingContent(""); setMessages([]);
    setActiveTask(null); setVulns([]); setSteps([]); setSuggestions([]);
    currentPhaseRef.current = null;
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    localStorage.removeItem(LS_TASK_ID);
    setConvId(id); localStorage.setItem(LS_CONV_ID, id);
    await loadMessages(id);
  }

  // ─── 删除对话 ───
  async function deleteConv(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    try {
      await request.delete("/chat/conversations/" + id);
      if (convId === id) { setConvId(null); localStorage.removeItem(LS_CONV_ID); setMessages([]); setActiveTask(null); setSuggestions([]); }
      await loadConvs(); antMsg.success("已删除");
    } catch { antMsg.error("删除失败"); }
  }

  // ─── 加载消息 ───
  async function loadMessages(cid: string) {
    setConvLoading(true);
    try { const r = await request.get("/chat/conversations/" + cid + "/messages"); setMessages(r.data || []); }
    catch { setMessages([]); }
    finally { setConvLoading(false); }
  }

  // ─── 静默重载消息（不显示loading，不覆盖streaming） ───
  async function reloadMessages(cid: string) {
    try { const r = await request.get("/chat/conversations/" + cid + "/messages"); const sm = r.data || []; if (sm.length > 0) setMessages(sm); } catch {}
  }

  // ─── 加载任务状态 ───
  async function loadTaskState(tid: string) {
    try {
      const r = await request.get("/tasks/" + tid);
      if (r.data?.id) {
        setActiveTask(r.data);
        if (r.data.status === "RUNNING" || r.data.status === "PENDING") startPolling(tid);
      }
    } catch {}
    try { const vr = await request.get("/tasks/" + tid + "/vulnerabilities"); setVulns(vr.data || []); } catch {}
    try { const sr = await request.get("/reasoning/chain/" + tid); setSteps(sr.data?.steps || []); } catch {}
  }

  function startPolling(tid: string) {
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    pollTimerRef.current = setInterval(async () => {
      try {
        const r = await request.get("/tasks/" + tid);
        if (r.data?.id) {
          setActiveTask((prev: any) => ({ ...prev, ...r.data }));
          if (["COMPLETED","FAILED","CANCELLED"].includes(r.data.status) && pollTimerRef.current) clearInterval(pollTimerRef.current);
        }
      } catch { if (pollTimerRef.current) clearInterval(pollTimerRef.current); }
    }, 3000);
  }

  // ─── WebSocket 实时进度 ───
  function connectWs(tid: string) {
    if (wsRef.current) wsRef.current.close();
    try {
      const protocol = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(protocol + "//" + location.host + "/api/ws/scan/" + tid);
      ws.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data);
          // 任务状态
          if (d.progress !== undefined) setActiveTask((p: any) => ({ ...p, progress: d.progress }));
          if (d.status) setActiveTask((p: any) => ({ ...p, status: d.status }));
          if (d.phase) currentPhaseRef.current = d.phase;
          
          // 执行流水：阶段完成 → 添加步骤
          if (d.type === "phase" && d.status === "done") {
            const detail = d.data?.data || {};
            const summary = Object.entries(detail).filter(([k,v]) => v).map(([k,v]) => `${k}=${v}`).join(" ") || "";
            setSteps((prev) => [...prev, {
              id: "phase-" + Date.now(),
              turn_id: prev.length + 1,
              phase: d.phase,
              tool: d.phase,
              llm_decision: d.phase,
              result_summary: summary,
              status: "done",
              risk_level: "info",
              created_at: new Date().toISOString(),
            } as ExecStep]);
          }
          // 执行流水：round_complete / completed → 最后步骤
          if (d.type === "round_complete" || d.type === "completed") {
            setSteps((prev) => [...prev, {
              id: "step-" + Date.now(),
              turn_id: prev.length + 1,
              phase: d.type === "round_complete" ? "round_complete" : "scan_complete",
              tool: d.type,
              llm_decision: d.type,
              result_summary: d.data?.findings ? `发现 ${d.data.findings} 个漏洞` : "完成",
              status: "done",
              risk_level: "info",
              created_at: new Date().toISOString(),
            } as ExecStep]);
          }
          // 执行流水：vuln_findings → 从 findings 解析漏洞
          if (d.type === "vuln_findings" && d.findings) {
            d.findings.forEach((f: any) => {
              setVulns((prev) => {
                if (prev.find((v: any) => v.id === f.id || v.name === f.name)) return prev;
                return [...prev, { id: f.id || f.name, name: f.name || "未知", severity: f.severity || "low", ...f }];
              });
            });
          }
          // 漏洞发现（兼容旧格式）
          if (d.vulnerability) {
            setVulns((prev) => {
              if (prev.find((v: any) => v.id === d.vulnerability.id)) return prev;
              return [...prev, d.vulnerability];
            });
          }
        } catch {}
      };
      ws.onerror = () => {};
      ws.onclose = () => {};
      wsRef.current = ws;
    } catch {}
  }

  // ─── 推测当前阶段 ───
  function inferCurrentPhase(): string | null {
    if (currentPhaseRef.current) return currentPhaseRef.current;
    if (steps.length === 0) return null;
    return steps[steps.length - 1].phase || null;
  }

  // ─── 发送建议响应 ───
  async function sendSuggestionResponse(type: string, toolCallId: string, params?: Record<string, any>) {
    const stored = localStorage.getItem("auth-storage");
    const token = stored ? JSON.parse(stored).state?.token : null;
    try {
      const resp = await fetch("/api/chat/suggestions/respond", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) },
        body: JSON.stringify({ type, tool_call_id: toolCallId, params }),
      });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      antMsg.success(data.message || "操作已发送");
      return data;
    } catch (err: any) {
      antMsg.error(err.message || "发送失败");
      return null;
    }
  }

  // ─── 确认建议 ───
  const confirmSuggestion = async (s: Suggestion) => {
    const result = await sendSuggestionResponse("confirm", s.tool_call_id);
    if (result) {
      setSuggestions((prev) => prev.map((sg) => sg.tool_call_id === s.tool_call_id ? { ...sg, status: "confirmed" as const } : sg));
    }
  };

  // ─── 否决建议 ───
  const rejectSuggestion = async (s: Suggestion) => {
    const result = await sendSuggestionResponse("reject", s.tool_call_id);
    if (result) {
      setSuggestions((prev) => prev.map((sg) => sg.tool_call_id === s.tool_call_id ? { ...sg, status: "rejected" as const } : sg));
    }
  };

  // ─── 打开修改弹窗 ───
  const openModifyModal = (s: Suggestion) => {
    setModifyTarget(s);
    setModifyParamsText(JSON.stringify(s.params, null, 2));
    setModifyModalVisible(true);
  };

  // ─── 提交修改 ───
  const submitModify = async () => {
    if (!modifyTarget) return;
    try {
      const parsedParams = JSON.parse(modifyParamsText);
      const result = await sendSuggestionResponse("modify", modifyTarget.tool_call_id, parsedParams);
      if (result) {
        setSuggestions((prev) => prev.map((sg) => sg.tool_call_id === modifyTarget.tool_call_id ? { ...sg, status: "confirmed" as const } : sg));
        setModifyModalVisible(false);
        setModifyTarget(null);
      }
    } catch {
      antMsg.error("参数格式错误，请输入有效的 JSON");
    }
  };

  // ─── 发送消息 (SSE流式) ───
  const handleSend = async () => {
    const text = input.trim();
    if (!text || sending) return;

    let cid = convId;
    if (!cid) {
      try {
        const r = await request.post("/chat/conversations", { title: text.slice(0, 50) });
        cid = r.data.id; setConvId(cid); localStorage.setItem(LS_CONV_ID, cid);
        await loadConvs();
      } catch { antMsg.error("创建对话失败"); return; }
    }

    setSending(true); setInput("");
    const um: Message = { id: "u-" + Date.now(), role: "user", content: text };
    setMessages((p) => [...p, um]);
    setStreamingContent("");

    try {
      const stored = localStorage.getItem("auth-storage");
      const token = stored ? JSON.parse(stored).state?.token : null;
      const resp = await fetch("/api/chat/conversations/" + cid + "/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) },
        body: JSON.stringify({ text, stream: true, mode: currentExpert }),
      });
      if (!resp.ok) throw new Error("HTTP " + resp.status);

      const reader = resp.body?.getReader();
      if (!reader) throw new Error("No reader");

      const decoder = new TextDecoder();
      let buf = "", full = "", done = false, hasToolCall = false;

      while (true) {
        const { done: rd, value } = await reader.read();
        if (rd) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() || "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const js = line.slice(6).trim();
          if (!js) continue;
          try {
            const chunk = JSON.parse(js);

            // ─── token 流 ───
            if (chunk.token !== undefined) { full += chunk.token; setStreamingContent(full); }

            // ─── LLM 建议 ───
            if (chunk.type === "suggestion" && chunk.tool_call_id) {
              const sug: Suggestion = {
                tool_call_id: chunk.tool_call_id,
                tool: chunk.tool || "",
                params: chunk.params || {},
                reasoning: chunk.reasoning || "",
                status: "pending",
              };
              setSuggestions((prev) => {
                const exists = prev.find((s) => s.tool_call_id === sug.tool_call_id);
                if (exists) return prev;
                return [...prev, sug];
              });
            }

            // ─── 工具调用 ───
            if (chunk.type === "tool_call" && chunk.tool_call?.function?.name === "start_scan") {
              hasToolCall = true;
              try {
                const args = typeof chunk.tool_call.function.arguments === "string"
                  ? JSON.parse(chunk.tool_call.function.arguments) : chunk.tool_call.function.arguments;
                if (args.target) {
                  setMessages((p) => [...p, { id: "start-" + Date.now(), role: "assistant", content: "🔧 正在对 **" + args.target + "** 启动全面安全检测..." }]);
                }
              } catch {}
            }
            if (chunk.type === "tool_result" && chunk.result?.task_id) {
              const tid = chunk.result.task_id;
              setActiveTask({ id: tid, target: chunk.result.target || "", status: "RUNNING", progress: 0 });
              localStorage.setItem(LS_TASK_ID, tid);
              connectWs(tid);
              loadTaskState(tid);
            }
          } catch {}
        }
      }

      // Always add assistant message from SSE content
      if (full || hasToolCall) {
        setMessages((p) => [...p, { id: "a-" + Date.now(), role: "assistant", content: full || "🔧 操作已执行" }]);
      }
      setStreamingContent("");
      await loadConvs();
    } catch (err: any) {
      antMsg.error(err.message || "发送失败");
    } finally { setSending(false); }
  };

  // ─── 阶段指示器 ───
  const renderPhaseIndicator = () => {
    const phase = inferCurrentPhase();
    const ci = PHASES.findIndex((p) => p.key === phase);
    return (
      <div style={{ display: "flex", gap: 4, alignItems: "center", padding: "6px 0" }}>
        {PHASES.map((p, i) => {
          const active = i === ci, done = ci !== -1 && i < ci;
          return (
            <Tooltip key={p.key} title={p.label}>
              <div style={{
                width: 24, height: 24, borderRadius: 12, display: "flex",
                alignItems: "center", justifyContent: "center", fontSize: 11,
                background: done ? p.color : active ? p.color + "20" : "#f1f5f9",
                border: "2px solid " + (done || active ? p.color : "#e2e8f0"),
                transition: "all 0.3s", cursor: "pointer",
              }}>
                {done ? "\u2713" : active ? <SyncOutlined spin style={{ fontSize: 9 }} /> : p.icon}
              </div>
            </Tooltip>
          );
        })}
      </div>
    );
  };

  // ─── 漏洞渲染 ───
  const renderVulns = () => {
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...vulns].sort((a, b) => (order[a.severity] ?? 99) - (order[b.severity] ?? 99));
    if (!sorted.length) return <div style={{ padding: 16, textAlign: "center", color: "#94a3b8", fontSize: 12 }}>暂无漏洞</div>;
    return (
      <div>
        {sorted.slice(0, 20).map((v) => (
          <div key={v.id} style={{ padding: "6px 8px", marginBottom: 4, borderRadius: 4, background: "#f8fafc", border: "1px solid #e2e8f0", fontSize: 11 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <Text strong style={{ fontSize: 11 }}>{v.name}</Text>
              <Tag color={v.severity === "critical" ? "red" : v.severity === "high" ? "orange" : v.severity === "medium" ? "gold" : "green"} style={{ fontSize: 9, margin: 0 }}>{v.severity}</Tag>
            </div>
            <Text style={{ fontSize: 10, color: "#64748b" }}>{(v.url || v.description || "").slice(0, 80)}</Text>
          </div>
        ))}
      </div>
    );
  };

  // ─── 步骤时间线 ───
  const renderSteps = () => {
    if (!steps.length) return <div style={{ padding: 12, textAlign: "center", color: "#94a3b8", fontSize: 12 }}>等待执行...</div>;
    return (
      <Timeline items={steps.slice(-15).map((s) => ({
        color: s.status === "success" ? "green" : s.status === "failed" ? "red" : s.status === "running" ? "blue" : "gray",
        children: <div style={{ fontSize: 10 }}><Text strong style={{ fontSize: 10 }}>{s.llm_decision || s.tool || s.phase}</Text>{s.result_summary ? <Text style={{ fontSize: 9, color: "#64748b", display: "block" }}>{s.result_summary.slice(0, 80)}</Text> : null}</div>,
      }))} />
    );
  };

  // ─── 建议卡片渲染 ───
  const renderSuggestionCard = (s: Suggestion) => {
    const expert = EXPERT_ROLES.find((e) => e.mode === currentExpert) || EXPERT_ROLES[0];
    const isPending = s.status === "pending";
    return (
      <div key={s.tool_call_id} style={{
        marginTop: 8,
        padding: "10px 14px",
        borderRadius: 8,
        background: "rgba(255, 248, 225, 0.6)",
        border: "1px solid #fde68a",
        fontSize: 12,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
          <Tag color="orange" style={{ fontSize: 9, margin: 0 }}>💡 建议</Tag>
          <Text code style={{ fontSize: 10 }}>{s.tool}</Text>
        </div>
        {s.reasoning && (
          <Text style={{ fontSize: 11, color: "#64748b", display: "block", marginBottom: 6 }}>
            {s.reasoning}
          </Text>
        )}
        <div style={{ background: "#f1f5f9", borderRadius: 4, padding: "4px 8px", marginBottom: 8, fontSize: 10, fontFamily: "monospace", whiteSpace: "pre-wrap", color: "#475569" }}>
          {JSON.stringify(s.params, null, 2)}
        </div>
        {isPending ? (
          <Space size={4}>
            <Button size="small" type="primary" icon={<CheckCircleOutlined />} onClick={() => confirmSuggestion(s)}
              style={{ fontSize: 10, height: 24, background: "#22c55e", borderColor: "#22c55e" }}>
              确认
            </Button>
            <Button size="small" danger icon={<CloseCircleOutlined />} onClick={() => rejectSuggestion(s)}
              style={{ fontSize: 10, height: 24 }}>
              否决
            </Button>
            <Button size="small" icon={<EditOutlined />} onClick={() => openModifyModal(s)}
              style={{ fontSize: 10, height: 24 }}>
              修改
            </Button>
          </Space>
        ) : (
          <Tag color={s.status === "confirmed" ? "success" : "error"} style={{ fontSize: 9, margin: 0 }}>
            {s.status === "confirmed" ? "✓ 已确认" : "✗ 已否决"}
          </Tag>
        )}
      </div>
    );
  };

  // ─── 消息气泡 ───
  const renderMessage = (msg: Message, streaming = false) => {
    const isUser = msg.role === "user";
    return (
      <div key={msg.id} style={{ display: "flex", justifyContent: isUser ? "flex-end" : "flex-start", marginBottom: 10 }}>
        <div style={{
          maxWidth: "78%", padding: "8px 12px", borderRadius: 10,
          background: isUser ? "#0284c7" : "#fff", color: isUser ? "#fff" : "#1e293b",
          border: isUser ? "none" : "1px solid #e2e8f0",
          boxShadow: isUser ? "0 2px 6px rgba(2,132,199,0.15)" : "none",
          wordBreak: "break-word",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 2 }}>
            {isUser ? <UserOutlined style={{ fontSize: 10, color: "rgba(255,255,255,0.7)" }} /> : <RobotOutlined style={{ fontSize: 10, color: "#0284c7" }} />}
            <Text style={{ fontSize: 9, fontWeight: 600, color: isUser ? "rgba(255,255,255,0.7)" : "#94a3b8" }}>{isUser ? "您" : currentExpertObj.emoji + " " + currentExpertObj.name}</Text>
          </div>
          <Paragraph style={{ margin: 0, color: "inherit", whiteSpace: "pre-wrap", fontSize: 12, lineHeight: 1.5 }}>{msg.content}</Paragraph>
        </div>
      </div>
    );
  };

  // ─── 渲染 ───
  const phase = inferCurrentPhase();
  return (
    <div style={{ display: "flex", height: "calc(100vh - 56px - 48px)", gap: 10, padding: 0 }}>
      
      {/* ─── 左侧：对话区 ─── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "#fff", borderRadius: 8, border: "1px solid #e2e8f0", overflow: "hidden", minWidth: 0 }}>
        
        {/* 头部 - 专家选择器 */}
        <div style={{
          padding: "8px 14px", borderBottom: "1px solid #e2e8f0",
          display: "flex", justifyContent: "space-between", alignItems: "center",
          flexShrink: 0, background: `linear-gradient(135deg, ${currentExpertObj.color} 0%, ${currentExpertObj.color}dd 100%)`,
        }}>
          <Space>
            <Dropdown
              menu={{
                items: EXPERT_ROLES.map((role) => ({
                  key: role.mode,
                  label: (
                    <div
                      onClick={() => handleExpertChange(role.mode)}
                      style={{
                        display: "flex", alignItems: "center", gap: 8, padding: "4px 0",
                        opacity: role.mode === currentExpert ? 1 : 0.7,
                      }}
                    >
                      <span style={{ fontSize: 18 }}>{role.emoji}</span>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: role.mode === currentExpert ? 600 : 400, color: "#1e293b" }}>
                          {role.name}
                          {role.mode === currentExpert && (
                            <Tag style={{ fontSize: 8, marginLeft: 6, padding: "0 4px" }} color="blue">当前</Tag>
                          )}
                        </div>
                        <div style={{ fontSize: 10, color: "#64748b" }}>{role.desc}</div>
                      </div>
                    </div>
                  ),
                })),
                style: { minWidth: 220 },
              }}
              trigger={["click"]}
            >
              <div style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 6, userSelect: "none" }}>
                <span style={{ fontSize: 20 }}>{currentExpertObj.emoji}</span>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <Text strong style={{ fontSize: 14, color: "#fff" }}>{currentExpertObj.name}</Text>
                    <DownOutlined style={{ fontSize: 9, color: "rgba(255,255,255,0.7)" }} />
                  </div>
                  <Text style={{ fontSize: 10, color: "rgba(255,255,255,0.75)", display: "block", lineHeight: 1.2 }}>{currentExpertObj.desc}</Text>
                </div>
              </div>
            </Dropdown>
            {activeTask?.status === "RUNNING" && <Badge status="processing" color="#fff" />}
          </Space>
          <Space size={4}>
            <Dropdown menu={{ items: convs.map((c) => ({ key: c.id, label: <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", maxWidth: 180 }}><Text ellipsis style={{ fontSize: 11, maxWidth: 140 }}>{c.title}</Text><Button type="text" size="small" icon={<DeleteOutlined style={{ fontSize: 9 }} />} onClick={(e) => deleteConv(c.id, e)} style={{ color: "#94a3b8" }} /></div>, onClick: () => switchConv(c.id) })), style: { maxHeight: 280, overflow: "auto" } }} trigger={["click"]}>
              <Button size="small" icon={<HistoryOutlined />} style={{ fontSize: 11 }}>历史</Button>
            </Dropdown>
            <Button size="small" type="primary" icon={<PlusOutlined />} onClick={createNewConv} style={{ fontSize: 11 }}>新对话</Button>
          </Space>
        </div>

        {/* 消息区 */}
        <div style={{ flex: 1, overflow: "auto", padding: "12px 16px", background: "#f8fafc" }}>
          {convLoading ? <div style={{ textAlign: "center", paddingTop: 40 }}><Spin /></div> : messages.length === 0 && !streamingContent ? (
            <div style={{ textAlign: "center", padding: "40px 20px" }}>
              <span style={{ fontSize: 48 }}>{currentExpertObj.emoji}</span>
              <Title level={4} style={{ color: "#1e293b", marginBottom: 8, fontWeight: 600 }}>
                {currentExpertObj.name} AI 渗透助手
              </Title>
              <Text style={{ fontSize: 12, color: "#64748b", display: "block", marginBottom: 20 }}>
                {currentExpertObj.desc} — 输入目标，AI 自动完成渗透测试全流程
              </Text>
              {/* 零基础快速入口 */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: 340, margin: "0 auto" }}>
                <div style={{ fontSize: 10, color: "#94a3b8", marginBottom: 4, textAlign: "left" }}>🚀 快速开始</div>
                <Button block size="middle" type="primary" icon={<ThunderboltOutlined />}
                  onClick={() => { setInput("全面扫描 192.168.1.180"); setTimeout(() => handleSend(), 150); }}
                  style={{ borderRadius: 8, height: 40, fontSize: 13 }}>
                  全面扫描 (默认目标)
                </Button>
                <Button block size="middle" icon={<AimOutlined />}
                  onClick={() => { setInput("快速检测 DVWA 靶场"); setTimeout(() => handleSend(), 150); }}
                  style={{ borderRadius: 8, height: 40, fontSize: 13 }}>
                  DVWA 靶场检测
                </Button>
                <Button block size="middle" icon={<BugOutlined />}
                  onClick={() => { setInput("扫描 192.168.1.180 的 Web 服务"); setTimeout(() => handleSend(), 150); }}
                  style={{ borderRadius: 8, height: 40, fontSize: 13 }}>
                  Web 专项扫描
                </Button>
                <div style={{ fontSize: 10, color: "#cbd5e1", marginTop: 8, textAlign: "center" }}>
                  不懂渗透？点上面按钮就行，AI 自动完成
                </div>
              </div>
            </div>
          ) : <>
            {messages.map((m) => renderMessage(m))}
            {streamingContent ? renderMessage({ id: "st", role: "assistant", content: streamingContent }, true) : null}
            {/* 建议卡片 */}
            {suggestions.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                {suggestions.map((s) => renderSuggestionCard(s))}
              </div>
            )}
          </>}
          <div ref={messagesEndRef} />
        </div>

        {/* 输入区 */}
        <div style={{ padding: "8px 14px", borderTop: "1px solid #e2e8f0", background: "#fff", flexShrink: 0 }}>
          <div style={{ display: "flex", gap: 6 }}>
            <TextArea value={input} onChange={(e) => setInput(e.target.value)} placeholder="输入目标资产（域名 / IP / URL），或直接提问..." autoSize={{ minRows: 1, maxRows: 3 }}
              onPressEnter={(e) => { if (!e.shiftKey) { e.preventDefault(); handleSend(); } }}
              style={{ borderRadius: 6, fontSize: 12 }} disabled={sending} />
            <Button type="primary" icon={<SendOutlined />} onClick={handleSend} loading={sending} style={{ borderRadius: 6, padding: "0 14px" }}>发送</Button>
          </div>
          <Text style={{ fontSize: 9, color: "#cbd5e1", marginTop: 2, display: "block" }}>Enter 发送 · Shift+Enter 换行</Text>
        </div>
      </div>

      {/* ─── 右侧：渗透详情面板 ─── */}
      <div style={{ width: 350, flexShrink: 0, display: "flex", flexDirection: "column", gap: 8, overflow: "auto" }}>

        {/* 任务状态 */}
        <Card size="small" title={<Space><ThunderboltOutlined style={{ color: "#0284c7" }} /><Text strong style={{ fontSize: 11 }}>攻击进度</Text></Space>} style={{ borderRadius: 6, border: "1px solid #e2e8f0" }}>
          {activeTask ? (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <Text style={{ fontSize: 10, fontFamily: "monospace", color: "#64748b" }}>{activeTask.target || String(activeTask.id || "").slice(0, 16)}</Text>
                <Tag color={STATUS_MAP[activeTask.status]?.color || "default"} style={{ fontSize: 9, margin: 0 }}>{STATUS_MAP[activeTask.status]?.text || activeTask.status}</Tag>
              </div>
              <Progress percent={activeTask.progress || 0} size="small" strokeColor="#0284c7" format={(p) => p + "%"} />
              {renderPhaseIndicator()}
              <Row gutter={6} style={{ marginTop: 6 }}>
                <Col span={12}><Statistic title={<Text style={{ fontSize: 9 }}>漏洞发现</Text>} value={vulns.length} valueStyle={{ fontSize: 16, color: vulns.length > 0 ? "#ef4444" : "#94a3b8" }} /></Col>
                <Col span={12}><Statistic title={<Text style={{ fontSize: 9 }}>执行步骤</Text>} value={steps.length} valueStyle={{ fontSize: 16, color: "#0284c7" }} /></Col>
              </Row>
            </div>
          ) : <Empty description={<Text style={{ fontSize: 10, color: "#94a3b8" }}>暂无任务</Text>} image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ margin: "8px 0" }} />}
        </Card>

        {/* 漏洞发现 */}
        <Card size="small" title={<Space><BugOutlined style={{ color: vulns.length > 0 ? "#ef4444" : "#94a3b8" }} /><Text strong style={{ fontSize: 11 }}>漏洞发现</Text>{vulns.length > 0 && <Tag color="red" style={{ fontSize: 9 }}>{vulns.length}</Tag>}</Space>}
          style={{ borderRadius: 6, border: "1px solid #e2e8f0", maxHeight: 250, overflow: "auto" }}>
          {renderVulns()}
        </Card>

        {/* 执行步骤 */}
        <Card size="small" title={<Space><BranchesOutlined style={{ color: "#0284c7" }} /><Text strong style={{ fontSize: 11 }}>执行流水</Text></Space>}
          style={{ flex: 1, borderRadius: 6, border: "1px solid #e2e8f0", overflow: "auto" }}>
          {renderSteps()}
        </Card>

        {/* 快速操作 */}
        <Space style={{ justifyContent: "center" }}>
          <Button size="small" icon={<SettingOutlined />} onClick={() => navigate("/settings")} style={{ fontSize: 11 }}>设置</Button>
          <Button size="small" icon={<FileTextOutlined />} onClick={() => navigate("/reports")} style={{ fontSize: 11 }}>报告</Button>
        </Space>
      </div>

      {/* 修改参数弹窗 */}
      <Modal
        title="✏ 修改建议参数"
        open={modifyModalVisible}
        onOk={submitModify}
        onCancel={() => setModifyModalVisible(false)}
        okText="提交修改"
        cancelText="取消"
      >
        {modifyTarget && (
          <div>
            <div style={{ marginBottom: 8 }}>
              <Text strong style={{ fontSize: 12 }}>工具：</Text>
              <Tag color="blue" style={{ fontSize: 10 }}>{modifyTarget.tool}</Tag>
            </div>
            <div style={{ marginBottom: 4 }}>
              <Text style={{ fontSize: 11, color: "#64748b" }}>参数 (JSON 格式)：</Text>
            </div>
            <TextArea
              value={modifyParamsText}
              onChange={(e) => setModifyParamsText(e.target.value)}
              rows={8}
              style={{ fontSize: 11, fontFamily: "monospace" }}
            />
          </div>
        )}
      </Modal>

      {/* 光标闪烁动画 */}
      <style>{".cursor-blink { animation: blink 1s infinite; } @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }"}</style>
    </div>
  );
}
