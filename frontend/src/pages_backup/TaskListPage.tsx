import { useState, useEffect, useCallback } from "react";
import {
  Table,
  Card,
  Tag,
  Button,
  Input,
  Select,
  Typography,
  Space,
  Progress,
  Badge,
  Drawer,
  Timeline,
  Tabs,
  Statistic,
  Row,
  Col,
  Spin,
  Empty,
  Tooltip,
  Popconfirm,
  message,
  Alert,
  Divider,
  List,
  Descriptions,
  DatePicker,
} from "antd";
import UnorderedListOutlined from "@ant-design/icons/es/icons/UnorderedListOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import PlayCircleOutlined from "@ant-design/icons/es/icons/PlayCircleOutlined";
import PauseCircleOutlined from "@ant-design/icons/es/icons/PauseCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import SyncOutlined from "@ant-design/icons/es/icons/SyncOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import EyeOutlined from "@ant-design/icons/es/icons/EyeOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import BugOutlined from "@ant-design/icons/es/icons/BugOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";;
import request from "../api/request";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";

const { Title, Text } = Typography;
const { Option } = Select;
const { RangePicker } = DatePicker;

// ===================== 类型定义 =====================

type TaskStatus = "running" | "completed" | "failed" | "queued" | "paused";

type ScanType = "full" | "quick" | "custom" | "web" | "host";

interface ScanPhase {
  phase: string;
  status: "done" | "running" | "pending" | "error";
  description: string;
  timestamp?: string;
}

interface Vulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  target: string;
  description: string;
}

interface TaskLog {
  time: string;
  level: "info" | "warn" | "error";
  message: string;
}

interface ScanTask {
  id: string;
  target: string;
  scan_type: ScanType;
  status: TaskStatus;
  progress: number;
  vuln_count: number;
  created_at: string;
  phases?: ScanPhase[];
  vulnerabilities?: Vulnerability[];
  logs?: TaskLog[];
}

// ===================== Mock 数据 =====================

const mockPhases: Record<string, ScanPhase[]> = {
  full: [
    { phase: "资产发现", status: "done", description: "发现 32 个存活主机", timestamp: "2026-06-02 09:00:12" },
    { phase: "端口扫描", status: "done", description: "扫描 1024 个端口", timestamp: "2026-06-02 09:03:45" },
    { phase: "服务识别", status: "done", description: "识别 156 个服务", timestamp: "2026-06-02 09:08:22" },
    { phase: "漏洞检测", status: "running", description: "正在检测 CVE-2026-..." },
    { phase: "报告生成", status: "pending", description: "等待漏洞检测完成" },
  ],
  quick: [
    { phase: "资产发现", status: "done", description: "快速发现模式", timestamp: "2026-06-02 08:30:00" },
    { phase: "高危检测", status: "done", description: "检测 12 个高危漏洞", timestamp: "2026-06-02 08:35:00" },
  ],
  web: [
    { phase: "爬虫阶段", status: "done", description: "爬取 245 个 URL", timestamp: "2026-06-02 10:00:00" },
    { phase: "XSS检测", status: "done", description: "发现 3 个反射型 XSS", timestamp: "2026-06-02 10:15:00" },
    { phase: "SQL注入检测", status: "running", description: "正在测试注入点..." },
  ],
};

function makeTask(
  id: string,
  target: string,
  scan_type: ScanType,
  status: TaskStatus,
  progress: number,
  vuln_count: number,
  timeOffset: string,
): ScanTask {
  const logs: TaskLog[] = [
    { time: `2026-06-02 0${timeOffset}:00:01`, level: "info", message: `任务 ${id} 已创建` },
    { time: `2026-06-02 0${timeOffset}:00:05`, level: "info", message: "开始资产发现阶段" },
    { time: `2026-06-02 0${timeOffset}:02:30`, level: "warn", message: `在 ${target} 上发现异常开放端口 8443` },
    { time: `2026-06-02 0${timeOffset}:05:12`, level: "info", message: `当前进度 ${progress}%` },
  ];

  return {
    id: `TASK-${id}`,
    target,
    scan_type,
    status,
    progress,
    vuln_count,
    created_at: `2026-06-02 0${timeOffset}:00:00`,
    phases: mockPhases[scan_type],
    vulnerabilities:
      vuln_count > 0
        ? [
            {
              id: `${id}-v1`,
              name: "CVE-2026-1234 - 远程代码执行",
              severity: "critical",
              target,
              description: "Apache Struts2 存在远程代码执行漏洞，攻击者可构造恶意请求执行任意代码。",
            },
            {
              id: `${id}-v2`,
              name: "弱口令检测",
              severity: "high",
              target,
              description: "SSH 服务使用弱密码，容易被暴力破解。",
            },
            {
              id: `${id}-v3`,
              name: "CVE-2025-5678 - SQL 注入",
              severity: "medium",
              target,
              description: "Web 应用存在 SQL 注入漏洞，可导致数据泄露。",
            },
            {
              id: `${id}-v4`,
              name: "TLS 1.0 协议启用",
              severity: "low",
              target,
              description: "服务器仍启用已弃用的 TLS 1.0 协议。",
            },
          ].slice(0, vuln_count)
        : [],
    logs,
  };
}

const mockData: ScanTask[] = [
  makeTask("20260602001", "192.168.1.0/24", "full", "running", 68, 12, "9"),
  makeTask("20260602002", "10.0.0.0/16", "full", "completed", 100, 34, "8"),
  makeTask("20260602003", "https://example.com", "web", "running", 45, 5, "7"),
  makeTask("20260602004", "192.168.100.1", "host", "failed", 23, 0, "6"),
  makeTask("20260602005", "172.16.0.0/12", "quick", "completed", 100, 8, "5"),
  makeTask("20260602006", "https://api.test.cn", "web", "queued", 0, 0, "4"),
  makeTask("20260602007", "10.10.10.0/24", "custom", "paused", 52, 3, "3"),
  makeTask("20260602008", "db.internal.com", "host", "completed", 100, 15, "2"),
  makeTask("20260602009", "192.168.200.1", "host", "running", 89, 7, "1"),
  makeTask("20260602010", "https://shop.test.cn", "web", "failed", 12, 0, "0"),
  makeTask("20260602011", "10.20.30.0/24", "quick", "queued", 0, 0, "0"),
  makeTask("20260602012", "vpn.corp.cn", "custom", "completed", 100, 21, "9"),
];

// ===================== 工具函数 =====================

const statusConfig: Record<
  TaskStatus,
  { color: string; icon: React.ReactNode; label: string }
> = {
  running: { color: "#0284c7", icon: <SyncOutlined spin />, label: "运行中" },
  completed: { color: "#52c41a", icon: <CheckCircleOutlined />, label: "已完成" },
  failed: { color: "#ff4d4f", icon: <CloseCircleOutlined />, label: "失败" },
  queued: { color: "#faad14", icon: <ClockCircleOutlined />, label: "排队中" },
  paused: { color: "#d9d9d9", icon: <PauseCircleOutlined />, label: "已暂停" },
};

const scanTypeLabels: Record<ScanType, string> = {
  full: "全量扫描",
  quick: "快速扫描",
  custom: "自定义扫描",
  web: "Web 扫描",
  host: "主机扫描",
};

const severityConfig: Record<string, { color: string; label: string }> = {
  critical: { color: "#8b0000", label: "严重" },
  high: { color: "#ff4d4f", label: "高危" },
  medium: { color: "#fa8c16", label: "中危" },
  low: { color: "#0284c7", label: "低危" },
  info: { color: "#52c41a", label: "信息" },
};

const phaseStatusIcons: Record<string, React.ReactNode> = {
  done: <CheckCircleOutlined style={{ color: "#52c41a" }} />,
  running: <SyncOutlined spin style={{ color: "#0284c7" }} />,
  pending: <ClockCircleOutlined style={{ color: "#d9d9d9" }} />,
  error: <CloseCircleOutlined style={{ color: "#ff4d4f" }} />,
};

const logLevelColors: Record<string, string> = {
  info: "#0284c7",
  warn: "#fa8c16",
  error: "#ff4d4f",
};

function formatDate(dateStr: string): string {
  if (!dateStr) return "-";
  return dayjs(dateStr).format("YYYY-MM-DD HH:mm:ss");
}

// ===================== 组件 =====================

const TaskListPage: React.FC = () => {
  // ---------- 数据状态 ----------
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // ---------- 筛选状态 ----------
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [timeFilter, setTimeFilter] = useState<string>("all");
  const [timeRange, setTimeRange] = useState<[dayjs.Dayjs, dayjs.Dayjs] | null>(null);
  const [searchText, setSearchText] = useState("");

  // ---------- 详情抽屉 ----------
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedTask, setSelectedTask] = useState<ScanTask | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // ---------- 分页 ----------
  const [pagination, setPagination] = useState({ current: 1, pageSize: 20, total: 0 });

  // ========== 获取数据 ==========

  const fetchTasks = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = {
        page: pagination.current,
        page_size: pagination.pageSize,
      };
      if (statusFilter !== "all") params.status = statusFilter;
      if (searchText) params.target = searchText;

      const res = await request.get("/tasks", { params });
      const list = res?.data?.items || res?.data || res || [];
      const total = res?.data?.total || list.length;
      setTasks(list.length > 0 ? list : mockData);
      setPagination((p) => ({ ...p, total: total || mockData.length }));
    } catch {
      // API 失败，使用 mockData 兜底
      let filtered = [...mockData];
      if (statusFilter !== "all") {
        filtered = filtered.filter((t) => t.status === statusFilter);
      }
      if (searchText) {
        const kw = searchText.toLowerCase();
        filtered = filtered.filter((t) => t.target.toLowerCase().includes(kw));
      }
      if (timeFilter !== "all" && timeRange) {
        const [start, end] = timeRange;
        filtered = filtered.filter((t) => {
          const d = dayjs(t.created_at);
          return d.isAfter(start.startOf("day")) && d.isBefore(end.endOf("day"));
        });
      }
      setTasks(filtered);
      setPagination((p) => ({ ...p, total: filtered.length }));
    } finally {
      setLoading(false);
    }
  }, [pagination.current, pagination.pageSize, statusFilter, searchText, timeFilter, timeRange]);

  useEffect(() => {
    fetchTasks();
  }, [fetchTasks]);

  // ========== 获取任务详情 ==========

  const fetchTaskDetail = async (taskId: string) => {
    setDetailLoading(true);
    try {
      const res = await request.get(`/tasks/${taskId}`);
      if (res?.data) {
        setSelectedTask(res.data);
      } else {
        // 从本地 mockData 查找兜底
        const found = mockData.find((t) => t.id === taskId) || null;
        setSelectedTask(found);
      }
    } catch {
      const found = mockData.find((t) => t.id === taskId) || null;
      setSelectedTask(found);
    } finally {
      setDetailLoading(false);
    }
  };

  // ========== 事件处理 ==========

  const handleRowClick = (record: ScanTask) => {
    setSelectedTask(record);
    setDrawerVisible(true);
    fetchTaskDetail(record.id);
  };

  const handleCancel = (taskId: string) => {
    message.success(`任务 ${taskId} 已取消`);
    setTasks((prev) => prev.map((t) => (t.id === taskId ? { ...t, status: "failed" as TaskStatus } : t)));
  };

  const handleRerun = (taskId: string) => {
    message.success(`任务 ${taskId} 已重新提交`);
    setTasks((prev) =>
      prev.map((t) => (t.id === taskId ? { ...t, status: "queued" as TaskStatus, progress: 0 } : t)),
    );
  };

  const handleViewReport = (taskId: string) => {
    message.info(`打开任务 ${taskId} 的扫描报告`);
  };

  const handleRefresh = () => {
    fetchTasks();
  };

  // ========== 统计数据 ==========

  const stats = {
    total: tasks.length,
    running: tasks.filter((t) => t.status === "running").length,
    completed: tasks.filter((t) => t.status === "completed").length,
    failed: tasks.filter((t) => t.status === "failed").length,
  };

  // ========== 表格列定义 ==========

  const columns: ColumnsType<ScanTask> = [
    {
      title: "任务 ID",
      dataIndex: "id",
      key: "id",
      width: 170,
      fixed: "left",
      render: (id: string) => (
        <Text copyable style={{ fontSize: 13, fontFamily: "monospace" }}>
          {id}
        </Text>
      ),
    },
    {
      title: "目标",
      dataIndex: "target",
      key: "target",
      width: 190,
      ellipsis: true,
      render: (target: string) => (
        <Tooltip title={target}>
          <Space>
            <SafetyOutlined style={{ color: "#0284c7" }} />
            <Text>{target}</Text>
          </Space>
        </Tooltip>
      ),
    },
    {
      title: "扫描类型",
      dataIndex: "scan_type",
      key: "scan_type",
      width: 110,
      render: (type: ScanType) => (
        <Tag style={{ borderRadius: 4 }}>{scanTypeLabels[type] || type}</Tag>
      ),
    },
    {
      title: "状态",
      dataIndex: "status",
      key: "status",
      width: 100,
      render: (status: TaskStatus) => {
        const cfg = statusConfig[status];
        return (
          <Badge
            status={status === "running" ? "processing" : status === "completed" ? "success" : status === "failed" ? "error" : status === "queued" ? "warning" : "default"}
            text={<span style={{ color: cfg.color, fontWeight: 500 }}>{cfg.label}</span>}
          />
        );
      },
    },
    {
      title: "进度",
      dataIndex: "progress",
      key: "progress",
      width: 160,
      render: (progress: number, record: ScanTask) => {
        const status = record.status;
        const strokeColor =
          status === "completed"
            ? "#52c41a"
            : status === "failed"
              ? "#ff4d4f"
              : "#0284c7";
        return (
          <Progress
            percent={progress}
            size="small"
            strokeColor={strokeColor}
            status={status === "failed" ? "exception" : status === "completed" ? "success" : "active"}
            style={{ marginBottom: 0 }}
          />
        );
      },
    },
    {
      title: "漏洞数",
      dataIndex: "vuln_count",
      key: "vuln_count",
      width: 90,
      sorter: (a, b) => a.vuln_count - b.vuln_count,
      render: (count: number) => (
        <Space>
          <BugOutlined style={{ color: count > 0 ? "#ff4d4f" : "#52c41a" }} />
          <Text strong style={{ color: count > 0 ? "#ff4d4f" : "#52c41a" }}>
            {count}
          </Text>
        </Space>
      ),
    },
    {
      title: "创建时间",
      dataIndex: "created_at",
      key: "created_at",
      width: 170,
      sorter: (a, b) => dayjs(a.created_at).unix() - dayjs(b.created_at).unix(),
      defaultSortOrder: "descend",
      render: (date: string) => (
        <Text style={{ fontSize: 13, color: "#8c8c8c" }}>{formatDate(date)}</Text>
      ),
    },
    {
      title: "操作",
      key: "actions",
      width: 220,
      fixed: "right",
      render: (_: unknown, record: ScanTask) => (
        <Space size="small">
          <Tooltip title="查看详情">
            <Button
              type="link"
              size="small"
              icon={<EyeOutlined />}
              onClick={(e) => {
                e.stopPropagation();
                handleRowClick(record);
              }}
            />
          </Tooltip>

          {record.status === "running" && (
            <Popconfirm
              title="确认取消此任务？"
              onConfirm={(e) => {
                e?.stopPropagation();
                handleCancel(record.id);
              }}
              okText="确认"
              cancelText="取消"
            >
              <Tooltip title="取消任务">
                <Button
                  type="link"
                  size="small"
                  danger
                  icon={<CloseCircleOutlined />}
                  onClick={(e) => e.stopPropagation()}
                />
              </Tooltip>
            </Popconfirm>
          )}

          {(record.status === "completed" || record.status === "failed") && (
            <Tooltip title="重新运行">
              <Button
                type="link"
                size="small"
                icon={<ReloadOutlined />}
                onClick={(e) => {
                  e.stopPropagation();
                  handleRerun(record.id);
                }}
              />
            </Tooltip>
          )}

          {record.status === "paused" && (
            <>
              <Tooltip title="继续任务">
                <Button
                  type="link"
                  size="small"
                  icon={<PlayCircleOutlined style={{ color: "#0284c7" }} />}
                  onClick={(e) => {
                    e.stopPropagation();
                    message.success(`任务 ${record.id} 已继续`);
                  }}
                />
              </Tooltip>
              <Popconfirm
                title="确认取消此任务？"
                onConfirm={(e) => {
                  e?.stopPropagation();
                  handleCancel(record.id);
                }}
              >
                <Tooltip title="取消任务">
                  <Button
                    type="link"
                    size="small"
                    danger
                    icon={<CloseCircleOutlined />}
                    onClick={(e) => e.stopPropagation()}
                  />
                </Tooltip>
              </Popconfirm>
            </>
          )}

          {record.status === "completed" && (
            <Tooltip title="查看报告">
              <Button
                type="link"
                size="small"
                icon={<FileTextOutlined style={{ color: "#0284c7" }} />}
                onClick={(e) => {
                  e.stopPropagation();
                  handleViewReport(record.id);
                }}
              />
            </Tooltip>
          )}
        </Space>
      ),
    },
  ];

  // ========== 渲染 ==========

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#fff",
        padding: "24px",
      }}
    >
      {/* ---- 标题 ---- */}
      <div style={{ marginBottom: 24 }}>
        <Title level={3} style={{ margin: 0 }}>
          <Space>
            <UnorderedListOutlined style={{ color: "#0284c7" }} />
            扫描任务
          </Space>
        </Title>
        <Text type="secondary" style={{ marginTop: 4, display: "block" }}>
          管理所有扫描任务，查看进度与结果
        </Text>
      </div>

      {/* ---- 统计卡片 ---- */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6}>
          <Card bordered bodyStyle={{ padding: "20px 24px" }}>
            <Statistic
              title="总任务"
              value={stats.total}
              prefix={<UnorderedListOutlined style={{ color: "#0284c7" }} />}
              valueStyle={{ color: "#0284c7" }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card bordered bodyStyle={{ padding: "20px 24px" }}>
            <Statistic
              title="已完成"
              value={stats.completed}
              prefix={<CheckCircleOutlined style={{ color: "#52c41a" }} />}
              valueStyle={{ color: "#52c41a" }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card bordered bodyStyle={{ padding: "20px 24px" }}>
            <Statistic
              title="失败"
              value={stats.failed}
              prefix={<CloseCircleOutlined style={{ color: "#ff4d4f" }} />}
              valueStyle={{ color: "#ff4d4f" }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card bordered bodyStyle={{ padding: "20px 24px" }}>
            <Statistic
              title="运行中"
              value={stats.running}
              prefix={<SyncOutlined spin style={{ color: "#0284c7" }} />}
              valueStyle={{ color: "#0284c7" }}
            />
          </Card>
        </Col>
      </Row>

      {/* ---- 筛选 & 工具栏 ---- */}
      <Card
        bordered
        style={{ marginBottom: 16 }}
        bodyStyle={{ padding: "16px 24px" }}
      >
        <Row gutter={[16, 16]} align="middle">
          <Col xs={24} sm={6} md={4}>
            <Select
              style={{ width: "100%" }}
              value={statusFilter}
              onChange={(v) => {
                setStatusFilter(v);
                setPagination((p) => ({ ...p, current: 1 }));
              }}
              placeholder="全部状态"
            >
              <Option value="all">全部状态</Option>
              <Option value="running">运行中</Option>
              <Option value="completed">已完成</Option>
              <Option value="failed">失败</Option>
              <Option value="queued">排队中</Option>
              <Option value="paused">已暂停</Option>
            </Select>
          </Col>
          <Col xs={24} sm={6} md={4}>
            <Select
              style={{ width: "100%" }}
              value={timeFilter}
              onChange={(v) => {
                setTimeFilter(v);
                if (v === "all") setTimeRange(null);
                if (v === "today") setTimeRange([dayjs().startOf("day"), dayjs().endOf("day")]);
                if (v === "week") setTimeRange([dayjs().startOf("week"), dayjs().endOf("week")]);
                if (v === "month") setTimeRange([dayjs().startOf("month"), dayjs().endOf("month")]);
                setPagination((p) => ({ ...p, current: 1 }));
              }}
            >
              <Option value="all">全部时间</Option>
              <Option value="today">今天</Option>
              <Option value="week">本周</Option>
              <Option value="month">本月</Option>
              <Option value="custom">自定义</Option>
            </Select>
          </Col>
          {timeFilter === "custom" && (
            <Col xs={24} sm={12} md={8}>
              <RangePicker
                style={{ width: "100%" }}
                value={timeRange as any}
                onChange={(dates) => {
                  setTimeRange(dates as [dayjs.Dayjs, dayjs.Dayjs] | null);
                }}
              />
            </Col>
          )}
          <Col xs={24} sm={12} md={4}>
            <Input
              placeholder="搜索目标地址..."
              prefix={<SearchOutlined style={{ color: "#bfbfbf" }} />}
              value={searchText}
              onChange={(e) => {
                setSearchText(e.target.value);
                setPagination((p) => ({ ...p, current: 1 }));
              }}
              allowClear
            />
          </Col>
          <Col xs={24} sm={4} md={3} style={{ textAlign: "right" }}>
            <Space>
              <Tooltip title="刷新">
                <Button icon={<ReloadOutlined />} onClick={handleRefresh} loading={loading} />
              </Tooltip>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* ---- 错误提示 ---- */}
      {error && (
        <Alert
          message={error}
          type="error"
          showIcon
          closable
          style={{ marginBottom: 16 }}
          onClose={() => setError(null)}
        />
      )}

      {/* ---- 数据表格 ---- */}
      <Card bordered bodyStyle={{ padding: 0 }}>
        <Table<ScanTask>
          rowKey="id"
          columns={columns}
          dataSource={tasks}
          loading={loading}
          pagination={{
            ...pagination,
            showSizeChanger: true,
            showQuickJumper: true,
            pageSizeOptions: ["10", "20", "50", "100"],
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
            onChange: (page, pageSize) => {
              setPagination({ current: page, pageSize, total: pagination.total });
            },
          }}
          scroll={{ x: 1200 }}
          onRow={(record) => ({
            onClick: () => handleRowClick(record),
            style: { cursor: "pointer" },
          })}
          locale={{
            emptyText: <Empty description="暂无扫描任务" />,
          }}
          size="middle"
        />
      </Card>

      {/* ========== 详情抽屉 ========== */}
      <Drawer
        title={
          <Space>
            <ExperimentOutlined style={{ color: "#0284c7" }} />
            <span>任务详情</span>
            {selectedTask && (
              <Tag color={statusConfig[selectedTask.status]?.color}>
                {statusConfig[selectedTask.status]?.label}
              </Tag>
            )}
          </Space>
        }
        placement="right"
        width={680}
        open={drawerVisible}
        onClose={() => {
          setDrawerVisible(false);
          setSelectedTask(null);
        }}
        destroyOnClose
      >
        {detailLoading ? (
          <div style={{ textAlign: "center", padding: "100px 0" }}>
            <Spin size="large" tip="加载详情中..." />
          </div>
        ) : selectedTask ? (
          <div>
            {/* 基本信息 */}
            <Descriptions
              title="基本信息"
              column={2}
              bordered
              size="small"
              style={{ marginBottom: 24 }}
            >
              <Descriptions.Item label="任务 ID">
                <Text copyable style={{ fontFamily: "monospace", fontSize: 13 }}>
                  {selectedTask.id}
                </Text>
              </Descriptions.Item>
              <Descriptions.Item label="扫描类型">
                <Tag style={{ borderRadius: 4 }}>
                  {scanTypeLabels[selectedTask.scan_type] || selectedTask.scan_type}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="目标">{selectedTask.target}</Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDate(selectedTask.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Badge
                  status={
                    selectedTask.status === "running"
                      ? "processing"
                      : selectedTask.status === "completed"
                        ? "success"
                        : selectedTask.status === "failed"
                          ? "error"
                          : "warning"
                  }
                  text={
                    <span style={{ color: statusConfig[selectedTask.status]?.color, fontWeight: 500 }}>
                      {statusConfig[selectedTask.status]?.label}
                    </span>
                  }
                />
              </Descriptions.Item>
              <Descriptions.Item label="漏洞数">
                <Space>
                  <BugOutlined
                    style={{ color: selectedTask.vuln_count > 0 ? "#ff4d4f" : "#52c41a" }}
                  />
                  <Text strong style={{ color: selectedTask.vuln_count > 0 ? "#ff4d4f" : "#52c41a" }}>
                    {selectedTask.vuln_count}
                  </Text>
                </Space>
              </Descriptions.Item>
            </Descriptions>

            {/* 进度 */}
            <div style={{ marginBottom: 24 }}>
              <Text strong>扫描进度</Text>
              <Progress
                percent={selectedTask.progress}
                strokeColor={
                  selectedTask.status === "completed"
                    ? "#52c41a"
                    : selectedTask.status === "failed"
                      ? "#ff4d4f"
                      : "#0284c7"
                }
                status={
                  selectedTask.status === "failed"
                    ? "exception"
                    : selectedTask.status === "completed"
                      ? "success"
                      : "active"
                }
              />
            </div>

            <Divider style={{ margin: "12px 0" }} />

            {/* Tabs: 阶段结果 / 漏洞列表 / 日志 */}
            <Tabs
              defaultActiveKey="phases"
              items={[
                {
                  key: "phases",
                  label: (
                    <span>
                      <ExperimentOutlined /> 阶段结果
                    </span>
                  ),
                  children: selectedTask.phases && selectedTask.phases.length > 0 ? (
                    <Timeline
                      items={selectedTask.phases.map((p, idx) => ({
                        dot: phaseStatusIcons[p.status],
                        color:
                          p.status === "done"
                            ? "#52c41a"
                            : p.status === "running"
                              ? "#0284c7"
                              : p.status === "error"
                                ? "#ff4d4f"
                                : "#d9d9d9",
                        children: (
                          <div key={idx}>
                            <Text strong>{p.phase}</Text>
                            <br />
                            <Text type="secondary" style={{ fontSize: 13 }}>
                              {p.description}
                            </Text>
                            {p.timestamp && (
                              <>
                                <br />
                                <Text
                                  type="secondary"
                                  style={{ fontSize: 12, color: "#bfbfbf" }}
                                >
                                  {p.timestamp}
                                </Text>
                              </>
                            )}
                          </div>
                        ),
                      }))}
                    />
                  ) : (
                    <Empty description="暂无阶段数据" />
                  ),
                },
                {
                  key: "vulnerabilities",
                  label: (
                    <span>
                      <BugOutlined /> 漏洞列表
                      {selectedTask.vuln_count > 0 && (
                        <span style={{ color: "#ff4d4f", marginLeft: 4 }}>
                          ({selectedTask.vuln_count})
                        </span>
                      )}
                    </span>
                  ),
                  children:
                    selectedTask.vulnerabilities && selectedTask.vulnerabilities.length > 0 ? (
                      <List
                        dataSource={selectedTask.vulnerabilities}
                        renderItem={(item) => (
                          <List.Item>
                            <List.Item.Meta
                              avatar={
                                <Tag
                                  color={severityConfig[item.severity]?.color}
                                  style={{ marginRight: 0 }}
                                >
                                  {severityConfig[item.severity]?.label || item.severity}
                                </Tag>
                              }
                              title={<Text>{item.name}</Text>}
                              description={
                                <div>
                                  <Text type="secondary" style={{ fontSize: 13 }}>
                                    目标: {item.target}
                                  </Text>
                                  <br />
                                  <Text type="secondary" style={{ fontSize: 13 }}>
                                    {item.description}
                                  </Text>
                                </div>
                              }
                            />
                          </List.Item>
                        )}
                      />
                    ) : (
                      <Empty description="未发现漏洞" />
                    ),
                },
                {
                  key: "logs",
                  label: (
                    <span>
                      <FileTextOutlined /> 日志
                    </span>
                  ),
                  children:
                    selectedTask.logs && selectedTask.logs.length > 0 ? (
                      <div
                        style={{
                          background: "#fafafa",
                          borderRadius: 6,
                          padding: 12,
                          maxHeight: 400,
                          overflow: "auto",
                          fontFamily: "monospace",
                          fontSize: 13,
                        }}
                      >
                        {selectedTask.logs.map((log, idx) => (
                          <div key={idx} style={{ marginBottom: 8 }}>
                            <Text style={{ color: "#bfbfbf" }}>{log.time}</Text>
                            {"  "}
                            <Text style={{ color: logLevelColors[log.level] || "#8c8c8c" }}>
                              [{log.level.toUpperCase()}] {log.message}
                            </Text>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <Empty description="暂无日志" />
                    ),
                },
              ]}
            />

            {/* 操作按钮 */}
            <Divider />
            <Space style={{ marginTop: 8 }}>
              {selectedTask.status === "running" && (
                <Popconfirm
                  title="确认取消此任务？"
                  onConfirm={() => handleCancel(selectedTask.id)}
                  okText="确认"
                  cancelText="取消"
                >
                  <Button danger icon={<CloseCircleOutlined />}>
                    取消任务
                  </Button>
                </Popconfirm>
              )}
              {(selectedTask.status === "completed" || selectedTask.status === "failed") && (
                <Button
                  icon={<ReloadOutlined />}
                  onClick={() => handleRerun(selectedTask.id)}
                >
                  重新运行
                </Button>
              )}
              {selectedTask.status === "completed" && (
                <Button
                  type="primary"
                  icon={<FileTextOutlined />}
                  onClick={() => handleViewReport(selectedTask.id)}
                  style={{ background: "#0284c7", borderColor: "#0284c7" }}
                >
                  查看报告
                </Button>
              )}
              {selectedTask.status === "paused" && (
                <>
                  <Button
                    icon={<PlayCircleOutlined />}
                    onClick={() => message.success(`任务 ${selectedTask.id} 已继续`)}
                  >
                    继续任务
                  </Button>
                  <Popconfirm
                    title="确认取消此任务？"
                    onConfirm={() => handleCancel(selectedTask.id)}
                  >
                    <Button danger icon={<CloseCircleOutlined />}>
                      取消任务
                    </Button>
                  </Popconfirm>
                </>
              )}
            </Space>
          </div>
        ) : (
          <Empty description="无法加载任务详情" />
        )}
      </Drawer>
    </div>
  );
};

export default TaskListPage;