import {useState, useEffect} from "react";
import {
 Tabs, Table, Card, Tag, Button, Input, Typography, Space, Switch,
 message, Modal, Form, Select, DatePicker, TimePicker, Row, Col,
 Spin, Empty, Tooltip, Badge, Popconfirm, Descriptions, Statistic,
} from "antd";














import request from "../api/request";
import ScheduleOutlined from "@ant-design/icons/es/icons/ScheduleOutlined";
import PlusOutlined from "@ant-design/icons/es/icons/PlusOutlined";
import EditOutlined from "@ant-design/icons/es/icons/EditOutlined";
import DeleteOutlined from "@ant-design/icons/es/icons/DeleteOutlined";
import PauseCircleOutlined from "@ant-design/icons/es/icons/PauseCircleOutlined";
import PlayCircleOutlined from "@ant-design/icons/es/icons/PlayCircleOutlined";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import SyncOutlined from "@ant-design/icons/es/icons/SyncOutlined";
import HistoryOutlined from "@ant-design/icons/es/icons/HistoryOutlined";
import FieldTimeOutlined from "@ant-design/icons/es/icons/FieldTimeOutlined";;

const {Title, Text} = Typography;
const {Option} = Select;

// ==================== 类型定义 ====================

interface Schedule {
 id: string;
 name: string;
 target: string;
 scanType: string;
 cron: string;
 enabled: boolean;
 nextRun: string;
 lastRun: string;
}

interface HistoryRecord {
 id: string;
 taskName: string;
 executeTime: string;
 status: "success" | "failed" | "running";
 duration: string;
 summary: string;
}

type ScheduleFormValues = {
 name: string;
 target: string;
 scanType: string;
 cron: string;
};

// ==================== Mock 数据 ====================





// ==================== 状态标签渲染 ====================

const renderStatusTag = (enabled: boolean) =>
 enabled ? (
 <Tag icon={<CheckCircleOutlined />} color="#16a34a">
 启用
 </Tag>
 ) : (
 <Tag icon={<PauseCircleOutlined />} color="#9ca3af">
 暂停
 </Tag>
 );

const renderHistoryStatusTag = (status: HistoryRecord["status"]) => {
 const map = {
 success: {color: "#16a34a", icon: <CheckCircleOutlined />, label: "成功"},
 failed: {color: "#dc2626", icon: <CloseCircleOutlined />, label: "失败"},
 running: {color: "#0284c7", icon: <SyncOutlined spin />, label: "运行中"},
};
 const s = map[status];
 return (
 <Tag icon={s.icon} color={s.color}>
 {s.label}
 </Tag>
 );
};

// ==================== 主组件 ====================

export default function ScheduleCenterPage() {
 // ---- 定时任务状态 ----
 const [schedules, setSchedules] = useState<Schedule[]>([]);
 const [scheduleLoading, setScheduleLoading] = useState(true);
 const [scheduleSearch, setScheduleSearch] = useState("");
 const [scheduleTypeFilter, setScheduleTypeFilter] = useState<string>("全部");

 // ---- 执行历史状态 ----
 const [history, setHistory] = useState<HistoryRecord[]>([]);
 const [historyLoading, setHistoryLoading] = useState(true);
 const [historySearch, setHistorySearch] = useState("");
 const [historyStatusFilter, setHistoryStatusFilter] = useState<string>("全部");

 // ---- Modal 状态 ----
 const [modalOpen, setModalOpen] = useState(false);
 const [editingSchedule, setEditingSchedule] = useState<Schedule | null>(null);
 const [modalLoading, setModalLoading] = useState(false);
 const [form] = Form.useForm<ScheduleFormValues>();

 // ==================== 数据加载 ====================

 const fetchSchedules = async () => {
 setScheduleLoading(true);
 try {
 const res = await request.get("/schedules");
 const data = res.data?.items || res.data || [];
 setSchedules(Array.isArray(data) ? data : []);
} catch {
 message.warning("加载定时任务失败");
} finally {
 setScheduleLoading(false);
}
};

 const fetchHistory = async () => {
 setHistoryLoading(true);
 try {
 const res = await request.get("/schedules/?history=true");
 const data = res.data?.items || res.data || [];
 setHistory(Array.isArray(data) ? data : []);
 setHistoryLoading(false);
} catch {
 message.warning("加载执行历史失败");
 setHistoryLoading(false);
}
};

 useEffect(() => {
 fetchSchedules();
 fetchHistory();
}, []);

 // ==================== 定时任务操作 ====================

 const handleToggle = async (record: Schedule) => {
 const newEnabled = !record.enabled;
 try {
 await request.post(`/schedules/${record.id}/toggle`);
 message.success(`任务已${newEnabled ? "启用" : "暂停"}`);
 setSchedules((prev) =>
 prev.map((s) => (s.id === record.id ? {...s, enabled: newEnabled} : s))
 );
} catch {
 message.warning("API 不可用，已本地切换");
 setSchedules((prev) =>
 prev.map((s) => (s.id === record.id ? {...s, enabled: newEnabled} : s))
 );
}
};

 const handleDelete = async (id: string) => {
 try {
 await request.delete(`/schedules/${id}`);
 message.success("任务已删除");
 setSchedules((prev) => prev.filter((s) => s.id !== id));
} catch {
 message.warning("API 不可用，已本地删除");
 setSchedules((prev) => prev.filter((s) => s.id !== id));
}
};

 const openCreateModal = () => {
 setEditingSchedule(null);
 form.resetFields();
 setModalOpen(true);
};

 const openEditModal = (record: Schedule) => {
 setEditingSchedule(record);
 form.setFieldsValue({
 name: record.name,
 target: record.target,
 scanType: record.scanType,
 cron: record.cron,
});
 setModalOpen(true);
};

 const handleModalOk = async () => {
 try {
 const values = await form.validateFields();
 setModalLoading(true);

 if (editingSchedule) {
 try {
 await request.put(`/schedules/${editingSchedule.id}`, values);
} catch {
 // API 不可用，本地更新
}
 setSchedules((prev) =>
 prev.map((s) =>
 s.id === editingSchedule.id
 ? {
 ...s,
 ...values,
 nextRun: s.nextRun,
 lastRun: s.lastRun,
}
 : s
 )
 );
 message.success("任务已更新");
} else {
 const newId = String(Date.now());
 const payload = {
 ...values,
 id: newId,
 enabled: true,
 nextRun: "待计算",
 lastRun: "—",
};
 try {
 await request.post("/schedules", payload);
} catch {
 // API 不可用，本地新增
}
 setSchedules((prev) => [...prev, payload]);
 message.success("任务已创建");
}

 setModalOpen(false);
 setEditingSchedule(null);
 form.resetFields();
} catch {
 // 表单校验失败
} finally {
 setModalLoading(false);
}
};

 const handleModalCancel = () => {
 setModalOpen(false);
 setEditingSchedule(null);
 form.resetFields();
};

 // ==================== 过滤逻辑 ====================

 const filteredSchedules = schedules.filter((s) => {
 const matchSearch =
 !scheduleSearch ||
 s.name.toLowerCase().includes(scheduleSearch.toLowerCase()) ||
 s.target.toLowerCase().includes(scheduleSearch.toLowerCase());
 const matchType =
 scheduleTypeFilter === "全部" || s.scanType === scheduleTypeFilter;
 return matchSearch && matchType;
});

 const filteredHistory = history.filter((h) => {
 const matchSearch =
 !historySearch ||
 h.taskName.toLowerCase().includes(historySearch.toLowerCase()) ||
 h.summary.toLowerCase().includes(historySearch.toLowerCase());
 const matchStatus =
 historyStatusFilter === "全部" || h.status === historyStatusFilter;
 return matchSearch && matchStatus;
});

 const scanTypeOptions = ["全部", ...new Set(schedules.map((s) => s.scanType))];

 // ==================== 表格列定义 ====================

 const scheduleColumns = [
 {
 title: "任务名",
 dataIndex: "name",
 key: "name",
 width: 180,
 render: (text: string, record: Schedule) => (
 <Space>
 <ScheduleOutlined style={{color: "#0284c7"}} />
 <Text strong>{text}</Text>
 </Space>
 ),
},
 {
 title: "目标",
 dataIndex: "target",
 key: "target",
 width: 220,
 ellipsis: true,
 render: (text: string) => (
 <Tooltip title={text}>
 <Text code style={{fontSize: 12}}>
 {text}
 </Text>
 </Tooltip>
 ),
},
 {
 title: "扫描类型",
 dataIndex: "scanType",
 key: "scanType",
 width: 130,
 render: (text: string) => <Tag color="#0284c7">{text}</Tag>,
},
 {
 title: "Cron 表达式",
 dataIndex: "cron",
 key: "cron",
 width: 130,
 render: (text: string) => (
 <Tooltip title={`Cron: ${text}`}>
 <Tag icon={<ClockCircleOutlined />} color="default">
 {text}
 </Tag>
 </Tooltip>
 ),
},
 {
 title: "状态",
 dataIndex: "enabled",
 key: "enabled",
 width: 90,
 render: (_: boolean, record: Schedule) => renderStatusTag(record.enabled),
},
 {
 title: "下次执行",
 dataIndex: "nextRun",
 key: "nextRun",
 width: 180,
 render: (text: string) => (
 <Space size={4}>
 <FieldTimeOutlined style={{color: "#0284c7"}} />
 <Text>{text}</Text>
 </Space>
 ),
},
 {
 title: "最后执行",
 dataIndex: "lastRun",
 key: "lastRun",
 width: 180,
 render: (text: string) => (
 <Space size={4}>
 <HistoryOutlined style={{color: "#6b7280"}} />
 <Text type="secondary">{text}</Text>
 </Space>
 ),
},
 {
 title: "操作",
 key: "actions",
 width: 200,
 fixed: "right" as const,
 render: (_: unknown, record: Schedule) => (
 <Space size="small">
 <Tooltip title="编辑">
 <Button
 type="link"
 size="small"
 icon={<EditOutlined />}
 onClick={() => openEditModal(record)}
 />
 </Tooltip>
 <Tooltip title={record.enabled ? "暂停" : "启用"}>
 <Button
 type="link"
 size="small"
 icon={
 record.enabled ? (
 <PauseCircleOutlined style={{color: "#d97706"}} />
 ) : (
 <PlayCircleOutlined style={{color: "#16a34a"}} />
 )
}
 onClick={() => handleToggle(record)}
 />
 </Tooltip>
 <Popconfirm
 title="确定删除该任务？"
 description="删除后无法恢复"
 onConfirm={() => handleDelete(record.id)}
 okText="删除"
 cancelText="取消"
 okButtonProps={{danger: true}}
 >
 <Tooltip title="删除">
 <Button
 type="link"
 size="small"
 danger
 icon={<DeleteOutlined />}
 />
 </Tooltip>
 </Popconfirm>
 </Space>
 ),
},
 ];

 const historyColumns = [
 {
 title: "任务名",
 dataIndex: "taskName",
 key: "taskName",
 width: 200,
 render: (text: string) => (
 <Space>
 <ScheduleOutlined style={{color: "#0284c7"}} />
 <Text strong>{text}</Text>
 </Space>
 ),
},
 {
 title: "执行时间",
 dataIndex: "executeTime",
 key: "executeTime",
 width: 180,
 render: (text: string) => (
 <Space size={4}>
 <ClockCircleOutlined style={{color: "#6b7280"}} />
 <Text>{text}</Text>
 </Space>
 ),
},
 {
 title: "状态",
 dataIndex: "status",
 key: "status",
 width: 110,
 render: (_: unknown, record: HistoryRecord) =>
 renderHistoryStatusTag(record.status),
},
 {
 title: "耗时",
 dataIndex: "duration",
 key: "duration",
 width: 120,
 render: (text: string) => (
 <Space size={4}>
 <FieldTimeOutlined
 style={{color: text === "进行中..." ? "#0284c7" : "#6b7280"}}
 />
 <Text>{text}</Text>
 </Space>
 ),
},
 {
 title: "结果摘要",
 dataIndex: "summary",
 key: "summary",
 ellipsis: true,
 render: (text: string) => (
 <Tooltip title={text}>
 <Text type="secondary" style={{fontSize: 13}}>
 {text}
 </Text>
 </Tooltip>
 ),
},
 ];

 // ==================== 统计 ====================

 const enabledCount = schedules.filter((s) => s.enabled).length;
 const pausedCount = schedules.filter((s) => !s.enabled).length;
 const successCount = history.filter((h) => h.status === "success").length;
 const failedCount = history.filter((h) => h.status === "failed").length;

 // ==================== 渲染 ====================

 return (
 <div
 style={{
 padding: "0 24px 24px",
 background: "#ffffff",
 minHeight: "100vh",
}}
 >
 {/* ========== 页面标题 ========== */}
 <Row align="middle" style={{marginBottom: 20}}>
 <Col flex="auto">
 <Space size={12}>
 <ScheduleOutlined style={{fontSize: 28, color: "#0284c7"}} />
 <div>
 <Title level={3} style={{margin: 0, color: "#1e293b"}}>
 调度中心
 </Title>
 <Text type="secondary" style={{fontSize: 13}}>
 管理定时扫描任务与执行历史
 </Text>
 </div>
 </Space>
 </Col>
 </Row>

 {/* ========== 统计卡片 ========== */}
 <Row gutter={16} style={{marginBottom: 16}}>
 <Col span={6}>
 <Card
 size="small"
 style={{
 borderLeft: "3px solid #0284c7",
 background: "#f0f9ff",
}}
 >
 <Statistic
 title="定时任务总数"
 value={schedules.length}
 prefix={<ScheduleOutlined />}
 valueStyle={{color: "#0284c7", fontSize: 24}}
 />
 </Card>
 </Col>
 <Col span={6}>
 <Card
 size="small"
 style={{
 borderLeft: "3px solid #16a34a",
 background: "#f0fdf4",
}}
 >
 <Statistic
 title="已启用"
 value={enabledCount}
 prefix={<PlayCircleOutlined />}
 valueStyle={{color: "#16a34a", fontSize: 24}}
 />
 </Card>
 </Col>
 <Col span={6}>
 <Card
 size="small"
 style={{
 borderLeft: "3px solid #d97706",
 background: "#fffbeb",
}}
 >
 <Statistic
 title="已暂停"
 value={pausedCount}
 prefix={<PauseCircleOutlined />}
 valueStyle={{color: "#d97706", fontSize: 24}}
 />
 </Card>
 </Col>
 <Col span={6}>
 <Card
 size="small"
 style={{
 borderLeft: "3px solid #dc2626",
 background: "#fef2f2",
}}
 >
 <Statistic
 title="执行失败"
 value={failedCount}
 prefix={<CloseCircleOutlined />}
 valueStyle={{color: "#dc2626", fontSize: 24}}
 />
 </Card>
 </Col>
 </Row>

 {/* ========== Tabs 主体 ========== */}
 <Card
 style={{
 background: "#ffffff",
 borderRadius: 8,
 boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
}}
 bodyStyle={{padding: "0 24px 24px"}}
 >
 <Tabs
 defaultActiveKey="schedules"
 size="large"
 tabBarStyle={{
 marginBottom: 0,
 borderBottom: "1px solid #e5e7eb",
}}
 items={[
 {
 key: "schedules",
 label: (
 <Space>
 <ScheduleOutlined />
 <span>定时任务</span>
 <Badge
 count={schedules.length}
 style={{backgroundColor: "#0284c7"}}
 overflowCount={99}
 />
 </Space>
 ),
 children: (
 <div style={{padding: "16px 0 0"}}>
 {/* 工具栏 */}
 <Row
 gutter={16}
 align="middle"
 style={{marginBottom: 16}}
 >
 <Col flex="auto">
 <Space size={12}>
 <Input
 placeholder="搜索任务名或目标..."
 prefix={
 <SearchOutlined style={{color: "#9ca3af"}} />
}
 allowClear
 style={{width: 280}}
 value={scheduleSearch}
 onChange={(e) => setScheduleSearch(e.target.value)}
 />
 <Select
 value={scheduleTypeFilter}
 onChange={setScheduleTypeFilter}
 style={{width: 140}}
 >
 {scanTypeOptions.map((t) => (
 <Option key={t} value={t}>
 {t === "全部" ? "全部类型" : t}
 </Option>
 ))}
 </Select>
 </Space>
 </Col>
 <Col>
 <Space>
 <Tooltip title="刷新">
 <Button
 icon={<ReloadOutlined />}
 onClick={fetchSchedules}
 />
 </Tooltip>
 <Button
 type="primary"
 icon={<PlusOutlined />}
 onClick={openCreateModal}
 style={{
 backgroundColor: "#0284c7",
 borderColor: "#0284c7",
}}
 >
 新建任务
 </Button>
 </Space>
 </Col>
 </Row>

 {/* 表格 */}
 <Spin spinning={scheduleLoading}>
 {filteredSchedules.length === 0 && !scheduleLoading ? (
 <Empty description="暂无定时任务" style={{marginTop: 60, marginBottom: 60}} />
 ) : (
 <Table
 rowKey="id"
 columns={scheduleColumns}
 dataSource={filteredSchedules}
 pagination={{
 pageSize: 10,
 showSizeChanger: true,
 showTotal: (total) => `共 ${total} 条任务`,
}}
 size="middle"
 scroll={{x: 1300}}
 />
 )}
 </Spin>
 </div>
 ),
},
 {
 key: "history",
 label: (
 <Space>
 <HistoryOutlined />
 <span>执行历史</span>
 <Badge
 count={history.length}
 style={{backgroundColor: "#6b7280"}}
 overflowCount={99}
 />
 </Space>
 ),
 children: (
 <div style={{padding: "16px 0 0"}}>
 {/* 工具栏 */}
 <Row
 gutter={16}
 align="middle"
 style={{marginBottom: 16}}
 >
 <Col flex="auto">
 <Space size={12}>
 <Input
 placeholder="搜索任务名或摘要..."
 prefix={
 <SearchOutlined style={{color: "#9ca3af"}} />
}
 allowClear
 style={{width: 280}}
 value={historySearch}
 onChange={(e) => setHistorySearch(e.target.value)}
 />
 <Select
 value={historyStatusFilter}
 onChange={setHistoryStatusFilter}
 style={{width: 120}}
 >
 <Option value="全部">全部状态</Option>
 <Option value="success">成功</Option>
 <Option value="failed">失败</Option>
 <Option value="running">运行中</Option>
 </Select>
 </Space>
 </Col>
 <Col>
 <Tooltip title="刷新">
 <Button
 icon={<ReloadOutlined />}
 onClick={fetchHistory}
 />
 </Tooltip>
 </Col>
 </Row>

 {/* 表格 */}
 <Spin spinning={historyLoading}>
 {filteredHistory.length === 0 && !historyLoading ? (
 <Empty description="暂无执行记录" style={{marginTop: 60, marginBottom: 60}} />
 ) : (
 <Table
 rowKey="id"
 columns={historyColumns}
 dataSource={filteredHistory}
 pagination={{
 pageSize: 10,
 showSizeChanger: true,
 showTotal: (total) => `共 ${total} 条记录`,
}}
 size="middle"
 scroll={{x: 800}}
 />
 )}
 </Spin>
 </div>
 ),
},
 ]}
 />
 </Card>

 {/* ========== 新建 / 编辑 Modal ========== */}
 <Modal
 title={
 <Space>
 <ScheduleOutlined style={{color: "#0284c7"}} />
 <span>{editingSchedule ? "编辑定时任务" : "新建定时任务"}</span>
 </Space>
}
 open={modalOpen}
 onOk={handleModalOk}
 onCancel={handleModalCancel}
 confirmLoading={modalLoading}
 okText={editingSchedule ? "保存" : "创建"}
 cancelText="取消"
 width={560}
 okButtonProps={{
 style: {
 backgroundColor: "#0284c7",
 borderColor: "#0284c7",
},
}}
 destroyOnClose
 >
 <Form
 form={form}
 layout="vertical"
 style={{marginTop: 16}}
 requiredMark="optional"
 >
 <Form.Item
 name="name"
 label="任务名称"
 rules={[{required: true, message: "请输入任务名称"}]}
 >
 <Input
 placeholder="例如：每日全端口扫描"
 maxLength={50}
 showCount
 />
 </Form.Item>

 <Form.Item
 name="target"
 label="扫描目标"
 rules={[{required: true, message: "请输入扫描目标"}]}
 >
 <Input
 placeholder="例如：192.168.1.0/24 或 https://example.com"
 />
 </Form.Item>

 <Form.Item
 name="scanType"
 label="扫描类型"
 rules={[{required: true, message: "请选择扫描类型"}]}
 >
 <Select placeholder="选择扫描类型">
 <Option value="全端口扫描">全端口扫描</Option>
 <Option value="Web漏洞扫描">Web 漏洞扫描</Option>
 <Option value="数据库扫描">数据库扫描</Option>
 <Option value="资产发现">资产发现</Option>
 <Option value="深度扫描">深度扫描</Option>
 <Option value="弱口令爆破">弱口令爆破</Option>
 <Option value="子域名收集">子域名收集</Option>
 </Select>
 </Form.Item>

 <Form.Item
 name="cron"
 label="Cron 表达式"
 rules={[{required: true, message: "请输入 Cron 表达式"}]}
 extra="格式：分 时 日 月 周。例如 0 2 * * * 表示每日凌晨2点"
 >
 <Input placeholder="0 2 * * *" />
 </Form.Item>
 </Form>
 </Modal>
 </div>
 );
}
