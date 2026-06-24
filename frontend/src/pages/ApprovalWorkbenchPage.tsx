// @ts-nocheck
import {useState, useEffect} from "react";
import {
 Card,
 Tag,
 Button,
 Typography,
 Space,
 Row,
 Col,
 Spin,
 Empty,
 Table,
 Drawer,
 List,
 Descriptions,
 Input,
 message,
 Alert,
 Statistic,
 Divider,
 Result,
} from "antd";













import request from "../api/request";
import {useNavigate} from "react-router-dom";
import BugIcon from "../components/BugIcon";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";
import WarningOutlined from "@ant-design/icons/es/icons/WarningOutlined";
import InfoCircleOutlined from "@ant-design/icons/es/icons/InfoCircleOutlined";
import ExperimentOutlined from "@ant-design/icons/es/icons/ExperimentOutlined";
import EyeOutlined from "@ant-design/icons/es/icons/EyeOutlined";
import AuditOutlined from "@ant-design/icons/es/icons/AuditOutlined";
import MessageOutlined from "@ant-design/icons/es/icons/MessageOutlined";
import SendOutlined from "@ant-design/icons/es/icons/SendOutlined";
import StopOutlined from "@ant-design/icons/es/icons/StopOutlined";;

const {Title, Text, Paragraph} = Typography;
const {TextArea} = Input;

// ---------- types ----------
interface SeverityLevel {
 level: "critical" | "high" | "medium" | "low" | "info";
 label: string;
 color: string;
}

interface AuditRecord {
 id: string;
 title: string;
 severity: SeverityLevel;
 taskName: string;
 target: string;
 submitTime: string;
 status: "pending" | "approved" | "rejected";
 description: string;
 exploitSteps: string[];
 screenshots: string[];
 submitter: string;
}

// ---------- helpers ----------
const SEVERITY_MAP: Record<string, SeverityLevel> = {
 critical: {level: "critical", label: "严重", color: "#8b0000"},
 high: {level: "high", label: "高危", color: "#cf1322"},
 medium: {level: "medium", label: "中危", color: "#d48806"},
 low: {level: "low", label: "低危", color: "#389e0d"},
 info: {level: "info", label: "提示", color: "#0284c7"},
};

// ---------- mock ----------


// ---------- component ----------
const ApprovalWorkbenchPage: React.FC = () => {
 useEffect(() => {
 request.get("/negative/list").then(res => {
 if (res?.data) {
 const items = Array.isArray(res.data) ? res.data : (res.data.results || res.data.items || []);
 if (items.length > 0) {
 setData(items.map((item) => ({
 id: item.id,
 task: item.task_id || item.task || "",
 target: item.target || "",
 vulnerability: item.name || item.title || item.vulnerability || "",
 severity: (item.severity || "medium").toLowerCase(),
 cvss: item.cvss || 0,
 status: item.confirmed === true ? "approved" : item.confirmed === false ? "rejected" : "pending",
 submitter: item.created_by || item.submitter || "system",
 createdAt: item.created_at ? new Date(item.created_at).toLocaleString() : "",
})));
}
}
}).catch(() => {});
 request.get("/negative/stats").then(res => {
 if (res?.data) {
 setStats({
 total: res.data.total || res.data.total_count || 0,
 pending: res.data.pending || 0,
 approved: res.data.approved || res.data.confirmed || 0,
 rejected: res.data.rejected || res.data.dismissed || 0,
});
}
}).catch(() => {});
}, []);

 const navigate = useNavigate();
 const [data, setData] = useState<AuditRecord[]>([]);
 const [loading] = useState(false);
 const [selected, setSelected] = useState<AuditRecord | null>(null);
 const [drawerOpen, setDrawerOpen] = useState(false);
 const [auditOpinion, setAuditOpinion] = useState("");
 const [submitting, setSubmitting] = useState(false);

 const stats = {
 total: data.length,
 pending: data.filter((r) => r.status === "pending").length,
 approved: data.filter((r) => r.status === "approved").length,
 rejected: data.filter((r) => r.status === "rejected").length,
};

 const openDrawer = (record: AuditRecord) => {
 setSelected(record);
 setAuditOpinion("");
 setDrawerOpen(true);
};

 const handleApprove = () => {
 if (!auditOpinion.trim()) {
 message.warning("请输入审核意见");
 return;
}
 setSubmitting(true);
 // mock API call
 setTimeout(() => {
 message.success("审核通过");
 setSubmitting(false);
 setDrawerOpen(false);
}, 600);
};

 const handleReject = () => {
 if (!auditOpinion.trim()) {
 message.warning("请输入驳回理由");
 return;
}
 setSubmitting(true);
 setTimeout(() => {
 message.success("已驳回");
 setSubmitting(false);
 setDrawerOpen(false);
}, 600);
};

 const getStatusTag = (status: string) => {
 switch (status) {
 case "approved":
 return (
 <Tag icon={<CheckCircleOutlined />} color="success">
 已通过
 </Tag>
 );
 case "rejected":
 return (
 <Tag icon={<CloseCircleOutlined />} color="error">
 已驳回
 </Tag>
 );
 case "pending":
 return (
 <Tag icon={<ClockCircleOutlined />} color="warning">
 待审核
 </Tag>
 );
 default:
 return <Tag>未知</Tag>;
}
};

 const columns = [
 {
 title: "漏洞标题",
 dataIndex: "title",
 key: "title",
 render: (text: string, record: AuditRecord) => (
 <Space>
 <BugIcon style={{color: record.severity.color}} />
 <a onClick={() => openDrawer(record)} style={{color: "#0284c7"}}>
 {text}
 </a>
 </Space>
 ),
},
 {
 title: "严重程度",
 dataIndex: "severity",
 key: "severity",
 width: 100,
 render: (sev: SeverityLevel) => (
 <Tag
 color={sev.color}
 style={{fontWeight: 600, border: `1px solid ${sev.color}30`}}
 >
 {sev.label}
 </Tag>
 ),
},
 {
 title: "任务名称",
 dataIndex: "taskName",
 key: "taskName",
 width: 200,
 ellipsis: true,
},
 {
 title: "目标",
 dataIndex: "target",
 key: "target",
 width: 180,
 render: (t: string) => (
 <Text code style={{fontSize: 12}}>
 {t}
 </Text>
 ),
},
 {
 title: "提交时间",
 dataIndex: "submitTime",
 key: "submitTime",
 width: 170,
 sorter: (a: AuditRecord, b: AuditRecord) =>
 new Date(a.submitTime).getTime() - new Date(b.submitTime).getTime(),
},
 {
 title: "状态",
 dataIndex: "status",
 key: "status",
 width: 100,
 render: (status: string) => getStatusTag(status),
},
 {
 title: "操作",
 key: "actions",
 width: 80,
 render: (_: unknown, record: AuditRecord) => (
 <Button
 type="link"
 size="small"
 icon={<EyeOutlined />}
 style={{color: "#0284c7"}}
 onClick={() => openDrawer(record)}
 >
 审核
 </Button>
 ),
},
 ];

 // ---- render ----
 return (
 <div style={{background: "#f0f2f5", minHeight: "100vh", padding: 24}}>
 {/* Header */}
 <div style={{marginBottom: 24}}>
 <Title level={3} style={{margin: 0, color: "#0284c7"}}>
 <AuditOutlined style={{marginRight: 8}} />
 审核工作台
 </Title>
 <Text type="secondary">渗透测试结果审核 · 严控质量，精准把关</Text>
 </div>

 {/* Stats */}
 <Row gutter={[16, 16]} style={{marginBottom: 24}}>
 <Col xs={24} sm={8}>
 <Card bordered={false} style={{borderRadius: 8}}>
 <Statistic
 title="待审核"
 value={stats.pending}
 prefix={<ClockCircleOutlined style={{color: "#faad14"}} />}
 valueStyle={{color: "#faad14"}}
 />
 </Card>
 </Col>
 <Col xs={24} sm={8}>
 <Card bordered={false} style={{borderRadius: 8}}>
 <Statistic
 title="已通过"
 value={stats.approved}
 prefix={<CheckCircleOutlined style={{color: "#52c41a"}} />}
 valueStyle={{color: "#52c41a"}}
 />
 </Card>
 </Col>
 <Col xs={24} sm={8}>
 <Card bordered={false} style={{borderRadius: 8}}>
 <Statistic
 title="已驳回"
 value={stats.rejected}
 prefix={<CloseCircleOutlined style={{color: "#ff4d4f"}} />}
 valueStyle={{color: "#ff4d4f"}}
 />
 </Card>
 </Col>
 </Row>

 {/* Table */}
 <Card
 bordered={false}
 title={
 <Space>
 <SafetyOutlined style={{color: "#0284c7"}} />
 <span>审核列表</span>
 </Space>
}
 style={{borderRadius: 8}}
 >
 <Spin spinning={loading}>
 {data.length === 0 ? (
 <Empty description="暂无待审核记录" />
 ) : (
 <Table
 dataSource={data}
 columns={columns}
 rowKey="id"
 pagination={{pageSize: 10, showSizeChanger: true, showTotal: (t) => `共 ${t} 条`}}
 onRow={(record) => ({
 style: {cursor: "pointer"},
 onClick: () => openDrawer(record),
})}
 />
 )}
 </Spin>
 </Card>

 {/* Audit Drawer - 类 Code Review 界面 */}
 <Drawer
 title={
 <Space>
 <AuditOutlined style={{color: "#0284c7"}} />
 <span>漏洞审核</span>
 </Space>
}
 placement="right"
 width={720}
 open={drawerOpen}
 onClose={() => {
 setDrawerOpen(false);
 setSelected(null);
}}
 footer={
 selected?.status === "pending" ? (
 <Space style={{width: "100%", justifyContent: "space-between"}}>
 <div>
 <Text type="secondary" style={{fontSize: 12}}>
 <InfoCircleOutlined style={{marginRight: 4}} />
 审核意见将记录在案，请认真填写
 </Text>
 </div>
 <Space>
 <Button
 danger
 icon={<StopOutlined />}
 loading={submitting}
 onClick={handleReject}
 >
 驳回
 </Button>
 <Button
 type="primary"
 icon={<CheckCircleOutlined />}
 loading={submitting}
 onClick={handleApprove}
 style={{background: "#0284c7", borderColor: "#0284c7"}}
 >
 通过
 </Button>
 </Space>
 </Space>
 ) : selected ? (
 <Result
 status={selected.status === "approved" ? "success" : "error"}
 title={selected.status === "approved" ? "已审核通过" : "已驳回"}
 subTitle={`由 ${selected.submitter} 提交`}
 />
 ) : null
}
 >
 {selected && (
 <div>
 {/* 头部摘要 */}
 <Card
 size="small"
 bordered={false}
 style={{
 background: "#f0f7ff",
 borderRadius: 8,
 marginBottom: 16,
 border: "1px solid #bae0ff",
}}
 >
 <Space direction="vertical" size={4} style={{width: "100%"}}>
 <Space size="middle">
 <BugIcon style={{color: selected.severity.color, fontSize: 18}} />
 <Text strong style={{fontSize: 16}}>
 {selected.title}
 </Text>
 <Tag color={selected.severity.color} style={{fontWeight: 600}}>
 {selected.severity.label}
 </Tag>
 {getStatusTag(selected.status)}
 </Space>
 </Space>
 </Card>

 {/* 基本信息 */}
 <Descriptions column={2} size="small" bordered style={{marginBottom: 16}}>
 <Descriptions.Item label="任务名称">{selected.taskName}</Descriptions.Item>
 <Descriptions.Item label="目标">
 <Text code>{selected.target}</Text>
 </Descriptions.Item>
 <Descriptions.Item label="提交人">{selected.submitter}</Descriptions.Item>
 <Descriptions.Item label="提交时间">{selected.submitTime}</Descriptions.Item>
 </Descriptions>

 <Divider orientation="left" style={{color: "#0284c7", borderColor: "#0284c7"}}>
 <ExperimentOutlined style={{marginRight: 6}} />
 漏洞详情
 </Divider>

 {/* 漏洞描述 */}
 <Card
 size="small"
 title={
 <Space>
 <FileTextOutlined style={{color: "#0284c7"}} />
 <span>漏洞描述</span>
 </Space>
}
 bordered={false}
 style={{background: "#fafafa", borderRadius: 8, marginBottom: 12}}
 >
 <Paragraph style={{whiteSpace: "pre-wrap", margin: 0}}>
 {selected.description}
 </Paragraph>
 </Card>

 {/* 利用过程 */}
 <Card
 size="small"
 title={
 <Space>
 <ExperimentOutlined style={{color: "#0284c7"}} />
 <span>利用过程</span>
 </Space>
}
 bordered={false}
 style={{background: "#fafafa", borderRadius: 8, marginBottom: 12}}
 >
 <List
 size="small"
 dataSource={selected.exploitSteps}
 renderItem={(step) => (
 <List.Item style={{padding: "4px 0", borderBottom: "1px dashed #e8e8e8"}}>
 <Text code style={{fontSize: 12, whiteSpace: "pre-wrap"}}>
 {step}
 </Text>
 </List.Item>
 )}
 />
 </Card>

 {/* 截图证据 */}
 <Card
 size="small"
 title={
 <Space>
 <EyeOutlined style={{color: "#0284c7"}} />
 <span>截图证据</span>
 </Space>
}
 bordered={false}
 style={{background: "#fafafa", borderRadius: 8, marginBottom: 12}}
 >
 <List
 size="small"
 dataSource={selected.screenshots}
 renderItem={(screenshot) => (
 <List.Item style={{padding: "4px 0"}}>
 <Space>
 <Tag color="blue">{screenshot}</Tag>
 <Button type="link" size="small" style={{color: "#0284c7", padding: 0}}>
 查看
 </Button>
 </Space>
 </List.Item>
 )}
 />
 {selected.screenshots.length === 0 && (
 <Text type="secondary">暂无截图证据</Text>
 )}
 </Card>

 {/* 审核意见 - 仅待审核显示 */}
 {selected.status === "pending" && (
 <>
 <Divider
 orientation="left"
 style={{color: "#0284c7", borderColor: "#0284c7"}}
 >
 <MessageOutlined style={{marginRight: 6}} />
 审核意见
 </Divider>
 <Alert
 message="审核提示"
 description="请基于漏洞描述、利用过程和截图证据综合判断。确认漏洞真实存在且危害等级准确后点击通过，否则填写驳回理由。"
 type="info"
 showIcon
 style={{marginBottom: 12}}
 />
 <TextArea
 rows={4}
 placeholder="请输入审核意见或驳回理由..."
 value={auditOpinion}
 onChange={(e) => setAuditOpinion(e.target.value)}
 style={{borderRadius: 6}}
 />
 </>
 )}
 </div>
 )}
 </Drawer>
 </div>
 );
};

export default ApprovalWorkbenchPage;
