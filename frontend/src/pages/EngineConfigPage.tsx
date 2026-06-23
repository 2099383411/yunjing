import {useState, useEffect} from "react";
import {
 Card, Form, Input, InputNumber, Select, Switch, Button, Typography,
 Space, Divider, Spin, message, Row, Col, Alert, Tabs,
} from "antd";






import request from "../api/request";
import BugIcon from "../components/BugIcon";
import SaveOutlined from "@ant-design/icons/es/icons/SaveOutlined";
import UndoOutlined from "@ant-design/icons/es/icons/UndoOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import ThunderboltOutlined from "@ant-design/icons/es/icons/ThunderboltOutlined";
import GlobalOutlined from "@ant-design/icons/es/icons/GlobalOutlined";
import FileTextOutlined from "@ant-design/icons/es/icons/FileTextOutlined";;

const {Title, Text} = Typography;

const DEFAULT_VALUES = {
 scan: {
 concurrency: 10,
 timeout: 300,
 retry_count: 3,
 scan_rate: 100,
},
 network: {
 proxy: "",
 dns: "8.8.8.8",
 interface_bind: "",
},
 report: {
 default_format: "html",
 auto_generate: true,
 screenshot_enabled: true,
},
 advanced: {
 log_level: "info",
 max_log_days: 30,
 enable_telemetry: false,
 debug_mode: false,
},
};

const tabItems = [
 {key: "scan", label: "扫描配置", icon: <ThunderboltOutlined />},
 {key: "network", label: "网络配置", icon: <GlobalOutlined />},
 {key: "report", label: "报告配置", icon: <FileTextOutlined />},
 {key: "advanced", label: "高级设置", icon: <BugIcon />},
];

export default function EngineConfigPage() {
 const [form] = Form.useForm();
 const [loading, setLoading] = useState(false);
 const [saving, setSaving] = useState(false);
 const [activeTab, setActiveTab] = useState("scan");

 useEffect(() => {
 fetchConfig();
}, []);

 const fetchConfig = async () => {
 setLoading(true);
 try {
 const res = await request.get("/engine/config");
 if (res.data) form.setFieldsValue(res.data);
} catch {
 form.setFieldsValue(DEFAULT_VALUES);
} finally {
 setLoading(false);
}
};

 const handleSave = async () => {
 setSaving(true);
 try {
 const values = await form.validateFields();
 await request.post("/engine/config", values);
 message.success("配置已保存");
} catch {
 message.error("保存失败，使用 mock 模式");
} finally {
 setSaving(false);
}
};

 const handleReset = () => {
 form.setFieldsValue(DEFAULT_VALUES);
 message.info("已重置为默认值");
};

 if (loading) {
 return (
 <div style={{display: "flex", justifyContent: "center", alignItems: "center", minHeight: 400}}>
 <Spin size="large" tip="加载配置中..." />
 </div>
 );
}

 return (
 <div>
 {/* Page Header */}
 <div style={{marginBottom: 20}}>
 <Title level={4} style={{margin: 0, color: "#0284c7"}}>
 <SettingOutlined style={{marginRight: 8}} />
 引擎配置
 </Title>
 <Text type="secondary">配置渗透测试引擎的运行参数</Text>
 </div>

 <Tabs
 activeKey={activeTab}
 onChange={setActiveTab}
 items={tabItems}
 style={{marginBottom: 16}}
 />

 <Card style={{borderRadius: 8, border: "1px solid #e8e8e8"}}>
 <Form form={form} layout="vertical" initialValues={DEFAULT_VALUES}>
 {/* 扫描配置 */}
 {activeTab === "scan" && (
 <Row gutter={[24, 0]}>
 <Col span={8}>
 <Form.Item label="并发数" name={["scan", "concurrency"]} rules={[{required: true, message: "请输入并发数"}]}>
 <InputNumber min={1} max={100} style={{width: "100%"}} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="超时时间 (秒)" name={["scan", "timeout"]} rules={[{required: true}]}>
 <InputNumber min={10} max={3600} style={{width: "100%"}} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="重试次数" name={["scan", "retry_count"]} rules={[{required: true}]}>
 <InputNumber min={0} max={10} style={{width: "100%"}} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="扫描速率 (包/秒)" name={["scan", "scan_rate"]}>
 <InputNumber min={1} max={10000} style={{width: "100%"}} />
 </Form.Item>
 </Col>
 </Row>
 )}

 {/* 网络配置 */}
 {activeTab === "network" && (
 <Row gutter={[24, 0]}>
 <Col span={12}>
 <Form.Item label="代理地址" name={["network", "proxy"]}>
 <Input placeholder="socks5://127.0.0.1:1080" />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="DNS 服务器" name={["network", "dns"]}>
 <Input placeholder="8.8.8.8" />
 </Form.Item>
 </Col>
 <Col span={12}>
 <Form.Item label="绑定网卡" name={["network", "interface_bind"]}>
 <Input placeholder="eth0" />
 </Form.Item>
 </Col>
 </Row>
 )}

 {/* 报告配置 */}
 {activeTab === "report" && (
 <Row gutter={[24, 0]}>
 <Col span={8}>
 <Form.Item label="默认格式" name={["report", "default_format"]}>
 <Select options={[
 {value: "html", label: "HTML"},
 {value: "pdf", label: "PDF"},
 {value: "word", label: "Word"},
 {value: "excel", label: "Excel"},
 ]} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="自动生成报告" name={["report", "auto_generate"]} valuePropName="checked">
 <Switch />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="启用截图" name={["report", "screenshot_enabled"]} valuePropName="checked">
 <Switch />
 </Form.Item>
 </Col>
 </Row>
 )}

 {/* 高级设置 */}
 {activeTab === "advanced" && (
 <Row gutter={[24, 0]}>
 <Col span={8}>
 <Form.Item label="日志级别" name={["advanced", "log_level"]}>
 <Select options={[
 {value: "debug", label: "Debug"},
 {value: "info", label: "Info"},
 {value: "warn", label: "Warn"},
 {value: "error", label: "Error"},
 ]} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="日志保留天数" name={["advanced", "max_log_days"]}>
 <InputNumber min={1} max={365} style={{width: "100%"}} />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="遥测采集" name={["advanced", "enable_telemetry"]} valuePropName="checked">
 <Switch />
 </Form.Item>
 </Col>
 <Col span={8}>
 <Form.Item label="调试模式" name={["advanced", "debug_mode"]} valuePropName="checked">
 <Switch />
 </Form.Item>
 </Col>
 </Row>
 )}

 <Divider />
 <div style={{display: "flex", gap: 12}}>
 <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={handleSave} style={{background: "#0284c7", borderColor: "#0284c7"}}>
 保存配置
 </Button>
 <Button icon={<UndoOutlined />} onClick={handleReset}>恢复默认</Button>
 </div>
 </Form>
 </Card>
 </div>
 );
}
