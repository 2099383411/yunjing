import { useState, useEffect } from "react";
import {
  Table, Card, Tag, Button, Input, Typography, Space, Switch,
  message, Modal, Upload, Row, Col, Spin, Empty, Tooltip, Badge,
  Alert, Divider, List, Rate, Tabs,
} from "antd";
import SearchOutlined from "@ant-design/icons/es/icons/SearchOutlined";
import ReloadOutlined from "@ant-design/icons/es/icons/ReloadOutlined";
import DownloadOutlined from "@ant-design/icons/es/icons/DownloadOutlined";
import UploadOutlined from "@ant-design/icons/es/icons/UploadOutlined";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
import ExclamationCircleOutlined from "@ant-design/icons/es/icons/ExclamationCircleOutlined";
import SettingOutlined from "@ant-design/icons/es/icons/SettingOutlined";
import StarOutlined from "@ant-design/icons/es/icons/StarOutlined";
import DeleteOutlined from "@ant-design/icons/es/icons/DeleteOutlined";;
import request from "../api/request";

const { Title, Text, Paragraph } = Typography;

const INSTALLED = [
  { name: "nmap", version: "7.95", status: "active", category: "扫描", desc: "网络发现和安全审计", rating: 5, author: "Insecure.org" },
  { name: "nuclei", version: "3.3.4", status: "active", category: "漏洞扫描", desc: "基于YAML模板的快速漏洞扫描", rating: 5, author: "ProjectDiscovery" },
  { name: "sqlmap", version: "1.8.12", status: "active", category: "注入检测", desc: "自动化SQL注入检测与利用", rating: 5, author: "Bernardo Damele" },
  { name: "hydra", version: "9.6", status: "active", category: "暴力破解", desc: "并行化网络登录破解工具", rating: 4, author: "van Hauser" },
  { name: "xray", version: "1.9.11", status: "active", category: "漏洞扫描", desc: "被动式Web漏洞扫描器", rating: 5, author: "Chaitin Tech" },
  { name: "ffuf", version: "2.1.0", status: "active", category: "目录发现", desc: "快速Web模糊测试工具", rating: 4, author: "ffuf" },
  { name: "metasploit", version: "6.4", status: "active", category: "渗透框架", desc: "渗透测试利用框架", rating: 5, author: "Rapid7" },
];

const MARKET = [
  { name: "amass", version: "4.2.0", category: "信息收集", desc: "主动子域名枚举工具", author: "OWASP", downloads: "15K+" },
  { name: "masscan", version: "1.3.2", category: "扫描", desc: "大规模端口扫描器（10万包/秒）", author: "Robert Graham", downloads: "8K+" },
  { name: "gobuster", version: "3.6.0", category: "目录发现", desc: "目录/文件/DNS暴力枚举", author: "OJ Reeves", downloads: "12K+" },
  { name: "bloodhound", version: "4.3.1", category: "AD测试", desc: "Active Directory攻击路径分析", author: "SpecterOps", downloads: "6K+" },
  { name: "responder", version: "3.1.4", category: "中继攻击", desc: "LLMNR/NBT-NS/mDNS投毒工具", author: "lgandx", downloads: "5K+" },
  { name: "jadx", version: "1.5.0", category: "逆向", desc: "Dex到Java反编译器", author: "skylot", downloads: "3K+" },
];

const STATUS_MAP: Record<string, { color: string; label: string }> = {
  active: { color: "green", label: "已启用" },
  inactive: { color: "default", label: "已禁用" },
  updating: { color: "blue", label: "更新中" },
};

const CAT_COLORS: Record<string, string> = {
  "扫描": "blue", "漏洞扫描": "red", "注入检测": "purple", "暴力破解": "orange",
  "目录发现": "cyan", "渗透框架": "geekblue", "信息收集": "green",
  "AD测试": "volcano", "中继攻击": "magenta", "逆向": "gold",
};

export default function SkillMarketPage() {
  const [tab, setTab] = useState("installed");
  const [installed, setInstalled] = useState(INSTALLED);
  const [marketData, setMarketData] = useState(MARKET);
  const [searchInstalled, setSearchInstalled] = useState("");
  const [searchMarket, setSearchMarket] = useState("");

  const handleToggle = (name: string) => {
    setInstalled((prev) => prev.map((s) => s.name === name ? { ...s, status: s.status === "active" ? "inactive" : "active" } : s));
    message.success(`已${installed.find((s) => s.name === name)?.status === "active" ? "禁用" : "启用"} ${name}`);
  };

  const handleUninstall = (name: string) => {
    Modal.confirm({ title: `确认卸载 ${name}?`, content: "卸载后相关配置将被清除", onOk: () => {
      setInstalled((prev) => prev.filter((s) => s.name !== name));
      message.success(`已卸载 ${name}`);
    }});
  };

  const handleInstall = (item: any) => {
    Modal.confirm({ title: `安装 ${item.name} v${item.version}`, content: `将从市场安装 ${item.name} 工具`, onOk: () => {
      setInstalled((prev) => [...prev, { ...item, status: "active", rating: 3 }]);
      message.success(`正在安装 ${item.name}...`);
    }});
  };

  const installedFiltered = installed.filter((s) => !searchInstalled || s.name.includes(searchInstalled) || s.desc.includes(searchInstalled));
  const marketFiltered = marketData.filter((s) => !searchMarket || s.name.includes(searchMarket) || s.desc.includes(searchMarket));

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Title level={4} style={{ margin: 0, color: "#0284c7" }}>技能管理</Title>
        <Space>
          <Upload showUploadList={false} beforeUpload={() => false}>
            <Button icon={<UploadOutlined />}>拖拽导入 .claw 文件</Button>
          </Upload>
          <Button icon={<ReloadOutlined />}>刷新</Button>
        </Space>
      </div>

      <Card>
        <Tabs defaultActiveKey="installed" onChange={setTab} items={[
          {
            key: "installed",
            label: `已安装 (${installed.length})`,
            children: (
              <div>
                <Input placeholder="搜索已安装技能..." prefix={<SearchOutlined />} style={{ width: 300, marginBottom: 16 }}
                  value={searchInstalled} onChange={(e) => setSearchInstalled(e.target.value)} allowClear />
                <Table dataSource={installedFiltered} rowKey="name" pagination={false} columns={[
                  { title: "名称", dataIndex: "name", key: "name", render: (v: string) => <Text strong>{v}</Text> },
                  { title: "版本", dataIndex: "version", key: "version" },
                  { title: "分类", dataIndex: "category", key: "category", render: (v: string) => <Tag color={CAT_COLORS[v]}>{v}</Tag> },
                  { title: "描述", dataIndex: "desc", key: "desc" },
                  { title: "评分", dataIndex: "rating", key: "rating", render: (v: number) => <Rate disabled defaultValue={v} style={{ fontSize: 14 }} /> },
                  { title: "状态", dataIndex: "status", key: "status", render: (v: string) => <Badge status={STATUS_MAP[v]?.color as any} text={STATUS_MAP[v]?.label || v} /> },
                  {
                    title: "操作", key: "action",
                    render: (_: any, r: any) => (
                      <Space>
                        <Switch checked={r.status === "active"} onChange={() => handleToggle(r.name)} size="small" />
                        <Tooltip title="卸载"><Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleUninstall(r.name)} /></Tooltip>
                      </Space>
                    ),
                  },
                ]} />
              </div>
            ),
          },
          {
            key: "market",
            label: "技能市场",
            children: (
              <div>
                <Input placeholder="搜索市场技能..." prefix={<SearchOutlined />} style={{ width: 300, marginBottom: 16 }}
                  value={searchMarket} onChange={(e) => setSearchMarket(e.target.value)} allowClear />
                <Table dataSource={marketFiltered} rowKey="name" pagination={false} columns={[
                  { title: "名称", dataIndex: "name", key: "name", render: (v: string) => <Text strong>{v}</Text> },
                  { title: "版本", dataIndex: "version", key: "version" },
                  { title: "分类", dataIndex: "category", key: "category", render: (v: string) => <Tag color={CAT_COLORS[v]}>{v}</Tag> },
                  { title: "描述", dataIndex: "desc", key: "desc" },
                  { title: "作者", dataIndex: "author", key: "author" },
                  { title: "下载", dataIndex: "downloads", key: "downloads" },
                  {
                    title: "操作", key: "action",
                    render: (_: any, r: any) => (
                      <Button type="primary" size="small" icon={<DownloadOutlined />} onClick={() => handleInstall(r)}>
                        安装
                      </Button>
                    ),
                  },
                ]} />
              </div>
            ),
          },
        ]} />
      </Card>
    </div>
  );
}
