#!/usr/bin/env python3
"""Enhance CredentialsSettings and NotificationsSettings in SettingsPage.tsx"""
import re

path = "/root/yunjing/frontend_nextgen/src/pages/SettingsPage.tsx"

with open(path) as f:
    c = f.read()

# ===== Fix 1: CredentialsSettings with real delete + create =====
old_creds = '''const CredentialsSettings = () => {
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    request.get("/api-keys/").then(res => {
      if (res?.data) {
        const items = Array.isArray(res.data) ? res.data : (res.data.keys || res.data.items || []);
        setApiKeys(items.map((k: any) => ({
          name: k.name || "-",
          key: k.key_prefix || "(未显示)",
          type: k.type || "API Key",
          status: k.is_active ? "valid" : "expired",
          lastUsed: k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "从未使用",
        })));
      }
      setLoading(false);
    }).catch(() => { setLoading(false); message.warning("加载凭证列表失败"); });
  }, []);

  return (
    <Card title="凭证管理 (API Key)" style={{ borderRadius: 8 }}
      extra={<Button type="primary" style={{ background: "#0284c7" }} icon={<PlusOutlined />}>新增凭证</Button>}>
      <Table dataSource={apiKeys} rowKey="name" pagination={false} loading={loading}
        locale={{ emptyText: <Empty description="暂无凭证" /> }}
        columns={[
          { title: "名称", dataIndex: "name" },
          { title: "密钥", dataIndex: "key", render: (v: string) => <Text code>{v}</Text> },
          { title: "类型", dataIndex: "type" },
          { title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "valid" ? "green" : "red"}>{v === "valid" ? "有效" : "已过期"}</Tag> },
          { title: "最后使用", dataIndex: "lastUsed" },
          { title: "操作", render: (_: any, record: any) => <Space><a onClick={() => message.info(`编辑 ${record.name}`)}>编辑</a><a onClick={() => message.info(`删除 ${record.name}`)}>删除</a></Space> },
        ]}
      />
    </Card>
  );
};'''

new_creds = '''const CredentialsSettings = () => {
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyResult, setNewKeyResult] = useState("");

  const fetchKeys = () => {
    setLoading(true);
    request.get("/api-keys/").then(res => {
      if (res?.data) {
        const items = Array.isArray(res.data) ? res.data : (res.data.keys || res.data.items || []);
        setApiKeys(items.map((k: any) => ({
          id: k.id,
          name: k.name || "-",
          key: k.key_prefix || "(未显示)",
          type: k.type || "API Key",
          status: k.is_active ? "valid" : "expired",
          lastUsed: k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "从未使用",
        })));
      }
      setLoading(false);
    }).catch(() => { setLoading(false); message.warning("加载凭证列表失败"); });
  };

  useEffect(() => { fetchKeys(); }, []);

  const handleDelete = (record: any) => {
    Modal.confirm({
      title: "确认删除",
      content: `确定删除凭证 "${record.name}"？此操作不可恢复。`,
      okText: "确定删除",
      okType: "danger",
      cancelText: "取消",
      onOk: async () => {
        try {
          await request.delete(\`/api-keys/\${record.id}\`);
          message.success("删除成功");
          fetchKeys();
        } catch { message.error("删除失败"); }
      }
    });
  };

  const handleCreate = async () => {
    if (!newKeyName.trim()) { message.warning("请输入凭证名称"); return; }
    try {
      const res = await request.post("/api-keys/", { name: newKeyName.trim() });
      setNewKeyResult(res?.data?.api_key || "(创建成功)");
      message.success("凭证已创建");
      fetchKeys();
    } catch {
      message.error("创建凭证失败");
    }
  };

  const handleCloseModal = () => {
    setModalOpen(false);
    setNewKeyName("");
    setNewKeyResult("");
  };

  return (
    <Card title="凭证管理 (API Key)" style={{ borderRadius: 8 }}
      extra={<Button type="primary" style={{ background: "#0284c7" }} icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>新增凭证</Button>}>
      <Table dataSource={apiKeys} rowKey="id" pagination={false} loading={loading}
        locale={{ emptyText: <Empty description="暂无凭证" /> }}
        columns={[
          { title: "名称", dataIndex: "name" },
          { title: "密钥前缀", dataIndex: "key", render: (v: string) => <Text code>{v}</Text> },
          { title: "类型", dataIndex: "type" },
          { title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "valid" ? "green" : "red"}>{v === "valid" ? "有效" : "已过期"}</Tag> },
          { title: "最后使用", dataIndex: "lastUsed" },
          { title: "操作", render: (_: any, record: any) => <Space><a onClick={() => handleDelete(record)} style={{ color: "#ff4d4f" }}>删除</a></Space> },
        ]}
      />
      <Modal title="新增 API Key" open={modalOpen} onCancel={handleCloseModal} footer={null}>
        {newKeyResult ? (
          <div>
            <Alert type="success" message="凭证已创建" description="请立即复制保存，此 Key 不会再显示。" showIcon style={{ marginBottom: 16 }} />
            <Input.TextArea value={newKeyResult} readOnly rows={3} style={{ marginBottom: 16, fontSize: 14, fontWeight: "bold" }} />
            <Button type="primary" style={{ background: "#0284c7" }} onClick={handleCloseModal}>我已保存，关闭</Button>
          </div>
        ) : (
          <div>
            <Form.Item label="凭证名称" style={{ marginBottom: 16 }}>
              <Input value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder="例如：开发环境 Key" />
            </Form.Item>
            <Button type="primary" style={{ background: "#0284c7" }} onClick={handleCreate}>生成 Key</Button>
          </div>
        )}
      </Modal>
    </Card>
  );
};'''

if old_creds in c:
    c = c.replace(old_creds, new_creds)
    print("CredentialsSettings enhanced!")
else:
    print("WARNING: Could not find CredentialsSettings block to replace")
    # Find relevant section to debug
    import re
    match = re.search(r'const CredentialsSettings = .*?\);\n\n', c, re.DOTALL)
    if match:
        print(f"Found at: {match.start()}-{match.end()}")
        print(f"Length: {len(match.group())}")
    else:
        print("Regex also failed to find")

# ===== Fix 2: Add Modal import if not present =====
if "Modal," not in c:
    c = c.replace(
        "Empty, message, Spin,",
        "Empty, message, Modal, Spin,"
    )
    print("Added Modal import!")

# ===== Fix 3: NotificationsSettings - Add edit modal =====
old_notif = '''          { title: "操作", render: (_: any, __: any, i: number) => <Space><a onClick={() => message.info(`编辑 ${channels[i]?.name}`)}>编辑</a><a onClick={() => message.loading(\`测试 ${channels[i]?.name}...\`)}>测试</a></Space> },'''

new_notif = '''          { title: "操作", render: (_: any, __: any, i: number) => <Space><a onClick={() => {
              const ch = channels[i];
              Modal.confirm({
                title: \`编辑 \${ch?.name}\`,
                content: <div><Form.Item label="名称"><Input id="edit-notif-name" defaultValue={ch?.name} /></Form.Item><Form.Item label="地址/URL"><Input id="edit-notif-url" defaultValue={ch?.webhook || ch?.url || ch?.smtp || ""} /></Form.Item></div>,
                onOk: () => {
                  const nameInput = document.getElementById("edit-notif-name") as HTMLInputElement;
                  const urlInput = document.getElementById("edit-notif-url") as HTMLInputElement;
                  const updated = [...channels];
                  updated[i] = { ...updated[i], name: nameInput?.value || ch.name, webhook: urlInput?.value || ch.webhook, url: urlInput?.value || ch.url };
                  setChannels(updated);
                  request.put("/notifications/channels", { channels: updated }).then(() => message.success("已更新")).catch(() => message.error("保存失败"));
                }
              });
            }}>编辑</a><a onClick={() => message.loading(\`测试 \${channels[i]?.name}...\`)}>测试</a></Space> },'''

if old_notif in c:
    c = c.replace(old_notif, new_notif)
    print("NotificationsSettings enhanced!")
else:
    print("WARNING: Could not find NotificationsSettings edit column")

# ===== Fix 4: ReportTemplateSettings - add create/delete modal =====
old_tmpl = '''const ReportTemplateSettings = () => {
  const [templates, setTemplates] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    request.get("/report-templates/templates").then(res => {
      if (res?.data?.templates) {
        setTemplates(res.data.templates.map((t: any) => ({
          name: t.name || "-",
          format: t.format || "-",
          sections: Array.isArray(t.sections) ? t.sections.join(", ") : t.sections || "-",
          lastUsed: t.last_used ? new Date(t.last_used).toLocaleString() : "从未使用",
          status: t.is_default ? "默认" : (t.is_active ? "启用" : "停用"),
        })));
      }
      setLoading(false);
    }).catch(() => { setLoading(false); message.warning("加载报告模板失败"); });
  }, []);

  return (
    <Card title="报告模板管理" style={{ borderRadius: 8 }}
      extra={<Button type="primary" style={{ background: "#0284c7" }} icon={<PlusOutlined />}>新建模板</Button>}>
      <Table dataSource={templates} rowKey="name" pagination={false} loading={loading}
        locale={{ emptyText: <Empty description="暂无报告模板" /> }}
        columns={[
          { title: "模板名称", dataIndex: "name" },
          { title: "格式", dataIndex: "format" },
          { title: "内容章节", dataIndex: "sections" },
          { title: "最后使用", dataIndex: "lastUsed" },
          { title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "默认" ? "blue" : v === "启用" ? "green" : "default"}>{v}</Tag> },
          { title: "操作", render: () => <Space><a>预览</a><a>编辑</a><a>设为默认</a></Space> },
        ]}
      />
    </Card>
  );
};'''

new_tmpl = '''const ReportTemplateSettings = () => {
  const [templates, setTemplates] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [newTmpl, setNewTmpl] = useState({ name: "", format: "PDF", sections: "" });

  const fetchTemplates = () => {
    setLoading(true);
    request.get("/report-templates/templates").then(res => {
      if (res?.data?.templates) {
        setTemplates(res.data.templates.map((t: any) => ({
          id: t.id || t.name,
          name: t.name || "-",
          format: t.format || "-",
          sections: Array.isArray(t.sections) ? t.sections.join(", ") : t.sections || "-",
          lastUsed: t.last_used ? new Date(t.last_used).toLocaleString() : "从未使用",
          status: t.is_default ? "默认" : (t.is_active ? "启用" : "停用"),
        })));
      }
      setLoading(false);
    }).catch(() => { setLoading(false); message.warning("加载报告模板失败"); });
  };

  useEffect(() => { fetchTemplates(); }, []);

  const handleCreate = async () => {
    if (!newTmpl.name.trim()) { message.warning("请输入模板名称"); return; }
    try {
      const existing = templates.filter(t => true);
      const updated = [...existing, { id: Date.now().toString(), ...newTmpl, is_active: true, sections: newTmpl.sections.split(",").map(s => s.trim()) }];
      await request.put("/report-templates/templates", { templates: updated });
      message.success("模板已创建");
      setModalOpen(false);
      setNewTmpl({ name: "", format: "PDF", sections: "" });
      fetchTemplates();
    } catch { message.error("创建模板失败"); }
  };

  const handleDelete = (name: string) => {
    Modal.confirm({
      title: "确认删除",
      content: \`确定删除模板 "\${name}"？\`,
      okText: "确定", cancelText: "取消",
      onOk: async () => {
        try {
          const remaining = templates.filter(t => t.name !== name);
          await request.put("/report-templates/templates", { templates: remaining });
          message.success("已删除");
          fetchTemplates();
        } catch { message.error("删除失败"); }
      }
    });
  };

  return (
    <Card title="报告模板管理" style={{ borderRadius: 8 }}
      extra={<Button type="primary" style={{ background: "#0284c7" }} icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>新建模板</Button>}>
      <Table dataSource={templates} rowKey="id" pagination={false} loading={loading}
        locale={{ emptyText: <Empty description="暂无报告模板" /> }}
        columns={[
          { title: "模板名称", dataIndex: "name" },
          { title: "格式", dataIndex: "format" },
          { title: "内容章节", dataIndex: "sections" },
          { title: "最后使用", dataIndex: "lastUsed" },
          { title: "状态", dataIndex: "status", render: (v: string) => <Tag color={v === "默认" ? "blue" : v === "启用" ? "green" : "default"}>{v}</Tag> },
          { title: "操作", render: (_: any, record: any) => <Space>
            <a onClick={() => message.info("预览功能待实现")}>预览</a>
            <a onClick={() => { setNewTmpl({ name: record.name, format: record.format, sections: record.sections }); setModalOpen(true); }}>编辑</a>
            <a onClick={() => handleDelete(record.name)} style={{ color: "#ff4d4f" }}>删除</a>
          </Space> },
        ]}
      />
      <Modal title={newTmpl.name ? "编辑模板" : "新建模板"} open={modalOpen} onCancel={() => { setModalOpen(false); setNewTmpl({ name: "", format: "PDF", sections: "" }); }}
        onOk={handleCreate} okText="保存">
        <Form.Item label="模板名称"><Input value={newTmpl.name} onChange={e => setNewTmpl(p => ({...p, name: e.target.value}))} /></Form.Item>
        <Form.Item label="格式">
          <Select value={newTmpl.format} onChange={v => setNewTmpl(p => ({...p, format: v}))} options={[{value:"PDF",label:"PDF"},{value:"Word",label:"Word"},{value:"HTML",label:"HTML"},{value:"Excel",label:"Excel"}]} />
        </Form.Item>
        <Form.Item label="内容章节（逗号分隔）"><Input value={newTmpl.sections} onChange={e => setNewTmpl(p => ({...p, sections: e.target.value}))} /></Form.Item>
      </Modal>
    </Card>
  );
};'''

if old_tmpl in c:
    c = c.replace(old_tmpl, new_tmpl)
    print("ReportTemplateSettings enhanced!")
else:
    print("WARNING: Could not find ReportTemplateSettings block")

with open(path, 'w') as f:
    f.write(c)

print("\nDone!")
