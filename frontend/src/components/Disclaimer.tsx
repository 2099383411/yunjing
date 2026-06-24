import { Modal, Checkbox, Space, Typography } from "antd";
import { useState } from "react";
<<<<<<< HEAD
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined";;
=======
import SafetyOutlined from "@ant-design/icons/es/icons/SafetyOutlined"
>>>>>>> server/master

const { Text } = Typography;

export default function Disclaimer({
  open,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [checked, setChecked] = useState([false, false, false]);
  const allChecked = checked.every(Boolean);

  const handleConfirm = () => {
    if (!allChecked) return;
    setChecked([false, false, false]);
    onConfirm();
  };

  const handleCancel = () => {
    setChecked([false, false, false]);
    onCancel();
  };

  return (
    <Modal
      title={
        <Space>
          <SafetyOutlined style={{ color: "#3b82f6" }} />
          <Text style={{ color: "#e2e8f0" }}>授权确认</Text>
        </Space>
      }
      open={open}
      closable={false}
      onOk={handleConfirm}
      okText="我确认已获授权"
      okButtonProps={{
        disabled: !allChecked,
        style: { borderRadius: 8 },
      }}
      cancelButtonProps={{ style: { display: "none" } }}
      style={{ borderRadius: 12 }}
      styles={{
        header: { background: "transparent", borderBottom: "1px solid #1e293b" },
        body: { padding: "20px 24px" },
        footer: { borderTop: "1px solid #1e293b" },
      }}
    >
      <Text style={{ color: "#e2e8f0", display: "block", marginBottom: 16, lineHeight: 1.6 }}>
        即将对目标进行安全检测。请逐条确认以下事项：
      </Text>

      <Space direction="vertical" style={{ width: "100%" }}>
        <Checkbox
          checked={checked[0]}
          onChange={(e) =>
            setChecked((c) => [e.target.checked, c[1], c[2]])
          }
          style={{ color: "#94a3b8" }}
        >
          <Text style={{ color: checked[0] ? "#e2e8f0" : "#94a3b8", fontSize: 13 }}>
            我已获得目标资产的<b>合法书面授权</b>
          </Text>
        </Checkbox>
        <Checkbox
          checked={checked[1]}
          onChange={(e) =>
            setChecked((c) => [c[0], e.target.checked, c[2]])
          }
          style={{ color: "#94a3b8" }}
        >
          <Text style={{ color: checked[1] ? "#e2e8f0" : "#94a3b8", fontSize: 13 }}>
            我承诺扫描行为<b>仅限于授权范围</b>，不进行非授权攻击
          </Text>
        </Checkbox>
        <Checkbox
          checked={checked[2]}
          onChange={(e) =>
            setChecked((c) => [c[0], c[1], e.target.checked])
          }
          style={{ color: "#94a3b8" }}
        >
          <Text style={{ color: checked[2] ? "#e2e8f0" : "#94a3b8", fontSize: 13 }}>
            我了解扫描可能对目标造成<b>性能影响</b>，已通知相关方
          </Text>
        </Checkbox>
      </Space>
    </Modal>
  );
}
