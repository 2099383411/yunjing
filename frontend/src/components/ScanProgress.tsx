import { Typography } from "antd";
import CheckCircleOutlined from "@ant-design/icons/es/icons/CheckCircleOutlined";
import LoadingOutlined from "@ant-design/icons/es/icons/LoadingOutlined";
import CloseCircleOutlined from "@ant-design/icons/es/icons/CloseCircleOutlined";
<<<<<<< HEAD
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined";;
=======
import ClockCircleOutlined from "@ant-design/icons/es/icons/ClockCircleOutlined"
>>>>>>> server/master

const { Text } = Typography;

interface Step {
  name: string;
  status: "pending" | "running" | "completed" | "failed";
  progress?: number;
}

export default function ScanProgress({ steps, current }: { steps: Step[]; current: string }) {
  return (
    <div
      style={{
        padding: "12px 16px",
        borderRadius: 8,
        background: "rgba(59, 130, 246, 0.04)",
        border: "1px solid rgba(59, 130, 246, 0.1)",
      }}
    >
      <Text style={{ color: "#94a3b8", fontSize: 12, marginBottom: 8, display: "block" }}>
        扫描进度
      </Text>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {steps.map((step, i) => {
          const Icon =
            step.status === "completed"
              ? CheckCircleOutlined
              : step.status === "running"
              ? LoadingOutlined
              : step.status === "failed"
              ? CloseCircleOutlined
              : ClockCircleOutlined;

          const color =
            step.status === "completed"
              ? "#00ff88"
              : step.status === "running"
              ? "#3b82f6"
              : step.status === "failed"
              ? "#ff3355"
              : "#64748b";

          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Icon style={{ color, fontSize: 12 }} />
              <Text style={{ color, fontSize: 12 }}>
                {step.name}
              </Text>
              {step.progress != null && step.status === "running" && (
                <div
                  style={{
                    flex: 1, height: 3, borderRadius: 2,
                    background: "#1e293b", maxWidth: 100,
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      width: `${step.progress}%`, height: "100%",
                      background: "linear-gradient(90deg, #3b82f6, #1d4ed8)",
                      borderRadius: 2,
                      transition: "width 0.5s ease",
                    }}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
