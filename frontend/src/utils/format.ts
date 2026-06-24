export const severityColor: Record<string, string> = {
  critical: "#ff4d4f", high: "#ff7a45", medium: "#ffa940", low: "#73d13d", info: "#1677ff",
};

export const severityLabel: Record<string, string> = {
  critical: "紧急", high: "高危", medium: "中危", low: "低危", info: "信息",
};

export const formatDate = (date: string) => new Date(date).toLocaleString("zh-CN");
