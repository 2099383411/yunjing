/**
 * WebSocket client for real-time scan progress
 */
export type ScanEventType = "status" | "phase" | "vuln_findings" | "completed" | "failed";

export interface ScanEvent {
  type: ScanEventType;
  task_id: string;
  timestamp: string;
  data: {
    phase?: string;
    status?: string;
    progress?: number;
    ports?: number[];
    count?: number;
    source?: string;
    error?: string;
    summary?: any;
    elapsed?: number;
  };
}

export function connectScanWS(
  taskId: string,
  onEvent: (event: ScanEvent) => void,
  onError?: (err: Event) => void,
  onClose?: () => void
) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/api/ws/scan/${taskId}`;
  const ws = new WebSocket(url);

  ws.onmessage = (event) => {
    try {
      const data: ScanEvent = JSON.parse(event.data);
      onEvent(data);
    } catch {
      console.error("Scan WS: failed to parse message", event.data);
    }
  };

  ws.onerror = (err) => {
    console.error("Scan WS error:", err);
    onError?.(err);
  };

  ws.onclose = () => {
    onClose?.();
  };

  return {
    close: () => {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
    },
    readyState: () => ws.readyState,
  };
}
