export function createWebSocket(sessionId: string, onMessage: (data: any) => void) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${protocol}//${window.location.host}/api/chat/ws/${sessionId}`);

  ws.onmessage = (event) => {
    try { onMessage(JSON.parse(event.data)); } catch { console.error("WS parse error"); }
  };
  ws.onerror = (err) => console.error("WS error:", err);
  ws.onclose = () => console.log("WS closed");

  return {
    send: (message: string) => ws.send(JSON.stringify({ message })),
    close: () => ws.close(),
  };
}
