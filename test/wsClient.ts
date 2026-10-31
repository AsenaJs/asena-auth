export type WsOutcome = { opened: true; protocol: string; message: any } | { opened: false };

/** Opens a socket and reports the negotiated subprotocol and the first message, or that it never opened. */
export function connect(url: string, init?: string[] | { headers?: Record<string, string>; protocols?: string[] }) {
  return new Promise<WsOutcome>((resolve) => {
    const ws = new (WebSocket as any)(url, init) as WebSocket;
    let opened = false;

    ws.onopen = () => {
      opened = true;
    };
    ws.onmessage = (event) => {
      resolve({ opened: true, protocol: ws.protocol, message: JSON.parse(String(event.data)) });
      ws.close();
    };
    ws.onclose = () => {
      if (!opened) {
        resolve({ opened: false });
      }
    };
  });
}
