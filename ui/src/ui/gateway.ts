export type GatewayEventFrame = {
  type: string;
  event?: unknown;
  [key: string]: unknown;
};

export type GatewayClientOptions = {
  url: string;
  onMessage?: (message: GatewayEventFrame) => void;
  onClose?: (info: { code: number; reason: string }) => void;
  onOpen?: () => void;
};

/**
 * OG Personal Gateway WebSocket client
 */
export class GatewayClient {
  private ws: WebSocket | null = null;
  private closed = false;
  private backoffMs = 800;

  constructor(private opts: GatewayClientOptions) {}

  start() {
    this.closed = false;
    this.connect();
  }

  stop() {
    this.closed = true;
    this.ws?.close();
    this.ws = null;
  }

  get connected() {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private connect() {
    if (this.closed) return;
    this.ws = new WebSocket(this.opts.url);

    this.ws.onopen = () => {
      this.backoffMs = 800;
      this.opts.onOpen?.();
    };

    this.ws.onmessage = (ev) => {
      try {
        const message = JSON.parse(String(ev.data ?? ""));
        this.opts.onMessage?.(message);
      } catch {
        // Ignore parse errors
      }
    };

    this.ws.onclose = (ev) => {
      this.ws = null;
      this.opts.onClose?.({ code: ev.code, reason: ev.reason });
      this.scheduleReconnect();
    };

    this.ws.onerror = () => {
      // Close handler will fire
    };
  }

  private scheduleReconnect() {
    if (this.closed) return;
    const delay = this.backoffMs;
    this.backoffMs = Math.min(this.backoffMs * 1.7, 15_000);
    window.setTimeout(() => this.connect(), delay);
  }

  send(message: unknown): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn("[OG] Cannot send: not connected");
      return;
    }
    this.ws.send(JSON.stringify(message));
  }

  // Convenience methods
  getStatus(): void {
    this.send({ type: "get-status" });
  }

  getMoltbotState(): void {
    this.send({ type: "get-openclaw-state" });
  }

  runScan(): void {
    this.send({ type: "run-scan" });
  }

  analyze(content: string, types?: string[]): void {
    this.send({ type: "analyze", content, types });
  }

  quickCheck(content: string): void {
    this.send({ type: "quick-check", content });
  }
}

/**
 * Create a gateway client with default URL
 */
export function createGatewayClient(
  onMessage: (message: GatewayEventFrame) => void,
  onStatusChange?: (connected: boolean) => void
): GatewayClient {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  const url = `${protocol}//${host}/ws`;

  return new GatewayClient({
    url,
    onMessage,
    onOpen: () => onStatusChange?.(true),
    onClose: () => onStatusChange?.(false),
  });
}
