import { createServer, type Server } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync, statSync } from "node:fs";
import { WebSocketServer, type WebSocket } from "ws";
import type { OGAgent, RiskAssessment } from "../agent/og-agent.js";
import type { OpenClawState } from "../agent/openclaw-watcher.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface GatewayClient {
  id: string;
  ws: WebSocket;
  connectedAt: number;
}

/**
 * Create the OG Personal gateway HTTP/WebSocket server
 */
export async function createGatewayServer(
  agent: OGAgent,
  port: number
): Promise<Server> {
  const clients = new Map<string, GatewayClient>();
  let clientIdCounter = 0;

  // Create HTTP server
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${port}`);

    // API routes
    if (url.pathname.startsWith("/api/")) {
      handleApiRequest(req, res, url, agent);
      return;
    }

    // Serve static UI files
    serveStaticFile(req, res, url);
  });

  // Create WebSocket server
  const wss = new WebSocketServer({ server, path: "/ws" });

  wss.on("connection", (ws) => {
    const clientId = `client-${++clientIdCounter}`;
    const client: GatewayClient = {
      id: clientId,
      ws,
      connectedAt: Date.now(),
    };
    clients.set(clientId, client);

    // Send initial state
    sendToClient(ws, {
      type: "hello",
      clientId,
      state: {
        configured: agent.isConfigured(),
        openclawInstalled: agent.isOpenClawInstalled(),
        assessment: agent.getLastAssessment(),
      },
    });

    ws.on("message", (data) => {
      try {
        const message = JSON.parse(data.toString());
        handleWebSocketMessage(ws, message, agent);
      } catch {
        sendToClient(ws, { type: "error", message: "Invalid message format" });
      }
    });

    ws.on("close", () => {
      clients.delete(clientId);
    });
  });

  // Forward agent events to all clients
  agent.onEvent((event) => {
    const message = { type: "agent-event", event };
    for (const client of clients.values()) {
      sendToClient(client.ws, message);
    }
  });

  // Absorb WSS errors — the underlying HTTP server error handler drives rejection
  wss.on("error", () => {});

  // Start listening
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, () => {
      resolve(server);
    });
  });
}

/**
 * Handle API requests
 */
function handleApiRequest(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  url: URL,
  agent: OGAgent
): void {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const sendJson = (data: unknown, status = 200) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  };

  const route = url.pathname.replace("/api/", "");

  switch (route) {
    case "status": {
      sendJson({
        configured: agent.isConfigured(),
        openclawInstalled: agent.isOpenClawInstalled(),
        assessment: agent.getLastAssessment(),
        config: agent.getConfig(),
      });
      break;
    }

    case "openclaw/state": {
      sendJson(agent.getOpenClawState());
      break;
    }

    case "scan": {
      if (req.method !== "POST") {
        sendJson({ error: "Method not allowed" }, 405);
        return;
      }
      agent
        .runScan()
        .then((assessment) => sendJson(assessment))
        .catch((err) => sendJson({ error: String(err) }, 500));
      break;
    }

    case "analyze": {
      if (req.method !== "POST") {
        sendJson({ error: "Method not allowed" }, 405);
        return;
      }
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          const { content, types } = JSON.parse(body);
          agent
            .analyzeContent(content, types)
            .then((results) => sendJson(results))
            .catch((err) => sendJson({ error: String(err) }, 500));
        } catch {
          sendJson({ error: "Invalid request body" }, 400);
        }
      });
      break;
    }

    case "quick-check": {
      if (req.method !== "POST") {
        sendJson({ error: "Method not allowed" }, 405);
        return;
      }
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          const { content } = JSON.parse(body);
          const result = agent.quickCheck(content);
          sendJson(result);
        } catch {
          sendJson({ error: "Invalid request body" }, 400);
        }
      });
      break;
    }

    default:
      sendJson({ error: "Not found" }, 404);
  }
}

/**
 * Handle WebSocket messages
 */
function handleWebSocketMessage(
  ws: WebSocket,
  message: { type: string; [key: string]: unknown },
  agent: OGAgent
): void {
  switch (message.type) {
    case "get-status": {
      sendToClient(ws, {
        type: "status",
        configured: agent.isConfigured(),
        openclawInstalled: agent.isOpenClawInstalled(),
        assessment: agent.getLastAssessment(),
      });
      break;
    }

    case "get-openclaw-state": {
      sendToClient(ws, {
        type: "openclaw-state",
        state: agent.getOpenClawState(),
      });
      break;
    }

    case "run-scan": {
      agent
        .runScan()
        .then((assessment) => {
          sendToClient(ws, { type: "scan-result", assessment });
        })
        .catch((err) => {
          sendToClient(ws, { type: "error", message: String(err) });
        });
      break;
    }

    case "analyze": {
      const content = message.content as string;
      const types = message.types as string[] | undefined;
      agent
        .analyzeContent(content, types as any)
        .then((results) => {
          sendToClient(ws, { type: "analyze-result", results });
        })
        .catch((err) => {
          sendToClient(ws, { type: "error", message: String(err) });
        });
      break;
    }

    case "quick-check": {
      const content = message.content as string;
      const result = agent.quickCheck(content);
      sendToClient(ws, { type: "quick-check-result", result });
      break;
    }

    default:
      sendToClient(ws, { type: "error", message: `Unknown message type: ${message.type}` });
  }
}

/**
 * Send a message to a WebSocket client
 */
function sendToClient(ws: WebSocket, message: unknown): void {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

/**
 * Serve static files from the UI dist directory
 */
function serveStaticFile(
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse,
  url: URL
): void {
  // UI dist directory - try multiple locations
  // 1. Development: ../ui/dist relative to compiled file
  // 2. Production: bundled location
  let uiDistPath = join(__dirname, "../ui/dist");
  if (!existsSync(uiDistPath)) {
    uiDistPath = join(__dirname, "../../ui/dist");
  }

  let filePath = url.pathname;
  if (filePath === "/" || filePath === "") {
    filePath = "/index.html";
  }

  const fullPath = join(uiDistPath, filePath);

  // Security: ensure path is within uiDistPath
  if (!fullPath.startsWith(uiDistPath)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  if (!existsSync(fullPath) || statSync(fullPath).isDirectory()) {
    // SPA fallback: serve index.html for unmatched routes and directory paths
    const indexPath = join(uiDistPath, "index.html");
    if (existsSync(indexPath)) {
      serveFile(res, indexPath, "text/html");
    } else {
      res.writeHead(404);
      res.end("Not found - UI not built. Run: pnpm ui:build");
    }
    return;
  }

  const ext = filePath.split(".").pop() ?? "";
  const mimeTypes: Record<string, string> = {
    html: "text/html",
    css: "text/css",
    js: "application/javascript",
    json: "application/json",
    png: "image/png",
    svg: "image/svg+xml",
    ico: "image/x-icon",
    woff2: "font/woff2",
  };

  serveFile(res, fullPath, mimeTypes[ext] ?? "application/octet-stream");
}

function serveFile(
  res: import("node:http").ServerResponse,
  filePath: string,
  contentType: string
): void {
  try {
    const content = readFileSync(filePath);
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  } catch {
    res.writeHead(500);
    res.end("Internal server error");
  }
}
