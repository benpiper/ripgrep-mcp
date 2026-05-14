import { spawn } from "node:child_process";
import { stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type SearchStatus = "running" | "done" | "cancelled" | "failed";

type SearchRequest = {
  root: string;
  pattern: string;
  globs?: string[];
  maxResults?: number;
  timeoutMs?: number;
  contextLines?: number;
};

type SearchMatch = {
  path: string;
  line: number;
  column: number | null;
  text: string;
};

type SearchDecision = {
  allow: boolean;
  redactSnippet?: boolean;
  redactPath?: boolean;
};

type SearchJob = {
  id: string;
  request: SearchRequest;
  status: SearchStatus;
  startedAt: string;
  finishedAt?: string;
  exitCode?: number | null;
  signal?: NodeJS.Signals | null;
  matches: SearchMatch[];
  redacted: number;
  error?: string;
  child?: ReturnType<typeof spawn>;
  timeout?: NodeJS.Timeout;
};

const jobs = new Map<string, SearchJob>();

function buildServer(): McpServer {
  const server = new McpServer({
    name: "ripgrep-mcp",
    version: "0.1.0",
  });

  const startSchema = z.object({
    root: z.string().min(1),
    pattern: z.string().min(1),
    globs: z.array(z.string()).optional(),
    maxResults: z.number().int().positive().max(1000).optional(),
    timeoutMs: z.number().int().positive().max(120_000).optional(),
    contextLines: z.number().int().nonnegative().max(20).optional(),
  });

  server.registerTool(
    "search_start",
    {
      title: "Start Search",
      description: "Start an asynchronous ripgrep search.",
      inputSchema: startSchema,
    },
    async (input) => {
      const request: SearchRequest = {
        root: input.root,
        pattern: input.pattern,
        globs: input.globs,
        maxResults: input.maxResults ?? 200,
        timeoutMs: input.timeoutMs ?? 30_000,
        contextLines: input.contextLines ?? 0,
      };

      const policyCheck = await evaluatePolicy({
        action: "start_search",
        request,
      });
      if (!policyCheck.allow) {
        return textResult({
          status: "denied",
          reason: "OPA denied the search request",
        });
      }

      try {
        await validateSearchRoot(request.root);
      } catch (error) {
        return textResult({
          status: "failed",
          reason: error instanceof Error ? error.message : String(error),
        });
      }

      const job = createJob(request);
      jobs.set(job.id, job);
      runSearch(job).catch((error) => {
        failJob(job, error);
      });

      return textResult({
        job_id: job.id,
        status: job.status,
        matches_returned: job.matches.length,
      });
    },
  );

  server.registerTool(
    "search_status",
    {
      title: "Search Status",
      description: "Check the status of a running search.",
      inputSchema: z.object({
        job_id: z.string().min(1),
      }),
    },
    async ({ job_id }) => {
      const job = jobs.get(job_id);
      if (!job) {
        return textResult({
          status: "not_found",
          job_id,
        });
      }

      return textResult({
        job_id,
        status: job.status,
        matches_returned: job.matches.length,
        redacted: job.redacted,
        error: job.error,
        results: job.matches,
      });
    },
  );

  server.registerTool(
    "search_cancel",
    {
      title: "Cancel Search",
      description: "Cancel a running search.",
      inputSchema: z.object({
        job_id: z.string().min(1),
      }),
    },
    async ({ job_id }) => {
      const job = jobs.get(job_id);
      if (!job) {
        return textResult({
          status: "not_found",
          job_id,
        });
      }

      cancelJob(job, "cancelled by client");
      return textResult({
        job_id,
        status: job.status,
      });
    },
  );

  return server;
}

const stdioServer = buildServer();

async function runSearch(job: SearchJob): Promise<void> {
  const rgBin = process.env.RG_BIN ?? "rg";
  const args = [
    "--json",
    "--no-messages",
    "--hidden",
    "--follow",
    "--glob",
    "!**/.git/**",
    "--glob",
    "!**/node_modules/**",
    ...buildGlobArgs(job.request.globs),
  ];

  if (job.request.contextLines && job.request.contextLines > 0) {
    args.push("--context", String(job.request.contextLines));
  }

  args.push(job.request.pattern, job.request.root);

  const child = spawn(rgBin, args, {
    stdio: ["ignore", "pipe", "pipe"],
  });
  job.child = child;

  const deadline = setTimeout(() => {
    cancelJob(job, "timeout");
  }, job.request.timeoutMs);
  job.timeout = deadline;

  const stdout = createInterface({ input: child.stdout });
  stdout.on("line", (line) => {
    void handleRgLine(job, line).catch((error) => {
      failJob(job, error);
    });
  });

  child.stderr.on("data", (chunk) => {
    if (job.status === "running") {
      job.error = chunk.toString("utf8").trim();
    }
  });

  child.once("error", (error) => {
    failJob(job, error);
  });

  child.once("close", (code, signal) => {
    clearTimeout(job.timeout);
    stdout.close();
    job.exitCode = code;
    job.signal = signal;

    if (job.status !== "running") {
      return;
    }

    if (signal) {
      job.status = "failed";
      job.error = job.error ?? `rg exited with signal ${signal}`;
    } else if (code === 0 || code === 1 || (code === 2 && job.matches.length > 0)) {
      job.status = "done";
      if (code === 2 && !job.error) {
        job.error = "rg exited with code 2";
      }
    } else {
      job.status = "failed";
      job.error = job.error ?? `rg exited with code ${code ?? "unknown"}`;
    }

    job.finishedAt = new Date().toISOString();
  });
}

async function handleRgLine(job: SearchJob, line: string): Promise<void> {
  if (job.status !== "running") {
    return;
  }

  if (job.request.maxResults !== undefined && job.matches.length >= job.request.maxResults) {
    cancelJob(job, "result limit reached");
    return;
  }

  let payload: unknown;
  try {
    payload = JSON.parse(line) as unknown;
  } catch {
    return;
  }

  const match = parseRgMatch(payload);
  if (!match) {
    return;
  }

  const decision = await evaluatePolicy({
    action: "read_search_result",
    request: job.request,
    match,
  });
  if (!decision.allow) {
    job.redacted += 1;
    return;
  }

  job.matches.push(applyDecision(match, decision));
}

function createJob(request: SearchRequest): SearchJob {
  return {
    id: randomUUID(),
    request,
    status: "running",
    startedAt: new Date().toISOString(),
    matches: [],
    redacted: 0,
  };
}

function cancelJob(job: SearchJob, reason: string): void {
  job.status = "cancelled";
  job.error = reason;
  job.finishedAt = new Date().toISOString();
  clearTimeout(job.timeout);
  job.child?.kill("SIGTERM");
}

function failJob(job: SearchJob, error: unknown): void {
  job.status = "failed";
  job.error = error instanceof Error ? error.message : String(error);
  job.finishedAt = new Date().toISOString();
  clearTimeout(job.timeout);
  job.child?.kill("SIGTERM");
}

function buildGlobArgs(globs: string[] | undefined): string[] {
  if (!globs || globs.length === 0) {
    return [];
  }

  return globs.flatMap((glob) => ["--glob", glob]);
}

async function validateSearchRoot(root: string): Promise<void> {
  try {
    await stat(root);
  } catch {
    throw new Error(`Search root is not accessible: ${root}`);
  }
}

function parseRgMatch(payload: unknown): SearchMatch | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  const record = payload as Record<string, unknown>;
  if (record.type !== "match") {
    return null;
  }

  const data = record.data as Record<string, unknown> | undefined;
  const pathText = data?.path && typeof data.path === "object" ? (data.path as Record<string, unknown>).text : undefined;
  const lineText = data?.line_number;
  const submatches = data?.submatches;
  const lines = data?.lines && typeof data.lines === "object" ? (data.lines as Record<string, unknown>).text : undefined;

  if (typeof pathText !== "string" || typeof lineText !== "number" || typeof lines !== "string") {
    return null;
  }

  const column = Array.isArray(submatches) && submatches.length > 0
    ? ((submatches[0] as Record<string, unknown>).start as number | undefined) ?? null
    : null;

  return {
    path: pathText,
    line: lineText,
    column,
    text: lines,
  };
}

function applyDecision(match: SearchMatch, decision: SearchDecision): SearchMatch {
  return {
    path: decision.redactPath ? "[REDACTED]" : match.path,
    line: match.line,
    column: match.column,
    text: decision.redactSnippet ? "[REDACTED]" : match.text,
  };
}

async function evaluatePolicy(input: Record<string, unknown>): Promise<SearchDecision> {
  const opaUrl = process.env.OPA_URL;
  const policyPath = process.env.OPA_POLICY_PATH ?? "search/decision";

  if (!opaUrl) {
    return { allow: true };
  }

  const response = await fetch(`${opaUrl.replace(/\/$/, "")}/v1/data/${policyPath.replace(/^\//, "")}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ input }),
  });

  if (!response.ok) {
    return {
      allow: false,
    };
  }

  const body = (await response.json()) as { result?: Partial<SearchDecision> };
  return {
    allow: body.result?.allow ?? false,
    redactSnippet: body.result?.redactSnippet ?? false,
    redactPath: body.result?.redactPath ?? false,
  };
}

function textResult(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

async function main(): Promise<void> {
  const transportMode = (process.env.MCP_TRANSPORT ?? "stdio").toLowerCase();
  if (transportMode === "streamable-http") {
    await startStreamableHttpServer();
    return;
  }

  const transport = new StdioServerTransport();
  await stdioServer.connect(transport);
}

async function startStreamableHttpServer(): Promise<void> {
  const host = process.env.MCP_HTTP_HOST ?? "0.0.0.0";
  const port = Number(process.env.MCP_HTTP_PORT ?? "3000");
  const enableJsonResponse = process.env.MCP_HTTP_ENABLE_JSON_RESPONSE !== "false";

  const httpServer = createServer(async (req, res) => {
    try {
      if (!req.url) {
        writeJsonError(res, 400, "Bad Request", -32600);
        return;
      }

      const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname !== "/mcp") {
        writeJsonError(res, 404, "Not Found", -32601);
        return;
      }

      const parsedBody = await readRequestBody(req);
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse,
      });

      await server.connect(transport);
      res.on("close", () => {
        void transport.close();
      });
      await transport.handleRequest(req, res, parsedBody);
    } catch (error) {
      if (!res.headersSent) {
        writeJsonError(res, 500, error instanceof Error ? error.message : "Internal server error", -32603);
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => resolve());
  });

  console.error(`MCP Streamable HTTP Server listening on http://${host}:${port}/mcp`);

  process.once("SIGINT", () => {
    httpServer.close(() => {
      process.exit(0);
    });
  });
}

async function readRequestBody(req: IncomingMessage): Promise<unknown | undefined> {
  if (req.method === "GET" || req.method === "HEAD") {
    return undefined;
  }

  const chunks: string[] = [];
  return new Promise((resolve, reject) => {
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = chunks.join("").trim();
      if (raw.length === 0) {
        resolve(undefined);
        return;
      }

      try {
        resolve(JSON.parse(raw) as unknown);
      } catch (error) {
        reject(error instanceof Error ? error : new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function writeJsonError(res: ServerResponse, statusCode: number, message: string, code: number): void {
  if (res.headersSent) {
    return;
  }

  res.statusCode = statusCode;
  res.setHeader("content-type", "application/json");
  res.end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code,
        message,
      },
      id: null,
    }),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
