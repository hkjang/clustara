# Clustara TypeScript SDK

A tiny, dependency-free client for the Clustara. Works in Node 18+
and modern browsers (uses the global `fetch`). No build step required — it is a
single `clustara.ts` you can copy in or compile with your own toolchain.

> Note: this SDK is hand-written and is **not** covered by the Go test suite
> (`go test ./...`), which only builds/tests the Go gateway. Verify in your own
> TS project before production use.

## Install

Copy `clustara.ts` into your project (or `tsc` it to `.js`). No dependencies.

## Usage

```ts
import { ClustaraClient } from "./clustara";

const clustara = new ClustaraClient({
  baseURL: "https://gateway.example.com",
  apiKey: process.env.CLUSTARA_API_KEY!,
});

// Chat (assistant text)
console.log(await clustara.chat("이 함수의 버그를 찾아줘", { model: "vibe/auto" }));

// Run a registered skill
console.log(await clustara.chat("PR 요약", { skill: "code-review" }));

// Read-only lookups (via the Clustara MCP server)
console.log(await clustara.quota());
console.log(await clustara.usage("7d"));
console.log(await clustara.routePreview("vibe/auto", "긴 문서 요약"));

// Work apps / workflows
console.log(await clustara.runApp("app_123"));
console.log(await vibe.runWorkflow("wf_123", "분기 매출 분석"));

// MCP client config for Claude / Cursor / Roo Code / Cline
console.log(JSON.stringify(vibe.mcpConfig(), null, 2));
```

## Methods

| Method | Endpoint | Notes |
|--------|----------|-------|
| `chat(prompt, {model, skill, maxTokens})` | `POST /v1/chat/completions` | returns assistant text |
| `models()` | `GET /v1/models` | OpenAI-compatible list |
| `runApp(appId)` | `POST /v1/apps/{id}/run` | execution plan + run id |
| `runWorkflow(id, input)` | `POST /v1/workflows/{id}/run` | server-side execution |
| `quota()` / `usage(window)` / `routePreview(model, prompt)` | `POST /mcp/gateway` | Clustara MCP tools |
| `mcpTool(tool, args)` | `POST /mcp/gateway` | any read-only MCP tool |
| `mcpConfig()` | — | MCP client config object |

All calls send `Authorization: Bearer <apiKey>` and run under that key's
permissions (model allowlist, team, quota, governance).
