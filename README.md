# MCP Security Kit

Production security middleware for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Problem

MCP servers run with powerful capabilities—file system access, database connections, API integrations—yet the official SDKs provide **zero built-in security middleware**. This gap leaves deployments vulnerable to:

- **DNS Rebinding** — External domains pivoting to localhost
- **Tool Description Injection** — Poisoned instructions in tool definitions  
- **Cross-Origin Attacks** — Missing origin validation
- **Credential Exposure** — Unsanitized terminal output

We've analyzed [16 CVEs](https://beyondit.blog/mcp-security) across all official SDKs. The vulnerabilities are real. The attacks are practical. This kit addresses them.

## What This Kit Provides

| Feature | Protection |
|---------|------------|
| `HostValidator` | DNS rebinding & SSRF protection |
| `ToolFilter` | Dangerous tool & description injection blocking |
| `CORSGuard` | Origin validation for HTTP transports |
| `ANSIFilter` | Terminal escape sequence sanitization |

## Quick Start

### TypeScript

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { secureServer, SecurityConfig } from "@beyondit/mcp-security";

const server = new Server({ ... });

const config: SecurityConfig = {
  allowedHosts: ["localhost", "127.0.0.1"],
  allowedOrigins: ["http://localhost:3000"],
  blockedTools: ["system_exec", "file_delete"]
};

const secured = secureServer(server, config);
```

### Python

```python
from mcp.server.fastmcp import FastMCP
from mcp_security import HostValidator, with_host_validation

mcp = FastMCP("My Server")

validator = HostValidator(
    allowed_hosts=["localhost", "127.0.0.1"],
    block_private_ips=True
)

mcp = with_host_validation(mcp, validator)
```

## Installation

**From Source (Current):**
```bash
# Clone and install TypeScript
git clone https://github.com/codeverseproo/mcp-security-kit.git
cd mcp-security-kit/ts-src
npm install
npm run build

# Clone and install Python  
git clone https://github.com/codeverseproo/mcp-security-kit.git
cd mcp-security-kit/py-src
pip install -e .
```

**From Package Registry (Coming Soon):**
```bash
# TypeScript
npm install @beyondit/mcp-security

# Python  
pip install mcp-security-kit
```

## Documentation

- [Security Analysis](https://beyondit.blog/mcp-security) — Our 16-CVE research
- [API Reference](./docs/api.md) — Complete middleware documentation
- [Examples](./examples/) — Hardened server templates

## CVE Coverage

This kit addresses vulnerability classes documented in:
- CVE-2025-66414 / CVE-2025-66416 — DNS Rebinding (TypeScript/Python)
- CVE-2026-34742 / CVE-2026-35568 — DNS Rebinding (Go/Java)
- CVE-2026-42559 — Host Validation Bypass (Rust)
- CVE-2026-25536 — Cross-Client Data Leakage (TypeScript)
- CVE-2026-33946 — Session Hijacking (Ruby)

## License

MIT — See [LICENSE](./LICENSE)

## About

Built by [BeyondIT](https://beyondit.blog) after analyzing systemic vulnerabilities in AI agent infrastructure.