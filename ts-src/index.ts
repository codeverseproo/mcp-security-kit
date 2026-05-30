import { Server } from "@modelcontextprotocol/sdk/server/index.js";

export interface SecurityConfig {
  allowedHosts?: string[];
  allowedOrigins?: string[];
  blockedTools?: string[];
  requireToolDescriptions?: boolean;
}

export class MCPSecurityError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = "MCPSecurityError";
  }
}

export function withHostValidation(server: Server, allowedHosts: string[]): Server {
  const wrapRequest = (handler: Function) => async (request: any) => {
    const host = request.headers?.host || request.host;
    if (!host || !allowedHosts.some(h => host.includes(h))) {
      throw new MCPSecurityError(
        `Host '${host}' not in allowed list: ${allowedHosts.join(", ")}`,
        "HOST_VALIDATION_FAILED"
      );
    }
    return handler(request);
  };
  
  return new Proxy(server, {
    get(target, prop) {
      const value = (target as any)[prop];
      if (typeof value === "function" && ["callTool", "readResource"].includes(prop as string)) {
        return wrapRequest(value.bind(target));
      }
      return value;
    }
  });
}

export function withCORSPolicy(server: Server, allowedOrigins: string[]): Server {
  return new Proxy(server, {
    get(target, prop) {
      const value = (target as any)[prop];
      if (prop === "getCapabilities") {
        return () => ({
          ...(target as any).getCapabilities(),
          security: {
            corsPolicy: { allowedOrigins, credentials: false }
          }
        });
      }
      return value;
    }
  });
}

export function withToolFilter(server: Server, blockedTools: string[]): Server {
  const originalListTools = (server as any).listTools?.bind(server);
  
  if (originalListTools) {
    (server as any).listTools = async () => {
      const tools = await originalListTools();
      return tools.filter((t: any) => !blockedTools.includes(t.name));
    };
  }
  
  return server;
}

export function secureServer(server: Server, config: SecurityConfig): Server {
  let secured = server;
  
  if (config.allowedHosts && config.allowedHosts.length > 0) {
    secured = withHostValidation(secured, config.allowedHosts);
  }
  
  if (config.allowedOrigins && config.allowedOrigins.length > 0) {
    secured = withCORSPolicy(secured, config.allowedOrigins);
  }
  
  if (config.blockedTools && config.blockedTools.length > 0) {
    secured = withToolFilter(secured, config.blockedTools);
  }
  
  return secured;
}

export { withHostValidation, withCORSPolicy, withToolFilter };