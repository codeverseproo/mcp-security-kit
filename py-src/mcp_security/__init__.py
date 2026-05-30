"""MCP Security Kit - Production security middleware for MCP servers."""

__version__ = "0.1.0"
__all__ = ["HostValidator", "ToolFilter", "with_host_validation", "with_tool_filter"]

import re
from typing import List, Optional, Callable, Any
from fastmcp import FastMCP


class MCPSecurityError(Exception):
    """Raised when a security check fails."""
    pass


class HostValidator:
    """Validates and blocks DNS rebinding attacks."""
    
    def __init__(
        self,
        allowed_hosts: List[str],
        allowed_ports: Optional[List[int]] = None,
        block_private_ips: bool = True
    ):
        self.allowed_hosts = allowed_hosts
        self.allowed_ports = allowed_ports or [8080, 3000, 8000]
        self.block_private_ips = block_private_ips
    
    def validate(self, host_header: str) -> bool:
        """Validate Host header against allowed hosts."""
        if not host_header:
            raise MCPSecurityError("Missing Host header", "HOST_MISSING")
        
        # Extract hostname (remove port)
        hostname = host_header.split(":")[0].lower()
        
        # Check against allowed hosts
        if not any(
            hostname == allowed.lower() or hostname.endswith(f".{allowed.lower()}")
            for allowed in self.allowed_hosts
        ):
            raise MCPSecurityError(
                f"Host '{hostname}' not in allowed list: {self.allowed_hosts}",
                "HOST_NOT_ALLOWED"
            )
        
        return True


class ToolFilter:
    """Filters dangerous tools from MCP server."""
    
    def __init__(
        self,
        blocked_tools: List[str],
        require_description: bool = True,
        max_description_length: int = 500
    ):
        self.blocked_tools = blocked_tools
        self.require_description = require_description
        self.max_description_length = max_description_length
    
    def filter_tools(self, tools: list) -> list:
        """Filter tool list."""
        filtered = []
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            
            # Block dangerous tools
            if name in self.blocked_tools:
                continue
            
            # Check for injection patterns
            if self._has_injection_pattern(description):
                continue
            
            # Require description
            if self.require_description and not description:
                continue
            
            # Limit description length
            if len(description) > self.max_description_length:
                tool["description"] = description[:self.max_description_length]
            
            filtered.append(tool)
        
        return filtered
    
    def _has_injection_pattern(self, text: str) -> bool:
        """Check for tool description injection patterns."""
        dangerous = [
            r"ignore previous instructions",
            r"system:.*admin",
            r"\x1b\[",  # ANSI escapes
            r"<script",
            r"javascript:",
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in dangerous)


def with_host_validation(mcp: FastMCP, validator: HostValidator) -> FastMCP:
    """Wrap FastMCP with host validation."""
    original_handler = mcp._request_handler
    
    async def secure_handler(request: Any) -> Any:
        host = request.headers.get("host") if hasattr(request, "headers") else None
        if host:
            validator.validate(host)
        return await original_handler(request)
    
    mcp._request_handler = secure_handler
    return mcp


def with_tool_filter(mcp: FastMCP, filter: ToolFilter) -> FastMCP:
    """Wrap FastMCP with tool filtering."""
    original_list_tools = mcp.list_tools if hasattr(mcp, "list_tools") else None
    
    if original_list_tools:
        async def filtered_list_tools() -> list:
            tools = await original_list_tools()
            return filter.filter_tools(tools)
        
        mcp.list_tools = filtered_list_tools
    
    return mcp