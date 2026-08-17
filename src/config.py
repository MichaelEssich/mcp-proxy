"""
Configuration management for MCP Proxy Server.
"""

from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class ProxyConfig(BaseSettings):
    """Proxy server configuration."""
    
    # Proxy server settings
    PROXY_HOST: str = "127.0.0.1"
    PROXY_PORT: int = 8000
    DEBUG: bool = False
    
    # Target MCP server settings
    TARGET_MCP_URL: str = "http://localhost:8080"
    TARGET_TIMEOUT: int = 30
    
    # Authentication settings
    BEARER_TOKEN: str = Field(..., description="Secret token for bearer authentication")
    AUTH_HEADER_NAME: str = "Authorization"
    
    # CORS settings
    ALLOWED_ORIGINS: str = "*"
    
    # Proxy prefix (optional base path for all proxy routes)
    PROXY_PREFIX: str = ""
    
    # Security settings
    MAX_REQUEST_SIZE: int = 10_000_000  # 10MB - More reasonable limit to prevent memory exhaustion
    MAX_RESPONSE_SIZE: int = 50_000_000  # 50MB - Cap upstream responses to prevent memory/bandwidth exhaustion
    MAX_CONCURRENT_REQUESTS: int = 50  # Max in-flight proxied requests (bounds memory: limit x MAX_REQUEST_SIZE)
    TRUSTED_PROXIES: str = ""  # Comma-separated IPs/CIDRs allowed to set forwarded headers (e.g. "172.16.0.0/12")
    REAL_IP_HEADER: str = "cf-connecting-ip"  # Header to trust for the real client IP when behind a reverse proxy. "cf-connecting-ip" (Cloudflare, default) or "x-forwarded-for" (nginx); empty = rightmost X-Forwarded-For
    
    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse allowed origins string to list."""
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def trusted_proxies_list(self) -> List[str]:
        """Parse trusted proxies string to list."""
        if not self.TRUSTED_PROXIES:
            return []
        return [entry.strip() for entry in self.TRUSTED_PROXIES.split(",") if entry.strip()]
    
    @field_validator('BEARER_TOKEN', mode='after')
    @classmethod
    def validate_bearer_token_length(cls, v: str) -> str:
        """Ensure bearer token meets minimum length to resist brute force."""
        if len(v) < 32:
            raise ValueError(
                "BEARER_TOKEN must be at least 32 characters long for security. "
                "Use a strong, randomly generated token."
            )
        return v

    @field_validator('TARGET_MCP_URL', mode='before')
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        """Ensure target URL doesn't end with a trailing slash."""
        if v.endswith('/'):
            return v[:-1]
        return v
    
    @field_validator('PROXY_PREFIX', mode='before')
    @classmethod
    def validate_proxy_prefix(cls, v: str) -> str:
        """Ensure proxy prefix starts with / and doesn't end with /."""
        if not v:
            return v
        # Remove leading slash if present
        v = v.lstrip('/')
        # Remove trailing slash if present
        v = v.rstrip('/')
        return f"/{v}" if v else ""
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8", 
        "case_sensitive": False
    }


# Global configuration instance (lazy-loaded so CLI args can be applied first)
_config: Optional[ProxyConfig] = None


def get_config() -> ProxyConfig:
    """Get the global configuration instance (lazy-loaded on first call)."""
    global _config
    if _config is None:
        _config = ProxyConfig()
    return _config
