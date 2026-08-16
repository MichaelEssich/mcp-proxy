"""
Configuration management for MCP Proxy Server.
"""

from typing import List
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
    
    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse allowed origins string to list."""
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]
    
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


# Global configuration instance
config = ProxyConfig()


def get_config() -> ProxyConfig:
    """Get the global configuration instance."""
    return config
