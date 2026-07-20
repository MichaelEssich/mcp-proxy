"""
MCP Proxy Server - Main proxy logic.

This module implements the core proxy functionality that forwards HTTP requests
to a target MCP server with bearer token authentication.
"""

import hmac
import logging
import re
from typing import Optional, AsyncGenerator, Dict, Tuple
from fastapi import FastAPI, Request, Response, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from urllib.parse import urljoin

# Rate limiting imports
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    Limiter = None
    SlowAPIMiddleware = None

from .config import get_config, ProxyConfig

logger = logging.getLogger(__name__)

# Security scheme for bearer token authentication
security = HTTPBearer()


class ProxyClient:
    """HTTP client for forwarding requests to the target MCP server."""
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.timeout = httpx.Timeout(self.config.TARGET_TIMEOUT)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False  # Disable redirects to prevent SSRF attacks
        )
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def forward_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
        query_params: Optional[Dict[str, str]] = None
    ) -> Tuple[int, Dict[str, str], AsyncGenerator[bytes, None]]:
        """
        Forward a request to the target MCP server.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: Request headers
            body: Request body
            query_params: Query parameters
            
        Returns:
            Tuple of (status_code, response_headers, response_body_generator)
        """
        # Build target URL
        target_url = urljoin(self.config.TARGET_MCP_URL, path)
        
        # Filter out headers that shouldn't be forwarded
        filtered_headers = self._filter_headers(headers)
        
        # Build request object
        request = httpx.Request(
            method=method,
            url=target_url,
            headers=filtered_headers,
            content=body,
            params=query_params
        )
        
        try:
            # Send request and get response
            response = await self.client.send(request)
            
            async def response_body_generator() -> AsyncGenerator[bytes, None]:
                """Generator for streaming response body."""
                async for chunk in response.aiter_bytes():
                    yield chunk
            
            # Convert response headers to dict
            response_headers = dict(response.headers)
            
            return response.status_code, response_headers, response_body_generator()
            
        except httpx.TimeoutException as e:
            logger.error(f"Request timeout to {target_url}: {e}")  # Internal logging only
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Request timed out"  # Generic message
            )
        except httpx.ConnectError as e:
            logger.error(f"Connection error to {target_url}: {e}")  # Internal logging only
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Service unavailable"  # Generic message
            )
        except httpx.RequestError as e:
            logger.error(f"Request error to {target_url}: {e}")  # Internal logging only
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Bad gateway"  # Generic message
            )
        except Exception as e:
            logger.error(f"Unexpected error processing request to {target_url}: {e}")  # Internal logging only
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"  # Generic message
            )
    
    def _filter_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter out headers that shouldn't be forwarded to the target server."""
        # Headers to remove from forwarded requests
        headers_to_remove = {
            "host",
            "content-length",
            "transfer-encoding",
            self.config.AUTH_HEADER_NAME.lower(),
            "user-agent",       # Prevent client identification
            "referer",         # Prevent referral information leak
            "x-forwarded-for", # Prevent IP forwarding (handle separately if needed)
            "x-real-ip",       # Prevent IP forwarding
            "via",             # Prevent proxy chain disclosure
        }
        
        filtered = {}
        for key, value in headers.items():
            if key.lower() not in headers_to_remove:
                filtered[key] = value
        
        return filtered


class MCPProxyApp:
    """MCP Proxy Application."""
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.app = FastAPI(
            debug=config.DEBUG,
            title="MCP Proxy Server",
            description="Proxy server for MCP HTTP endpoints with bearer token authentication",
            version="1.0.0",
            strict_content_type=False,  # Disable strict Content-Type checking for proxy
            docs_url=None,      # Disable Swagger UI docs
            openapi_url=None,  # Disable OpenAPI schema
        )
        
        # Setup CORS
        self._setup_cors()
        
        # Setup path validation middleware
        self._setup_path_validation()
        
        # Setup rate limiting if available
        self._setup_rate_limiting()
        
        # Setup routes
        self._setup_routes()
        
        # Create proxy client
        self.proxy_client = ProxyClient(config)
    
    def _setup_cors(self):
        """Setup CORS middleware."""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.allowed_origins_list,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def _setup_path_validation(self):
        """Setup path validation middleware to prevent path traversal attacks."""
        @self.app.middleware("http")
        async def validate_path(request: Request, call_next):
            path = request.url.path
            # Block path traversal attempts
            if ".." in path or "//" in path:
                raise HTTPException(status_code=400, detail="Invalid path")
            # Validate path characters (alphanumeric, hyphen, underscore, slash, dot)
            if not re.match(r'^[a-zA-Z0-9\-_.~\/]+$', path):
                raise HTTPException(status_code=400, detail="Invalid path characters")
            return await call_next(request)
    
    def _setup_rate_limiting(self):
        """Setup rate limiting if slowapi is available."""
        if RATE_LIMITING_AVAILABLE:
            self.limiter = Limiter(
                key_func=get_remote_address,
                default_limits=["100/minute"]
            )
            self.app.state.limiter = self.limiter
            self.app.add_exception_handler(
                RateLimitExceeded, 
                lambda r, e: Response("Rate limit exceeded", status_code=429)
            )
            # Add rate limiting middleware
            if SlowAPIMiddleware:
                self.app.add_middleware(SlowAPIMiddleware)
    
    def _setup_routes(self):
        """Setup API routes."""
        # Main proxy endpoint - catches all paths
        @self.app.api_route(
            f"{self.config.PROXY_PREFIX}/{{path:path}}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"],
        )
        async def proxy_endpoint(
            request: Request,
            path: str,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """
            Proxy endpoint that forwards requests to the target MCP server.
            
            This endpoint catches all HTTP methods and paths, validates the bearer token,
            and forwards the request to the configured MCP server.
            """
            # Validate bearer token
            self._validate_bearer_token(credentials)
            
            # Extract request information
            method = request.method
            headers = dict(request.headers)
            query_params = dict(request.query_params)
            
            # Read request body if present
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Forward request to target server
            status_code, response_headers, response_body = await self.proxy_client.forward_request(
                method=method,
                path=path,
                headers=headers,
                body=body,
                query_params=query_params if query_params else None
            )
            
            # Remove headers that shouldn't be returned to client
            filtered_headers = self._filter_response_headers(response_headers)
            
            # Stream the response back to the client
            return StreamingResponse(
                content=response_body,
                status_code=status_code,
                headers=filtered_headers,
                media_type=response_headers.get("content-type", "application/octet-stream")
            )
        
    def _validate_bearer_token(self, credentials: HTTPAuthorizationCredentials) -> bool:
        """Validate the bearer token from request credentials."""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Extract token from credentials
        token = credentials.credentials
        
        # Compare with configured token (constant-time comparison)
        if not hmac.compare_digest(token, self.config.BEARER_TOKEN):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
            )
        
        return True
    
    def _filter_response_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter response headers before sending to client."""
        # Headers to potentially filter
        headers_to_filter = {
            "transfer-encoding",
            "connection",
            "keep-alive",
        }
        
        filtered = {}
        for key, value in headers.items():
            if key.lower() not in headers_to_filter:
                filtered[key] = value
        
        return filtered
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI application instance."""
        return self.app


async def create_proxy_app(config: ProxyConfig = None) -> MCPProxyApp:
    """Create and configure the MCP proxy application."""
    if config is None:
        config = get_config()
    
    return MCPProxyApp(config)
