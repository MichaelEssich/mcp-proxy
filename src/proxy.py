"""
MCP Proxy Server - Main proxy logic.

This module implements the core proxy functionality that forwards HTTP requests
to a target MCP server with bearer token authentication.
"""

import asyncio
import hmac
import inspect
import ipaddress
import logging
import re
from typing import Optional, AsyncGenerator, Dict, Tuple
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx2 as httpx

# Rate limiting imports
try:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    Limiter = None
    SlowAPIMiddleware = None
    RateLimitExceeded = None

from .config import get_config, ProxyConfig

logger = logging.getLogger(__name__)

# Headers from upstream responses that must not be forwarded to clients
_RESPONSE_HEADERS_TO_STRIP = {
    "transfer-encoding",
    "connection",
    "keep-alive",
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-debug",
    "x-debug-info",
    "x-runtime",
    "via",
    "set-cookie",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    # We stream decoded bytes (aiter_bytes handles gzip/deflate/brotli/zstd),
    # so the upstream content-encoding/content-length no longer match the body
    # we send. Let StreamingResponse recompute framing.
    "content-encoding",
    "content-length",
}


def _resolve_client_ip(request: Request, trusted_networks: list, real_ip_header: str = "") -> str:
    """Extract the real client IP for rate-limit keying.

    Forwarded headers are only consulted when the TCP peer is trusted —
    loopback by default, plus any CIDRs in ``TRUSTED_PROXIES``.  Direct
    (untrusted) connections use the TCP peer address, preventing header
    spoofing to bypass rate limits when the origin is exposed.

    When the peer is trusted, the resolution order is:

      1. ``real_ip_header`` -- the operator-configured header (e.g.
         ``cf-connecting-ip`` for Cloudflare Tunnel, which Cloudflare
         overwrites with the true client IP). Only one named header is
         trusted, so an attacker behind a different reverse proxy cannot
         rotate it at will.
      2. Rightmost entry of ``X-Forwarded-For`` -- appended by the last
         trusted reverse proxy (e.g. nginx with
         ``proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for``).
         The rightmost entry is set by the trusted proxy and cannot be
         forged by the client.
      3. ``request.client.host`` -- the TCP peer address.
    """
    peer = request.client.host if request.client else None

    def _is_trusted(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip.is_loopback:
            return True
        for net in trusted_networks:
            if ip in net:
                return True
        return False

    if peer and _is_trusted(peer):
        # 1. Operator-configured real-IP header (Cloudflare overwrites
        #    cf-connecting-ip; nginx operators should set "" to fall back
        #    to X-Forwarded-For below).
        if real_ip_header:
            real_ip = request.headers.get(real_ip_header)
            if real_ip:
                return real_ip.strip()

        # 2. Rightmost X-Forwarded-For entry (set by the last trusted proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
            if parts:
                return parts[-1]

    # 3. Direct TCP connection (or untrusted peer)
    return peer or "unknown"


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
        # Build target URL by appending the path to the base URL.
        # We use explicit concatenation instead of urljoin because urljoin
        # performs URL resolution — a path like "//evil.com" would be
        # resolved to "http://evil.com", enabling SSRF.
        safe_path = path.lstrip("/")
        target_url = f"{self.config.TARGET_MCP_URL}/{safe_path}"
        
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
            # Send request with stream=True so the upstream response is
            # streamed incrementally rather than buffered entirely in memory.
            response = await self.client.send(request, stream=True)

            # Fast path: reject oversized responses before streaming begins.
            # This covers the common case where upstream advertises a
            # Content-Length. We still guard chunked streams below.
            upstream_cl = response.headers.get("content-length")
            if upstream_cl:
                try:
                    cl_val = int(upstream_cl)
                except ValueError:
                    cl_val = -1
                if cl_val > self.config.MAX_RESPONSE_SIZE:
                    await response.aclose()
                    logger.error(
                        f"Upstream Content-Length ({cl_val}) exceeds maximum "
                        f"({self.config.MAX_RESPONSE_SIZE}) for path: {path}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="Upstream response exceeds maximum allowed size"
                    )

            async def response_body_generator() -> AsyncGenerator[bytes, None]:
                """Stream the upstream response body to the client.

                If the body exceeds ``MAX_RESPONSE_SIZE`` mid-stream (only
                possible with chunked transfer encoding -- responses with a
                known Content-Length are rejected before streaming starts),
                the generator raises ``httpx.StreamError``. Because the
                status code and headers have already been sent, the proxy
                cannot change the response status. Instead, the exception
                propagates through ``StreamingResponse`` to uvicorn, which
                closes the connection without sending a proper terminator.
                Well-behaved HTTP clients detect this as an incomplete
                response.
                """
                try:
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > self.config.MAX_RESPONSE_SIZE:
                            # Chunked stream with no Content-Length exceeded the
                            # cap mid-stream. Abort rather than silently serving
                            # a truncated body.
                            logger.error(
                                f"Response body exceeded maximum size "
                                f"({self.config.MAX_RESPONSE_SIZE} bytes) for path: {path}"
                            )
                            raise httpx.StreamError("Response size limit exceeded")
                        yield chunk
                finally:
                    await response.aclose()

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
        except HTTPException:
            # Re-raise HTTPExceptions (e.g. 413 from response size check) without wrapping
            raise
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
            "connection",          # Hop-by-hop (RFC 7230 §6.1)
            "keep-alive",          # Hop-by-hop
            "proxy-connection",    # Non-standard hop-by-hop
            "proxy-authorization",  # Prevent credential leakage
            "authorization",  # Always strip, even when AUTH_HEADER_NAME is custom
            self.config.AUTH_HEADER_NAME.lower(),
            "user-agent",       # Prevent client identification
            "referer",         # Prevent referral information leak
            "x-forwarded-for", # Prevent IP forwarding (handle separately if needed)
            "x-real-ip",       # Prevent IP forwarding
            "via",             # Prevent proxy chain disclosure
            "cookie",          # Prevent cookie/session leakage
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
        self.trusted_networks = self._parse_trusted_networks(config.TRUSTED_PROXIES)
        self.real_ip_header = (config.REAL_IP_HEADER or "").lower()
        self._concurrency_sem = asyncio.Semaphore(config.MAX_CONCURRENT_REQUESTS)
        self.app = FastAPI(
            debug=config.DEBUG,
            title="MCP Proxy Server",
            description="Proxy server for MCP HTTP endpoints with bearer token authentication",
            version="1.0.0",
            strict_content_type=False,  # Disable strict Content-Type checking for proxy
            docs_url=None,      # Disable Swagger UI docs
            openapi_url=None,  # Disable OpenAPI schema
            redoc_url=None,   # Disable ReDoc docs
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
        """Setup CORS middleware.

        ``allow_credentials=True`` with ``allow_origins=["*"]`` is invalid per
        the CORS spec and causes Starlette to reflect any Origin back, allowing
        any website to make credentialed cross-origin requests. When origins
        are wildcarded we disable credentials; users who need credentials must
        set ``ALLOWED_ORIGINS`` to specific domains.
        """
        origins = self.config.allowed_origins_list
        is_wildcard = "*" in origins
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=not is_wildcard,
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
            response = await call_next(request)
            # Add security response headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "0"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            return response
    
    def _setup_rate_limiting(self):
        """Setup rate limiting if slowapi is available.

        Uses ``_resolve_client_ip`` which resolves the real client IP from
        ``CF-Connecting-IP`` (Cloudflare), then the rightmost
        ``X-Forwarded-For`` entry (nginx), then the TCP peer.  Forwarded
        headers are only trusted when the TCP peer is loopback or in the
        configured ``TRUSTED_PROXIES`` list, preventing clients from
        spoofing headers to bypass per-client limits.
        """
        if RATE_LIMITING_AVAILABLE:
            trusted_networks = self.trusted_networks
            real_ip_header = self.real_ip_header
            allowed_origins = self.config.allowed_origins_list
            is_wildcard_origin = "*" in allowed_origins

            def get_client_ip(request: Request) -> str:
                return _resolve_client_ip(request, trusted_networks, real_ip_header)

            self.limiter = Limiter(
                key_func=get_client_ip,
                default_limits=["100/minute"]
            )
            self.app.state.limiter = self.limiter

            # SlowAPIMiddleware is the outermost user middleware, so it
            # returns the 429 response directly to uvicorn -- bypassing
            # CORSMiddleware (which is inner). The handler must therefore
            # add CORS headers itself, otherwise browser clients get a CORS
            # error instead of the rate-limit response.
            def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
                headers = {}
                origin = request.headers.get("origin")
                if origin:
                    if is_wildcard_origin:
                        headers["Access-Control-Allow-Origin"] = "*"
                    elif origin in allowed_origins:
                        headers["Access-Control-Allow-Origin"] = origin
                        headers["Access-Control-Allow-Credentials"] = "true"
                return Response(
                    "Rate limit exceeded",
                    status_code=429,
                    headers=headers,
                )

            self.app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
            # Add rate limiting middleware
            if SlowAPIMiddleware:
                self.app.add_middleware(SlowAPIMiddleware)

    @staticmethod
    def _parse_trusted_networks(trusted_proxies: str) -> list:
        """Parse comma-separated IPs/CIDRs into ip_network objects."""
        networks = []
        if not trusted_proxies:
            return networks
        for entry in trusted_proxies.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.warning(f"Invalid trusted proxy entry: {entry}")
        return networks

    def _setup_routes(self):
        """Setup API routes."""
        # Main proxy endpoint - catches all paths
        # TRACE is excluded to prevent Cross-Site Tracing (XST) attacks
        @self.app.api_route(
            f"{self.config.PROXY_PREFIX}/{{path:path}}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        )
        async def proxy_endpoint(
            request: Request,
            path: str,
        ):
            """
            Proxy endpoint that forwards requests to the target MCP server.
            
            This endpoint catches all HTTP methods and paths, validates the bearer token,
            and forwards the request to the configured MCP server.
            """
            # Validate bearer token from the configured auth header
            token = self._extract_token(request)
            self._validate_bearer_token(token)

            # Enforce maximum request body size.
            # We check Content-Length when present (fast path) AND read the
            # body incrementally so that chunked transfer encoding (which has
            # no Content-Length) cannot bypass the limit.
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    cl = int(content_length)
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid Content-Length header"
                    )
                if cl < 0:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid Content-Length header"
                    )
                if cl > self.config.MAX_REQUEST_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="Request body exceeds maximum allowed size"
                    )

            # Extract request information
            method = request.method
            headers = dict(request.headers)
            query_params = dict(request.query_params)

            # Bound concurrent in-flight requests AND body buffering to prevent
            # memory exhaustion under load. The semaphore is held for the full
            # duration of upstream response streaming — not just until headers
            # arrive — so that slow clients cannot exceed the concurrency limit
            # by opening many requests and reading responses slowly. Reading
            # the body inside the semaphore bounds worst-case memory to
            # MAX_CONCURRENT_REQUESTS x MAX_REQUEST_SIZE.
            await self._concurrency_sem.acquire()
            response_body = None
            try:
                # Read request body if present, enforcing size limit for
                # chunked transfers or mismatched Content-Length values.
                body = None
                if request.method in ["POST", "PUT", "PATCH"]:
                    body_chunks = []
                    total = 0
                    async for chunk in request.stream():
                        total += len(chunk)
                        if total > self.config.MAX_REQUEST_SIZE:
                            raise HTTPException(
                                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                                detail="Request body exceeds maximum allowed size"
                            )
                        body_chunks.append(chunk)
                    body = b"".join(body_chunks) if body_chunks else b""

                status_code, response_headers, response_body = await self.proxy_client.forward_request(
                    method=method,
                    path=path,
                    headers=headers,
                    body=body,
                    query_params=query_params if query_params else None
                )

                # Remove headers that shouldn't be returned to client
                filtered_headers = self._filter_response_headers(response_headers)
            except Exception:
                # Close the upstream response if it was opened, to avoid
                # leaking the connection when header filtering or body
                # reading fails.
                if response_body is not None:
                    if inspect.isasyncgen(response_body):
                        await response_body.aclose()
                    elif hasattr(response_body, "close"):
                        response_body.close()
                self._concurrency_sem.release()
                raise

            # Stream the response back to the client. The semaphore is
            # released in the generator's finally block — after the upstream
            # response body has been fully consumed or the client
            # disconnected — so the concurrency limit covers the entire
            # streaming duration.
            async def _stream_and_release():
                try:
                    if inspect.isasyncgen(response_body):
                        async for chunk in response_body:
                            yield chunk
                    else:
                        for chunk in response_body:
                            yield chunk
                finally:
                    self._concurrency_sem.release()

            return StreamingResponse(
                content=_stream_and_release(),
                status_code=status_code,
                headers=filtered_headers,
                media_type=response_headers.get("content-type", "application/octet-stream")
            )

    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract the bearer token from the configured auth header.

        For the standard ``Authorization`` header the ``Bearer`` scheme is
        expected (``Authorization: Bearer <token>``). For a custom
        ``AUTH_HEADER_NAME`` (e.g. ``X-Api-Key``) the raw header value is used.
        Returns ``None`` if the header is missing or malformed.
        """
        header_name = self.config.AUTH_HEADER_NAME
        raw = request.headers.get(header_name)
        if not raw:
            return None
        raw = raw.strip()
        if header_name.lower() == "authorization":
            # Parse "Bearer <token>"
            parts = raw.split(None, 1)
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return None
            return parts[1].strip()
        return raw

    def _validate_bearer_token(self, token: Optional[str]) -> bool:
        """Validate the bearer token from request credentials."""
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Compare with configured token (constant-time comparison).
        # Encode to bytes so non-ASCII tokens return 403 instead of raising
        # TypeError (which would surface as a 500).
        if not hmac.compare_digest(token.encode("utf-8"), self.config.BEARER_TOKEN.encode("utf-8")):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
            )

        return True
    
    def _filter_response_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter response headers before sending to client.

        Strips hop-by-hop headers as well as headers that leak information
        about the upstream server (type, version, framework, debug info).
        """
        filtered = {}
        for key, value in headers.items():
            if key.lower() not in _RESPONSE_HEADERS_TO_STRIP:
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
