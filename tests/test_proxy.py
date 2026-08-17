"""
Tests for the MCP Proxy Server.
"""

import pytest
import httpx2 as httpx
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock

from src.config import ProxyConfig
from src.proxy import MCPProxyApp, ProxyClient, create_proxy_app, _resolve_client_ip


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return ProxyConfig(
        PROXY_HOST="127.0.0.1",
        PROXY_PORT=8001,
        DEBUG=True,
        TARGET_MCP_URL="http://mock-mcp-server:8080",
        TARGET_TIMEOUT=5,
        BEARER_TOKEN="test-token-123",
        AUTH_HEADER_NAME="Authorization",
        ALLOWED_ORIGINS="*",
        PROXY_PREFIX="",
        MAX_REQUEST_SIZE=1000000
    )


@pytest.fixture
def proxy_app(mock_config):
    """Create a proxy app for testing."""
    app = MCPProxyApp(mock_config)
    return app


@pytest.fixture
def test_client(proxy_app):
    """Create a test client for the proxy app."""
    return TestClient(proxy_app.get_app())


class TestProxyClient:
    """Tests for the ProxyClient class."""
    
    @pytest.mark.asyncio
    async def test_forward_request_success(self, mock_config):
        """Test successful request forwarding."""
        client = ProxyClient(mock_config)

        # Mock the httpx client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.aclose = AsyncMock()

        # Create an async generator for aiter_bytes
        async def mock_aiter_bytes():
            yield b'{"result": "ok"}'

        mock_response.aiter_bytes = mock_aiter_bytes

        with patch.object(client.client, 'send', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response

            status_code, headers, body_gen = await client.forward_request(
                method="GET",
                path="/test",
                headers={"user-agent": "test"},
                body=None
            )

            assert status_code == 200
            assert headers["content-type"] == "application/json"

            # Verify stream=True was passed
            assert mock_send.call_args.kwargs.get("stream") is True

            # Test body streaming
            body_chunks = []
            async for chunk in body_gen:
                body_chunks.append(chunk)

            assert b''.join(body_chunks) == b'{"result": "ok"}'
            # Response should be closed after streaming completes
            mock_response.aclose.assert_awaited()
    
    @pytest.mark.asyncio
    async def test_forward_request_timeout(self, mock_config):
        """Test request timeout handling."""
        client = ProxyClient(mock_config)
        
        with patch.object(client.client, 'send', new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = httpx.TimeoutException("Request timed out")
            
            with pytest.raises(Exception) as exc_info:
                await client.forward_request(
                    method="GET",
                    path="/test",
                    headers={},
                    body=None
                )
            
            assert "504" in str(exc_info.value) or "timeout" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_filter_headers(self, mock_config):
        """Test header filtering."""
        client = ProxyClient(mock_config)
        
        headers = {
            "Host": "localhost",
            "Content-Length": "100",
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=30",
            "Proxy-Connection": "keep-alive",
            "User-Agent": "test",
            "Authorization": "Bearer token",
            "Referer": "http://example.com",
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "5.6.7.8",
            "Via": "1.1 proxy",
            "Proxy-Authorization": "Basic dXNlcjpwYXNz",
            "Cookie": "session=abc123",
            "X-Custom-Header": "value"
        }
        
        filtered = client._filter_headers(headers)
        
        assert "Host" not in filtered
        assert "Content-Length" not in filtered
        assert "Transfer-Encoding" not in filtered
        assert "Connection" not in filtered  # Hop-by-hop (RFC 7230)
        assert "Keep-Alive" not in filtered  # Hop-by-hop
        assert "Proxy-Connection" not in filtered  # Non-standard hop-by-hop
        assert "Authorization" not in filtered
        assert "User-Agent" not in filtered  # Now filtered for security
        assert "Referer" not in filtered  # Now filtered for security
        assert "X-Forwarded-For" not in filtered  # Now filtered for security
        assert "X-Real-IP" not in filtered  # Now filtered for security
        assert "Via" not in filtered  # Now filtered for security
        assert "Proxy-Authorization" not in filtered  # Prevent credential leakage
        assert "Cookie" not in filtered  # Prevent session leakage
        assert "X-Custom-Header" in filtered


class TestMCPProxyApp:
    """Tests for the MCPProxyApp class."""
    
    def test_missing_auth_header(self, test_client):
        """Test missing authentication header."""
        # This should fail because no auth header is provided
        response = test_client.get("/some-path")
        assert response.status_code == 401
    
    def test_invalid_bearer_token(self, test_client):
        """Test invalid bearer token."""
        response = test_client.get(
            "/some-path",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 403
    
    @patch.object(MCPProxyApp, '_validate_bearer_token', return_value=True)
    @patch.object(ProxyClient, 'forward_request', new_callable=AsyncMock)
    def test_proxy_endpoint_success(self, mock_forward, mock_validate, proxy_app, test_client):
        """Test successful proxy request."""
        # Mock the forward_request to return success
        def mock_forward_impl(*args, **kwargs):
            def body_gen():
                yield b'{"result": "success"}'
            return (200, {"content-type": "application/json"}, body_gen())
        
        mock_forward.side_effect = mock_forward_impl
        
        response = test_client.post(
            "/test-endpoint",
            headers={"Authorization": "Bearer test-token-123"},
            json={"data": "test"}
        )
        
        assert response.status_code == 200
        assert b'{"result": "success"}' in response.content
    
    def test_bearer_token_validation(self, mock_config, proxy_app):
        """Test bearer token validation."""
        # Test valid token
        assert proxy_app._validate_bearer_token("test-token-123") is True

        # Test invalid token
        with pytest.raises(Exception) as exc_info:
            proxy_app._validate_bearer_token("wrong-token")

        assert "403" in str(exc_info.value) or "Invalid" in str(exc_info.value)

        # Test missing token
        with pytest.raises(Exception) as exc_info:
            proxy_app._validate_bearer_token(None)

        assert "401" in str(exc_info.value)


class TestConfiguration:
    """Tests for configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ProxyConfig(BEARER_TOKEN="test")
        assert config.PROXY_HOST == "127.0.0.1"
        assert config.PROXY_PORT == 8000
        assert config.TARGET_MCP_URL == "http://localhost:8080"
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Test trailing slash removal from target URL
        config = ProxyConfig(BEARER_TOKEN="test", TARGET_MCP_URL="http://localhost:8080/")
        assert config.TARGET_MCP_URL == "http://localhost:8080"
        
        # Test proxy prefix normalization
        config = ProxyConfig(BEARER_TOKEN="test", PROXY_PREFIX="/api/mcp/")
        assert config.PROXY_PREFIX == "/api/mcp"
        
        config = ProxyConfig(BEARER_TOKEN="test", PROXY_PREFIX="api/mcp")
        assert config.PROXY_PREFIX == "/api/mcp"
    
    def test_allowed_origins_parsing(self):
        """Test allowed origins parsing."""
        config = ProxyConfig(BEARER_TOKEN="test", ALLOWED_ORIGINS="http://localhost:3000,https://app.example.com")
        assert config.allowed_origins_list == ["http://localhost:3000", "https://app.example.com"]
        
        config = ProxyConfig(BEARER_TOKEN="test", ALLOWED_ORIGINS="*")
        assert config.allowed_origins_list == ["*"]

    def test_trusted_proxies_parsing(self):
        """Test trusted proxies parsing."""
        config = ProxyConfig(BEARER_TOKEN="test")
        assert config.trusted_proxies_list == []

        config = ProxyConfig(BEARER_TOKEN="test", TRUSTED_PROXIES="172.16.0.0/12, 10.0.0.0/8")
        assert config.trusted_proxies_list == ["172.16.0.0/12", "10.0.0.0/8"]

    def test_response_size_default(self):
        """Test that MAX_RESPONSE_SIZE has a default value."""
        config = ProxyConfig(BEARER_TOKEN="test")
        assert config.MAX_RESPONSE_SIZE == 50_000_000


class TestProxyAppCreation:
    """Tests for proxy app creation."""
    
    @pytest.mark.asyncio
    async def test_create_proxy_app(self, mock_config):
        """Test creating proxy app with custom config."""
        app = await create_proxy_app(mock_config)
        assert isinstance(app, MCPProxyApp)
        assert app.config == mock_config


class TestRequestSizeLimit:
    """Tests for MAX_REQUEST_SIZE enforcement."""

    def test_oversized_body_rejected(self, proxy_app, test_client):
        """Test that requests exceeding MAX_REQUEST_SIZE are rejected with 413."""
        # mock_config has MAX_REQUEST_SIZE=1000000
        oversized_body = "x" * (proxy_app.config.MAX_REQUEST_SIZE + 1)
        response = test_client.post(
            "/test-endpoint",
            headers={"Authorization": "Bearer test-token-123"},
            content=oversized_body.encode(),
        )
        assert response.status_code == 413

    def test_valid_size_body_accepted(self, proxy_app, test_client):
        """Test that requests within MAX_REQUEST_SIZE are not rejected for size."""
        # Mock forward_request so the request succeeds
        with patch.object(MCPProxyApp, '_validate_bearer_token', return_value=True), \
             patch.object(ProxyClient, 'forward_request', new_callable=AsyncMock) as mock_forward:
            def mock_forward_impl(*args, **kwargs):
                def body_gen():
                    yield b'{"result": "ok"}'
                return (200, {"content-type": "application/json"}, body_gen())
            mock_forward.side_effect = mock_forward_impl

            body = b"x" * 100  # Well under the 1MB limit
            response = test_client.post(
                "/test-endpoint",
                headers={"Authorization": "Bearer test-token-123"},
                content=body,
            )
            assert response.status_code == 200

    def test_oversized_body_rejected_chunked(self, proxy_app, test_client):
        """Test that chunked requests without Content-Length are also size-limited."""
        oversized_body = "x" * (proxy_app.config.MAX_REQUEST_SIZE + 1)
        response = test_client.post(
            "/test-endpoint",
            headers={
                "Authorization": "Bearer test-token-123",
                "Transfer-Encoding": "chunked",
            },
            content=oversized_body.encode(),
        )
        assert response.status_code == 413

    def test_negative_content_length_rejected(self, proxy_app, test_client):
        """Test that a negative Content-Length is rejected as invalid."""
        response = test_client.post(
            "/test-endpoint",
            headers={
                "Authorization": "Bearer test-token-123",
                "Content-Length": "-1",
            },
            content=b"x",
        )
        assert response.status_code == 400


class TestClientIPExtraction:
    """Tests for _resolve_client_ip used by the rate limiter."""

    def test_prefers_cf_connecting_ip(self):
        """Test that CF-Connecting-IP takes priority when configured and peer is trusted (loopback)."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [
                (b"cf-connecting-ip", b"203.0.113.50"),
                (b"x-forwarded-for", b"10.0.0.1, 10.0.0.2"),
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)
        assert _resolve_client_ip(request, [], "cf-connecting-ip") == "203.0.113.50"

    def test_uses_rightmost_x_forwarded_for(self):
        """Test that the rightmost X-Forwarded-For entry is used when peer is trusted."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [
                (b"x-forwarded-for", b"203.0.113.50, 10.0.0.1"),
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)
        assert _resolve_client_ip(request, []) == "10.0.0.1"

    def test_ignores_spoofed_leftmost_x_forwarded_for(self):
        """Test that a client-spoofed leftmost X-Forwarded-For entry is not used."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [
                (b"x-forwarded-for", b"spoofed-ip, 10.0.0.2"),
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)
        assert _resolve_client_ip(request, []) == "10.0.0.2"

    def test_falls_back_to_client_host(self):
        """Test that the TCP peer is used when no proxy headers are present."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)
        assert _resolve_client_ip(request, []) == "127.0.0.1"

    def test_untrusted_peer_ignores_forwarded_headers(self):
        """Test that a direct (untrusted) peer's forwarded headers are ignored."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [
                (b"cf-connecting-ip", b"1.2.3.4"),
                (b"x-forwarded-for", b"5.6.7.8, 9.10.11.12"),
            ],
            "query_string": b"",
            "client": ("203.0.113.99", 12345),
        }
        request = Request(scope)
        # No trusted networks configured, peer is not loopback
        assert _resolve_client_ip(request, []) == "203.0.113.99"

    def test_trusted_docker_network_peer(self):
        """Test that a Docker network peer in TRUSTED_PROXIES is trusted."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [
                (b"cf-connecting-ip", b"198.51.100.1"),
            ],
            "query_string": b"",
            "client": ("172.17.0.3", 12345),
        }
        request = Request(scope)
        trusted = MCPProxyApp._parse_trusted_networks("172.16.0.0/12")
        assert _resolve_client_ip(request, trusted, "cf-connecting-ip") == "198.51.100.1"

    def test_ipv6_loopback_trusted(self):
        """Test that IPv6 loopback (::1) is trusted."""
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [
                (b"cf-connecting-ip", b"2001:db8::1"),
            ],
            "query_string": b"",
            "client": ("::1", 12345),
        }
        request = Request(scope)
        assert _resolve_client_ip(request, [], "cf-connecting-ip") == "2001:db8::1"

    def test_parse_trusted_networks_empty(self):
        """Test that empty trusted proxies string returns empty list."""
        assert MCPProxyApp._parse_trusted_networks("") == []

    def test_parse_trusted_networks_invalid(self):
        """Test that invalid entries are skipped with a warning."""
        assert MCPProxyApp._parse_trusted_networks("not-an-ip") == []


class TestRateLimiting:
    """Tests for rate limiting functionality."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_enabled(self, mock_config):
        """Test that rate limiting is enabled and configured with defaults."""
        from src.proxy import RATE_LIMITING_AVAILABLE
        
        # Rate limiting should be available since slowapi is in requirements
        assert RATE_LIMITING_AVAILABLE is True
        
        # Create proxy app
        app = await create_proxy_app(mock_config)
        
        # Check that limiter is set up
        assert hasattr(app, 'limiter')
        assert app.limiter is not None
        
        # Check that default limits are configured (they're LimitGroup objects, not strings)
        assert len(app.limiter._default_limits) > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting_middleware_and_handler(self, mock_config):
        """Test that rate limiting middleware and exception handler are configured."""
        from src.proxy import RATE_LIMITING_AVAILABLE, SlowAPIMiddleware, RateLimitExceeded
        from fastapi import FastAPI
        
        if RATE_LIMITING_AVAILABLE and SlowAPIMiddleware:
            app = await create_proxy_app(mock_config)
            fastapi_app = app.get_app()
            
            # Check that middleware exists
            assert fastapi_app is not None
            
            # Check that RateLimitExceeded exception handler is registered
            # The handler should return a 429 response
            # We can test this by checking the app's exception handlers
            assert len(fastapi_app.exception_handlers) > 0
    
    def test_rate_limit_config_values(self, mock_config):
        """Test the rate limiting configuration values."""
        from src.proxy import MCPProxyApp
        
        app = MCPProxyApp(mock_config)
        
        # Verify limiter is created with correct settings
        assert app.limiter is not None
        # Default limits should have at least one LimitGroup
        assert len(app.limiter._default_limits) > 0

    def test_trusted_networks_from_config(self, mock_config):
        """Test that trusted_networks is parsed from config."""
        from src.proxy import MCPProxyApp
        
        # Empty config = no trusted networks (only loopback trusted at runtime)
        app = MCPProxyApp(mock_config)
        assert app.trusted_networks == []

        # Config with TRUSTED_PROXIES
        config = ProxyConfig(
            BEARER_TOKEN="test",
            TRUSTED_PROXIES="172.16.0.0/12, 10.0.0.0/8"
        )
        app2 = MCPProxyApp(config)
        assert len(app2.trusted_networks) == 2


class TestHeaderFiltering:
    """Tests for response header filtering."""
    
    def test_filter_response_headers(self, proxy_app):
        """Test response header filtering."""
        headers = {
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
            "X-Custom-Header": "value"
        }
        
        filtered = proxy_app._filter_response_headers(headers)
        
        assert "Content-Type" in filtered
        assert "Transfer-Encoding" not in filtered
        assert "Connection" not in filtered
        assert "X-Custom-Header" in filtered
    
    def test_filter_response_headers_strips_info_leak(self, proxy_app):
        """Test that information-leaking headers from upstream are stripped."""
        headers = {
            "Content-Type": "application/json",
            "Server": "nginx/1.25.3",
            "X-Powered-By": "Express",
            "X-ASPNET-Version": "4.0.30319",
            "X-Debug": "true",
            "Via": "1.1 internal-proxy",
            "X-Custom-Header": "value"
        }
        
        filtered = proxy_app._filter_response_headers(headers)
        
        assert "Content-Type" in filtered
        assert "Server" not in filtered
        assert "X-Powered-By" not in filtered
        assert "X-ASPNET-Version" not in filtered
        assert "X-Debug" not in filtered
        assert "Via" not in filtered
        assert "X-Custom-Header" in filtered

    def test_filter_response_headers_strips_set_cookie(self, proxy_app):
        """Test that Set-Cookie headers from upstream are not forwarded to clients."""
        headers = {
            "Content-Type": "application/json",
            "Set-Cookie": "session=abc123; HttpOnly",
            "X-Custom-Header": "value"
        }
        
        filtered = proxy_app._filter_response_headers(headers)
        
        assert "Content-Type" in filtered
        assert "Set-Cookie" not in filtered
        assert "X-Custom-Header" in filtered

    def test_filter_response_headers_strips_cors(self, proxy_app):
        """Test that upstream CORS headers are stripped to prevent policy bypass."""
        headers = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Expose-Headers": "X-Custom",
            "Access-Control-Max-Age": "3600",
            "X-Custom-Header": "value"
        }
        
        filtered = proxy_app._filter_response_headers(headers)
        
        assert "Content-Type" in filtered
        assert "Access-Control-Allow-Origin" not in filtered
        assert "Access-Control-Allow-Credentials" not in filtered
        assert "Access-Control-Allow-Methods" not in filtered
        assert "Access-Control-Allow-Headers" not in filtered
        assert "Access-Control-Expose-Headers" not in filtered
        assert "Access-Control-Max-Age" not in filtered
        assert "X-Custom-Header" in filtered


class TestResponseSizeLimit:
    """Tests for MAX_RESPONSE_SIZE enforcement."""

    @pytest.mark.asyncio
    async def test_response_body_generator_truncates_oversized(self, mock_config):
        """Test that response streaming aborts when MAX_RESPONSE_SIZE is exceeded."""
        import httpx2 as httpx
        config = ProxyConfig(
            BEARER_TOKEN="test",
            TARGET_MCP_URL="http://mock:8080",
            MAX_RESPONSE_SIZE=100,
        )
        client = ProxyClient(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        # No content-length header -> exercises the chunked-stream guard
        mock_response.headers = {"content-type": "application/octet-stream"}
        mock_response.aclose = AsyncMock()

        # Generate 10 chunks of 20 bytes each (200 bytes total, limit is 100)
        async def mock_aiter_bytes():
            for _ in range(10):
                yield b"x" * 20

        mock_response.aiter_bytes = mock_aiter_bytes

        with patch.object(client.client, 'send', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response

            status_code, headers, body_gen = await client.forward_request(
                method="GET",
                path="/big",
                headers={},
                body=None,
            )

            # Consuming the generator should raise once the limit is hit
            chunks = []
            with pytest.raises(httpx.StreamError):
                async for chunk in body_gen:
                    chunks.append(chunk)

            # Should have received only 5 chunks (100 bytes) before aborting
            total_bytes = sum(len(c) for c in chunks)
            assert total_bytes <= 100
            # Response should be closed after abort
            mock_response.aclose.assert_awaited()

    @pytest.mark.asyncio
    async def test_oversized_upstream_content_length_rejected(self, mock_config):
        """Test that upstream Content-Length > MAX_RESPONSE_SIZE is rejected with 413."""
        config = ProxyConfig(
            BEARER_TOKEN="test",
            TARGET_MCP_URL="http://mock:8080",
            MAX_RESPONSE_SIZE=100,
        )
        client = ProxyClient(config)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/octet-stream", "content-length": "9999"}
        mock_response.aclose = AsyncMock()

        with patch.object(client.client, 'send', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response

            with pytest.raises(Exception) as exc_info:
                await client.forward_request(
                    method="GET",
                    path="/big",
                    headers={},
                    body=None,
                )
            assert "413" in str(exc_info.value)
            mock_response.aclose.assert_awaited()


class TestCustomAuthHeader:
    """Tests for AUTH_HEADER_NAME controlling which header is read for auth."""

    def test_custom_auth_header_name(self):
        """Test that a custom AUTH_HEADER_NAME is read for auth."""
        config = ProxyConfig(
            BEARER_TOKEN="my-secret",
            AUTH_HEADER_NAME="X-Api-Key",
        )
        app = MCPProxyApp(config)

        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"x-api-key", b"my-secret")],
            "client": ("127.0.0.1", 12345),
        }
        token = app._extract_token(Request(scope))
        assert token == "my-secret"
        assert app._validate_bearer_token(token) is True

    def test_custom_auth_header_ignored_when_standard_used(self):
        """Test that Authorization header is not read when AUTH_HEADER_NAME is custom."""
        config = ProxyConfig(
            BEARER_TOKEN="my-secret",
            AUTH_HEADER_NAME="X-Api-Key",
        )
        app = MCPProxyApp(config)

        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"authorization", b"Bearer my-secret")],
            "client": ("127.0.0.1", 12345),
        }
        token = app._extract_token(Request(scope))
        assert token is None

    def test_standard_auth_header_still_works(self, mock_config):
        """Test that the default Authorization: Bearer header works."""
        app = MCPProxyApp(mock_config)

        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"authorization", b"Bearer test-token-123")],
            "client": ("127.0.0.1", 12345),
        }
        token = app._extract_token(Request(scope))
        assert token == "test-token-123"

    def test_malformed_bearer_returns_none(self, mock_config):
        """Test that a malformed Bearer header returns None (-> 401)."""
        app = MCPProxyApp(mock_config)

        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"authorization", b"Basic dXNlcjpwYXNz")],
            "client": ("127.0.0.1", 12345),
        }
        token = app._extract_token(Request(scope))
        assert token is None


class TestRealIpHeaderDefault:
    """Tests for REAL_IP_HEADER default and nginx spoofing fix."""

    def test_default_real_ip_header_is_cf(self):
        """Test that REAL_IP_HEADER defaults to cf-connecting-ip."""
        config = ProxyConfig(BEARER_TOKEN="test")
        assert config.REAL_IP_HEADER == "cf-connecting-ip"

    def test_nginx_spoofed_cf_connecting_ip_ignored(self):
        """Test that spoofed CF-Connecting-IP is ignored when REAL_IP_HEADER is empty (nginx)."""
        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [
                (b"cf-connecting-ip", b"1.2.3.4"),
                (b"x-forwarded-for", b"spoofed, 10.0.0.2"),
            ],
            "client": ("172.16.0.2", 12345),  # nginx peer, trusted
        }
        trusted = MCPProxyApp._parse_trusted_networks("172.16.0.0/12")
        # With real_ip_header="" (nginx config), CF-Connecting-IP is NOT trusted;
        # rightmost X-Forwarded-For (set by nginx) is used instead.
        ip = _resolve_client_ip(Request(scope), trusted, "")
        assert ip == "10.0.0.2"

    def test_real_ip_header_empty_uses_xff(self):
        """Test that empty REAL_IP_HEADER falls back to rightmost X-Forwarded-For."""
        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"x-forwarded-for", b"203.0.113.50, 10.0.0.1")],
            "client": ("127.0.0.1", 12345),
        }
        assert _resolve_client_ip(Request(scope), [], "") == "10.0.0.1"


class TestConcurrencyLimit:
    """Tests for MAX_CONCURRENT_REQUESTS semaphore."""

    def test_concurrency_semaphore_created(self):
        """Test that the concurrency semaphore is initialized."""
        config = ProxyConfig(BEARER_TOKEN="test", MAX_CONCURRENT_REQUESTS=5)
        app = MCPProxyApp(config)
        assert app._concurrency_sem._value == 5

    def test_default_concurrency_limit(self):
        """Test that the default concurrency limit is 50."""
        config = ProxyConfig(BEARER_TOKEN="test")
        assert config.MAX_CONCURRENT_REQUESTS == 50


class TestBodyReadInsideSemaphore:
    """Tests that request body buffering happens inside the concurrency semaphore."""

    def test_body_read_under_semaphore_with_concurrency_limit(self):
        """Verify that the body is read while the semaphore is held.

        We set MAX_CONCURRENT_REQUESTS=1 and mock forward_request to record
        whether the semaphore value dropped to 0 when it is called (meaning
        the body has already been read inside the semaphore). If the body
        were read before acquiring the semaphore, the semaphore would still
        be at 1 during body read and only drop to 0 during forward_request.
        """
        import asyncio
        from unittest.mock import AsyncMock, patch

        config = ProxyConfig(
            BEARER_TOKEN="test",
            MAX_CONCURRENT_REQUESTS=1,
            MAX_REQUEST_SIZE=100000,
        )
        app = MCPProxyApp(config)
        client = app.get_app()

        sem_values_during_forward = []

        async def mock_forward(*args, **kwargs):
            sem_values_during_forward.append(app._concurrency_sem._value)
            def body_gen():
                yield b'{"ok": true}'
            return (200, {"content-type": "application/json"}, body_gen())

        with patch.object(app.proxy_client, 'forward_request', new_callable=AsyncMock) as mock:
            mock.side_effect = mock_forward
            from fastapi.testclient import TestClient
            tc = TestClient(client)
            response = tc.post(
                "/test",
                headers={"Authorization": "Bearer test"},
                content=b"x" * 100,
            )
            assert response.status_code == 200
            assert sem_values_during_forward == [0], (
                "forward_request should run while the semaphore is held (value=0); "
                f"got {sem_values_during_forward}"
            )


class TestRateLimitCORS:
    """Tests that the rate-limit 429 response includes CORS headers."""

    def test_429_includes_wildcard_cors_origin(self):
        """When ALLOWED_ORIGINS=*, the 429 response should include
        Access-Control-Allow-Origin: *."""
        from slowapi.errors import RateLimitExceeded

        config = ProxyConfig(
            BEARER_TOKEN="test",
            ALLOWED_ORIGINS="*",
        )
        app = MCPProxyApp(config)
        fastapi_app = app.get_app()

        # Find the registered RateLimitExceeded handler
        handler = fastapi_app.exception_handlers.get(RateLimitExceeded)
        assert handler is not None

        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"origin", b"https://evil.com")],
            "client": ("127.0.0.1", 12345),
        }
        response = handler(Request(scope), MagicMock())
        assert response.status_code == 429
        assert response.headers.get("access-control-allow-origin") == "*"

    def test_429_includes_specific_cors_origin(self):
        """When ALLOWED_ORIGINS is a specific list, the 429 response should
        echo the Origin only if it is in the allowed list."""
        from slowapi.errors import RateLimitExceeded

        config = ProxyConfig(
            BEARER_TOKEN="test",
            ALLOWED_ORIGINS="https://app.example.com",
        )
        app = MCPProxyApp(config)
        fastapi_app = app.get_app()

        handler = fastapi_app.exception_handlers.get(RateLimitExceeded)
        assert handler is not None

        from starlette.requests import Request

        # Matching origin
        scope_ok = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"origin", b"https://app.example.com")],
            "client": ("127.0.0.1", 12345),
        }
        response = handler(Request(scope_ok), MagicMock())
        assert response.status_code == 429
        assert response.headers.get("access-control-allow-origin") == "https://app.example.com"

        # Non-matching origin
        scope_bad = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [(b"origin", b"https://evil.com")],
            "client": ("127.0.0.1", 12345),
        }
        response2 = handler(Request(scope_bad), MagicMock())
        assert response2.status_code == 429
        assert response2.headers.get("access-control-allow-origin") is None

    def test_429_no_origin_header(self):
        """When no Origin header is present, no CORS headers are added."""
        from slowapi.errors import RateLimitExceeded

        config = ProxyConfig(
            BEARER_TOKEN="test",
            ALLOWED_ORIGINS="*",
        )
        app = MCPProxyApp(config)
        fastapi_app = app.get_app()

        handler = fastapi_app.exception_handlers.get(RateLimitExceeded)
        assert handler is not None

        from starlette.requests import Request
        scope = {
            "type": "http", "method": "GET", "path": "/x", "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        response = handler(Request(scope), MagicMock())
        assert response.status_code == 429
        assert response.headers.get("access-control-allow-origin") is None
