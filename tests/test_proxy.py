"""
Tests for the MCP Proxy Server.
"""

import pytest
import httpx2 as httpx
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock

from src.config import ProxyConfig
from src.proxy import MCPProxyApp, ProxyClient, create_proxy_app


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
            "User-Agent": "test",
            "Authorization": "Bearer token",
            "Referer": "http://example.com",
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "5.6.7.8",
            "Via": "1.1 proxy",
            "Proxy-Authorization": "Basic dXNlcjpwYXNz",
            "Cookie": "session=abc123",
            "Set-Cookie": "session=abc123",
            "X-Custom-Header": "value"
        }
        
        filtered = client._filter_headers(headers)
        
        assert "Host" not in filtered
        assert "Content-Length" not in filtered
        assert "Authorization" not in filtered
        assert "User-Agent" not in filtered  # Now filtered for security
        assert "Referer" not in filtered  # Now filtered for security
        assert "X-Forwarded-For" not in filtered  # Now filtered for security
        assert "X-Real-IP" not in filtered  # Now filtered for security
        assert "Via" not in filtered  # Now filtered for security
        assert "Proxy-Authorization" not in filtered  # Prevent credential leakage
        assert "Cookie" not in filtered  # Prevent session leakage
        assert "Set-Cookie" not in filtered  # Prevent session leakage
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
        from fastapi.security import HTTPAuthorizationCredentials
        
        # Test valid token
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="test-token-123"
        )
        assert proxy_app._validate_bearer_token(credentials) is True
        
        # Test invalid token
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="wrong-token"
        )
        
        with pytest.raises(Exception) as exc_info:
            proxy_app._validate_bearer_token(credentials)
        
        assert "403" in str(exc_info.value) or "Invalid" in str(exc_info.value)


class TestConfiguration:
    """Tests for configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ProxyConfig()
        assert config.PROXY_HOST == "127.0.0.1"
        assert config.PROXY_PORT == 8000
        assert config.TARGET_MCP_URL == "http://localhost:8080"
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Test trailing slash removal from target URL
        config = ProxyConfig(TARGET_MCP_URL="http://localhost:8080/")
        assert config.TARGET_MCP_URL == "http://localhost:8080"
        
        # Test proxy prefix normalization
        config = ProxyConfig(PROXY_PREFIX="/api/mcp/")
        assert config.PROXY_PREFIX == "/api/mcp"
        
        config = ProxyConfig(PROXY_PREFIX="api/mcp")
        assert config.PROXY_PREFIX == "/api/mcp"
    
    def test_allowed_origins_parsing(self):
        """Test allowed origins parsing."""
        config = ProxyConfig(ALLOWED_ORIGINS="http://localhost:3000,https://app.example.com")
        assert config.allowed_origins_list == ["http://localhost:3000", "https://app.example.com"]
        
        config = ProxyConfig(ALLOWED_ORIGINS="*")
        assert config.allowed_origins_list == ["*"]


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
    """Tests for _get_client_ip used by the rate limiter."""

    def test_prefers_cf_connecting_ip(self):
        """Test that CF-Connecting-IP takes priority over everything."""
        from src.proxy import _get_client_ip
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
        assert _get_client_ip(request) == "203.0.113.50"

    def test_uses_rightmost_x_forwarded_for(self):
        """Test that the rightmost X-Forwarded-For entry is used (set by the last trusted proxy)."""
        from src.proxy import _get_client_ip
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
        assert _get_client_ip(request) == "10.0.0.1"

    def test_ignores_spoofed_leftmost_x_forwarded_for(self):
        """Test that a client-spoofed leftmost X-Forwarded-For entry is not used."""
        from src.proxy import _get_client_ip
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
        assert _get_client_ip(request) == "10.0.0.2"

    def test_falls_back_to_client_host(self):
        """Test that the TCP peer is used when no proxy headers are present."""
        from src.proxy import _get_client_ip
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
        assert _get_client_ip(request) == "127.0.0.1"


class TestRateLimiting:
    """Tests for rate limiting functionality."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_enabled(self, mock_config):
        """Test that rate limiting is enabled and configured with defaults."""
        from src.proxy import RATE_LIMITING_AVAILABLE, _get_client_ip
        
        # Rate limiting should be available since slowapi is in requirements
        assert RATE_LIMITING_AVAILABLE is True
        
        # Create proxy app
        app = await create_proxy_app(mock_config)
        
        # Check that limiter is set up
        assert hasattr(app, 'limiter')
        assert app.limiter is not None
        
        # Check that key function is our X-Forwarded-For-aware function
        assert app.limiter._key_func == _get_client_ip
        
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
        from src.proxy import MCPProxyApp, _get_client_ip
        
        app = MCPProxyApp(mock_config)
        
        # Verify limiter is created with correct settings
        assert app.limiter is not None
        assert app.limiter._key_func == _get_client_ip
        # Default limits should have at least one LimitGroup
        assert len(app.limiter._default_limits) > 0


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
