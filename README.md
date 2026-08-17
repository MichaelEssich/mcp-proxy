# MCP Proxy Server

A Python-based proxy server that forwards MCP (Model Context Protocol) HTTP requests to a target MCP server with bearer token authentication.

## Features

- **Bearer Token Authentication**: Secure your MCP server endpoint with API key authentication (constant-time comparison)
- **Streaming Support**: Full support for MCP's streamable HTTP responses
- **HTTP/1.1 Proxy**: Forward all HTTP methods (GET, POST, PUT, DELETE, etc.)
- **Configurable**: Easy configuration via environment variables or config files
- **Async**: Built with FastAPI and async/await for high performance
- **Path Validation**: Built-in protection against path traversal attacks
- **Rate Limiting**: Built-in rate limiting (100 requests/minute per IP by default) to prevent abuse
- **Security Headers**: Automatic filtering of sensitive headers to prevent information leakage
- **SSRF Protection**: Disabled redirects to prevent Server-Side Request Forgery

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file or set environment variables:

```bash
# Proxy server configuration
PROXY_HOST=127.0.0.1
PROXY_PORT=8000

# Target MCP server configuration
TARGET_MCP_URL=http://localhost:8080
TARGET_TIMEOUT=30

# Authentication configuration
BEARER_TOKEN=your-secret-token
AUTH_HEADER_NAME=Authorization

# CORS settings
ALLOWED_ORIGINS=*  # CORS origins, comma-separated

# Proxy routing
PROXY_PREFIX=/mcp  # Optional: serve proxy under this subpath

# Optional settings
DEBUG=false
MAX_REQUEST_SIZE=10000000  # 10MB - More reasonable limit to prevent memory exhaustion
```

### 3. Run the Proxy

```bash
duv run src/main.py
# or
python -m src.main
# or with command-line arguments
python -m src.main --host 0.0.0.0 --port 8000 --reload --debug
```

The proxy will be available at `http://localhost:8000` and will forward requests to your MCP server.

#### Command-line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--host` | Host to bind the server | From config |
| `--port` | Port to bind the server | From config |
| `--reload` | Enable auto-reload for development | False |
| `--debug` | Enable debug mode | False |
| `--config` | Path to configuration file | `.env` |

## API Usage

All requests to the proxy must include the bearer token in the Authorization header:

```bash
curl -X POST http://localhost:8000/mcp/endpoints \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"method": "GET", "path": "/some-endpoint"}'
```

### Subpath Support

The proxy supports serving under a subpath using `PROXY_PREFIX`:

```bash
# Configure proxy to serve under /mcp
export PROXY_PREFIX=/mcp

# Now requests to /mcp/* will be proxied
curl http://localhost:8000/mcp/any-endpoint \
  -H "Authorization: Bearer your-secret-token"
```

## Docker Deployment

### Build and Run

```bash
docker-compose up --build
```

### Environment Variables in Docker

Set environment variables in the `docker-compose.yml` file or via a `.env` file.

## Configuration Options

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PROXY_HOST` | Host to bind the proxy server | `127.0.0.1` | No |
| `PROXY_PORT` | Port to bind the proxy server | `8000` | No |
| `TARGET_MCP_URL` | URL of the target MCP server | `http://localhost:8080` | No |
| `TARGET_TIMEOUT` | Request timeout to target server (seconds) | `30` | No |
| `BEARER_TOKEN` | Secret token for authentication (min 32 chars) | - | **Yes** |
| `AUTH_HEADER_NAME` | Header name for token | `Authorization` | No |
| `DEBUG` | Enable debug mode | `false` | No |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated or `*`) | `*` | No |
| `PROXY_PREFIX` | URL prefix for all proxy routes | `""` (empty) | No |
| `MAX_REQUEST_SIZE` | Maximum request body size (bytes) | `10000000` (10MB) | No |
| `MAX_RESPONSE_SIZE` | Maximum upstream response size (bytes) | `50000000` (50MB) | No |
| `MAX_CONCURRENT_REQUESTS` | Max in-flight proxied requests | `50` | No |
| `TRUSTED_PROXIES` | Trusted reverse proxy IPs/CIDRs (comma-separated) | `""` (loopback only) | No |
| `REAL_IP_HEADER` | Header for real client IP (`cf-connecting-ip` for Cloudflare, `""` for nginx/X-Forwarded-For) | `cf-connecting-ip` | No |

## Architecture

```
Client → [Bearer Token Auth] → MCP Proxy → Target MCP Server
                ↓
           Token Validation (hmac compare)
                ↓
           Path Validation
                ↓
           Header Filtering
                ↓
           Request Forwarding
                ↓
           Response Streaming
                ↓
           Rate Limiting (optional)
```

## Security Considerations

1. **HTTPS**: Use HTTPS in production with a valid SSL certificate. **This proxy does not provide HTTPS support! Use a separate HTTPS proxy!**
2. **Token Security**: Always use strong, randomly generated tokens (minimum 32 characters, enforced at startup). Tokens are compared using constant-time comparison (hmac.compare_digest) to prevent timing attacks.
3. **Network Security**: Restrict access to the proxy server
4. **Rate Limiting**: Built-in rate limiting (100 requests/minute per IP address by default) via the `slowapi` library. Can be customized by modifying the `default_limits` parameter in the Limiter configuration.
5. **Path Validation**: Built-in protection against path traversal attacks (`..` and `//`)
6. **Header Filtering**: Sensitive headers are automatically filtered (both request and response directions):
   - `Authorization` (authentication token — always stripped, even when `AUTH_HEADER_NAME` is custom)
   - `User-Agent` (client identification)
   - `Referer` (referral information)
   - `X-Forwarded-For`, `X-Real-IP` (IP forwarding)
   - `Via` (proxy chain disclosure)
   - `Host`, `Content-Length`, `Transfer-Encoding`
   - `Cookie` / `Set-Cookie` (session leakage prevention)
   - `Proxy-Authorization` (credential leakage prevention)
7. **SSRF Protection**: HTTP redirects are disabled to prevent Server-Side Request Forgery
8. **Request Size Limit**: Default 10MB limit prevents memory exhaustion attacks
9. **Response Size Limit**: Upstream responses are capped at 50MB; oversized responses are rejected with 413
10. **Concurrency Limiting**: In-flight proxied requests are capped (default 50) to bound memory usage
11. **Custom Auth Header**: `AUTH_HEADER_NAME` controls which header the token is read from (standard `Authorization: Bearer` or a custom header like `X-Api-Key`)
12. **Rate-Limit Integrity**: The real client IP is resolved from `REAL_IP_HEADER` (default `cf-connecting-ip` for Cloudflare) or the rightmost `X-Forwarded-For` entry. Set `REAL_IP_HEADER=""` for nginx to avoid trusting client-spoofed `CF-Connecting-IP` headers

## Deployment Notes

### Cloudflare Tunnel (default)
`REAL_IP_HEADER` defaults to `cf-connecting-ip`, which Cloudflare overwrites with the true client IP. **When cloudflared runs on the host** (connecting to the proxy via loopback/127.0.0.1), no additional configuration is needed.

**When cloudflared runs in a separate container** (connecting over the Docker network), the proxy receives cloudflared's requests from a non-loopback IP (e.g. `172.x.x.x`). Since only loopback IPs are trusted by default, the proxy will ignore the `cf-connecting-ip` header and fall back to cloudflared's single container IP as the rate-limit key. This means all clients share one 100 req/min bucket and per-client rate limiting is effectively disabled. To fix this, set `TRUSTED_PROXIES` to the Docker network CIDR (e.g. `172.16.0.0/12`):

```bash
TRUSTED_PROXIES=172.16.0.0/12
REAL_IP_HEADER=cf-connecting-ip
```

### nginx Proxy Manager
Set `REAL_IP_HEADER=""` (empty) so the proxy uses the rightmost `X-Forwarded-For` entry, which nginx appends to and clients cannot forge on the right. Also set `TRUSTED_PROXIES` to your nginx peer's CIDR (e.g. `172.16.0.0/12` for Docker). Otherwise the proxy will not trust forwarded headers from nginx.

## License

MIT License
