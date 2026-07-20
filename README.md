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
PROXY_HOST=0.0.0.0
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
| `PROXY_HOST` | Host to bind the proxy server | `0.0.0.0` | No |
| `PROXY_PORT` | Port to bind the proxy server | `8000` | No |
| `TARGET_MCP_URL` | URL of the target MCP server | `http://localhost:8080` | No |
| `TARGET_TIMEOUT` | Request timeout to target server (seconds) | `30` | No |
| `BEARER_TOKEN` | Secret token for authentication | - | **Yes** |
| `AUTH_HEADER_NAME` | Header name for token | `Authorization` | No |
| `DEBUG` | Enable debug mode | `false` | No |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated or `*`) | `*` | No |
| `PROXY_PREFIX` | URL prefix for all proxy routes | `""` (empty) | No |
| `MAX_REQUEST_SIZE` | Maximum request body size (bytes) | `10000000` (10MB) | No |

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
2. **Token Security**: Always use strong, randomly generated tokens. Tokens are compared using constant-time comparison (hmac.compare_digest) to prevent timing attacks.
3. **Network Security**: Restrict access to the proxy server
4. **Rate Limiting**: Built-in rate limiting (100 requests/minute per IP address by default) via the `slowapi` library. Can be customized by modifying the `default_limits` parameter in the Limiter configuration.
5. **Path Validation**: Built-in protection against path traversal attacks (`..` and `//`)
6. **Header Filtering**: Sensitive headers are automatically filtered:
   - `Authorization` (authentication token)
   - `User-Agent` (client identification)
   - `Referer` (referral information)
   - `X-Forwarded-For`, `X-Real-IP` (IP forwarding)
   - `Via` (proxy chain disclosure)
   - `Host`, `Content-Length`, `Transfer-Encoding`
7. **SSRF Protection**: HTTP redirects are disabled to prevent Server-Side Request Forgery
8. **Request Size Limit**: Default 10MB limit prevents memory exhaustion attacks

## License

MIT License
