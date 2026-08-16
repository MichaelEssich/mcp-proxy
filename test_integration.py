#!/usr/bin/env python3
"""
Integration test for MCP Proxy Server.

This script tests the proxy server with a simple HTTP server to verify
the proxy functionality works end-to-end.
"""

import asyncio
import logging
import os
import sys
import httpx2 as httpx
import uvicorn
from fastapi import FastAPI, Request

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.config import ProxyConfig
from src.proxy import MCPProxyApp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Mock MCP Server
class MockMCPServer:
    """A simple mock MCP server for testing."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8081):
        self.host = host
        self.port = port
        self.app = FastAPI()
        
        @self.app.get("/")
        async def root():
            return {"message": "Mock MCP Server", "status": "ok"}
        
        @self.app.get("/endpoints")
        async def get_endpoints():
            return {
                "endpoints": [
                    {"id": "1", "name": "test-endpoint", "type": "GET"},
                    {"id": "2", "name": "data-endpoint", "type": "POST"}
                ]
            }
        
        @self.app.post("/process")
        async def process_data(request: Request):
            data = await request.json()
            return {
                "result": "processed",
                "input": data,
                "status": "success"
            }
        
        @self.app.get("/stream")
        async def stream_data():
            # Simulate streaming response
            for i in range(5):
                yield f"data: chunk {i}\n\n"
    
    async def start(self):
        """Start the mock server."""
        self.server = uvicorn.Server(
            config=uvicorn.Config(
                app=self.app,
                host=self.host,
                port=self.port,
                log_level="error"
            )
        )
        logger.info(f"Starting mock MCP server on {self.host}:{self.port}")
        
        # For uvicorn 0.51.0+, use serve() instead of startup() + main_loop()
        self.serve_task = asyncio.create_task(self.server.serve())
        
        # Wait a bit for server to start
        await asyncio.sleep(0.5)
    
    async def stop(self):
        """Stop the mock server."""
        self.server.should_exit = True
        try:
            await self.serve_task
        except Exception:
            pass
        logger.info("Mock MCP server stopped")


async def test_proxy_integration():
    """Test the proxy server integration."""
    
    # Create mock MCP server
    mock_server = MockMCPServer(host="127.0.0.1", port=8081)
    
    try:
        # Start mock server
        await mock_server.start()
        
        # Create proxy config
        config = ProxyConfig(
            PROXY_HOST="127.0.0.1",
            PROXY_PORT=8001,
            DEBUG=True,
            TARGET_MCP_URL="http://127.0.0.1:8081",
            BEARER_TOKEN="test-secret-token",
            AUTH_HEADER_NAME="Authorization",
            ALLOWED_ORIGINS="*"
        )
        
        # Create proxy app
        proxy_app = MCPProxyApp(config)
        app = proxy_app.get_app()
        
        # Start proxy server
        proxy_server = uvicorn.Server(
            config=uvicorn.Config(
                app=app,
                host=config.PROXY_HOST,
                port=config.PROXY_PORT,
                log_level="error"
            )
        )
        
        logger.info(f"Starting proxy server on {config.PROXY_HOST}:{config.PROXY_PORT}")
        
        # For uvicorn 0.51.0+, use serve() instead of startup() + main_loop()
        proxy_task = asyncio.create_task(proxy_server.serve())
        
        # Wait for servers to start
        await asyncio.sleep(1)
        
        # Test client
        async with httpx.AsyncClient(timeout=30) as client:
            proxy_url = f"http://{config.PROXY_HOST}:{config.PROXY_PORT}"
            
            # Test 1: Missing authentication
            logger.info("Test 1: Missing authentication")
            response = await client.get(f"{proxy_url}/endpoints")
            assert response.status_code == 401
            logger.info("✓ Missing auth check passed")
            
            # Test 2: Invalid token
            logger.info("Test 2: Invalid token")
            response = await client.get(
                f"{proxy_url}/endpoints",
                headers={"Authorization": "Bearer invalid-token"}
            )
            assert response.status_code == 403
            logger.info("✓ Invalid token check passed")
            
            # Test 3: Valid token - GET request
            logger.info("Test 3: Valid token - GET request")
            response = await client.get(
                f"{proxy_url}/endpoints",
                headers={"Authorization": "Bearer test-secret-token"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "endpoints" in data
            logger.info("✓ GET request passed")
            
            # Test 4: Valid token - POST request
            logger.info("Test 4: Valid token - POST request")
            response = await client.post(
                f"{proxy_url}/process",
                headers={
                    "Authorization": "Bearer test-secret-token",
                    "Content-Type": "application/json"
                },
                json={"test": "data"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            logger.info("✓ POST request passed")
            
            # Test 5: Stream response
            logger.info("Test 5: Stream response")
            response = await client.get(
                f"{proxy_url}/stream",
                headers={"Authorization": "Bearer test-secret-token"}
            )
            assert response.status_code == 200
            text = response.text
            assert "chunk 0" in text
            assert "chunk 4" in text
            logger.info("✓ Stream response passed")
            
            # Test 6: Rate limiting (100 requests/minute default)
            logger.info("Test 6: Rate limiting at 100/minute")
            # Make 101 requests rapidly - with 100/minute limit, 
            # some requests should be rate limited (429)
            rate_limit_hit = False
            success_count = 0
            rate_limited_count = 0
            
            for i in range(101):
                response = await client.get(
                    f"{proxy_url}/endpoints",
                    headers={"Authorization": "Bearer test-secret-token"}
                )
                if response.status_code == 429:
                    rate_limited_count += 1
                    rate_limit_hit = True
                    logger.info(f"✓ Rate limit hit at request {i+1} with 429 status")
                elif response.status_code == 200:
                    success_count += 1
            
            # With 100/minute limit and 101 requests, at least some should be rate limited
            # Note: slowapi uses a sliding window, so the exact behavior depends on timing
            # but we should see at least some 429 responses
            assert rate_limit_hit, "Rate limiting should have been triggered with 101 requests at 100/minute limit"
            assert rate_limited_count > 0, "At least one request should have been rate limited"
            assert success_count <= 100, "No more than 100 requests should succeed"
            logger.info(f"✓ Rate limiting test passed ({success_count} succeeded, {rate_limited_count} rate limited)")
        
        logger.info("\n🎉 All integration tests passed!")
        
    finally:
        # Stop servers
        proxy_server.should_exit = True
        try:
            await proxy_task
        except Exception:
            pass
        await mock_server.stop()
        await proxy_app.proxy_client.close()


def main():
    """Main function to run integration tests."""
    logger.info("Starting MCP Proxy Server integration tests...")
    
    try:
        asyncio.run(test_proxy_integration())
        return 0
    except Exception as e:
        logger.error(f"Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
