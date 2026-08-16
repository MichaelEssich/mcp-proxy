#!/usr/bin/env python3
"""
MCP Proxy Server - Main entry point.

This module provides the main entry point for running the MCP proxy server.
"""

import argparse
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import uvicorn
from fastapi import FastAPI

from .config import get_config, ProxyConfig
from .proxy import create_proxy_app, MCPProxyApp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)


def create_lifespan(proxy_app: MCPProxyApp):
    """Create a lifespan context manager that also closes the proxy client."""
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        """Application lifespan manager."""
        # Startup
        logger.info("Starting MCP Proxy Server")
        
        yield
        
        # Shutdown - close the proxy client
        await proxy_app.proxy_client.close()
        logger.info("Shutting down MCP Proxy Server")
    
    return lifespan


async def run_server(
    host: str = None,
    port: int = None,
    config: ProxyConfig = None,
    reload: bool = False
) -> None:
    """
    Run the MCP proxy server.
    
    Args:
        host: Host to bind the server (overrides config)
        port: Port to bind the server (overrides config)
        config: Configuration object
        reload: Enable auto-reload for development
    """
    if config is None:
        config = get_config()
    
    # Override with command line arguments if provided
    host = host or config.PROXY_HOST
    port = port or config.PROXY_PORT
    
    # Create proxy app
    proxy_app = await create_proxy_app(config)
    app = proxy_app.get_app()
    
    # Set lifespan with proxy client cleanup
    app.router.lifespan_context = create_lifespan(proxy_app)
    
    logger.info(f"Starting server on {host}:{port}")
    logger.info("Press Ctrl+C to stop the server")
    
    try:
        # Run with uvicorn
        await uvicorn.Server(
            config=uvicorn.Config(
                app=app,
                host=host,
                port=port,
                reload=reload,
                log_config=None,  # Use our own logging config
                access_log=config.DEBUG,
            )
        ).serve()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


def main():
    """Main entry point for the MCP proxy server."""
    parser = argparse.ArgumentParser(
        description="MCP Proxy Server - Proxy MCP HTTP endpoints with bearer token authentication"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host to bind the server (default: from config)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind the server (default: from config)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug mode"
    )
    parser.add_argument(
        "--config",
        type=str,
        default=".env",
        help="Path to configuration file (default: .env)"
    )
    
    args = parser.parse_args()
    
    # Override debug from command line
    if args.debug:
        os.environ["DEBUG"] = "true"
    
    # Load configuration with the specified env file.
    # ProxyConfig is constructed here (not at import time) so that the
    # --config flag actually takes effect.
    config = ProxyConfig(_env_file=args.config)
    
    # Run the server
    asyncio.run(run_server(
        host=args.host,
        port=args.port,
        config=config,
        reload=args.reload
    ))


if __name__ == "__main__":
    main()
