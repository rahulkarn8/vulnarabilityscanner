"""
Security Middleware for FastAPI
Provides rate limiting, security headers, and brute force protection
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from typing import Callable
import time
from collections import defaultdict
import threading
from datetime import datetime, timedelta

# In-memory rate limit cache (for simple rate limiting)
# For production with multiple instances, use Redis
_rate_limit_cache = defaultdict(list)
_cache_lock = threading.Lock()

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware to prevent abuse"""
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health checks, static files, and OPTIONS (CORS preflight)
        if request.url.path in ["/", "/health", "/docs", "/openapi.json", "/redoc"] or request.method == "OPTIONS":
            return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        # Clean old entries
        with _cache_lock:
            if client_ip in _rate_limit_cache:
                _rate_limit_cache[client_ip] = [
                    timestamp for timestamp in _rate_limit_cache[client_ip]
                    if current_time - timestamp < 60  # Last minute
                ]
            
            # Check rate limit
            request_count = len(_rate_limit_cache[client_ip])
            if request_count >= self.requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": f"Too many requests. Maximum {self.requests_per_minute} requests per minute.",
                        "retry_after": 60
                    },
                    headers={"Retry-After": "60"}
                )
            
            # Record this request
            _rate_limit_cache[client_ip].append(current_time)
        
        response = await call_next(request)
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

