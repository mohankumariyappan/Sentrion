"""
===============================================================================
SENTRION COMPANION SECURITY ARCHITECTURE & HANDSHAKE FLOW AUDIT DOCUMENTATION
===============================================================================

SECURITY MODEL OVERVIEW:
-----------------------
The Sentrion native companion runs a local HTTP bridge on 127.0.0.1:9999.
To protect this endpoint against unauthorized local scripts, cross-origin web page
attacks (CSRF/DNS rebinding), and automated brute-force attacks, Sentrion enforces
a multi-layered security protocol:

1. INITIAL HANDSHAKE & TOKEN ISSUANCE:
   - Web portal sends a POST request to `/session/start`.
   - Origin & Referer headers are verified against trusted exam domains.
   - Server generates a cryptographically strong, 256-bit secret per-process instance.
   - Server issues a signed HMAC-SHA256 session token (`token_id.timestamp.signature`).

2. PER-REQUEST AUTHENTICATION:
   - Every subsequent API call (`/status`, `/keystroke/event`, `/simulate`, `/session/end`)
     MUST supply the session token via `X-Session-Token` or `Authorization` header.
   - The token signature is verified in constant time (`hmac.compare_digest`) to prevent
     timing side-channel attacks.
   - TTL expiry (4 hours) and revocation status are strictly checked.

3. ORIGIN & REFERER VALIDATION:
   - Non-static requests check `Origin` or `Referer` headers against an explicit
     whitelist (`http://127.0.0.1:9999`, `http://localhost:9999`).
   - Wildcard origins (`*`) are prohibited for CORS in production mode.

4. RATE LIMITING & THROTTLING:
   - Requests are throttled using a sliding-window rate limiter (default: max 30 req / 5s window
     per token or IP address) to prevent Denial-of-Service or brute-force enumeration.

===============================================================================
"""

import hmac
import hashlib
import os
import time
import secrets
from collections import defaultdict, deque

from companion.config import CONFIG_MANAGER, DEFAULT_CONFIG

class RateLimiter:
    """Sliding-window request rate limiter per identifier (token or IP)."""
    def __init__(self, max_requests: int = 40, window_seconds: float = 5.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)

    def is_allowed(self, identifier: str) -> tuple[bool, str]:
        now = time.time()
        timestamps = self.requests[identifier]
        
        # Purge timestamps outside the sliding window
        while timestamps and (now - timestamps[0]) > self.window_seconds:
            timestamps.popleft()
            
        if len(timestamps) >= self.max_requests:
            return False, f"Rate limit exceeded: max {self.max_requests} requests per {int(self.window_seconds)}s"
            
        timestamps.append(now)
        return True, "Allowed"

class SessionSecurityManager:
    def __init__(self, ttl_seconds: int = 14400):
        # 256-bit random secret generated per companion process boot
        self.secret_key = secrets.token_bytes(32)
        self.ttl_seconds = ttl_seconds
        self.active_sessions = {} # token_id -> creation_timestamp
        self.revoked_tokens = set()
        self.rate_limiter = RateLimiter(max_requests=40, window_seconds=5.0)

    def validate_origin(self, origin: str, referer: str) -> tuple[bool, str]:
        """Validates Origin or Referer header against configurable exam portal allowlist."""
        return CONFIG_MANAGER.is_origin_allowed(origin, referer)

    def check_rate_limit(self, identifier: str) -> tuple[bool, str]:
        return self.rate_limiter.is_allowed(identifier)

    def generate_token(self) -> dict:
        """Generates a cryptographically random session token signed with HMAC-SHA256."""
        token_id = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        payload = f"{token_id}:{timestamp}".encode('utf-8')
        signature = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
        
        full_token = f"{token_id}.{timestamp}.{signature}"
        self.active_sessions[token_id] = time.time()
        
        return {
            "token": full_token,
            "expires_in": self.ttl_seconds
        }

    def verify_token(self, full_token: str) -> tuple[bool, str]:
        """
        Verifies HMAC-SHA256 signature using constant-time comparison (hmac.compare_digest)
        and checks 4-hour TTL expiry.
        """
        if not full_token or not isinstance(full_token, str):
            return False, "Missing or invalid token format"
            
        parts = full_token.split(".")
        if len(parts) != 3:
            return False, "Malformed token structure"
            
        token_id, timestamp_str, received_signature = parts
        
        if token_id in self.revoked_tokens:
            return False, "Session token has been revoked/ended"
            
        try:
            created_at = float(timestamp_str)
        except ValueError:
            return False, "Invalid token timestamp"
            
        # Check TTL Expiry
        if time.time() - created_at > self.ttl_seconds:
            return False, "Session token expired (TTL exceeded)"
            
        # Recompute HMAC-SHA256 signature
        payload = f"{token_id}:{timestamp_str}".encode('utf-8')
        expected_signature = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
        
        # Constant-time signature comparison to eliminate timing attacks
        if not hmac.compare_digest(expected_signature, received_signature):
            return False, "HMAC signature mismatch - untrusted token"
            
        return True, "Token valid"

    def revoke_token(self, full_token: str) -> bool:
        """Revokes a session token server-side."""
        if not full_token or "." not in full_token:
            return False
        token_id = full_token.split(".")[0]
        self.revoked_tokens.add(token_id)
        if token_id in self.active_sessions:
            del self.active_sessions[token_id]
        return True

# Shared singleton instance
SECURITY_MANAGER = SessionSecurityManager()
