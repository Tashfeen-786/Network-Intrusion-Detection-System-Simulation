"""Small API-key, role and in-memory rate-limit layer for the teaching simulation."""
from __future__ import annotations
import os, time
from collections import defaultdict, deque
from fastapi import Header, HTTPException, Request

WINDOW=60; calls=defaultdict(deque)
def require_user(request: Request,x_api_key: str|None=Header(default=None),x_role: str=Header(default="analyst")):
    if os.getenv("AUTH_DISABLED","false").lower()!="true" and x_api_key!=os.getenv("API_KEY","dev-analyst-key"):
        raise HTTPException(401,"valid X-API-Key header required")
    role=x_role.lower()
    if role not in {"analyst","viewer"}: raise HTTPException(403,"role must be analyst or viewer")
    key=x_api_key or request.client.host if request.client else "test"; now=time.time(); q=calls[key]
    while q and q[0]<now-WINDOW: q.popleft()
    limit=int(os.getenv("RATE_LIMIT_PER_MINUTE","600"))
    if len(q)>=limit: raise HTTPException(429,"API rate limit exceeded")
    q.append(now); return {"name":key,"role":role}
def require_analyst(user):
    if user["role"]!="analyst": raise HTTPException(403,"analyst role required")
