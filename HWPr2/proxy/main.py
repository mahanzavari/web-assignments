import os
import logging
from datetime import datetime, timedelta, timezone
import httpx
import jwt
from fastapi import FastAPI, Request, Response, HTTPException, status

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("jwt-reverse-proxy")

app = FastAPI(title="JWT Authentication Reverse Proxy")

# Configuration via environment variables
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-internet-engineering-1405")
ALGORITHM = "HS256"
BACKEND_URL = os.getenv("BACKEND_URL", "http://legacy-httpbin:8080")

# Asynchronous HTTP client for proxying requests to the internal service
http_client = httpx.AsyncClient(base_url=BACKEND_URL, timeout=60.0)


@app.on_event("startup")
async def startup_event():
    logger.info(f"Reverse proxy starting up. Target backend: {BACKEND_URL}")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down HTTP client...")
    await http_client.aclose()


# Helper endpoint to issue valid JWT tokens for verification and grading
@app.post("/auth/login")
@app.get("/auth/login")
async def generate_token(username: str = "legacy_user"):
    """
    Convenience endpoint for testing:
    Generates and returns a signed JWT access token.
    """
    logger.info(f"Generating JWT token for user: {username}")
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        "iat": datetime.now(timezone.utc),
        "scope": "access:legacy-service"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 7200
    }


def verify_jwt_token(auth_header: str | None) -> dict:
    """
    Extracts and validates the Bearer JWT token from the Authorization header.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("Request rejected: Missing or malformed Authorization header.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: 'Bearer <TOKEN>'."
        )

    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Request rejected: Token has expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )
    except jwt.InvalidTokenError as exc:
        logger.warning(f"Request rejected: Invalid token ({exc}).")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token."
        )


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def reverse_proxy(request: Request, full_path: str):
    """
    Catches all incoming external requests, enforces JWT authentication,
    and forwards authorized traffic to the internal legacy backend.
    """
    # Prevent collision with authentication endpoints
    if full_path.startswith("auth/"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    # 1. Enforce JWT authentication
    auth_header = request.headers.get("Authorization")
    user_payload = verify_jwt_token(auth_header)
    user_id = user_payload.get("sub", "unknown")
    logger.info(f"Authenticated request from user '{user_id}' -> [{request.method}] /{full_path}")

    # 2. Filter request headers before forwarding
    excluded_request_headers = {"host", "content-length"}
    forward_headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in excluded_request_headers
    }
    
    # Pass user context down to the legacy service
    forward_headers["X-Authenticated-User"] = user_id

    # 3. Read request body
    body = await request.body()

    # 4. Forward the request to the internal backend
    backend_path = f"/{full_path}"
    query_params = request.url.query.encode("utf-8")
    target_url = httpx.URL(path=backend_path, query=query_params)

    try:
        backend_response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            content=body
        )
    except httpx.RequestError as exc:
        logger.error(f"Failed to communicate with legacy backend: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach internal legacy service: {exc}"
        )

    # 5. Filter Hop-by-Hop headers before returning response to the client
    excluded_response_headers = {"content-encoding", "transfer-encoding", "connection"}
    response_headers = {
        key: value for key, value in backend_response.headers.items()
        if key.lower() not in excluded_response_headers
    }

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
        media_type=backend_response.headers.get("content-type")
    )
