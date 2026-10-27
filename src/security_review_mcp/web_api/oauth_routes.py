"""Routes of the OAuth login of the MCP clients used by the web interface (see oauth_server).

The consent screen reads a pending request and approves or denies it, and My account lists and
revokes the approved clients: only a logged-in web user reaches them (403 for a bearer token),
so a token never approves a client. The Tokens screen lists every client and grant, revokes a
grant and deletes a client, with ``tokens.manage``. The OAuth routes themselves
(``/authorize``, ``/token``...) are those of the MCP SDK, mounted by create_app when
SECREVIEW_MCP_OAUTH_ENABLED is set.
"""

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool

from ..auth import oauth_server
from ..config import get_settings
from .auth_routes import LOGIN_HEADERS
from .deps import (
    CurrentIdentity,
    Permission,
    TokensManager,
    actor_of,
    has_permission,
    web_user_id,
)
from .schemas import (
    OAuthGrantPublic,
    OAuthOverview,
    OAuthPendingRequest,
    OAuthRedirect,
    OAuthRequestRef,
)

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["account"])


def _enabled() -> None:
    """404 while the OAuth login of the MCP clients is disabled."""
    if not get_settings().mcp_oauth_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "The OAuth login of MCP clients is off")


@router.post("/oauth/request")
async def oauth_request(
    request: Request, body: OAuthRequestRef, _: CurrentIdentity, response: Response
) -> OAuthPendingRequest:
    """A pending OAuth request, for the consent screen (404 when unknown or expired)."""
    _enabled()
    web_user_id(request)
    response.headers.update(LOGIN_HEADERS)
    return await run_in_threadpool(oauth_server.pending_request, body.request)


@router.post("/oauth/approve")
async def oauth_approve(
    request: Request, body: OAuthRequestRef, identity: CurrentIdentity, response: Response
) -> OAuthRedirect:
    """Approve a pending OAuth request for the logged-in user: the client gets tokens that act
    as a personal MCP token of the user, so the ``mcp_tokens.create`` permission is needed."""
    _enabled()
    user_id = web_user_id(request)
    if not has_permission(identity, Permission.MCP_TOKENS_CREATE):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Permission '{Permission.MCP_TOKENS_CREATE}' required"
        )
    url = await run_in_threadpool(oauth_server.approve, body.request, user_id, identity.client)
    logger.info("OAuth client approved by %s", identity.client)
    response.headers.update(LOGIN_HEADERS)
    return OAuthRedirect(redirect_url=url)


@router.post("/oauth/deny")
async def oauth_deny(
    request: Request, body: OAuthRequestRef, identity: CurrentIdentity, response: Response
) -> OAuthRedirect:
    """Deny a pending OAuth request: the client gets the ``access_denied`` error."""
    _enabled()
    web_user_id(request)
    url = await run_in_threadpool(oauth_server.deny, body.request, identity.client)
    logger.info("OAuth client denied by %s", identity.client)
    response.headers.update(LOGIN_HEADERS)
    return OAuthRedirect(redirect_url=url)


@router.get("/me/oauth-grants")
async def my_oauth_grants(request: Request, _: CurrentIdentity) -> list[OAuthGrantPublic]:
    """The MCP clients the logged-in user approved (never their tokens)."""
    user_id = web_user_id(request)
    return await run_in_threadpool(oauth_server.list_user_grants, user_id)


@router.delete("/me/oauth-grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_my_oauth_grant(
    request: Request, grant_id: str, identity: CurrentIdentity
) -> Response:
    """Revoke an MCP client approved by the logged-in user (that of another user is not found):
    its tokens stop working at once."""
    user_id = web_user_id(request)
    await run_in_threadpool(oauth_server.revoke_user_grant, user_id, grant_id[:64], identity.client)
    logger.info("OAuth client revoked by %s", identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/oauth/clients")
async def oauth_overview(_: TokensManager) -> OAuthOverview:
    """The OAuth login of the MCP clients: settings, registered clients and every grant."""
    return await run_in_threadpool(oauth_server.overview)


@router.delete("/oauth/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_oauth_grant(grant_id: str, identity: TokensManager) -> Response:
    """Revoke the grant of any user: the tokens of that client stop working at once."""
    await run_in_threadpool(oauth_server.revoke_grant, grant_id[:64], actor_of(identity))
    logger.info("OAuth grant %s revoked by %s", grant_id[:64], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/oauth/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_oauth_client(client_id: str, identity: TokensManager) -> Response:
    """Delete a registered client with its grants: it must register again."""
    await run_in_threadpool(oauth_server.delete_client, client_id[:64], actor_of(identity))
    logger.info("OAuth client %s deleted by %s", client_id[:64], identity.client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
