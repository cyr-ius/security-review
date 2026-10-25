"""Public download of the pipeline client (``/api/ci-client/``, see ci_wheel).

Served when SECREVIEW_CI_CLIENT_DOWNLOAD_ENABLED is set: ``uv`` reads the links page with
``--find-links`` and sends no token, so the two routes are public and read-only. They tell the
version of the controller, like the API documentation.
"""

from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response

from ..clients import ci_wheel
from ..http_server import CI_CLIENT_PREFIX

router = APIRouter(prefix=CI_CLIENT_PREFIX, include_in_schema=False)

_HEADERS = {"X-Content-Type-Options": "nosniff"}


@router.get("/")
async def ci_client_links() -> HTMLResponse:
    """Links page of ``uv --find-links`` (revalidated at every install)."""
    wheel = await run_in_threadpool(ci_wheel.build_wheel)
    return HTMLResponse(
        ci_wheel.links_page(wheel), headers=_HEADERS | {"Cache-Control": "no-cache"}
    )


@router.get("/{filename}")
async def ci_client_wheel(filename: str) -> Response:
    """The wheel of the client, at the version of the controller."""
    wheel = await run_in_threadpool(ci_wheel.build_wheel)
    if filename != wheel.filename:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown file")
    return Response(
        wheel.content,
        media_type="application/zip",
        headers=_HEADERS
        | {
            "Cache-Control": "public, max-age=3600",
            "Content-Disposition": f'attachment; filename="{wheel.filename}"',
        },
    )
