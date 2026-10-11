"""End-to-end tests: a real MCP client talking to the server in memory."""

import json

import pytest
from mcp.client import Client

from security_review_mcp.server import mcp

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    """Run the async tests with asyncio only."""
    return "asyncio"


def text_of(result) -> str:
    """Concatenate the text blocks of a tool result."""
    return "".join(block.text for block in result.content if hasattr(block, "text"))


async def test_capabilities_are_exposed():
    async with Client(mcp) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        prompts = {p.name for p in (await client.list_prompts()).prompts}
    assert {"scan_code", "save_security_report", "get_security_report"} <= tools
    assert {"security-review", "api-security-review", "configuration-review"} <= prompts


async def test_security_review_prompt_embeds_code_and_checklist():
    async with Client(mcp) as client:
        result = await client.get_prompt(
            "security-review",
            {"language": "java", "code": "class A {}", "focus": "deserialization"},
        )
    text = result.messages[0].content.text
    assert "class A {}" in text
    assert "JV-02" in text  # Java checklist
    assert "API-01" in text  # API checklist is always included
    assert "save_security_report" in text
    assert "deserialization" in text


async def test_full_review_flow():
    async with Client(mcp) as client:
        scan = await client.call_tool(
            "scan_code",
            {
                "content": 'subprocess.run(c, shell=True)\npassword = "Sup3rSecret99"',
                "language": "python",
            },
        )
        scan_data = json.loads(text_of(scan))
        assert scan_data["matches_count"] >= 2
        assert "Sup3rSecret99" not in text_of(scan)

        saved = await client.call_tool(
            "save_security_report",
            {
                "project": "demo",
                "summary": "Demo review",
                "findings": [
                    {
                        "title": "Command injection",
                        "severity": "critical",
                        "description": "shell=True with user input",
                        "cwe": "CWE-78",
                        "file_path": "app.py",
                        "line_start": 1,
                    }
                ],
            },
        )
        report_id = json.loads(text_of(saved))["report_id"]

        markdown = await client.call_tool("get_security_report", {"report_id": report_id})
        assert "Command injection" in text_of(markdown)

        listed = await client.call_tool("list_security_reports", {"project": "demo"})
        assert "demo" in text_of(listed)

        resource = await client.read_resource(f"report://{report_id}")
        assert "Command injection" in resource.contents[0].text


async def test_invalid_input_returns_a_tool_error():
    async with Client(mcp) as client:
        result = await client.call_tool("get_security_report", {"report_id": 424242})
    assert result.is_error
    assert "not found" in text_of(result).lower()


async def test_unknown_checklist_is_an_error():
    async with Client(mcp) as client:
        result = await client.call_tool("get_review_checklist", {"domain": "cobol"})
    assert result.is_error
