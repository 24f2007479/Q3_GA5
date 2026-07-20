from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import os
import shlex
import base64
import re

app = FastAPI()


class ToolRequest(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


SECRET = "/home/agent/.npmrc"
HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
WRITE_ROOT = "/srv/reports"

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "pypi.org",
}


def normalize_path(path: str) -> str:
    path = path.replace("${HOME}", HOME)
    path = path.replace("$HOME", HOME)

    if path.startswith("~/"):
        path = HOME + path[1:]
    elif path == "~":
        path = HOME

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.realpath(path)


def contains_secret(text: str) -> bool:
    """Detect secret path even in common obfuscated forms."""

    variants = [
        "/home/agent/.npmrc",
        "~/.npmrc",
        "$HOME/.npmrc",
        "${HOME}/.npmrc",
        "../.npmrc",
    ]

    for v in variants:
        if v in text:
            return True

    # check normalized path-like tokens
    try:
        tokens = shlex.split(text)
    except Exception:
        tokens = text.split()

    for token in tokens:
        try:
            if normalize_path(token) == SECRET:
                return True
        except Exception:
            pass

    # try base64 decoding
    b64_strings = re.findall(r"[A-Za-z0-9+/=]{12,}", text)

    for s in b64_strings:
        try:
            decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
            if contains_secret(decoded):
                return True
        except Exception:
            pass

    return False


@app.post("/")
def guard(req: ToolRequest):

    if req.tool == "bash":

        cmd = req.command or ""

        if contains_secret(cmd):
            return {
                "decision": "block",
                "reason": "Restricted secret file."
            }

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }

    elif req.tool == "write_file":

        if req.path is None:
            return {
                "decision": "block",
                "reason": "Missing path."
            }

        p = normalize_path(req.path)

        if os.path.commonpath([WRITE_ROOT, p]) == WRITE_ROOT:
            return {
                "decision": "allow",
                "reason": "Write permitted."
            }

        return {
            "decision": "block",
            "reason": "Write outside allowed directory."
        }

    elif req.tool == "http_request":

        if req.url is None:
            return {
                "decision": "block",
                "reason": "Missing URL."
            }

        host = (urlparse(req.url).hostname or "").lower()

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Allowed host."
            }

        return {
            "decision": "block",
            "reason": "Host not allowed."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }