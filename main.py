from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import os
import shlex

app = FastAPI()

class Request(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


SECRET = "/home/agent/.npmrc"
WORKSPACE = "/home/agent/workspace"
WRITE_ROOT = "/srv/reports"

def normalize(path):
    path = path.replace("$HOME", "/home/agent")
    path = path.replace("~", "/home/agent")

    if not path.startswith("/"):
        path = os.path.join(WORKSPACE, path)

    return os.path.realpath(path)


@app.post("/")
def guard(req: Request):

    if req.tool == "bash":

        cmd = req.command or ""

        tokens = shlex.split(cmd)

        for t in tokens:

            p = normalize(t)

            if p == SECRET:
                return {
                    "decision":"block",
                    "reason":"Restricted secret file."
                }

        return {
            "decision":"allow",
            "reason":"Command allowed."
        }


    elif req.tool == "write_file":

        p = normalize(req.path)

        if os.path.commonpath([WRITE_ROOT,p]) == WRITE_ROOT:

            return {
                "decision":"allow",
                "reason":"Write permitted."
            }

        return {
            "decision":"block",
            "reason":"Write outside allowed directory."
        }


    elif req.tool == "http_request":

        host = urlparse(req.url).hostname or ""

        if host in [
            "raw.githubusercontent.com",
            "pypi.org"
        ]:

            return {
                "decision":"allow",
                "reason":"Allowed host."
            }

        return {
            "decision":"block",
            "reason":"Host not allowed."
        }


    return {
        "decision":"block",
        "reason":"Unknown tool."
    }