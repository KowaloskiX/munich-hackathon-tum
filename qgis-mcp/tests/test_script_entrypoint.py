"""Regression tests for running the server via its file path."""

import os
import subprocess
import sys
from pathlib import Path


def test_server_script_runs_without_package_install():
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["QGIS_MCP_LOG_FILE"] = ""

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy; "
                "runpy.run_path('src/qgis_mcp/server.py', run_name='qgis_mcp_script_test')"
            ),
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
