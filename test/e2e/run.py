#!/usr/bin/env python3
"""End-to-end regression harness for FlowSight.

Starts the daemon, tests all pages and API endpoints, and fails on errors.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


class E2ETest:
    def __init__(self, data_dir, port=8889, chrome_path=None, timeout=30):
        self.data_dir = data_dir
        self.port = port
        self.chrome_path = chrome_path
        self.timeout = timeout
        self.daemon_proc = None
        self.passed = 0
        self.failed = 0
        self.base_url = f"http://localhost:{port}"
        self.token = "test-token"

    def log(self, msg, level="INFO"):
        print(f"[{level}] {msg}", file=sys.stderr)

    def find_chrome(self):
        """Find Chrome executable."""
        if self.chrome_path and os.path.exists(self.chrome_path):
            return self.chrome_path

        # Common Chrome paths
        paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            shutil.which("google-chrome"),
            shutil.which("chromium"),
        ]

        for p in paths:
            if p and os.path.exists(p):
                return p

        return None

    def start_daemon(self):
        """Start the FlowSight daemon."""
        self.log("Starting daemon...")

        # Look for daemon in multiple places
        repo_root = Path(__file__).parent.parent.parent
        daemon_candidates = [
            repo_root / "bin" / "flowsightd",
            repo_root / "cmd" / "flowsightd" / "flowsightd",
            Path("/tmp/flowsightd-e2e"),
            Path("/tmp/flowsightd"),
        ]

        daemon_path = None
        for candidate in daemon_candidates:
            if candidate.exists():
                daemon_path = candidate
                break

        # Build daemon if not found
        if not daemon_path:
            self.log("Building flowsightd...")
            build_path = repo_root / "bin" / "flowsightd"
            build_path.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["go", "build", "-o", str(build_path), "./cmd/flowsightd"],
                cwd=repo_root,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                self.log(f"Failed to build flowsightd: {result.stderr}", "ERROR")
                return False
            daemon_path = build_path

        # Start daemon
        env = os.environ.copy()
        env["GOMEMLIMIT"] = "256MiB"
        try:
            self.daemon_proc = subprocess.Popen(
                [str(daemon_path), "-data-dir", self.data_dir, "-log-level", "warn"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            self.log(f"Failed to start daemon: {e}", "ERROR")
            return False

        # Wait for daemon to be ready
        for i in range(30):
            try:
                urllib.request.urlopen(f"{self.base_url}/api/system/info", timeout=1)
                self.log("Daemon is ready")
                return True
            except Exception:
                time.sleep(0.5)

        self.log("Daemon failed to start in time", "ERROR")
        return False

    def stop_daemon(self):
        """Stop the FlowSight daemon."""
        if self.daemon_proc:
            try:
                self.daemon_proc.terminate()
                self.daemon_proc.wait(timeout=5)
            except Exception:
                self.daemon_proc.kill()

    def get_pages(self):
        """Get list of pages to test."""
        pages = [
            "#findings",
            "#events",
            "#system",
            "#overview",
            "#host/192.168.1.2",
            "#policies",
        ]

        # Try to get dynamic pages from panels API
        try:
            req = urllib.request.Request(f"{self.base_url}/api/system/panels")
            req.add_header("Authorization", f"Bearer {self.token}")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.load(resp)
                for item in data:
                    pages.append(f"#{item}")
        except Exception as e:
            self.log(f"Failed to fetch panels: {e}", "WARN")

        return pages

    def test_page(self, page):
        """Test a single page."""
        url = f"{self.base_url}/?token={self.token}{page}"
        self.log(f"Testing {page}...", "INFO")

        # Try to use Chrome if available
        chrome = self.find_chrome()
        if chrome:
            try:
                result = subprocess.run(
                    [
                        chrome,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--virtual-time-budget=5000",
                        "--dump-dom",
                        url,
                    ],
                    capture_output=True,
                    timeout=10,
                    text=True,
                )
                html = result.stdout + result.stderr

                # Check for view element
                if '<div id="view">' not in html:
                    self.log(f"  FAIL: no view element", "ERROR")
                    self.failed += 1
                    return False

                # Check for empty view
                view_start = html.find('<div id="view">')
                view_end = html.find("</div>", view_start)
                if view_end - view_start < 50:
                    self.log(f"  FAIL: empty view", "ERROR")
                    self.failed += 1
                    return False

                # Check for error boxes (excluding expected errors like license)
                if 'class="err"' in html:
                    lines = [line for line in html.split("\n") if 'class="err"' in line]
                    for line in lines:
                        if not any(x in line.lower() for x in ["license", "feature"]):
                            self.log(f"  FAIL: error in page: {line[:80]}", "ERROR")
                            self.failed += 1
                            return False

                self.log(f"  OK", "INFO")
                self.passed += 1
                return True
            except subprocess.TimeoutExpired:
                self.log(f"  FAIL: Chrome timeout", "ERROR")
                self.failed += 1
                return False
            except Exception as e:
                self.log(f"  FAIL: {e}", "ERROR")
                self.failed += 1
                return False
        else:
            # Fallback: just check that page responds without error
            self.log(f"  (Chrome not found, using simple HTTP test)", "WARN")
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status >= 400:
                        self.log(f"  FAIL: HTTP {resp.status}", "ERROR")
                        self.failed += 1
                        return False
                self.log(f"  OK (HTTP {resp.status})", "INFO")
                self.passed += 1
                return True
            except Exception as e:
                self.log(f"  FAIL: {e}", "ERROR")
                self.failed += 1
                return False

    def test_api_endpoints(self):
        """Test API endpoints via OpenAPI contract."""
        self.log("Testing OpenAPI contract...", "INFO")

        try:
            req = urllib.request.Request(f"{self.base_url}/api/openapi.json")
            with urllib.request.urlopen(req, timeout=5) as resp:
                openapi = json.load(resp)
        except Exception as e:
            self.log(f"  FAIL: Cannot fetch OpenAPI: {e}", "ERROR")
            self.failed += 1
            return

        # Test GET endpoints
        paths = openapi.get("paths", {})
        for path_key, path_item in paths.items():
            if "get" not in path_item:
                continue

            # Skip paths with required parameters
            if "{" in path_key:
                continue

            try:
                req = urllib.request.Request(f"{self.base_url}{path_key}")
                req.add_header("Authorization", f"Bearer {self.token}")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status >= 500:
                        self.log(f"  FAIL: GET {path_key} returned {resp.status}", "ERROR")
                        self.failed += 1
                    else:
                        self.log(f"  OK: GET {path_key}", "INFO")
                        self.passed += 1
            except urllib.error.HTTPError as e:
                if e.code >= 500:
                    self.log(f"  FAIL: GET {path_key} returned {e.code}", "ERROR")
                    self.failed += 1
                else:
                    self.log(f"  OK: GET {path_key} ({e.code})", "INFO")
                    self.passed += 1
            except Exception as e:
                self.log(f"  FAIL: GET {path_key}: {e}", "ERROR")
                self.failed += 1

    def run(self):
        """Run all tests."""
        self.log("Starting E2E test suite", "INFO")

        if not self.start_daemon():
            self.log("Failed to start daemon", "ERROR")
            return False

        try:
            # Test pages
            pages = self.get_pages()
            for page in pages:
                self.test_page(page)

            # Test API endpoints
            self.test_api_endpoints()
        finally:
            self.stop_daemon()

        # Print summary
        total = self.passed + self.failed
        self.log(
            f"Results: {self.passed} passed, {self.failed} failed (total {total})",
            "INFO" if self.failed == 0 else "ERROR",
        )

        return self.failed == 0


def main():
    parser = argparse.ArgumentParser(description="FlowSight E2E test harness")
    parser.add_argument("--data-dir", help="data directory (auto-generates if not provided)")
    parser.add_argument("--port", type=int, default=8889, help="port to run daemon on")
    parser.add_argument("--chrome", help="path to Chrome executable")
    parser.add_argument("--timeout", type=int, default=30, help="request timeout")
    args = parser.parse_args()

    # Generate test data if needed
    if args.data_dir:
        data_dir = args.data_dir
    else:
        data_dir = tempfile.mkdtemp(prefix="flowsight-e2e-")

    # Build fsload if needed
    fsload_path = Path(__file__).parent.parent.parent / "cmd" / "fsload" / "fsload"
    if not fsload_path.exists():
        print(f"Building fsload...", file=sys.stderr)
        result = subprocess.run(
            ["go", "build", "-o", str(fsload_path), "./cmd/fsload"],
            cwd=Path(__file__).parent.parent.parent,
        )
        if result.returncode != 0:
            print("Failed to build fsload", file=sys.stderr)
            return 1

    # Generate test data
    print(f"Generating test data in {data_dir}...", file=sys.stderr)
    result = subprocess.run(
        [
            str(fsload_path),
            "-devices=10",
            "-days=1",
            "-flows-per-device-per-day=10",
            f"-out={data_dir}",
        ]
    )
    if result.returncode != 0:
        print("Failed to generate test data", file=sys.stderr)
        return 1

    # Run tests
    tester = E2ETest(data_dir, port=args.port, chrome_path=args.chrome, timeout=args.timeout)
    try:
        success = tester.run()
        return 0 if success else 1
    finally:
        # Clean up unless user provided data dir
        if not args.data_dir:
            shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
