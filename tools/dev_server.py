"""Local preview server for web/.

Sends the same headers Cloudflare Pages adds from web/_headers, so local testing runs under the
real Content-Security-Policy. Two test-only routes exist here and not on the deployed site:

    GET  /__apk/<file>    serves an APK from the --apks folder
    POST /__save/<file>   writes the request body to the --out folder

Usage:  python tools/dev_server.py [--port 8253] [--apks DIR] [--out DIR]
"""

import argparse
import http.server
import pathlib
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent / "web"


def site_headers():
    headers = []
    for line in (ROOT / "_headers").read_text().splitlines():
        if line[:1] in (" ", "\t") and ":" in line:
            name, value = line.strip().split(":", 1)
            headers.append((name.strip(), value.strip()))
    return headers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8253)
    parser.add_argument("--apks", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path)
    args = parser.parse_args()

    class Handler(http.server.SimpleHTTPRequestHandler):
        # Windows can map .js to text/plain, which browsers refuse to run as a module.
        extensions_map = {
            **http.server.SimpleHTTPRequestHandler.extensions_map,
            ".js": "text/javascript",
            ".css": "text/css",
            ".svg": "image/svg+xml",
        }

        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(ROOT), **k)

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            for name, value in site_headers():
                self.send_header(name, value)
            super().end_headers()

        def test_file(self, prefix, folder):
            name = pathlib.PurePath(urllib.parse.unquote(self.path[len(prefix):])).name
            return folder / name if folder and name else None

        def do_GET(self):
            if not self.path.startswith("/__apk/"):
                return super().do_GET()
            path = self.test_file("/__apk/", args.apks)
            if not path or not path.is_file():
                return self.send_error(404)
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            path = self.test_file("/__save/", args.out) if self.path.startswith("/__save/") else None
            if not path:
                return self.send_error(404)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(204)
            self.end_headers()

    http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
