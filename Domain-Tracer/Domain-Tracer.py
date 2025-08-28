import re
import ssl
import socketserver

from http.server import BaseHTTPRequestHandler
import http.client
from urllib.parse import urlparse, unquote
import os
import hashlib
import socket
import select
record_file = "hosts.txt"
CACHE_DIR = "./cached_files"
os.makedirs(CACHE_DIR, exist_ok=True)
FORCE_LOCALHOST = True
#os.environ['http_proxy'] = 'http://127.0.0.1:7890'
#os.environ['https_proxy'] = 'http://127.0.0.1:7890'
# 自动识别文件类型
UPSTREAM_PROXY = ("127.0.0.1", 7890)
def detect_extension(data: bytes) -> str:
    if data.startswith(b'\xFF\xD8'):
        return ".jpg"
    elif data.startswith(b'\x89PNG'):
        return ".png"
    elif data.startswith(b'GIF89a') or data.startswith(b'GIF87a'):
        return ".gif"
    elif data.startswith(b'%PDF-'):
        return ".pdf"
    elif data.startswith(b'\xD0\xCF\x11\xE0'):
        return ".doc"
    elif data.startswith(b'PK\x03\x04'):
        return ".zip"
    elif data.startswith(b'Rar!\x1A\x07\x00'):
        return ".rar"
    elif data.startswith(b'7z\xBC\xAF\x27\x1C'):
        return ".7z"
    elif data.startswith(b'\x1F\x8B'):
        return ".gz"
    elif data.startswith(b'BZh'):
        return ".bz2"
    elif data.startswith(b'\xFD7zXZ\x00'):
        return ".xz"
    elif data.startswith(b'MSCF'):
        return ".cab"
    elif data.startswith(b'!<arch>\n'):
        return ".ar"
    elif data.startswith(b'MZ'):
        return ".exe"
    elif data.startswith(b'{') or data.startswith(b'['):
        return ".json"
    elif b'<html' in data.lower() or b'<!doctype html' in data.lower():
        return ".html"
    elif all(32 <= b <= 126 or b in (9, 10, 13) for b in data[:64]):
        return ".txt"
    else:
        return ".bin"
request_log_file = "http.txt"
logged_requests = set()

def load_existing_requests():
    """首次加载请求记录"""
    global logged_requests
    if not os.path.exists(request_log_file):
        return
    with open(request_log_file, "r", encoding="utf-8") as f:
        for line in f:
            logged_requests.add(line.strip())

def record_request(method: str, url: str):
    """记录请求（去重）"""
    entry = f"[{method}] {url}"
    if entry in logged_requests:
        return
    try:
        with open(request_log_file, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
        logged_requests.add(entry)
        print(f"The request is logged: {entry}")
    except Exception as e:
        print(f"Write request log failed: {e}")

# 生成不带扩展名的基础路径
def url_to_path(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    path = unquote(parsed.path)
    base_name = os.path.basename(path.rstrip("/")) or "index"
    if parsed.query:
        query_hash = hashlib.md5(parsed.query.encode()).hexdigest()[:8]
        base_name += f"_{query_hash}"
    dir_path = os.path.join(CACHE_DIR, host, *path.strip("/").split("/")[:-1])
    os.makedirs(dir_path, exist_ok=True)
    return os.path.join(dir_path, base_name)


cached_domains = set()
max_dns_index = 0
loaded = False

def load_existing_records():
    """首次调用时加载文件，填充缓存"""
    global cached_domains, max_dns_index, loaded
    if loaded or not os.path.exists(record_file):
        loaded = True
        return

    try:
        with open(record_file, "r") as f:
            for line in f:
                match = re.match(r"DNS\.(\d+)\s*=\s*(.+)", line.strip())
                if match:
                    index = int(match.group(1))
                    value = match.group(2).strip()
                    cached_domains.add(value)
                    max_dns_index = max(max_dns_index, index)
        loaded = True
    except Exception as e:
        print(f"Failed to load existing records: {e}")
        loaded = True

def record_ip_domain(domain):
    global max_dns_index
    load_existing_records()

    if domain in cached_domains:
        print(f"exists: {domain}, skipping writes")
        return

    max_dns_index += 1
    line = f"DNS.{max_dns_index} = {domain}\n"

    try:
        with open(record_file, "a") as f:
            f.write(line)
        cached_domains.add(domain)
        print(f"Add a new record: {line.strip()}")
    except Exception as e:
        print(f"Write record failed: {e}")

class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        global FORCE_LOCALHOST
        with open("allowed_hosts.txt", "r", encoding="utf-8") as f:
            ALLOWED_HOSTS = {line.strip() for line in f if line.strip()}
        try:
            host, port = self.path.split(":")
            port = int(port)
            record_ip_domain(host)
            print(f"🔌 CONNECT requested to: {host}:{port}")

            if FORCE_LOCALHOST and host not in ALLOWED_HOSTS:
                niganma_ip = "127.0.0.1"
                print(f" Forced parsing {host} -> {niganma_ip}")
            else:
                # 默认 DNS 解析
                try:
                    # 正常 DNS 解析
                    niganma_ip  = socket.gethostbyname(host)
                    print(f"Resolved {host} -> {niganma_ip}")
                except Exception as e:
                    print(f"❌ Failed to resolve {host}: {e}")
                    self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

            with socket.create_connection((niganma_ip, port)) as remote :
                self.send_response(200, "Connection Established")
                self.end_headers()

                conns = [self.connection, remote]
                while True:
                    rlist, _, _ = select.select(conns, [], [], 10)
                    if not rlist:
                        break
                    for r in rlist:
                        other = remote if r is self.connection else self.connection
                        data = r.recv(4096)
                        if not data:
                            return
                        other.sendall(data)

        except Exception as e:
            print(f"[CONNECT ERROR] {self.path} -> {e}")
            self.send_error(502, "Tunnel Error")
    def do_METHOD(self):
        load_existing_requests()  # 确保加载历史请求
        parsed_url = urlparse(self.path)
        if not parsed_url.scheme.startswith("http"):
            self.send_error(400, "Bad URL scheme")
            return

        full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        record_request(self.command, full_url)  # ✨记录请求

        hostname = parsed_url.hostname
        port = parsed_url.port or 80
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += "?" + parsed_url.query

        base_path = url_to_path(self.path)
        SUPPORTED_SUFFIXES = [
            "", ".html", ".jpg", ".png", ".gif", ".json", ".txt", ".pdf", ".exe",
            ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".cab", ".ar", ".doc", ".bin"
        ]
        # 尝试匹配已缓存文件
        for suffix in SUPPORTED_SUFFIXES:
            test_path = base_path + suffix
            if os.path.exists(test_path):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                with open(test_path, "rb") as f:
                    self.wfile.write(f.read())
                print(f"Hit the cache: {test_path}")
                return

        conn = http.client.HTTPConnection(hostname, port)
        headers = dict(self.headers)
        body = None
        if self.command == "POST":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

        try:
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()

            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                self.send_header(k, v)
            self.end_headers()

            data = resp.read()

            ext = detect_extension(data)
            full_path = base_path + ext
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            with open(full_path, "wb") as f:
                f.write(data)
            self.wfile.write(data)
            print(f"Cache writes: {full_path}")
        except Exception as e:
            error_message = f"Proxy error: {e}"
            self.send_error(502, error_message.encode("latin-1", "replace").decode("latin-1"))
        finally:
            conn.close()

    def do_GET(self): self.do_CONNECT()
    def do_POST(self): self.do_CONNECT()
    def do_HEAD(self): self.do_CONNECT()
    def do_PUT(self): self.do_CONNECT()
    def do_DELETE(self): self.do_CONNECT()
    def do_OPTIONS(self): self.do_CONNECT()

def run_proxy(host='0.0.0.0', port=8888):
    server = socketserver.ThreadingTCPServer((host, port), ProxyHandler)
    print(f"HTTP/HTTPS The forward agent is running: {host}:{port}")
    server.serve_forever()
import threading

def control_console():
    global FORCE_LOCALHOST
    while True:
        cmd = input(">>> Input the ON/off toggle forces a resolution to 127.0.0.1：").strip().lower()
        if cmd == "on":
            FORCE_LOCALHOST = True
            print("Forced mode: On (all domain resolves to 127.0.0.1)")
        elif cmd == "off":
            FORCE_LOCALHOST = False
            print("Forced mode: Off (normal DNS resolution)")
        else:
            print("Invalid command, enter on or off")
if __name__ == "__main__":
    threading.Thread(target=control_console, daemon=True).start()
    run_proxy()
