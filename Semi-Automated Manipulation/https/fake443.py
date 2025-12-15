import http.server, ssl, os, threading, requests, mimetypes, zipfile
import sys
import time
import urllib
from urllib.parse import urlparse
from pathlib import Path

import magic

from https.check import analyze_archive, log_results
#os.environ['http_proxy'] = 'http://127.0.0.1:7890'
#os.environ['https_proxy'] = 'http://127.0.0.1:7890'
map_type = {}  # 请求路径 -> 文件类型

DOWNLOAD_ROOT = Path("download")
TMP_DIR = Path("tmp")
FAKE_DIR = Path("fake")
LOG_FILE = "https.txt"
POST_LOG = Path("post.txt")
POST_LOG_SET = set()

logged_requests = set()
log_file_path = "https.txt"

# 启动时加载已有记录
if os.path.exists(log_file_path):
    with open(log_file_path, "r") as f:
        for line in f:
            logged_requests.add(line.strip())



suspicious_hash_responses = set()

def check_response_headers_for_hash(url, headers):
    keywords = ["md5", "sha", "sha1", "sha256", "sha512"]
    matched = False
    for k, v in headers.items():
        header_line = f"{k}: {v}"
        if any(kw in header_line.lower() for kw in keywords):
            matched = True
            break

    if matched and url not in suspicious_hash_responses:
        suspicious_hash_responses.add(url)
        try:
            with open("suspicious_headers.txt", "a", encoding="utf-8") as f:
                f.write(f"[Match] {url}\n")
                for k, v in headers.items():
                    if any(kw in k.lower() or kw in v.lower() for kw in keywords):
                        f.write(f"{k}: {v}\n")
                f.write("\n")
            print(f"Record sensitive headers: {url}")
        except Exception as e:
            print(f"[ERROR] Write suspicious_headers.txt failed: {e}")


# ========== 下载远程资源 ==========
def download_from_remote(path: str, headers) -> Path | None:
    client_host = headers.get("Host", "")
    if not client_host:
        #print("⚠️ 未提供 Host，跳过下载")
        return None

    # 去掉 query 参数部分
    parsed_url = urllib.parse.urlparse(path)
    clean_path = parsed_url.path  # 只保留路径，不含查询参数
    parts = clean_path.lstrip("/").split("/") if clean_path else []
    local_path = DOWNLOAD_ROOT.joinpath(client_host, *parts)

    # 如果路径以 '/' 结尾，说明是文件夹，追加 index.html
    if not parts or path.endswith("/"):
        local_path = local_path / "index.html"

    # 如果文件已存在，直接返回
    if local_path.exists():
        print(f"{local_path} already exists, skip the download")
        return local_path

    try:
        full_url = f"https://{client_host}{path}"
        print(f"Downloading {full_url}...")
        print(headers)
        resp = requests.get(full_url,  timeout=10, verify=False,headers=headers)
        check_response_headers_for_hash(full_url, resp.headers)
        if resp.status_code != 200:
            print(f"Download failed {full_url}，code: {resp.status_code}")
            return None

        os.makedirs(local_path.parent, exist_ok=True)
        with open(local_path, 'wb') as f:
            f.write(resp.content)

        print(f"Successful download {full_url} to {local_path}")
        return local_path
    except Exception as e:
        print(f" Request an exception:{e}")
        return None
def head_from_remote(path: str, headers) -> Path | None:
    import urllib.parse
    import os

    client_host = headers.get("Host", "")
    if not client_host:
        print("Host is not provided, skipping the HEAD request")
        return None

    # 构造本地 headers 文件路径
    parsed_url = urllib.parse.urlparse(path)
    clean_path = parsed_url.path
    parts = clean_path.lstrip("/").split("/") if clean_path else []
    local_path = DOWNLOAD_ROOT.joinpath(client_host, *parts)

    if not parts or path.endswith("/"):
        local_path = local_path / "index.html"

    header_path = local_path.with_suffix(local_path.suffix + ".headers")
    os.makedirs(header_path.parent, exist_ok=True)

    # ✅ 如果 header 文件已经存在，直接返回
    if header_path.exists():
        print(f"Cached headers: {header_path}")
        return header_path

    # 否则发起 HEAD 请求
    try:
        full_url = f"https://{client_host}{path}"
        print(f"HEAD Request: {full_url}")
        resp = requests.head(full_url, timeout=10, verify=False)
        check_response_headers_for_hash(full_url, resp.headers)
        with open(header_path, "w", encoding="utf-8") as f:
            for k, v in resp.headers.items():
                f.write(f"{k}: {v}\n")

        print(f"headers have been written to {header_path}")
        return header_path
    except Exception as e:
        print(f"Request an exception：{e}")
        return None
# ========== 简单文件头判断 ==========
def judge(path: Path):
    try:
        mime = magic.Magic(mime=True)
        # 使用 POSIX 风格路径
        ftype = mime.from_file(path.as_posix())
        map_type[str(path)] = ftype
        print(ftype)
        return ftype
    except Exception as e:
        print(f"[!] Error: {e}")
        map_type[str(path)] = "unknown"
        return "unknown"

def clean_local_path(host: str, path: str) -> Path:
    parsed_url = urllib.parse.urlparse(path)
    clean_path = parsed_url.path  # 去掉 query 参数
    parts = clean_path.lstrip("/").split("/") if clean_path else []
    local_path = DOWNLOAD_ROOT.joinpath(host, *parts)
    if not parts or path.endswith("/"):
        local_path = local_path / "index"
    local_path = local_path.with_name(local_path.name + ".postback")

    return local_path

def save_postback_file(host, path, content):
    parsed_url = urllib.parse.urlparse(path)
    clean_path = parsed_url.path
    parts = clean_path.lstrip("/").split("/") if clean_path else []
    local_path = DOWNLOAD_ROOT.joinpath(host, *parts)

    if not parts or path.endswith("/"):
        local_path = local_path / "index"

    header_path = local_path.with_suffix(local_path.suffix + ".postback")
    os.makedirs(header_path.parent, exist_ok=True)
    try:
        with open(header_path, "wb") as f:
            f.write(content)
        print(f"The POST response is saved to: {local_path}")
    except Exception as e:
        print(f"[ERROR] Saving the postback file failed: {e}")
# ========== 返回对应资源 ==========
def give(handler, path: str):
    file_type = map_type.get(str(path), "unknown")
    if file_type == "application/zip":
        file_path = FAKE_DIR / "1.zip"
    elif file_type == "application/x-dosexec":  # Windows EXE
        file_path = FAKE_DIR / "1.exe"
    elif file_type == "application/x-tar":
        file_path = FAKE_DIR / "1.tar"
    elif file_type == "application/gzip":
        file_path = FAKE_DIR / "1.gz"
    elif file_type == "application/x-bzip2":
        file_path = FAKE_DIR / "1.bz2"
    elif file_type == "application/x-7z-compressed":
        file_path = FAKE_DIR / "1.7z"
    elif file_type == "application/vnd.ms-cab-compressed":
        file_path = FAKE_DIR / "1.cab"
    elif file_type == "application/vnd.ms-opentype":
        file_path = FAKE_DIR / "1.msi"
    elif file_type == "text/xml":
        file_path = FAKE_DIR / "1.xml"
    else:
        file_path = path # 默认使用原始路径

    if not file_path.exists():
        handler.send_error(404, "File Not Found")
        return
    handler.send_response(200)
    ctype = file_type
    handler.send_header("Content-type", ctype)
    handler.end_headers()


    # 发送响应头（过滤掉 Transfer-Encoding: chunked 等可能造成问题的字段）

    with open(file_path, "rb") as f:
        handler.wfile.write(f.read())
    print(f"return packege : {file_path}")

# ========== 解压并检测签名 ==========

checked_files = set()  # 已检测过的路径集合

def check():
    while True:
        for req, ftype in list(map_type.items()):
            if req in checked_files:
                continue  # 跳过已检测的
            checked_files.add(req)
            test_ = Path(req)
            res = analyze_archive(test_, ftype)
            log_results(test_, res)
        time.sleep(10)


privacy_keywords = ["uid", "vmware", "mac", "device_id","exe","dll","zip","7z","token","update","upgrade"]
privacy_log_path = "privacy.txt"
# ========== 自定义 Handler ==========
class VerboseHandler(http.server.SimpleHTTPRequestHandler):
    def handle_error(self, request, client_address):
        exc_type, exc, tb = sys.exc_info()
        # 屏蔽握手阶段的 SSL 错误（如 certificate unknown）
        if isinstance(exc, ssl.SSLError):
            return
        # 其他错误按默认处理
        return super().handle_error(request, client_address)

    def log_request_details(self, method):
        host = self.headers.get("Host", "")
        full_url = f"https://{host}{self.path}"  # 含 query
        parsed_path = urlparse(self.path).path  # 不含 query

        log_line = f"[{method}] {full_url}"
        dedup_key = f"[{method}] https://{host}{parsed_path}"

        # ✅ 检测隐私关键词（含 query 判断）
        if any(keyword in log_line.lower() for keyword in privacy_keywords):
            with open(privacy_log_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
            print(f"Privacy logging: {log_line}")

        # ✅ 日志去重依据 path（不含 query），但记录完整 URL
        if dedup_key not in logged_requests:
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
            logged_requests.add(dedup_key)
            print(f"Log logs: {log_line}")
        else:
            print(f"Exists (deduplication by path): {log_line}")

    def do_GET(self):
        self.log_request_details("GET")
        if self.path.lower().endswith(".exe"):
            self.send_response(200)
            self.send_header("Content-Type", "application/x-dosexec")
            self.end_headers()
            file_path = "fake/1.exe"
            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
            print(f"Return EXE alternative resources: {file_path}")
            return
        local_path = download_from_remote(self.path, self.headers)

        if local_path is None:
            self.send_response(200)
            file_path = "fake/1.zip"
            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
            print(f" Back to resources: {file_path}")
            return
        print(local_path)
        judge(local_path)
        give(self, local_path)



    def do_POST(self):
        self.log_request_details("POST")

        # 读取 POST 请求体
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        host = self.headers.get("Host", "")
        path = self.path

        print(f"[POST] Host: {host}, Path: {path}")
        print(post_data)

        # 记录请求内容
        try:
            with open("post.txt", "ab") as f:
                f.write(f"\n==== Request from {host} ====\n".encode())
                f.write(post_data)
                f.write(b"\n")
        except Exception as e:
            print(f"[ERROR] Write post.txt fails: {e}")

        # === ✅ 检查本地缓存文件是否存在 ===
        if host:
            local_path = clean_local_path(host, path)
            print(local_path)
            if local_path.exists():
                print(f"Locally cached：{local_path}")
                try:
                    content = local_path.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    print(f"[ERROR] Failed to read the local cache: {e}")
                    self.send_error(500, "Failed to read the local cache")
                    return
        else:
            print("The request does not include Host, skipping the local check")

        # === 🔄 发起实际 POST 请求转发 ===
        url = f"https://{host}{path}"

        forward_headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ['host', 'content-length', 'connection']}

        try:
            resp = requests.post(url, data=post_data, headers=forward_headers, timeout=10)
            check_response_headers_for_hash(url, resp.headers)

            # 保存响应副本
            try:
                with open("postback.txt", "ab") as f:
                    f.write(f"\n==== Response from {url} ====\n".encode())
                    f.write(resp.content)
                    f.write(b"\n")
            except Exception as e:
                print(f"[ERROR] Write postback.txt fails: {e}")
            save_postback_file(host, path, resp.content)
            # 返回给客户端
            self.send_response(resp.status_code)
            for key, value in resp.headers.items():
                if key.lower() not in ["content-encoding", "transfer-encoding", "content-length"]:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(resp.content)))
            self.end_headers()
            self.wfile.write(resp.content)

        except Exception as e:
            print(f"[POST ERROR] {url} -> {e}")
            self.send_error(502, f"Upstream POST Failed: {e}")

    def do_PUT(self):
        self.log_request_details("PUT")
        self.send_response(200)
        self.end_headers()

    def do_DELETE(self):
        self.log_request_details("DELETE")
        self.send_response(200)
        self.end_headers()

    def do_HEAD(self):
        self.log_request_details("HEAD")
        header_path = head_from_remote(self.path, self.headers)

        if header_path is None:
            self.send_response(502)
            self.end_headers()
            return

        # 你可以选择是否将 header 回写给客户端，也可以仅记录不返回
        with open(header_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        self.send_response(200)
        for line in lines:
            if ':' in line:
                k, v = line.split(':', 1)
                self.send_header(k.strip(), v.strip())
        self.end_headers()

        print(f"return header, source：{header_path}")

    def do_OPTIONS(self):
        self.log_request_details("OPTIONS")
        self.send_response(204)
        self.send_header('Allow', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH')
        self.end_headers()

    def do_PATCH(self):
        self.log_request_details("PATCH")
        self.send_response(200)
        self.end_headers()

# ========== 启动主函数 ==========
def run():
    # 启动签名检测线程
    threading.Thread(target=check, daemon=True).start()

    # 启动 HTTPS 服务器
    server_address = ('0.0.0.0', 443)
    httpd = http.server.HTTPServer(server_address, VerboseHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='cert.key')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("Serving HTTPS on https://127.0.0.1:443")
    httpd.serve_forever()

if __name__ == '__main__':
    run()