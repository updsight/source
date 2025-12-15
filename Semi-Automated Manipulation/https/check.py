import os
import gzip
import bz2
import py7zr
import tarfile
import zipfile

import shutil
import filetype
import xml.etree.ElementTree as ET
from pathlib import Path


TMP_DIR = Path("tmp")
LOG_FILE = Path("signature_check_results.txt")
TMP_DIR.mkdir(exist_ok=True)

def extract(file_path: Path, tmp_folder: Path,suffix):
    os.makedirs(tmp_folder, exist_ok=True)

    try:
        if suffix == "application/zip":
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(tmp_folder)

        elif suffix == "application/x-tar":
            with tarfile.open(file_path, 'r') as t:
                t.extractall(tmp_folder)

        elif suffix == "application/gzip":
            # 只适用于压缩单个文件的 .gz
            output_file = tmp_folder / file_path.stem
            with gzip.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        elif suffix == "application/x-bzip2":
            output_file = tmp_folder / file_path.stem
            with bz2.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        elif suffix == "application/x-7z-compressed":
            with py7zr.SevenZipFile(file_path, mode='r') as z:
                z.extractall(path=tmp_folder)
        else:
            # 不解压，直接复制到临时目录
            shutil.copy(file_path, tmp_folder / file_path.name)
    except Exception as e:
        print(f"⚠️ 解压失败 {file_path}: {e}")

def detect_file_type(path: Path) -> str:
    kind = filetype.guess(str(path))
    if kind:
        return kind.extension
    return "unknown"

import ctypes
from ctypes import wintypes
from pathlib import Path

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8)
    ]

    def __init__(self, guid_str):
        import uuid
        u = uuid.UUID(guid_str)
        ctypes.Structure.__init__(self)
        self.Data1 = u.time_low
        self.Data2 = u.time_mid
        self.Data3 = u.time_hi_version
        data4 = u.bytes[8:]
        for i in range(8):
            self.Data4[i] = data4[i]

WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID('{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}')
WTD_UI_NONE = 0x00000002
WTD_REVOKE_NONE = 0x00000000
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 0x00000001
WTD_STATEACTION_CLOSE = 0x00000002
ERROR_SUCCESS = 0

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [('cbStruct', wintypes.DWORD),
                ('pcwszFilePath', wintypes.LPCWSTR),
                ('hFile', wintypes.HANDLE),
                ('pgKnownSubject', ctypes.POINTER(GUID))]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [('cbStruct', wintypes.DWORD),
                ('pPolicyCallbackData', wintypes.LPVOID),
                ('pSIPClientData', wintypes.LPVOID),
                ('dwUIChoice', wintypes.DWORD),
                ('fdwRevocationChecks', wintypes.DWORD),
                ('dwUnionChoice', wintypes.DWORD),
                ('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                ('dwStateAction', wintypes.DWORD),
                ('hWVTStateData', wintypes.HANDLE),
                ('pwszURLReference', wintypes.LPCWSTR),
                ('dwProvFlags', wintypes.DWORD),
                ('dwUIContext', wintypes.DWORD),
                ('pSignatureSettings', wintypes.LPVOID)]

def check_exe_signature(filepath: Path) -> bool:
    filepath = filepath.resolve()
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(filepath)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.pPolicyCallbackData = None
    trust_data.pSIPClientData = None
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.hWVTStateData = None
    trust_data.pwszURLReference = None
    trust_data.dwProvFlags = 0
    trust_data.dwUIContext = 0
    trust_data.pSignatureSettings = None

    wintrust = ctypes.windll.wintrust
    result = wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))

    # 关闭状态数据
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(trust_data))

    return result == ERROR_SUCCESS


def check_xml_signature(path: Path) -> bool:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        ns = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
        signature = root.find('.//ds:Signature', ns)
        return signature is not None
    except:
        return False

def analyze_archive(zip_path: Path, suffix):
    tmp_folder = TMP_DIR / zip_path.stem
    if tmp_folder.exists():
        shutil.rmtree(tmp_folder)
    os.makedirs(tmp_folder, exist_ok=True)

    results = []
    try:
        extract(zip_path, tmp_folder, suffix)
    except Exception as e:
        results.append(f"解压失败: {e}")
        return results

    keywords = ("md5", "sha", "sha1", "sha256", "sha512")

    for file in tmp_folder.rglob("*"):
        if file.is_file():
            ext = detect_file_type(file)
            rel_path = file.relative_to(tmp_folder)
            sign_status = ""
            hash_found = False
            signature_issue = False

            # 签名检查
            if ext in ('exe', 'dll'):
                if not check_exe_signature(file):
                    signature_issue = True
                    sign_status = "未签名"
            elif ext == 'xml':
                if not check_xml_signature(file):
                    signature_issue = True
                    sign_status = "未签名"
            else:
                sign_status = "无签名检测"

            # 内容中是否包含 hash 关键词
            try:
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    if any(keyword in content for keyword in keywords):
                        hash_found = True
            except Exception as e:
                results.append(f"{rel_path}: 读取失败: {e}")
                continue

            # 只输出有问题的文件
            if signature_issue or hash_found:
                line = f"{rel_path}: "
                if signature_issue:
                    line += sign_status
                if signature_issue and hash_found:
                    line += ", "
                if hash_found:
                    line += "⚠️ 内容含 MD5/SHA 等关键词"
                results.append(line)

    shutil.rmtree(tmp_folder)
    return results



def log_results(zip_path: Path, results: list):
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"原路径: {zip_path}\n里面的文件有:\n")
        for line in results:
            f.write(f"  - {line}\n")
        f.write("\n")

# 调用示例
if __name__ == "__main__":
    test_zip = Path("fake/1.msi")
    res = analyze_archive(test_zip,"1")

    log_results(test_zip, res)

