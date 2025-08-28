import os
import time
import subprocess
import win32service
import win32serviceutil
import win32com.client

# 集合记录
seen_exe = set()
seen_tasks = set()
seen_services = set()

# 1. 扫描当前目录及子目录 exe
def scan_exe(root="."):
    new_exe = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.lower().endswith(".exe") and f.lower() != "uninstall.exe":
                full_path = os.path.abspath(os.path.join(dirpath, f))
                if full_path not in seen_exe:
                    new_exe.append(full_path)
    return new_exe

# 运行 exe
def run_exe(path):
    try:
        print(f"[EXE] 运行: {path}")
        subprocess.Popen(path, shell=True)
        seen_exe.add(path)
    except Exception as e:
        print(f"[EXE] 运行失败 {path}: {e}")

# 2. 计划任务
def scan_tasks():
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    rootFolder = scheduler.GetFolder("\\")
    tasks = []

    def recurse(folder):
        for task in folder.GetTasks(0):
            name = task.Name
            if name not in seen_tasks:
                tasks.append(name)
        for sub in folder.GetFolders(0):
            recurse(sub)

    recurse(rootFolder)
    return tasks

def run_task(name):
    try:
        print(f"[TASK] 运行任务: {name}")
        subprocess.run(["schtasks", "/Run", "/TN", name], check=False)
        seen_tasks.add(name)
    except Exception as e:
        print(f"[TASK] 运行失败 {name}: {e}")

# 3. 服务
def scan_services():
    services = []
    hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    statuses = win32service.EnumServicesStatus(hscm)
    for (svc_name, display_name, status) in statuses:
        if svc_name not in seen_services:
            services.append(svc_name)
    return services

def run_service(name):
    try:
        print(f"[SERVICE] 启动服务: {name}")
        win32serviceutil.StartService(name)
        seen_services.add(name)
    except Exception as e:
        print(f"[SERVICE] 启动失败 {name}: {e}")

# 主循环
if __name__ == "__main__":
    print("🔍 开始监控 exe / 计划任务 / 服务 ...")

    while True:
        # exe
        for exe in scan_exe("."):
            run_exe(exe)

        # task
        for task in scan_tasks():
            run_task(task)

        # service
        for svc in scan_services():
            run_service(svc)

        time.sleep(10)  # 每 10 秒扫描一次
