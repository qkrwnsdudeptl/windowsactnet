import os
import sys
import subprocess
import re
import ctypes
import configparser
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog

# --- 관리자 권한 확인 및 상승 로직 ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()
# -----------------------------------------

CMD_ENCODING = 'cp949'

class SystemUtilityApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 유틸리티 (최종 완성본)")
        master.geometry("500x700")

        self.notebook = ttk.Notebook(master, padding=10)
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ")
        self.notebook.pack(expand=True, fill="both")

        log_frame = ttk.LabelFrame(master, text=" 실행 로그 ")
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_area.pack(pady=5, padx=5, expand=True, fill="both")
        
        self.create_network_widgets(self.network_tab)
        self.create_windows_widgets(self.windows_tab)
        
        self.log("관리자 권한으로 실행되었습니다.")
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    def log(self, message):
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n"); self.log_area.see(tk.END)
    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?"): self.master.destroy()
    def run_command(self, command, encoding=CMD_ENCODING):
        try:
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding=encoding, startupinfo=startupinfo)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.log(f"명령어 실행 오류: {e.stderr or e.stdout}"); return None
        except FileNotFoundError: self.log("명령어를 찾을 수 없습니다."); return None

    # === 1. 네트워크 탭 ===
    def create_network_widgets(self, parent_tab):
        self.original_settings = {}
        self.interface_name = ""
        info_frame = ttk.LabelFrame(parent_tab, text=" 현재 네트워크 정보 "); info_frame.pack(fill=tk.X, padx=10, pady=5)
        self.ip_var, self.subnet_var, self.gateway_var, self.dns_var = tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음")
        labels = {"IP 주소:": self.ip_var, "서브넷 마스크:": self.subnet_var, "기본 게이트웨이:": self.gateway_var, "DNS 서버:": self.dns_var}
        for i, (text, var) in enumerate(labels.items()):
            ttk.Label(info_frame, text=text, width=15).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)
        btn_frame = ttk.Frame(parent_tab); btn_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Button(btn_frame, text="1. 현재 설정 불러오기 및 파일로 백업", command=self.backup_current_settings).pack(fill=tk.X, padx=10, pady=3)
        tk.Button(btn_frame, text="2. config.txt 설정 적용하기", command=self.apply_from_config_file).pack(fill=tk.X, padx=10, pady=3)
        self.btn_restore = tk.Button(btn_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED); self.btn_restore.pack(fill=tk.X, padx=10, pady=3)
        tk.Button(btn_frame, text="종료", command=self.cleanup_and_exit, bg="#FFDDDD").pack(fill=tk.X, padx=10, pady=(10, 5))
        self.create_default_config_if_not_exists()
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")

    # === 이 부분이 수정되었습니다: config.txt 생성 ===
    def create_default_config_if_not_exists(self):
        if not os.path.exists("config.txt"):
            self.log("`config.txt` 파일이 없어 새로 생성합니다.")
            with open("config.txt", "w", encoding="utf-8") as f:
                f.write("# 이 파일에 변경할 네트워크 설정을 입력하세요.\n"
                        "# 각 줄의 맨 앞에 있는 #을 지우고 값을 수정한 뒤 저장하세요.\n\n"
                        "#ip=192.168.0.100\n"
                        "#subnet=255.255.255.0\n"
                        "#gateway=192.168.0.1\n"
                        "#dns1=8.8.8.8\n"
                        "#dns2=8.8.4.4\n")
            self.log("`config.txt`에 예시 설정을 작성했습니다.")
    
    def get_netsh_compatible_name(self):
        try:
            route_output = self.run_command("route print -4 0.0.0.0");
            if not route_output: return None
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", route_output, re.MULTILINE)
            if not match: return None
            interface_ip = match.group(1)
            ipconfig_output = self.run_command("ipconfig /all")
            if not ipconfig_output: return None
            ipv6_match = re.search(r"링크-로컬 IPv6 주소[ .]+: .+(%\d+)", ipconfig_output)
            if not ipv6_match: return None
            if_index = ipv6_match.group(1).replace('%','')
            netsh_output = self.run_command("netsh interface ipv4 show interfaces")
            if not netsh_output: return None
            for line in netsh_output.splitlines():
                if line.strip().startswith(if_index):
                    parts = re.split(r'\s{2,}', line.strip())
                    if len(parts) > 3: return parts[-1]
            return None
        except Exception: return None

    # === 이 부분이 수정되었습니다: 네트워크 정보 파싱 강화 ===
    def backup_current_settings(self):
        self.interface_name = self.get_netsh_compatible_name()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다."); return

        self.log(f"인터페이스 [{self.interface_name}]의 설정을 백업합니다.")
        output = self.run_command(f'netsh interface ipv4 show config name="{self.interface_name}"')
        if not output: messagebox.showerror("오류", "설정 정보를 가져오는 데 실패했습니다."); return
        
        self.log("설정 정보 분석을 시작합니다...")
        settings = {}
        # 각 항목을 더 정확하게 찾기 위해 정규식 보완
        ip_match = re.search(r"(?:IP 주소|IP Address)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        subnet_match = re.search(r"(?:서브넷 마스크|Subnet Mask)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        gateway_match = re.search(r"(?:기본 게이트웨이|Default Gateway)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        dns_matches = re.findall(r"(?:DNS 서버|DNS Server)[^:\n]*:\s*([0-9.]+)", output, re.IGNORECASE)
        
        settings['ip'] = ip_match.group(1) if ip_match else None
        settings['subnet'] = subnet_match.group(1) if subnet_match else None
        settings['gateway'] = gateway_match.group(1) if gateway_match else None
        settings['dns'] = dns_matches if dns_matches else []

        self.original_settings = settings
        self.ip_var.set(settings.get('ip') or 'N/A')
        self.subnet_var.set(settings.get('subnet') or 'N/A')
        self.gateway_var.set(settings.get('gateway') or 'N/A')
        self.dns_var.set(", ".join(settings['dns']) if settings['dns'] else 'N/A')
        
        if not all([settings.get('ip'), settings.get('subnet')]):
             self.log("오류: IP 또는 서브넷을 읽지 못했습니다."); messagebox.showerror("파싱 오류", "IP 또는 서브넷 마스크를 읽어오지 못했습니다."); return
        
        with open("backup_settings.txt", "w", encoding="utf-8") as f:
            f.write(f"# {self.interface_name} 설정 백업\n")
            for key, value in settings.items(): f.write(f"{key}={value}\n")
        
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")
    
    def apply_from_config_file(self): pass # 로직 생략
    def restore_original_settings(self): pass # 로직 생략

    # === 2. 윈도우 인증 탭 (기존과 동일) ===
    def create_windows_widgets(self, parent_tab):
        win_frame = ttk.LabelFrame(parent_tab, text=" 윈도우 정품 키 관리 "); win_frame.pack(fill=tk.X, padx=10, pady=10, expand=True)
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        center_frame = ttk.Frame(win_frame); center_frame.pack(expand=True)
        ttk.Label(center_frame, text="현재 키 (일부):", font=('Malgun Gothic', 10)).pack(pady=5)
        ttk.Label(center_frame, textvariable=self.win_key_var, font=('Helvetica', 12, 'bold'), foreground="blue").pack(pady=5)
        ttk.Button(parent_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow).pack(fill=tk.X, padx=10, pady=20)

    def run_windows_activation_flow(self): # 로직 생략
        pass
    def get_win_partial_key(self): # 로직 생략
        pass
    def apply_windows_key(self, key): # 로직 생략
        pass

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()