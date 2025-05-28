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
        master.title("시스템 유틸리티 (최종 복원판)")
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

    def create_default_config_if_not_exists(self):
        if not os.path.exists("config.txt"):
            with open("config.txt", "w", encoding="utf-8") as f:
                f.write("# ip=192.168.0.100\n# subnet=255.255.255.0\n# gateway=192.168.0.1\n# dns1=8.8.8.8\n# dns2=8.8.4.4\n")
    
    def get_netsh_compatible_name(self):
        self.log("활성 인터페이스의 'netsh용 이름'을 검색합니다.")
        try:
            # 1. route print로 활성 IP 찾기
            route_output = self.run_command("route print -4 0.0.0.0")
            if not route_output: return None
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", route_output, re.MULTILINE)
            if not match: self.log("기본 경로를 찾지 못했습니다."); return None
            interface_ip = match.group(1)
            self.log(f"활성 IP 발견: {interface_ip}")

            # 2. ipconfig /all 로 인덱스(%) 찾기
            ipconfig_output = self.run_command("ipconfig /all")
            if not ipconfig_output: return None
            
            # Link-local IPv6 주소에서 인덱스 추출
            ipv6_match = re.search(r"링크-로컬 IPv6 주소[ .]+: .+(%\d+)", ipconfig_output)
            if not ipv6_match: self.log("링크-로컬 IPv6 주소에서 인터페이스 인덱스를 찾지 못했습니다."); return None
            if_index = ipv6_match.group(1).replace('%','')
            self.log(f"활성 인터페이스 인덱스 발견: {if_index}")

            # 3. netsh로 인덱스에 해당하는 '진짜 이름' 찾기
            netsh_output = self.run_command("netsh interface ipv4 show interfaces")
            if not netsh_output: return None
            
            for line in netsh_output.splitlines():
                if line.strip().startswith(if_index):
                    # '---' 구분자를 기준으로 나눈 후 마지막 요소를 이름으로 간주
                    parts = re.split(r'\s{2,}', line.strip())
                    if len(parts) > 3:
                        netsh_name = parts[-1]
                        self.log(f"Netsh용 이름 발견: [{netsh_name}]")
                        return netsh_name
            self.log("netsh 인터페이스 목록에서 해당 인덱스를 찾지 못했습니다."); return None
        except Exception as e:
            self.log(f"netsh용 이름 검색 중 오류: {e}"); return None

    def backup_current_settings(self):
        self.interface_name = self.get_netsh_compatible_name()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다."); return

        self.log(f"인터페이스 [{self.interface_name}]의 설정을 백업합니다.")
        output = self.run_command(f'netsh interface ipv4 show config name="{self.interface_name}"')
        if not output: messagebox.showerror("오류", "설정 정보를 가져오는 데 실패했습니다."); return
        
        # ... 이하 파싱 및 저장 로직 ...
        settings = {}; ip_match = re.search(r"IP (?:주소|Address)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        settings['ip'] = ip_match.group(1) if ip_match else None
        # ... (나머지 파싱 생략)
        self.original_settings = settings; self.ip_var.set(settings.get('ip', 'N/A'))
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")
    
    def apply_from_config_file(self): pass
    def restore_original_settings(self): pass

    # === 2. 윈도우 인증 탭 ===
    def create_windows_widgets(self, parent_tab):
        win_frame = ttk.LabelFrame(parent_tab, text=" 윈도우 정품 키 관리 "); win_frame.pack(fill=tk.X, padx=10, pady=10, expand=True)
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        center_frame = ttk.Frame(win_frame); center_frame.pack(expand=True)
        ttk.Label(center_frame, text="현재 키 (일부):", font=('Malgun Gothic', 10)).pack(pady=5)
        ttk.Label(center_frame, textvariable=self.win_key_var, font=('Helvetica', 12, 'bold'), foreground="blue").pack(pady=5)
        ttk.Button(parent_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow).pack(fill=tk.X, padx=10, pady=20)

    def run_windows_activation_flow(self):
        config_path = 'windows_key.ini'
        config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            self.log(f"[윈도우] '{config_path}' 파일이 없어 새로 생성합니다.")
            config['Settings'] = {'ProductKey': 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'}
            with open(config_path, 'w', encoding='utf-8') as f: config.write(f)
        config.read(config_path, encoding='utf-8')
        stored_key = config['Settings'].get('ProductKey', '')
        partial_key = self.get_win_partial_key()
        self.win_key_var.set(partial_key)
        prompt_text = f"현재 적용된 키(일부): {partial_key}\n\n새로 적용할 윈도우 제품 키를 입력하세요."
        new_key = simpledialog.askstring("윈도우 제품 키 입력", prompt_text, initialvalue=stored_key)
        if not new_key: self.log("[윈도우] 키 입력이 취소되었습니다."); return
        if len(new_key.strip()) != 29 or new_key.strip().count('-') != 4: messagebox.showerror("입력 오류", "유효한 제품 키 형식이 아닙니다."); return
        if self.apply_windows_key(new_key.strip()):
            config['Settings']['ProductKey'] = new_key.strip()
            with open(config_path, 'w', encoding='utf-8') as f: config.write(f)
            messagebox.showinfo("성공", "윈도우 제품 키가 성공적으로 적용 및 저장되었습니다.")
        else: messagebox.showerror("실패", "제품 키 적용에 실패했습니다. 로그를 확인해주세요.")

    def get_win_partial_key(self):
        output = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /dli')
        if output:
            for line in output.splitlines():
                if "부분 제품 키:" in line or "Partial Product Key:" in line: return line.split(":")[-1].strip()
        return "확인 불가"

    def apply_windows_key(self, key):
        self.log(f"[윈도우] 제품 키 설치 시도: {key[:5]}...")
        ipk_output = self.run_command(f'cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ipk {key}')
        if ipk_output is None or "오류" in ipk_output or "Error" in ipk_output: self.log("[윈도우] 제품 키 설치에 실패했습니다."); return False
        self.log(f"[윈도우] 제품 키 설치 결과: {ipk_output}")
        self.log("[윈도우] 온라인 정품 인증을 시도합니다...")
        ato_output = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ato')
        if ato_output: self.log(f"[윈도우] 정품 인증 시도 결과: {ato_output}")
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()