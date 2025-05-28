import subprocess
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, scrolledtext, simpledialog
import re
import os
import sys
from datetime import datetime
import ctypes
import configparser

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
# 설정 파일 이름 정의
CONFIG_NETWORK = 'config.txt'
CONFIG_WINDOWS = 'config.ini'


class SystemToolApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 관리 도우미 v6.0")
        master.geometry("500x650") 

        # --- 메인 탭(Notebook) 생성 ---
        self.notebook = ttk.Notebook(master, padding=5)
        self.notebook.pack(expand=True, fill='both')

        # 각 탭에 들어갈 프레임 생성
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  Windows 정품 인증  ")
        # ---------------------------------
        
        # --- 공통 로그 영역 및 종료 버튼 ---
        self.log_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=10)
        self.log_area.pack(padx=10, pady=(5,0), fill='x')

        self.btn_exit = tk.Button(master, text="종료 (백업 파일 삭제)", bg="#FFDDDD", command=self.cleanup_and_exit)
        self.btn_exit.pack(fill=tk.X, padx=10, pady=(10, 10))
        # ---------------------------------

        # 각 탭의 UI 구성
        self.setup_network_tab()
        self.setup_windows_tab()

        self.log("관리자 권한으로 실행되었습니다.")
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)


    # =================================================================================
    # 네트워크 탭 관련 메서드들
    # =================================================================================
    def setup_network_tab(self):
        # 네트워크 정보 표시 프레임
        info_frame = ttk.LabelFrame(self.network_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        self.ip_var = tk.StringVar(value="정보 없음")
        self.subnet_var = tk.StringVar(value="정보 없음")
        self.gateway_var = tk.StringVar(value="정보 없음")
        self.dns_var = tk.StringVar(value="정보 없음")
        
        ttk.Label(info_frame, text="IP 주소:", width=15).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.ip_var).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, text="서브넷 마스크:", width=15).grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.subnet_var).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, text="기본 게이트웨이:", width=15).grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.gateway_var).grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, text="DNS 서버:", width=15).grid(row=3, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.dns_var).grid(row=3, column=1, sticky="w", padx=5, pady=2)

        # 네트워크 제어 버튼 프레임
        button_frame = ttk.Frame(self.network_tab)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        self.btn_load = tk.Button(button_frame, text="1. 현재 설정 불러오기 및 파일로 백업", command=self.backup_network_settings)
        self.btn_load.pack(fill=tk.X, padx=5, pady=3)
        
        self.btn_apply = tk.Button(button_frame, text=f"2. {CONFIG_NETWORK} 설정 적용하기", command=self.apply_network_from_config)
        self.btn_apply.pack(fill=tk.X, padx=5, pady=3)

        self.btn_restore = tk.Button(button_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED)
        self.btn_restore.pack(fill=tk.X, padx=5, pady=3)
        
        self.create_default_network_config()
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")

    def create_default_network_config(self):
        if not os.path.exists(CONFIG_NETWORK):
            self.log(f"`{CONFIG_NETWORK}` 파일이 없어 새로 생성합니다.")
            with open(CONFIG_NETWORK, "w", encoding="utf-8") as f:
                f.write("# [네트워크] 이 파일에 변경할 네트워크 설정을 입력하세요.\n#ip=192.168.0.100\n#subnet=255.255.255.0\n#gateway=192.168.0.1\n#dns1=8.8.8.8\n#dns2=8.8.4.4\n")
    
    def get_active_interface(self):
        self.log("[네트워크] 활성 인터페이스 검색 중...")
        try:
            output = self.run_command("route print -4 0.0.0.0")
            if not output: return None
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", output, re.MULTILINE)
            if not match: return None
            interface_ip = match.group(1)
        except Exception: return None
        try:
            output = self.run_command("ipconfig")
            if not output: return None
            full_output = output.replace('\n', ' ')
            match = re.search(r"([가-힣\w\s]+ 어댑터\s+[^:]+):\s*.*?IPv4 주소.*?: \s*" + re.escape(interface_ip), full_output, re.IGNORECASE)
            if match:
                interface_name = match.group(1).strip().split('어댑터')[-1].strip()
                self.log(f"[네트워크] 활성 인터페이스 발견: {interface_name}")
                return interface_name
        except Exception: return None
        return None

    def backup_network_settings(self):
        self.interface_name = self.get_active_interface()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.")
            return

        output = self.run_command(f'netsh interface ipv4 show config name="{self.interface_name}"')
        if not output: return

        settings = {}
        # ... (이하 파싱 로직은 이전과 동일)
        dhcp_match = re.search(r"(DHCP 사용|DHCP Enabled)\s*:\s*(.*)", output, re.IGNORECASE)
        settings['dhcp_enabled'] = dhcp_match and dhcp_match.group(2).strip().lower() in ['yes', '예']
        ip_match = re.search(r"(IP 주소|IP Address)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        settings['ip'] = ip_match.group(2) if ip_match else None
        subnet_match = re.search(r"(서브넷 접두사|Subnet Prefix).*\(.*(마스크|Mask)\s+([0-9.]+)\)", output, re.IGNORECASE)
        if subnet_match: settings['subnet'] = subnet_match.group(3)
        else:
            subnet_match_fallback = re.search(r"(서브넷 마스크|Subnet Mask)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
            settings['subnet'] = subnet_match_fallback.group(2) if subnet_match_fallback else None
        gateway_match = re.search(r"(기본 게이트웨이|Default Gateway)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        settings['gateway'] = gateway_match.group(2) if gateway_match else None
        dns_match = re.search(r"(정적으로 구성된 DNS 서버|Statically Configured DNS Servers)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        if dns_match:
            settings['dns'] = [dns_match.group(2)]
            additional_dns = re.findall(r"^\s+([0-9.]+)", output[dns_match.end():], re.MULTILINE)
            settings['dns'].extend(additional_dns)
        else: settings['dns'] = []
        
        self.original_settings = settings
        if not all([settings.get('ip'), settings.get('subnet')]):
             messagebox.showerror("파싱 오류", "IP 또는 서브넷 마스크를 읽어오지 못했습니다.")
             return
        
        self.ip_var.set(settings.get('ip', 'N/A'))
        self.subnet_var.set(settings.get('subnet', 'N/A'))
        self.gateway_var.set(settings.get('gateway', 'N/A'))
        dns_list = settings.get('dns', [])
        self.dns_var.set(", ".join(dns_list) if dns_list else 'N/A')

        with open("backup_settings.txt", "w", encoding="utf-8") as f:
            f.write("# 네트워크 설정 백업\n" + "\n".join([f"{k}={v}" for k, v in settings.items()]))
        self.log("[네트워크] 현재 설정을 백업했습니다.")
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 백업했습니다.")

    def apply_network_from_config(self):
        if not self.interface_name:
            messagebox.showwarning("경고", "먼저 '현재 설정 불러오기' 버튼을 눌러주세요.")
            return
        with open(CONFIG_NETWORK, "r", encoding="utf-8") as f:
            config = dict(line.strip().split('=', 1) for line in f if '=' in line and not line.strip().startswith('#'))
        
        ip, subnet, gateway, dns1 = config.get("ip"), config.get("subnet"), config.get("gateway"), config.get("dns1")
        if not all([ip, subnet, gateway, dns1]):
            messagebox.showerror("설정 오류", f"{CONFIG_NETWORK}의 필수 항목을 확인하세요.")
            return
        
        self.log("[네트워크] 설정 파일 적용 중...")
        self.run_command(f'netsh interface ipv4 set address name="{self.interface_name}" static {ip} {subnet} {gateway}')
        self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name}" static {dns1}')
        if config.get("dns2"): self.run_command(f'netsh interface ipv4 add dns name="{self.interface_name}" {config.get("dns2")} index=2')
        messagebox.showinfo("성공", "네트워크 설정을 변경했습니다.")

    def restore_original_settings(self):
        if not self.original_settings:
            messagebox.showerror("오류", "백업된 설정이 없습니다.")
            return
        
        self.log("[네트워크] 원래 설정으로 복원 중...")
        if self.original_settings.get('dhcp_enabled'):
            self.run_command(f'netsh interface ipv4 set address name="{self.interface_name}" dhcp')
            self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name}" dhcp')
        else:
            ip, subnet, gateway = self.original_settings.get('ip'), self.original_settings.get('subnet'), self.original_settings.get('gateway')
            self.run_command(f'netsh interface ipv4 set address name="{self.interface_name}" static {ip} {subnet} {gateway}')
            dns_servers = self.original_settings.get('dns', [])
            if dns_servers:
                self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name}" static {dns_servers[0]}')
                for i, dns in enumerate(dns_servers[1:], start=2):
                    self.run_command(f'netsh interface ipv4 add dns name="{self.interface_name}" {dns} index={i}')
        messagebox.showinfo("성공", "원래의 네트워크 설정으로 복원했습니다.")


    # =================================================================================
    # Windows 정품 인증 탭 관련 메서드들
    # =================================================================================
    def setup_windows_tab(self):
        info_frame = ttk.LabelFrame(self.windows_tab, text=" 현재 Windows 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        self.partial_key_var = tk.StringVar(value="정보 없음")
        
        ttk.Label(info_frame, text="부분 제품 키:", width=15).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.partial_key_var).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        button_frame = ttk.Frame(self.windows_tab)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(button_frame, text="현재 키 정보 새로고침", command=self.refresh_windows_key_info).pack(fill=tk.X, padx=5, pady=3)
        tk.Button(button_frame, text="새 제품 키 입력 및 정품 인증", command=self.run_windows_activation).pack(fill=tk.X, padx=5, pady=3)

        self.manage_windows_config_file()
        self.refresh_windows_key_info()

    def manage_windows_config_file(self, config_path=CONFIG_WINDOWS):
        self.win_config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            self.log(f"[Windows] '{config_path}' 파일이 없어 새로 생성합니다.")
            self.win_config['Settings'] = {'ProductKey': '제품 키를 여기에 입력하세요'}
            with open(config_path, 'w', encoding='utf-8') as configfile:
                self.win_config.write(configfile)
        self.win_config.read(config_path, encoding='utf-8')
        return self.win_config['Settings'].get('ProductKey', '')

    def update_windows_config_key(self, new_key, config_path=CONFIG_WINDOWS):
        self.win_config['Settings']['ProductKey'] = new_key
        with open(config_path, 'w', encoding='utf-8') as configfile:
            self.win_config.write(configfile)
        self.log(f"[Windows] 새 제품 키를 {config_path}에 저장했습니다.")

    def get_current_partial_key(self):
        self.log("[Windows] 현재 설치된 제품 키 확인 중...")
        try:
            result = self.run_command("cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /dli")
            if not result: return "확인 실패"
            for line in result.splitlines():
                if "부분 제품 키:" in line or "Partial Product Key:" in line:
                    key = line.split(":")[1].strip()
                    self.log(f"[Windows] 확인된 부분 제품 키: {key}")
                    return key
            return "설치 안됨"
        except Exception:
            return "확인 오류"

    def refresh_windows_key_info(self):
        self.partial_key_var.set(self.get_current_partial_key())

    def apply_product_key(self, key):
        try:
            self.log(f"[Windows] 제품 키 설치 시도: {key}")
            result_ipk = self.run_command(f'cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ipk {key}')
            messagebox.showinfo("제품 키 설치 결과", result_ipk.strip())
            
            self.log("[Windows] 온라인 정품 인증 시도...")
            result_ato = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ato')
            messagebox.showinfo("정품 인증 시도 결과", result_ato.strip())
            return True
        except Exception as e:
            messagebox.showerror("인증 오류", f"명령어 실행에 실패했습니다.\n{e}")
            return False

    def run_windows_activation(self):
        stored_key = self.manage_windows_config_file()
        current_partial_key = self.get_current_partial_key()
        
        prompt_text = f"현재 키(마지막 5자리): {current_partial_key}\n\n아래에 새로 적용할 윈도우 제품 키를 입력하세요."
        new_key = simpledialog.askstring("윈도우 제품 키 입력", prompt_text, initialvalue=stored_key, parent=self.master)
        
        if new_key is None:
            self.log("[Windows] 작업이 취소되었습니다.")
            return
        
        new_key = new_key.strip()
        if len(new_key) != 29 or new_key.count('-') != 4:
            messagebox.showerror("입력 오류", "유효한 제품 키 형식이 아닙니다.\n(예: AAAAA-BBBBB-CCCCC-DDDDD-EEEEE)")
            return
        
        if self.apply_product_key(new_key):
            self.update_windows_config_key(new_key)
            self.log("[Windows] 새 제품 키가 성공적으로 적용 및 저장되었습니다.")
            self.refresh_windows_key_info() # 성공 후 정보 갱신


    # =================================================================================
    # 공통 헬퍼 메서드들
    # =================================================================================
    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)

    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?\n(`backup_settings.txt` 파일이 삭제됩니다.)"):
            if os.path.exists("backup_settings.txt"):
                os.remove("backup_settings.txt")
            self.master.destroy()

    def run_command(self, command):
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding=CMD_ENCODING, startupinfo=startupinfo)
            self.log(f"명령어 실행: {command}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.log(f"명령어 오류: {command}\n{e.stderr.strip()}")
            return e.stdout.strip() + "\n" + e.stderr.strip() # 오류 시에도 출력 반환
        except FileNotFoundError:
            self.log(f"오류: {command.split()[0]} 명령어를 찾을 수 없습니다.")
            return None


if __name__ == "__main__":
    root = tk.Tk()
    app = SystemToolApp(root)
    root.mainloop()