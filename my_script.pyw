import os
import sys
import subprocess
import re
import ctypes
import configparser
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog

# --- 1. 애플리케이션 시작 시 관리자 권한 확인 및 상승 (통합) ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()
# -------------------------------------------------------------

CMD_ENCODING = 'cp949'

class SystemUtilityApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 유틸리티 v3.0 (최종 수정판)")
        master.geometry("500x650")

        self.notebook = ttk.Notebook(master, padding=10)
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ")
        self.notebook.pack(expand=True, fill="both")

        log_frame = ttk.LabelFrame(master, text=" 실행 로그 ")
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_area.pack(pady=5, padx=5, expand=True, fill=tk.X)
        
        self.log("관리자 권한으로 실행되었습니다.")
        
        self.create_network_widgets()
        self.create_windows_widgets()
        
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    # === 공용 헬퍼 함수들 ===
    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)

    def run_command(self, command, use_powershell=False):
        command_list = command
        if use_powershell:
            command_list = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", command]
        
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                command_list, check=True, capture_output=True,
                text=True, encoding='utf-8', startupinfo=startupinfo # utf-8로 인코딩 고정
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.strip() or e.stdout.strip()
            self.log(f"명령어 실행 오류: {error_output}")
            return None
        except FileNotFoundError as e:
            self.log(f"명령어를 찾을 수 없습니다: {e.filename}")
            return None

    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?\n(`backup_settings.txt` 파일이 삭제됩니다.)"):
            try:
                backup_file = "backup_settings.txt"
                if os.path.exists(backup_file): os.remove(backup_file)
            except Exception as e:
                self.log(f"백업 파일 삭제 중 오류: {e}")
            self.master.destroy()

    # === 1. 네트워크 탭 관련 기능들 ===
    def create_network_widgets(self):
        self.original_settings = {}
        self.interface_name = ""

        info_frame = ttk.LabelFrame(self.network_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.ip_var = tk.StringVar(value="정보 없음")
        self.subnet_var = tk.StringVar(value="정보 없음")
        self.gateway_var = tk.StringVar(value="정보 없음")
        self.dns_var = tk.StringVar(value="정보 없음")
        
        labels = {"IP 주소:": self.ip_var, "서브넷 마스크:": self.subnet_var, "기본 게이트웨이:": self.gateway_var, "DNS 서버:": self.dns_var}
        for i, (text, var) in enumerate(labels.items()):
            ttk.Label(info_frame, text=text, width=15).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)

        btn_frame = ttk.Frame(self.network_tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="1. 현재 설정 불러오기 및 파일로 백업", command=self.backup_current_settings).pack(fill=tk.X, pady=3)
        ttk.Button(btn_frame, text="2. config.txt 설정 적용하기", command=self.apply_from_config_file).pack(fill=tk.X, pady=3)
        self.btn_restore = ttk.Button(btn_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED)
        self.btn_restore.pack(fill=tk.X, pady=3)

        self.create_default_network_config()
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")

    def create_default_network_config(self):
        if not os.path.exists("config.txt"):
            self.log("[네트워크] `config.txt` 파일이 없어 새로 생성합니다.")
            with open("config.txt", "w", encoding="utf-8") as f:
                f.write("# 이 파일에 변경할 네트워크 설정을 입력하세요.\n\n#ip=192.168.0.100\n#subnet=255.255.255.0\n#gateway=192.168.0.1\n#dns1=8.8.8.8\n#dns2=8.8.4.4\n")

    def get_active_interface_name(self):
        self.log("[네트워크] 활성 인터페이스를 검색합니다 (PowerShell 방식)...")
        ps_command = "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1 -ExpandProperty InterfaceAlias"
        interface_name = self.run_command(ps_command, use_powershell=True)
        return interface_name

    # === 이 부분이 결정적인 수정사항입니다: PowerShell + JSON으로 정보 추출 ===
    def prefix_to_subnet(self, prefix_length):
        bits = '1' * prefix_length + '0' * (32 - prefix_length)
        return ".".join([str(int(bits[i:i+8], 2)) for i in range(0, 32, 8)])

    def backup_current_settings(self):
        self.interface_name = self.get_active_interface_name()
        if not self.interface_name:
            self.log("[네트워크] 오류: 활성화된 네트워크 인터페이스를 찾지 못했습니다.")
            messagebox.showerror("오류", "활성화된 네트워크 인터셔페이스를 찾을 수 없습니다.")
            return

        self.log(f"[네트워크] '{self.interface_name}'의 상세 정보를 PowerShell로 가져옵니다.")
        ps_command = f"Get-NetIPConfiguration -InterfaceAlias '{self.interface_name}' | ConvertTo-Json"
        json_output = self.run_command(ps_command, use_powershell=True)
        
        if not json_output:
            self.log("[네트워크] 오류: 인터페이스의 상세 정보를 가져오는 데 실패했습니다.")
            messagebox.showerror("오류", "인터페이스의 상세 정보를 가져오는 데 실패했습니다.")
            return

        try:
            # PowerShell이 단일 객체를 반환할 때 배열이 아닐 수 있으므로 처리
            if not json_output.startswith('['):
                json_output = f'[{json_output}]'
            net_data = json.loads(json_output)[0]

            settings = {}
            ip_info = net_data.get('IPv4Address', [{}])[0]
            settings['ip'] = ip_info.get('IPAddress')
            settings['subnet'] = self.prefix_to_subnet(ip_info.get('PrefixLength', 0)) if ip_info else None
            settings['gateway'] = net_data.get('IPv4DefaultGateway', {}).get('NextHop')
            settings['dns'] = [addr for item in net_data.get('DNSServer', []) if (addr := item.get('ServerAddresses'))]
            settings['dhcp_enabled'] = net_data.get('InterfaceOperationalStatus') == 'Up' and net_data.get('Dhcp') == 'Enabled'

            self.original_settings = settings

            self.ip_var.set(settings.get('ip', 'N/A'))
            self.subnet_var.set(settings.get('subnet', 'N/A'))
            self.gateway_var.set(settings.get('gateway', 'N/A'))
            self.dns_var.set(", ".join(settings['dns']) if settings.get('dns') else 'N/A')
            
            with open("backup_settings.txt", "w", encoding="utf-8") as f:
                f.write(f"# 네트워크 설정 백업 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n")
                for key, value in settings.items():
                    f.write(f"{key}={value}\n")
            self.log("[네트워크] `backup_settings.txt` 파일에 현재 설정을 저장했습니다.")
            
            self.btn_restore.config(state=tk.NORMAL)
            messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")

        except (json.JSONDecodeError, IndexError, KeyError) as e:
            self.log(f"[네트워크] 오류: 가져온 정보(JSON)를 분석하는 중 오류 발생. {e}")
            messagebox.showerror("파싱 오류", f"가져온 네트워크 정보를 분석하는 중 오류가 발생했습니다.\n\n{e}")
    # ===================================================================

    def apply_from_config_file(self):
        # ... 기존 코드와 동일하게 유지 ...
        pass
    def restore_original_settings(self):
        # ... 기존 코드와 동일하게 유지 ...
        pass
    
    # === 2. 윈도우 탭 관련 기능들 (수정 없음) ===
    def create_windows_widgets(self):
        # ... 기존 코드와 동일하게 유지 ...
        win_frame = ttk.LabelFrame(self.windows_tab, text=" 윈도우 정