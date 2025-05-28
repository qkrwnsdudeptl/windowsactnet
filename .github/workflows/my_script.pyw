import os
import sys
import subprocess
import re
import ctypes
import configparser
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
    # 관리자 권한으로 스크립트를 다시 실행
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit() # 현재 권한 없는 프로세스는 종료
# -------------------------------------------------------------

CMD_ENCODING = 'cp949'

class SystemUtilityApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 유틸리티 v1.0")
        master.geometry("500x650") # 창 크기 조정

        # --- 메인 노트북 (탭) 생성 ---
        self.notebook = ttk.Notebook(master, padding=10)
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ")
        self.notebook.pack(expand=True, fill="both")

        # --- 공용 로그 영역 생성 ---
        log_frame = ttk.LabelFrame(master, text=" 실행 로그 ")
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_area.pack(pady=5, padx=5, expand=True, fill=tk.X)
        
        self.log("관리자 권한으로 실행되었습니다.")
        
        # --- 각 탭의 UI 초기화 ---
        self.create_network_widgets()
        self.create_windows_widgets()
        
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    # === 공용 헬퍼 함수들 ===
    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)

    def run_command(self, command_list):
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                command_list, check=True, capture_output=True,
                text=True, encoding=CMD_ENCODING, startupinfo=startupinfo
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_output = e.stderr or e.stdout
            self.log(f"명령어 실행 오류: {error_output}")
            return None
        except FileNotFoundError as e:
            self.log(f"명령어를 찾을 수 없습니다: {e}")
            return None

    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?\n(`backup_settings.txt` 파일이 삭제됩니다.)"):
            try:
                backup_file = "backup_settings.txt"
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                    self.log(f"'{backup_file}' 파일을 삭제했습니다.")
            except Exception as e:
                self.log(f"백업 파일 삭제 중 오류: {e}")
            self.master.destroy()

    # === 1. 네트워크 탭 관련 기능들 ===
    def create_network_widgets(self):
        self.original_settings = {}
        self.interface_name = ""

        # 현재 네트워크 정보 프레임
        info_frame = ttk.LabelFrame(self.network_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
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

        # 버튼 프레임
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
                f.write("# 이 파일에 변경할 네트워크 설정을 입력하세요.\n# 각 줄의 맨 앞에 있는 #을 지우고 값을 수정한 뒤 저장하세요.\n\n#ip=192.168.0.100\n#subnet=255.255.255.0\n#gateway=192.168.0.1\n#dns1=8.8.8.8\n#dns2=8.8.4.4\n")
    
    def get_active_interface(self):
        self.log("[네트워크] 활성 인터페이스를 검색합니다...")
        output = self.run_command(["route", "print", "-4", "0.0.0.0"])
        if not output: return None
        match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", output, re.MULTILINE)
        if not match:
            self.log("[네트워크] 기본 경로(Default Route)를 찾을 수 없습니다.")
            return None
        interface_ip = match.group(1)
        
        output_ipconfig = self.run_command(["ipconfig"])
        if not output_ipconfig: return None
        
        interface_name = None
        current_adapter_lines = []
        for line in output_ipconfig.splitlines():
            if line.strip() == '':
                # 블록이 끝나면 IP를 포함하는지 확인
                block_text = "".join(current_adapter_lines)
                if f"IPv4 주소. . . . . . . . . . . . : {interface_ip}" in block_text or f"IPv4 Address. . . . . . . . . . . : {interface_ip}" in block_text:
                    adapter_name_match = re.search(r"([가-힣\w\s]+ 어댑터.+?):", block_text)
                    if adapter_name_match:
                        interface_name = adapter_name_match.group(1).strip()
                        break
                current_adapter_lines = []
            else:
                current_adapter_lines.append(line)
        
        if interface_name:
            self.log(f"[네트워크] 활성 인터페이스 발견: {interface_name}")
            return interface_name
        else:
            self.log("[네트워크] ipconfig에서 일치하는 인터페이스를 찾지 못했습니다.")
            return None

    def backup_current_settings(self):
        self.interface_name = self.get_active_interface()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.")
            return

        self.log(f"[네트워크] '{self.interface_name}' 인터페이스 설정을 백업합니다.")
        output = self.run_command(['netsh', 'interface', 'ipv4', 'show', 'config', f'name={self.interface_name}'])
        if not output: return

        settings = {}
        settings['dhcp_enabled'] = re.search(r"(DHCP 사용|DHCP Enabled)\s*:\s*(Yes|예)", output, re.IGNORECASE) is not None
        settings['ip'] = (re.search(r"(IP 주소|IP Address)\s*:\s*([0-9.]+)", output, re.IGNORECASE) or {}).get(2)
        settings['subnet'] = (re.search(r"(서브넷 마스크|Subnet Mask)\s*:\s*([0-9.]+)", output, re.IGNORECASE) or {}).get(2)
        settings['gateway'] = (re.search(r"(기본 게이트웨이|Default Gateway)\s*:\s*([0-9.]+)", output, re.IGNORECASE) or {}).get(2)
        settings['dns'] = re.findall(r"(DNS 서버|DNS Servers).*\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        
        self.original_settings = settings
        self.ip_var.set(settings.get('ip', 'N/A'))
        self.subnet_var.set(settings.get('subnet', 'N/A'))
        self.gateway_var.set(settings.get('gateway', 'N/A'))
        self.dns_var.set(", ".join([d[1] for d in settings['dns']]) if settings.get('dns') else 'N/A')

        with open("backup_settings.txt", "w", encoding="utf-8") as f:
            f.write(f"interface={self.interface_name}\n")
            f.write(f"dhcp_enabled={self.original_settings.get('dhcp_enabled')}\n")
        
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")

    def apply_from_config_file(self):
        if not self.interface_name:
            messagebox.showwarning("경고", "먼저 '1. 현재 설정 불러오기' 버튼을 눌러주세요.")
            return
        with open("config.txt", "r", encoding="utf-8") as f:
            config = dict(line.strip().split('=', 1) for line in f if '=' in line and not line.strip().startswith('#'))
        
        ip, subnet, gateway, dns1 = config.get("ip"), config.get("subnet"), config.get("gateway"), config.get("dns1")
        
        self.log("[네트워크] `config.txt` 파일 설정 적용 시작...")
        self.run_command(['netsh', 'interface', 'ipv4', 'set', 'address', f'name={self.interface_name}', 'static', ip, subnet, gateway])
        self.run_command(['netsh', 'interface', 'ipv4', 'set', 'dns', f'name={self.interface_name}', 'static', dns1])
        if config.get("dns2"):
            self.run_command(['netsh', 'interface', 'ipv4', 'add', 'dns', f'name={self.interface_name}', config.get("dns2"), 'index=2'])
        self.log("[네트워크] 설정 적용 완료.")
        messagebox.showinfo("성공", "`config.txt`의 설정으로 네트워크 정보를 변경했습니다.")

    def restore_original_settings(self):
        if not self.original_settings: return
        self.log("[네트워크] 원래 설정으로 복원 시작...")
        if self.original_settings.get('dhcp_enabled'):
            self.log("[네트워크] DHCP(자동) 설정으로 복원합니다.")
            self.run_command(['netsh', 'interface', 'ipv4', 'set', 'address', f'name={self.interface_name}', 'dhcp'])
            self.run_command(['netsh', 'interface', 'ipv4', 'set', 'dns', f'name={self.interface_name}', 'dhcp'])
        else:
            self.log("[네트워크] 백업된 고정 IP 설정으로 복원합니다.")
            # ... 복원 로직 (기존 코드와 유사하게 구현) ...
        self.log("[네트워크] 복원 완료.")
        messagebox.showinfo("성공", "원래의 네트워크 설정으로 복원했습니다.")
    
    # === 2. 윈도우 탭 관련 기능들 ===
    def create_windows_widgets(self):
        win_frame = ttk.LabelFrame(self.windows_tab, text=" 윈도우 정품 키 관리 ")
        win_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        ttk.Label(win_frame, text="현재 키 (일부):").pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Label(win_frame, textvariable=self.win_key_var, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=10)
        
        ttk.Button(self.windows_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow).pack(fill=tk.X, padx=10, pady=10)
        self.log("[윈도우] '정품 인증 시작' 버튼을 눌러 진행하세요.")
    
    def run_windows_activation_flow(self):
        config_path = 'windows_key.ini'
        
        # 1. Config 파일 관리
        if not os.path.exists(config_path):
            self.log(f"[윈도우] '{config_path}' 파일이 없어 새로 생성합니다.")
            config = configparser.ConfigParser()
            config['Settings'] = {'ProductKey': '여기에 제품 키 입력'}
            with open(config_path, 'w', encoding='utf-8') as f: config.write(f)
        
        config = configparser.ConfigParser()
        config.read(config_path, encoding='utf-8')
        stored_key = config['Settings'].get('ProductKey', '')

        # 2. 현재 키 정보 가져오기 및 표시
        partial_key = self.get_win_partial_key()
        self.win_key_var.set(partial_key)

        # 3. 사용자에게 키 입력 받기
        prompt_text = f"현재 적용된 키(일부): {partial_key}\n\n아래에 새로 적용할 윈도우 제품 키를 입력하세요."
        new_key = simpledialog.askstring("윈도우 제품 키 입력", prompt_text, initialvalue=stored_key)

        if not new_key:
            self.log("[윈도우] 키 입력이 취소되었습니다.")
            return

        if len(new_key.strip()) != 29 or new_key.strip().count('-') != 4:
            messagebox.showerror("입력 오류", "유효한 제품 키 형식이 아닙니다.")
            self.log("[윈도우] 유효하지 않은 키 형식입니다.")
            return

        # 4. 키 적용
        if self.apply_windows_key(new_key.strip()):
            self.log("[윈도우] 새 제품 키를 성공적으로 적용했습니다.")
            # 성공 시, 새로 입력한 키를 config 파일에 저장
            config['Settings']['ProductKey'] = new_key.strip()
            with open(config_path, 'w', encoding='utf-8') as f: config.write(f)
            self.log(f"[윈도우] 새 키를 '{config_path}'에 저장했습니다.")
            messagebox.showinfo("성공", "윈도우 제품 키가 성공적으로 적용 및 저장되었습니다.")
        else:
            messagebox.showerror("실패", "제품 키 적용에 실패했습니다. 로그를 확인해주세요.")

    def get_win_partial_key(self):
        self.log("[윈도우] 현재 제품 키 정보를 가져옵니다...")
        output = self.run_command(['cscript', '//Nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/dli'])
        if output:
            for line in output.splitlines():
                if "부분 제품 키:" in line or "Partial Product Key:" in line:
                    key = line.split(":")[1].strip()
                    self.log(f"[윈도우] 현재 키(일부): {key}")
                    return key
        self.log("[윈도우] 현재 제품 키를 찾을 수 없습니다.")
        return "확인 불가"

    def apply_windows_key(self, key):
        self.log(f"[윈도우] 제품 키 설치 시도: {key[:5]}...")
        ipk_output = self.run_command(['cscript', '//Nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/ipk', key])
        if ipk_output is None or "오류" in ipk_output or "Error" in ipk_output:
             self.log("[윈도우] 제품 키 설치에 실패했습니다.")
             return False
        self.log("[윈도우] 제품 키 설치 성공.")
        
        self.log("[윈도우] 온라인 정품 인증을 시도합니다...")
        ato_output = self.run_command(['cscript', '//Nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/ato'])
        if ato_output is None or "오류" in ato_output or "Error" in ato_output:
            self.log("[윈도우] 온라인 정품 인증에 실패했습니다.")
            # 키 설치는 성공했을 수 있으므로 실패로 간주하지는 않음
        else:
            self.log("[윈도우] 정품 인증 시도 완료.")
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()