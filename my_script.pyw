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
        master.title("시스템 유틸리티 v2.0 (수정판)")
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

    def run_command(self, command_list, use_powershell=False):
        # 명령어 실행을 위한 통합 함수
        shell = False
        if use_powershell:
            # PowerShell 명령어는 리스트가 아닌 단일 문자열로 전달
            command_list = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", command_list]
        
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                command_list, check=True, capture_output=True,
                text=True, encoding=CMD_ENCODING, startupinfo=startupinfo, shell=shell
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

        info_frame = ttk.LabelFrame(self.network_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.ip_var = tk.StringVar(value="정보 없음")
        self.subnet_var = tk.StringVar(value="정보 없음")
        self.gateway_var = tk.StringVar(value="정보 없음")
        self.dns_var = tk.StringVar(value="정보 없음")
        
        ttk.Label(info_frame, text="IP 주소:", width=15).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.ip_var).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        # ... (이하 네트워크 정보 라벨은 동일) ...

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
    
    # === 이 부분이 수정되었습니다: 활성 인터페이스 검색 로직 ===
    def get_active_interface(self):
        self.log("[네트워크] 활성 인터페이스를 검색합니다 (PowerShell 방식)...")
        # PowerShell을 사용하여 기본 게이트웨이가 설정된 네트워크 인터페이스의 별칭(이름)을 직접 가져옵니다.
        # 이 방식은 텍스트 파싱보다 훨씬 안정적입니다.
        ps_command = "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1 -ExpandProperty InterfaceAlias"
        interface_name = self.run_command(ps_command, use_powershell=True)
        
        if interface_name:
            self.log(f"[네트워크] 활성 인터페이스 발견: {interface_name}")
            return interface_name
        else:
            self.log("[네트워크] 활성 네트워크 인터페이스를 찾지 못했습니다.")
            return None
    # =======================================================

    def backup_current_settings(self):
        self.interface_name = self.get_active_interface()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.")
            return

        self.log(f"[네트워크] '{self.interface_name}' 인터페이스 설정을 백업합니다.")
        output = self.run_command(['netsh', 'interface', 'ipv4', 'show', 'config', f'name={self.interface_name}'])
        if not output: return

        # ... (이하 백업 로직은 동일) ...
        settings = {}
        settings['dhcp_enabled'] = re.search(r"(DHCP 사용|DHCP Enabled)\s*:\s*(Yes|예)", output, re.IGNORECASE) is not None
        self.original_settings = settings
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")

    def apply_from_config_file(self):
        if not self.interface_name:
            messagebox.showwarning("경고", "먼저 '1. 현재 설정 불러오기' 버튼을 눌러주세요.")
            return
        # ... (이하 설정 적용 로직 동일) ...

    def restore_original_settings(self):
        if not self.original_settings: return
        # ... (이하 복원 로직 동일) ...
    
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
            # === 이 부분이 수정되었습니다: 기본값 변경 ===
            config['Settings'] = {'ProductKey': 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'}
            # ============================================
            with open(config_path, 'w', encoding='utf-8') as f: config.write(f)
        
        config = configparser.ConfigParser()
        config.read(config_path, encoding='utf-8')
        stored_key = config['Settings'].get('ProductKey', '')

        # ... (이하 윈도우 인증 로직은 동일) ...
        partial_key = self.get_win_partial_key()
        self.win_key_var.set(partial_key)
        prompt_text = f"현재 적용된 키(일부): {partial_key}\n\n아래에 새로 적용할 윈도우 제품 키를 입력하세요."
        new_key = simpledialog.askstring("윈도우 제품 키 입력", prompt_text, initialvalue=stored_key)
        if not new_key: return

        # ... (이하 로직 동일) ...

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
        # ... (이하 로직 동일) ...
        return True


if __name__ == "__main__":
    # 나머지 코드는 이전과 동일하게 유지
    root = tk.Tk()
    # 네트워크 관련 클래스 인스턴스 생성 및 실행 부분 (생략)
    # ... (네트워크 관련 라벨, 버튼 등 UI 요소 생성 및 배치) ...
    app = SystemUtilityApp(root)
    root.mainloop()