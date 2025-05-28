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

class SystemUtilityApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 유틸리티 v4.0 (안정화 버전)")
        master.geometry("500x650")

        self.notebook = ttk.Notebook(master, padding=10)
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ")
        self.notebook.pack(expand=True, fill="both")

        log_frame = ttk.LabelFrame(master, text=" 실행 로그 (문제가 발생하면 이 내용을 복사해주세요) ")
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

    def run_command(self, command_list, encoding='utf-8'):
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                command_list, check=True, capture_output=True,
                text=True, encoding=encoding, startupinfo=startupinfo
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
        # ... UI 생성 부분은 동일 ...
        self.original_settings = {}
        self.interface_name = ""
        info_frame = ttk.LabelFrame(self.network_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        self.ip_var = tk.StringVar(value="정보 없음"); self.subnet_var = tk.StringVar(value="정보 없음")
        self.gateway_var = tk.StringVar(value="정보 없음"); self.dns_var = tk.StringVar(value="정보 없음")
        labels = {"IP 주소:": self.ip_var, "서브넷 마스크:": self.subnet_var, "기본 게이트웨이:": self.gateway_var, "DNS 서버:": self.dns_var}
        for i, (text, var) in enumerate(labels.items()):
            ttk.Label(info_frame, text=text, width=15).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)
        btn_frame = ttk.Frame(self.network_tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_frame, text="1. 현재 설정 불러오기 및 파일로 백업", command=self.backup_current_settings).pack(fill=tk.X, pady=3)
        self.btn_restore = ttk.Button(btn_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED)
        self.btn_restore.pack(fill=tk.X, pady=3)
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")

    # === 이 부분이 요청대로 수정한 '라우팅 테이블' 방식입니다 ===
    def get_active_interface_name_by_route(self):
        self.log("[네트워크] 라우팅 테이블(route print) 방식으로 인터페이스를 검색합니다.")
        route_output = self.run_command(['route', 'print', '0.0.0.0'], encoding='cp949')
        if not route_output:
            self.log("[네트워크] 오류: 'route print' 명령어 실행에 실패했습니다.")
            return None

        # 1. 기본 경로(Default Route)의 IP 주소 찾기
        match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)", route_output, re.MULTILINE)
        if not match:
            self.log("[네트워크] 오류: 라우팅 테이블에서 기본 경로(0.0.0.0)를 찾을 수 없습니다.")
            return None
        interface_ip = match.group(1)
        self.log(f"[네트워크] 라우팅 테이블에서 찾은 활성 IP: {interface_ip}")

        # 2. ipconfig 결과에서 해당 IP를 사용하는 어댑터 이름 찾기
        ipconfig_output = self.run_command(['ipconfig'], encoding='cp949')
        if not ipconfig_output:
            self.log("[네트워크] 오류: 'ipconfig' 명령어 실행에 실패했습니다.")
            return None

        lines = ipconfig_output.splitlines()
        for i, line in enumerate(lines):
            if interface_ip in line and ("IPv4" in line or "IP Address" in line):
                self.log(f"[네트워크] ipconfig에서 IP 주소 '{interface_ip}'를 찾았습니다.")
                # IP 주소를 찾았으면 위로 올라가면서 어댑터 이름을 찾음
                for j in range(i, -1, -1):
                    if "어댑터" in lines[j] or "adapter" in lines[j]:
                        adapter_name = lines[j].split(":")[0].strip()
                        self.log(f"[네트워크] 최종 활성 인터페이스 발견: {adapter_name}")
                        return adapter_name
        
        self.log("[네트워크] 오류: ipconfig 결과에서 해당 IP를 사용하는 어댑터를 찾지 못했습니다.")
        return None

    def backup_current_settings(self):
        self.interface_name = self.get_active_interface_name_by_route()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.\n하단 로그를 확인해주세요.")
            return

        self.log(f"[네트워크] '{self.interface_name}'의 상세 정보를 netsh로 가져옵니다.")
        output = self.run_command(['netsh', 'interface', 'ipv4', 'show', 'config', f'name={self.interface_name}'], encoding='cp949')
        if not output:
            messagebox.showerror("오류", "네트워크 상세 정보를 가져오지 못했습니다.")
            return

        # 상세 정보 파싱 및 GUI/파일 저장 로직
        try:
            settings = {}
            settings['dhcp_enabled'] = "아니요" not in (re.search(r"DHCP 사용\s*:\s*(.+)", output) or ['',''])[1]
            settings['ip'] = (re.search(r"IP 주소\s*:\s*([0-9.]+)", output) or ['',''])[1]
            settings['subnet'] = (re.search(r"서브넷 마스크\s*:\s*([0-9.]+)", output) or ['',''])[1]
            settings['gateway'] = (re.search(r"기본 게이트웨이\s*:\s*([0-9.]+)", output) or ['',''])[1]
            settings['dns'] = re.findall(r"DNS 서버.*:\s*([0-9.]+)", output)

            self.original_settings = settings
            self.ip_var.set(settings.get('ip') or 'N/A')
            self.subnet_var.set(settings.get('subnet') or 'N/A')
            self.gateway_var.set(settings.get('gateway') or 'N/A')
            self.dns_var.set(", ".join(settings.get('dns', [])) or 'N/A')

            with open("backup_settings.txt", "w", encoding="utf-8") as f:
                f.write(f"# {self.interface_name} 설정 백업\n")
                for key, value in settings.items(): f.write(f"{key}={value}\n")
            self.log("[네트워크] `backup_settings.txt` 파일에 현재 설정을 저장했습니다.")
            self.btn_restore.config(state=tk.NORMAL)
            messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")
        except Exception as e:
            self.log(f"[네트워크] 가져온 정보 분석 중 오류: {e}")
            messagebox.showerror("파싱 오류", "가져온 정보를 분석하는 중 오류가 발생했습니다.")

    def restore_original_settings(self):
        # 복원 로직...
        pass

    # === 2. 윈도우 탭 관련 기능들 ===
    def create_windows_widgets(self):
        # UI 생성 부분...
        win_frame = ttk.LabelFrame(self.windows_tab, text=" 윈도우 정품 키 관리 ")
        win_frame.pack(fill=tk.X, padx=10, pady=10)
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        ttk.Label(win_frame, text="현재 키 (일부):").pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Label(win_frame, textvariable=self.win_key_var, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(self.windows_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow).pack(fill=tk.X, padx=10, pady=10)
        self.log("[윈도우] '정품 인증 시작' 버튼을 눌러 진행하세요.")
    
    def run_windows_activation_flow(self):
        # ... (이전과 동일) ...
        config_path = 'windows_key.ini'; config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            self.log(f"[윈도우] '{config_path}' 파일이 없어 새로 생성합니다.")
            config['Settings'] = {'ProductKey': 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'}
            with open(config_path, 'w', encoding='utf-8') as f: config.write(f)
        config.read(config_path, encoding='utf-8')
        stored_key = config['Settings'].get('ProductKey', '')
        partial_key = self.get_win_partial_key()
        self.win_key_var.set(partial_key)
        prompt_text = f"현재 적용된 키(일부): {partial_key}\n\n아래에 새로 적용할 윈도우 제품 키를 입력하세요."
        new_key = simpledialog.askstring("윈도우 제품 키 입력", prompt_text, initialvalue=stored_key)
        if new_key:
            pass # 키 적용 로직...

    # === 이 부분이 인코딩 문제를 수정한 '윈도우 키 확인' 방식입니다 ===
    def get_win_partial_key(self):
        self.log("[윈도우] 현재 제품 키 정보를 가져옵니다 (slmgr)...")
        # 윈도우 명령어의 한글 깨짐 방지를 위해 'cp949' 인코딩 사용
        output = self.run_command(['cscript', '//Nologo', 'C:\\Windows\\System32\\slmgr.vbs', '/dli'], encoding='cp949')
        
        if output:
            self.log(f"--- slmgr.vbs 실행 결과 (raw) ---\n{output}\n---------------------------------")
            for line in output.splitlines():
                if "부분 제품 키:" in line or "Partial Product Key:" in line:
                    key = line.split(":")[-1].strip()
                    self.log(f"[윈도우] 현재 키(일부) 찾음: {key}")
                    return key
            self.log("[윈도우] 오류: 실행 결과에서 '부분 제품 키' 문자열을 찾지 못했습니다.")
            return "확인 불가 (로그 확인)"
        else:
            self.log("[윈도우] 오류: slmgr.vbs 명령어 실행에 실패했거나 결과가 없습니다.")
            return "실행 실패 (로그 확인)"

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()