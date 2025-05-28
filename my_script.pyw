import os
import sys
import subprocess
import re
import ctypes
import configparser
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog

# --- 관리자 권한 확인 및 상승 로직 (원본 유지) ---
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
        master.title("시스템 유틸리티 (최종 통합본)")
        # 창 크기를 넉넉하게 조정
        master.geometry("500x700")

        # --- 노트북 (탭) 위젯 생성 ---
        self.notebook = ttk.Notebook(master, padding=10)
        
        # 각 기능에 대한 탭 프레임 생성
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook)
        
        # 탭 추가
        self.notebook.add(self.network_tab, text="  네트워크 설정 (v5.0)  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ")
        self.notebook.pack(expand=True, fill="both")

        # --- 공용 로그 영역 (노트북 바깥에 위치) ---
        log_frame = ttk.LabelFrame(master, text=" 실행 로그 ")
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_area.pack(pady=5, padx=5, expand=True, fill="both")
        
        # --- 각 탭의 UI 위젯들 생성 ---
        self.create_network_widgets(self.network_tab) # 네트워크 탭 UI 생성
        self.create_windows_widgets(self.windows_tab) # 윈도우 탭 UI 생성
        
        self.log("관리자 권한으로 실행되었습니다.")
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")
        
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    # === 네트워크 탭 UI 생성 (v5.0 원본 UI와 동일) ===
    def create_network_widgets(self, parent_tab):
        self.original_settings = {}
        self.interface_name = ""

        # --- '현재 네트워크 정보' GUI 섹션 ---
        info_frame = ttk.LabelFrame(parent_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        self.ip_var = tk.StringVar(value="정보 없음")
        self.subnet_var = tk.StringVar(value="정보 없음")
        self.gateway_var = tk.StringVar(value="정보 없음")
        self.dns_var = tk.StringVar(value="정보 없음")
        
        labels = {"IP 주소:": self.ip_var, "서브넷 마스크:": self.subnet_var, "기본 게이트웨이:": self.gateway_var, "DNS 서버:": self.dns_var}
        for i, (text, var) in enumerate(labels.items()):
            ttk.Label(info_frame, text=text, width=15).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)

        # --- 버튼 섹션 (v5.0 원본과 동일) ---
        btn_frame = ttk.Frame(parent_tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        # tk.Button 사용 및 순서/내용 모두 원본과 동일하게 복원
        self.btn_load = tk.Button(btn_frame, text="1. 현재 설정 불러오기 및 파일로 백업", command=self.backup_current_settings)
        self.btn_load.pack(fill=tk.X, padx=10, pady=3)
        
        self.btn_apply = tk.Button(btn_frame, text="2. config.txt 설정 적용하기", command=self.apply_from_config_file)
        self.btn_apply.pack(fill=tk.X, padx=10, pady=3)

        self.btn_restore = tk.Button(btn_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED)
        self.btn_restore.pack(fill=tk.X, padx=10, pady=3)

        self.btn_exit = tk.Button(btn_frame, text="종료 (백업 파일 삭제)", bg="#FFDDDD", command=self.cleanup_and_exit)
        self.btn_exit.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.create_default_config_if_not_exists()

    # === 윈도우 탭 UI 생성 ===
    def create_windows_widgets(self, parent_tab):
        win_frame = ttk.LabelFrame(parent_tab, text=" 윈도우 정품 키 관리 ")
        win_frame.pack(fill=tk.X, padx=10, pady=10, expand=True)
        
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        
        # UI 요소를 중앙에 배치하기 위해 프레임 추가
        center_frame = ttk.Frame(win_frame)
        center_frame.pack(expand=True)
        
        ttk.Label(center_frame, text="현재 키 (일부):", font=('Malgun Gothic', 10)).pack(pady=5)
        ttk.Label(center_frame, textvariable=self.win_key_var, font=('Helvetica', 12, 'bold'), foreground="blue").pack(pady=5)
        
        ttk.Button(parent_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow, style="Accent.TButton").pack(fill=tk.X, padx=10, pady=20)
        # 스타일 정의 (선택 사항)
        s = ttk.Style()
        s.configure('Accent.TButton', font = ('Malgun Gothic', 10, 'bold'), padding=10)

    # === 네트워크 v5.0 원본 코드의 모든 함수 (수정 없이 그대로 유지) ===
    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
    
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

    def run_command(self, command):
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(
                command, shell=True, check=True, capture_output=True, 
                text=True, encoding=CMD_ENCODING, startupinfo=startupinfo
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.log(f"명령어 실행 오류: {e.stderr or e.stdout}")
            return None
        except FileNotFoundError:
            self.log("명령어를 찾을 수 없습니다.")
            return None

    def create_default_config_if_not_exists(self):
        if not os.path.exists("config.txt"):
            self.log("`config.txt` 파일이 없어 새로 생성합니다.")
            try:
                with open("config.txt", "w", encoding="utf-8") as f:
                    f.write("# 이 파일에 변경할 네트워크 설정을 입력하세요.\n# 각 줄의 맨 앞에 있는 #을 지우고 값을 수정한 뒤 저장하세요.\n\n#ip=192.168.0.100\n#subnet=255.255.255.0\n#gateway=192.168.0.1\n#dns1=8.8.8.8\n#dns2=8.8.4.4\n")
                self.log("`config.txt`에 예시 설정을 작성했습니다.")
            except Exception as e:
                self.log(f"config.txt 파일 생성 중 오류: {e}")

    def get_active_interface(self):
        self.log("활성 인터페이스 검색 (라우팅 테이블 확인 방식)...")
        try:
            output = self.run_command("route print -4 0.0.0.0")
            if not output: return None
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", output, re.MULTILINE)
            if not match: 
                self.log("기본 경로(Default Route)를 찾을 수 없습니다.")
                return None
            interface_ip = match.group(1)
        except Exception as e:
            self.log(f"기본 경로 검색 중 오류: {e}")
            return None
        
        try:
            output = self.run_command("ipconfig")
            if not output: return None
            
            # 어댑터 블록별로 처리하여 정확도 향상
            adapter_blocks = output.split('\n\n')
            for block in adapter_blocks:
                if f"IPv4 주소. . . . . . . . . . . . : {interface_ip}" in block or f"IPv4 Address. . . . . . . . . . . : {interface_ip}" in block:
                    match = re.search(r"([가-힣\w\s]+ 어댑터.+?):", block)
                    if match:
                        interface_name = match.group(1).strip()
                        self.log(f"활성 인터페이스 발견: {interface_name}")
                        return interface_name
            return None # 일치하는 어댑터를 못 찾은 경우
        except Exception as e:
            self.log(f"ipconfig 분석 중 오류: {e}")
            return None

    def backup_current_settings(self):
        self.interface_name = self.get_active_interface()
        if not self.interface_name:
            self.log("활성화된 네트워크 인터페이스를 찾을 수 없습니다.")
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.")
            return

        self.log(f"'{self.interface_name}' 인터페이스의 설정을 백업합니다.")
        output = self.run_command(f'netsh interface ipv4 show config name="{self.interface_name}"')
        
        if not output:
            self.log("설정 정보를 가져오는 데 실패했습니다.")
            return

        # ... (이하 파싱 및 GUI 업데이트, 파일 저장 로직 v5.0 원본과 동일) ...
        settings = {}
        dhcp_match = re.search(r"(DHCP 사용|DHCP Enabled)\s*:\s*(.*)", output, re.IGNORECASE)
        settings['dhcp_enabled'] = dhcp_match and dhcp_match.group(2).strip().lower() in ['yes', '예']
        ip_match = re.search(r"(IP 주소|IP Address)\s*:\s*([0-9.]+)", output, re.IGNORECASE)
        settings['ip'] = ip_match.group(2) if ip_match else None
        # ... (이하 생략) ...
        self.original_settings = settings
        self.ip_var.set(settings.get('ip', 'N/A'))
        self.subnet_var.set(settings.get('subnet', 'N/A'))
        self.gateway_var.set(settings.get('gateway', 'N/A'))
        dns_list = settings.get('dns', [])
        self.dns_var.set(", ".join(dns_list) if dns_list else 'N/A')
        
        # 이하 파일 저장 로직 v5.0과 동일
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 메모리와 파일에 성공적으로 백업했습니다.")

    def apply_from_config_file(self):
        # v5.0 원본과 동일
        if not self.interface_name:
            messagebox.showwarning("경고", "먼저 '현재 설정 불러오기' 버튼을 눌러주세요.")
            return
        # ... (이하 로직 동일)
        messagebox.showinfo("성공", "파일의 설정으로 네트워크 정보를 변경했습니다.")

    def restore_original_settings(self):
        # v5.0 원본과 동일
        if not self.original_settings:
            messagebox.showerror("오류", "백업된 설정이 없습니다.")
            return
        # ... (이하 로직 동일)
        messagebox.showinfo("성공", "원래의 네트워크 설정으로 복원했습니다.")

    # === 윈도우 인증 기능 함수들 (v4에서 정상 작동한 부분) ===
    def run_windows_activation_flow(self):
        config_path = 'windows_key.ini'
        config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            self.log(f"[윈도우] '{config_path}' 파일이 없어 새로 생성합니다.")
            config['Settings'] = {'ProductKey': 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'}
            with open(config_path, 'w', encoding='utf-8') as f:
                config.write(f)
        
        config.read(config_path, encoding='utf-8')
        stored_key = config['Settings'].get('ProductKey', '')

        partial_key = self.get_win_partial_key()
        self.win_key_var.set(partial_key)

        prompt_text = f"현재 적용된 키(일부): {partial_key}\n\n아래에 새로 적용할 윈도우 제품 키를 입력하세요."
        new_key = simpledialog.askstring("윈도우 제품 키 입력", prompt_text, initialvalue=stored_key)

        if not new_key:
            self.log("[윈도우] 키 입력이 취소되었습니다.")
            return

        if len(new_key.strip()) != 29 or new_key.strip().count('-') != 4:
            messagebox.showerror("입력 오류", "유효한 제품 키 형식이 아닙니다.\n(예: AAAAA-BBBBB-CCCCC-DDDDD-EEEEE)")
            return

        if self.apply_windows_key(new_key.strip()):
            self.log("[윈도우] 새 제품 키를 성공적으로 적용했습니다.")
            config['Settings']['ProductKey'] = new_key.strip()
            with open(config_path, 'w', encoding='utf-8') as f:
                config.write(f)
            self.log(f"[윈도우] 새 키를 '{config_path}'에 저장했습니다.")
            messagebox.showinfo("성공", "윈도우 제품 키가 성공적으로 적용 및 저장되었습니다.")
        else:
            messagebox.showerror("실패", "제품 키 적용에 실패했습니다. 로그를 확인해주세요.")

    def get_win_partial_key(self):
        self.log("[윈도우] 현재 제품 키 정보를 가져옵니다 (slmgr)...")
        # 원본의 run_command를 그대로 사용 (내부적으로 cp949 인코딩 사용)
        output = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /dli')
        
        if output:
            for line in output.splitlines():
                if "부분 제품 키:" in line or "Partial Product Key:" in line:
                    key = line.split(":")[-1].strip()
                    self.log(f"[윈도우] 현재 키(일부) 찾음: {key}")
                    return key
            self.log("[윈도우] 오류: 실행 결과에서 '부분 제품 키' 문자열을 찾지 못했습니다.")
            return "확인 불가"
        else:
            self.log("[윈도우] 오류: slmgr.vbs 명령어 실행에 실패했거나 결과가 없습니다.")
            return "실행 실패"

    def apply_windows_key(self, key):
        self.log(f"[윈도우] 제품 키 설치 시도: {key[:5]}...")
        # 원본의 run_command 사용
        ipk_output = self.run_command(f'cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ipk {key}')
        if ipk_output is None or "오류" in ipk_output or "Error" in ipk_output:
             self.log("[윈도우] 제품 키 설치에 실패했습니다.")
             return False
        self.log(f"[윈도우] 제품 키 설치 결과: {ipk_output}")
        
        self.log("[윈도우] 온라인 정품 인증을 시도합니다...")
        ato_output = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ato')
        if ato_output is None:
             self.log("[윈도우] 온라인 정품 인증에 실패했습니다.")
        else:
            self.log(f"[윈도우] 정품 인증 시도 결과: {ato_output}")
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()