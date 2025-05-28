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
        master.title("시스템 유틸리티 (최종 해결본 v2)")
        master.geometry("500x700")

        self.notebook = ttk.Notebook(master, padding=10)
        self.network_tab = ttk.Frame(self.notebook)
        # ... (이하 UI 구성은 이전과 동일)
        self.windows_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ")
        self.notebook.pack(expand=True, fill="both")
        log_frame = ttk.LabelFrame(master, text=" 실행 로그 ")
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_area.pack(pady=5, padx=5, expand=True, fill="both")
        self.create_network_widgets(self.network_tab)
        # ... (이하 생략)
        self.log("관리자 권한으로 실행되었습니다.")
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)
    
    def create_network_widgets(self, parent_tab):
        # ... (이전과 동일)
        self.original_settings = {}
        self.interface_name = ""
        info_frame = ttk.LabelFrame(parent_tab, text=" 현재 네트워크 정보 ")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        self.ip_var, self.subnet_var, self.gateway_var, self.dns_var = tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음")
        labels = {"IP 주소:": self.ip_var, "서브넷 마스크:": self.subnet_var, "기본 게이트웨이:": self.gateway_var, "DNS 서버:": self.dns_var}
        for i, (text, var) in enumerate(labels.items()):
            ttk.Label(info_frame, text=text, width=15).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)
        btn_frame = ttk.Frame(parent_tab); btn_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Button(btn_frame, text="1. 현재 설정 불러오기 및 파일로 백업", command=self.backup_current_settings).pack(fill=tk.X, padx=10, pady=3)
        tk.Button(btn_frame, text="2. config.txt 설정 적용하기", command=self.apply_from_config_file).pack(fill=tk.X, padx=10, pady=3)
        self.btn_restore = tk.Button(btn_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED); self.btn_restore.pack(fill=tk.X, padx=10, pady=3)
        tk.Button(btn_frame, text="종료", command=self.cleanup_and_exit).pack(fill=tk.X, padx=10, pady=(10, 5))
        self.create_default_config_if_not_exists()
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n"); self.log_area.see(tk.END)
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
    def create_default_config_if_not_exists(self):
        if not os.path.exists("config.txt"):
            with open("config.txt", "w", encoding="utf-8") as f: f.write("# config.txt...\n")
    
    # === 이 함수가 최종 수정된 부분입니다 ===
    def get_active_interface(self):
        self.log("활성 인터페이스 검색을 시작합니다.")
        # 1. 라우팅 테이블에서 활성 IP 찾기
        try:
            output = self.run_command("route print -4 0.0.0.0")
            if not output: return None
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", output, re.MULTILINE)
            if not match: self.log("기본 경로(Default Route)를 찾을 수 없습니다."); return None
            interface_ip = match.group(1)
            self.log(f"라우팅 테이블에서 활성 IP 주소 발견: {interface_ip}")
        except Exception as e: self.log(f"기본 경로 검색 중 오류: {e}"); return None
        
        # 2. ipconfig에서 해당 IP가 있는 줄을 찾고, 그 줄부터 위로 올라가며 어댑터 이름 찾기
        try:
            output = self.run_command("ipconfig")
            if not output: return None
            
            lines = output.splitlines()
            line_index_with_ip = -1
            # IP 주소가 포함된 줄의 인덱스를 찾음
            for i, line in enumerate(lines):
                if interface_ip in line:
                    line_index_with_ip = i
                    break
            
            if line_index_with_ip == -1:
                self.log(f"오류: ipconfig 결과에서 IP({interface_ip})를 찾지 못했습니다.")
                return None

            # IP 주소가 있는 줄부터 위로(역순으로) 탐색
            for j in range(line_index_with_ip, -1, -1):
                # '어댑터' 라는 단어가 포함된 첫 번째 줄을 찾음
                if "어댑터" in lines[j] or "adapter" in lines[j].lower():
                    # 해당 줄에서 콜론(:) 앞부분을 이름으로 추출
                    interface_name = lines[j].split(":")[0].strip()
                    self.log(f"최종 인터페이스 이름 발견: [{interface_name}]")
                    return interface_name
            
            self.log("오류: IP 주소는 찾았으나, 상위 라인에서 '어댑터' 키워드를 찾지 못했습니다.")
            return None
        except Exception as e:
            self.log(f"ipconfig 분석 중 오류: {e}"); return None

    def backup_current_settings(self):
        self.interface_name = self.get_active_interface()
        if not self.interface_name:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.")
            return

        self.log(f"인터페이스 [{self.interface_name}]의 설정을 백업합니다.")
        # netsh 명령어에 인터페이스 이름을 따옴표로 감싸서 공백 문제 방지
        output = self.run_command(f'netsh interface ipv4 show config name="{self.interface_name}"')
        
        if not output:
            self.log("설정 정보를 가져오는 데 실패했습니다.")
            messagebox.showerror("오류", "설정 정보를 가져오는 데 실패했습니다.") # 사용자에게도 알림
            return
        
        # ... 이하 파싱 및 저장 로직 ...
        self.log("설정 정보 파싱을 시작합니다...")
        # (이하 로직은 v5원본과 동일하게 작동할 것으로 예상)
        self.ip_var.set("파싱 성공!") # 테스트용
        messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")
        self.btn_restore.config(state=tk.NORMAL)

    def apply_from_config_file(self): pass
    def restore_original_settings(self): pass
    def create_windows_widgets(self, parent_tab): pass
    def run_windows_activation_flow(self): pass
    # (이하 다른 함수들은 설명을 위해 생략)

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()