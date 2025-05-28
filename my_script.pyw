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

CMD_ENCODING = 'cp949' # netsh, ipconfig 등 한글 CMD 명령어 출력을 위한 인코딩

class SystemUtilityApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 유틸리티 (netsh 최종 수정본)")
        master.geometry("500x700")

        # 파일 경로 설정 (스크립트 실행 위치 기준)
        try:
            self.script_dir = os.path.dirname(os.path.abspath(__file__))
        except NameError: # PyInstaller 등으로 exe로 만들었을 경우
            self.script_dir = os.path.dirname(sys.executable)
        
        self.network_config_path = os.path.join(self.script_dir, "config.txt")
        self.network_backup_path = os.path.join(self.script_dir, "backup_settings.txt") # 백업 파일 이름 원복
        self.windows_config_path = os.path.join(self.script_dir, "windows_key.ini")


        self.notebook = ttk.Notebook(master, padding=10)
        self.network_tab = ttk.Frame(self.notebook)
        self.windows_tab = ttk.Frame(self.notebook) # 윈도우 탭 다시 생성
        
        self.notebook.add(self.network_tab, text="  네트워크 설정  ")
        self.notebook.add(self.windows_tab, text="  윈도우 정품 인증  ") # 탭 추가
        self.notebook.pack(expand=True, fill="both")

        log_frame = ttk.LabelFrame(master, text=" 실행 로그 ")
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_area.pack(pady=5, padx=5, expand=True, fill="both")
        
        self.create_network_widgets(self.network_tab)
        self.create_windows_widgets(self.windows_tab) # 윈도우 탭 UI 생성 호출
        
        self.log("관리자 권한으로 실행되었습니다.")
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    def log(self, message):
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n"); self.log_area.see(tk.END)
    
    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?\n(`backup_settings.txt` 파일이 삭제됩니다.)"):
            try:
                if os.path.exists(self.network_backup_path): # 경로 변수 사용
                    os.remove(self.network_backup_path)
                    self.log(f"'{os.path.basename(self.network_backup_path)}' 파일을 삭제했습니다.")
            except Exception as e:
                self.log(f"백업 파일 삭제 중 오류: {e}")
            self.master.destroy()

    def run_command(self, command, encoding=CMD_ENCODING): # 기본 인코딩을 CMD_ENCODING으로
        try:
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding=encoding, startupinfo=startupinfo)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.log(f"명령어 실행 오류: {e.stderr or e.stdout or '내용 없음'}"); return None
        except FileNotFoundError: self.log("명령어를 찾을 수 없습니다."); return None

    # === 1. 네트워크 탭 ===
    def create_network_widgets(self, parent_tab):
        self.original_settings = {}
        self.interface_name_for_netsh = "" # netsh용으로 찾은 이름

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
        tk.Button(btn_frame, text="종료 (백업 파일 삭제)", command=self.cleanup_and_exit, bg="#FFDDDD").pack(fill=tk.X, padx=10, pady=(10, 5))
        self.create_default_config_if_not_exists()
        self.log("[네트워크] 1번 버튼을 눌러 현재 설정을 불러오세요.")

    def create_default_config_if_not_exists(self):
        if not os.path.exists(self.network_config_path):
            self.log(f"`{os.path.basename(self.network_config_path)}` 파일이 없어 새로 생성합니다.")
            with open(self.network_config_path, "w", encoding="utf-8") as f:
                f.write("# 이 파일에 변경할 네트워크 설정을 입력하세요.\n# 각 줄의 맨 앞에 있는 #을 지우고 값을 수정한 뒤 저장하세요.\n\n#ip=192.168.0.100\n#subnet=255.255.255.0\n#gateway=192.168.0.1\n#dns1=8.8.8.8\n#dns2=8.8.4.4\n")
            self.log(f"`{os.path.basename(self.network_config_path)}`에 예시 설정을 작성했습니다.")
    
    def get_netsh_compatible_interface_name(self):
        self.log("[네트워크] 활성 인터페이스의 'netsh용 이름'을 검색합니다.")
        try:
            # 1. route print로 활성 IP 찾기
            route_output = self.run_command("route print -4 0.0.0.0")
            if not route_output: self.log("[네트워크] 오류: 'route print' 결과 없음"); return None
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+[\d\.]+\s+([\d\.]+)\s+.*$", route_output, re.MULTILINE)
            if not match: self.log("[네트워크] 오류: 기본 경로 IP를 찾지 못했습니다."); return None
            interface_ip = match.group(1)
            self.log(f"[네트워크] 활성 IP 발견: {interface_ip}")

            # 2. ipconfig /all 로 인덱스 찾기
            ipconfig_output = self.run_command("ipconfig /all")
            if not ipconfig_output: self.log("[네트워크] 오류: 'ipconfig /all' 결과 없음"); return None
            
            # 활성 IP를 포함하는 블록에서 링크-로컬 IPv6 주소 줄 찾기
            current_block = []
            target_block_found = False
            if_index = None
            for line in ipconfig_output.splitlines():
                if interface_ip in line: # IP 주소가 포함된 블록 시작으로 간주
                    target_block_found = True
                if target_block_found:
                    current_block.append(line)
                    ipv6_match = re.search(r"링크-로컬 IPv6 주소[ .]+: .+(%\d+)", line)
                    if ipv6_match:
                        if_index = ipv6_match.group(1).replace('%','')
                        self.log(f"[네트워크] 인터페이스 인덱스 발견: {if_index}")
                        break # 인덱스 찾았으면 해당 블록 탐색 종료
                    if line.strip() == "" and current_block: # 블록 끝
                        break # IP는 찾았으나 인덱스를 못찾은 경우
            
            if not if_index:
                 self.log("[네트워크] 오류: ipconfig에서 인터페이스 인덱스를 찾지 못했습니다."); return None

            # 3. netsh로 인덱스에 해당하는 '진짜 이름' 찾기
            netsh_output = self.run_command("netsh interface ipv4 show interfaces")
            if not netsh_output: self.log("[네트워크] 오류: 'netsh show interfaces' 결과 없음"); return None
            
            for line in netsh_output.splitlines():
                if line.strip().startswith(if_index):
                    parts = re.split(r'\s{2,}', line.strip()) # 2개 이상 공백으로 분리
                    if len(parts) >= 4: # Idx, Met, MTU, Name 최소 4개 컬럼
                        netsh_name = parts[-1] # 이름이 마지막 컬럼이라고 가정
                        self.log(f"[네트워크] Netsh용 이름 최종 발견: [{netsh_name}]")
                        return netsh_name
            self.log("[네트워크] 오류: netsh 인터페이스 목록에서 해당 인덱스의 이름을 찾지 못했습니다."); return None
        except Exception as e:
            self.log(f"[네트워크] 'netsh용 이름' 검색 중 예외 발생: {e}"); return None

    def backup_current_settings(self):
        self.interface_name_for_netsh = self.get_netsh_compatible_interface_name()
        if not self.interface_name_for_netsh:
            messagebox.showerror("오류", "활성화된 네트워크 인터페이스를 찾을 수 없습니다.\n하단 로그를 확인해주세요."); return

        self.log(f"인터페이스 [{self.interface_name_for_netsh}]의 설정을 백업합니다.")
        output = self.run_command(f'netsh interface ipv4 show config name="{self.interface_name_for_netsh}"')
        if not output: messagebox.showerror("오류", "설정 정보를 가져오는 데 실패했습니다.\n하단 로그를 확인해주세요."); return
        
        self.log(f"--- netsh config 결과 ---\n{output}\n-------------------------") # 전체 결과 로깅
        settings = {}
        
        ip_match = re.search(r"(?:IP 주소|IP Address)[\s.]*:\s*([0-9.]+)", output, re.IGNORECASE)
        # === 서브넷 마스크 추출 로직 (사용자 데이터 기반) ===
        subnet_val = None
        subnet_prefix_match = re.search(r"(?:서브넷 접두사|Subnet Prefix)[\s.]*:.*\(마스크\s+([0-9.]+)\)", output, re.IGNORECASE)
        if subnet_prefix_match:
            subnet_val = subnet_prefix_match.group(1).strip()
            self.log(f"서브넷 마스크 (접두사 방식): {subnet_val}")
        else:
            # 이전의 일반적인 '서브넷 마스크:' 패턴도 시도
            subnet_mask_match = re.search(r"(?:서브넷 마스크|Subnet Mask)[\s.]*:\s*([0-9.]+)", output, re.IGNORECASE)
            if subnet_mask_match:
                subnet_val = subnet_mask_match.group(1).strip()
                self.log(f"서브넷 마스크 (일반 방식): {subnet_val}")
            else:
                self.log("서브넷 마스크를 찾지 못했습니다.")
        # ===============================================

        gateway_match = re.search(r"(?:기본 게이트웨이|Default Gateway)[\s.]*:\s*([0-9.]+)", output, re.IGNORECASE)
        # DNS는 여러 줄에 걸쳐 나올 수 있으므로 findall 사용
        dns_matches = re.findall(r"(?:정적으로 구성된 DNS 서버|DNS Servers Statically Configured|DNS 서버)[\s.]*:\s*([0-9.]+)", output, re.IGNORECASE)
        
        dhcp_match = re.search(r"(?:DHCP 사용|DHCP Enabled)[\s.]*:\s*(.+)", output, re.IGNORECASE)
        
        settings['ip'] = ip_match.group(1).strip() if ip_match else None
        settings['subnet'] = subnet_val
        settings['gateway'] = gateway_match.group(1).strip() if gateway_match else None
        settings['dns'] = [dns.strip() for dns in dns_matches] if dns_matches else []
        settings['dhcp_enabled'] = dhcp_match and dhcp_match.group(1).strip().lower() in ['yes', '예']

        self.original_settings = settings
        self.log(f"파싱된 설정: IP={settings['ip']}, 서브넷={settings['subnet']}, 게이트웨이={settings['gateway']}, DNS={settings['dns']}")
        
        self.ip_var.set(settings.get('ip') or 'N/A'); self.subnet_var.set(settings.get('subnet') or 'N/A')
        self.gateway_var.set(settings.get('gateway') or 'N/A'); self.dns_var.set(", ".join(settings['dns']) if settings['dns'] else 'N/A')
        
        if not all([settings.get('ip'), settings.get('subnet')]):
             self.log(f"오류: IP({settings.get('ip')}) 또는 서브넷({settings.get('subnet')})을 최종적으로 읽지 못했습니다."); 
             messagebox.showerror("파싱 오류", "IP 또는 서브넷 마스크를 읽어오지 못했습니다."); return
        
        try:
            with open(self.network_backup_path, "w", encoding="utf-8") as f:
                f.write(f"# {self.interface_name_for_netsh} 설정 백업 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n")
                f.write(f"dhcp_enabled={settings.get('dhcp_enabled', False)}\n")
                f.write(f"ip={settings.get('ip', 'N/A')}\n"); f.write(f"subnet={settings.get('subnet', 'N/A')}\n")
                f.write(f"gateway={settings.get('gateway', 'N/A')}\n")
                dns_list = settings.get('dns', [])
                if dns_list:
                    for i, dns_server in enumerate(dns_list, 1): f.write(f"dns{i}={dns_server}\n")
                else: f.write("dns1=N/A\n")
            self.log(f"`{os.path.basename(self.network_backup_path)}` 파일에 현재 설정을 저장했습니다.")
        except Exception as e: self.log(f"백업 파일 저장 중 오류: {e}")
        
        self.btn_restore.config(state=tk.NORMAL)
        messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 백업했습니다.")
    
    def apply_from_config_file(self):
        if not self.interface_name_for_netsh: messagebox.showwarning("경고", "먼저 '1. 현재 설정 불러오기' 버튼을 눌러주세요."); return
        try:
            with open(self.network_config_path, "r", encoding="utf-8") as f:
                config = dict(line.strip().split('=', 1) for line in f if '=' in line and not line.strip().startswith('#'))
        except FileNotFoundError: messagebox.showerror("파일 없음", f"`{os.path.basename(self.network_config_path)}` 파일을 찾을 수 없습니다."); return
        
        ip=config.get("ip"); subnet=config.get("subnet"); gateway=config.get("gateway"); dns1=config.get("dns1"); dns2=config.get("dns2")
        if not all([ip, subnet, gateway, dns1]): messagebox.showerror("설정 오류", "config.txt의 필수 항목을 확인하세요."); return
        
        self.log(f"--- [{self.interface_name_for_netsh}] 파일에서 설정 적용 시작 ---")
        self.run_command(f'netsh interface ipv4 set address name="{self.interface_name_for_netsh}" static {ip} {subnet} {gateway}')
        self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name_for_netsh}" static {dns1}')
        if dns2: self.run_command(f'netsh interface ipv4 add dns name="{self.interface_name_for_netsh}" {dns2} index=2')
        self.log("--- 설정 적용 완료 ---"); messagebox.showinfo("성공", "파일의 설정으로 네트워크 정보를 변경했습니다.")

    def restore_original_settings(self):
        if not self.original_settings: messagebox.showerror("오류", "백업된 설정이 없습니다."); return
        if not self.interface_name_for_netsh: messagebox.showerror("오류", "활성 인터페이스 이름이 없습니다."); return

        self.log(f"--- [{self.interface_name_for_netsh}] 원래 설정으로 복원 시작 ---")
        if self.original_settings.get('dhcp_enabled'):
            self.log("DHCP(자동) 설정으로 복원합니다.")
            self.run_command(f'netsh interface ipv4 set address name="{self.interface_name_for_netsh}" dhcp')
            self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name_for_netsh}" dhcp')
        else:
            self.log("백업된 고정 IP 설정으로 복원합니다.")
            ip = self.original_settings.get('ip'); subnet = self.original_settings.get('subnet'); gateway = self.original_settings.get('gateway')
            self.run_command(f'netsh interface ipv4 set address name="{self.interface_name_for_netsh}" static {ip} {subnet} {gateway}')
            dns_servers = self.original_settings.get('dns', [])
            if dns_servers:
                self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name_for_netsh}" static {dns_servers[0]}')
                if len(dns_servers) > 1:
                    for i, dns_server in enumerate(dns_servers[1:], start=2):
                        self.run_command(f'netsh interface ipv4 add dns name="{self.interface_name_for_netsh}" {dns_server} index={i}')
            else: self.run_command(f'netsh interface ipv4 set dns name="{self.interface_name_for_netsh}" dhcp')
        self.log("--- 복원 완료 ---"); messagebox.showinfo("성공", "원래의 네트워크 설정으로 복원했습니다.")

    # === 2. 윈도우 인증 탭 ===
    def create_windows_widgets(self, parent_tab):
        win_frame = ttk.LabelFrame(parent_tab, text=" 윈도우 정품 키 관리 "); win_frame.pack(fill=tk.X, padx=10, pady=10, expand=True)
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        center_frame = ttk.Frame(win_frame); center_frame.pack(expand=True)
        ttk.Label(center_frame, text="현재 키 (일부):", font=('Malgun Gothic', 10)).pack(pady=5)
        ttk.Label(center_frame, textvariable=self.win_key_var, font=('Helvetica', 12, 'bold'), foreground="blue").pack(pady=5)
        ttk.Button(parent_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow).pack(fill=tk.X, padx=10, pady=20)

    def run_windows_activation_flow(self):
        config = configparser.ConfigParser()
        if not os.path.exists(self.windows_config_path):
            config['Settings'] = {'ProductKey': 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'}
            with open(self.windows_config_path, 'w', encoding='utf-8') as f: config.write(f)
        config.read(self.windows_config_path, encoding='utf-8')
        self.win_key_var.set(self.get_win_partial_key())
        new_key = simpledialog.askstring("윈도우 제품 키 입력", "새로 적용할 윈도우 제품 키를 입력하세요.", initialvalue=config['Settings'].get('ProductKey', ''))
        if not new_key: self.log("[윈도우] 키 입력이 취소되었습니다."); return
        if len(new_key.strip()) != 29 or new_key.strip().count('-') != 4 : messagebox.showerror("입력 오류", "유효한 제품 키 형식이 아닙니다."); return
        if self.apply_windows_key(new_key.strip()):
            config['Settings']['ProductKey'] = new_key.strip()
            with open(self.windows_config_path, 'w', encoding='utf-8') as f: config.write(f)
            messagebox.showinfo("성공", "윈도우 제품 키가 성공적으로 적용 및 저장되었습니다.")
        else: messagebox.showerror("실패", "제품 키 적용에 실패했습니다. 로그를 확인해주세요.")

    def get_win_partial_key(self):
        output = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /dli', encoding=CMD_ENCODING) # 인코딩 명시
        if output:
            for line in output.splitlines():
                if "부분 제품 키:" in line: return line.split(":")[-1].strip()
        return "확인 불가"

    def apply_windows_key(self, key):
        self.log(f"[윈도우] 제품 키 설치 시도: {key[:5]}...")
        ipk_output = self.run_command(f'cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ipk {key}')
        if ipk_output is None or "오류" in ipk_output or "Error" in ipk_output.lower() or "성공적으로" not in ipk_output: # '성공' 확인 강화
            self.log(f"[윈도우] 제품 키 설치 실패: {ipk_output}"); return False
        self.log(f"[윈도우] 제품 키 설치 결과: {ipk_output}")
        self.log("[윈도우] 온라인 정품 인증을 시도합니다...")
        ato_output = self.run_command('cscript //Nologo C:\\Windows\\System32\\slmgr.vbs /ato')
        if ato_output: self.log(f"[윈도우] 정품 인증 시도 결과: {ato_output}")
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()