import os
import sys
import subprocess
import json
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

class SystemUtilityApp:
    def __init__(self, master):
        self.master = master
        master.title("시스템 유틸리티 (최종 안정화 버전)")
        master.geometry("500x700")

        # === 파일 경로 문제 해결 로직 ===
        # 스크립트가 실행되는 위치를 기준으로 파일 경로를 절대적으로 지정
        # 이렇게 하면 C:\Windows\System32 등에서 실행해도 권한 오류가 발생하지 않음
        try:
            # .py, .pyw로 실행될 때
            self.script_dir = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            # .exe로 변환되었을 때
            self.script_dir = os.path.dirname(sys.executable)

        self.network_config_path = os.path.join(self.script_dir, "config.txt")
        self.network_backup_path = os.path.join(self.script_dir, "backup_settings.json") # 백업 포맷 변경
        self.windows_config_path = os.path.join(self.script_dir, "windows_key.ini")
        # ================================

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
        self.log("안정성을 위해 모든 기능을 PowerShell 기반으로 구성했습니다.")
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    def log(self, message):
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n"); self.log_area.see(tk.END)
    
    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?\n(백업 파일은 삭제되지 않습니다)"):
            self.master.destroy()
    
    def run_ps_command(self, command):
        full_command = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", command]
        try:
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(full_command, check=True, capture_output=True, text=True, encoding='utf-8', startupinfo=startupinfo)
            return result.stdout.strip() or result.stderr.strip()
        except subprocess.CalledProcessError as e:
            self.log(f"PowerShell 오류: {e.stderr.strip() or e.stdout.strip()}"); return None

    # === 1. 네트워크 탭 (PowerShell 기반) ===
    def create_network_widgets(self, parent_tab):
        self.active_interface_info = {}
        info_frame = ttk.LabelFrame(parent_tab, text=" 현재 네트워크 정보 "); info_frame.pack(fill=tk.X, padx=10, pady=5)
        self.ip_var, self.subnet_var, self.gateway_var, self.dns_var = tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음"), tk.StringVar(value="정보 없음")
        labels = {"IP 주소:": self.ip_var, "서브넷 마스크:": self.subnet_var, "기본 게이트웨이:": self.gateway_var, "DNS 서버:": self.dns_var}
        for i, (text, var) in enumerate(labels.items()):
            ttk.Label(info_frame, text=text, width=15).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(info_frame, textvariable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)
        btn_frame = ttk.Frame(parent_tab); btn_frame.pack(fill=tk.X, padx=10, pady=10)
        tk.Button(btn_frame, text="1. 현재 설정 불러오기 및 백업", command=self.get_and_backup_settings).pack(fill=tk.X, padx=10, pady=3)
        tk.Button(btn_frame, text="2. config.txt 설정 적용하기", command=self.apply_settings_from_config).pack(fill=tk.X, padx=10, pady=3)
        self.btn_restore = tk.Button(btn_frame, text="3. 원래 설정으로 복원", command=self.restore_original_settings, state=tk.DISABLED); self.btn_restore.pack(fill=tk.X, padx=10, pady=3)
        tk.Button(btn_frame, text="종료", command=self.cleanup_and_exit).pack(fill=tk.X, padx=10, pady=(10, 5))
        self.create_default_config_if_not_exists()

    def create_default_config_if_not_exists(self):
        if not os.path.exists(self.network_config_path):
            with open(self.network_config_path, "w", encoding="utf-8") as f:
                f.write("# 서브넷은 Prefix 길이로 입력하세요 (예: 255.255.255.0 -> 24)\n# dns는 콤마(,)로 여러 개 입력 가능\n\n#ip=192.168.0.100\n#subnet_prefix=24\n#gateway=192.168.0.1\n#dns=8.8.8.8,8.8.4.4\n")
            self.log(f"`{self.network_config_path}` 파일 생성")

    def prefix_to_subnet(self, prefix_length):
        if not isinstance(prefix_length, int): return "N/A"
        bits = '1' * prefix_length + '0' * (32 - prefix_length)
        return ".".join([str(int(bits[i:i+8], 2)) for i in range(0, 32, 8)])

    def get_and_backup_settings(self):
        self.log("PowerShell로 활성 네트워크 정보를 가져옵니다...")
        ps_command = "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1 | ConvertTo-Json -Depth 3"
        json_output = self.run_ps_command(ps_command)
        if not json_output: messagebox.showerror("오류", "활성 네트워크 정보를 가져올 수 없습니다."); return

        try:
            data = json.loads(json_output)
            self.active_interface_info = {
                'if_index': data.get('InterfaceIndex'),
                'ip': data.get('IPv4Address', [{}])[0].get('IPAddress'),
                'prefix_length': data.get('IPv4Address', [{}])[0].get('PrefixLength'),
                'gateway': data.get('IPv4DefaultGateway', {}).get('NextHop'),
                'dns': (data.get('DNSServer', [{}])[0].get('ServerAddresses') or [])
            }
            if not all([self.active_interface_info['if_index'], self.active_interface_info['ip']]):
                messagebox.showerror("오류", "핵심 정보(인덱스, IP)를 찾지 못했습니다."); return
            
            self.log(f"인터페이스: {data.get('InterfaceAlias')} (인덱스: {self.active_interface_info['if_index']})")
            self.ip_var.set(self.active_interface_info['ip'])
            self.subnet_var.set(self.prefix_to_subnet(self.active_interface_info['prefix_length']))
            self.gateway_var.set(self.active_interface_info.get('gateway', 'N/A'))
            self.dns_var.set(", ".join(self.active_interface_info['dns']) if self.active_interface_info['dns'] else 'N/A')
            
            with open(self.network_backup_path, "w", encoding='utf-8') as f:
                json.dump(self.active_interface_info, f, ensure_ascii=False, indent=4)
            self.log(f"설정 백업 완료: {self.network_backup_path}")

            self.btn_restore.config(state=tk.NORMAL)
            messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 불러오고 백업했습니다.")
        except (json.JSONDecodeError, IndexError, KeyError) as e:
            self.log(f"정보 분석 중 오류: {e}"); messagebox.showerror("파싱 오류", f"가져온 정보를 분석하는 중 오류가 발생했습니다.\n\n{e}")

    def apply_settings_from_config(self):
        if not self.active_interface_info.get('if_index'): messagebox.showwarning("경고", "먼저 '1. 현재 설정 불러오기'를 실행하세요."); return
        try:
            with open(self.network_config_path, "r", encoding="utf-8") as f:
                config = dict(line.strip().split('=', 1) for line in f if '=' in line and not line.strip().startswith('#'))
        except FileNotFoundError: messagebox.showerror("오류", f"`{os.path.basename(self.network_config_path)}` 파일을 찾을 수 없습니다."); return

        ip=config.get('ip'); prefix=config.get('subnet_prefix'); gateway=config.get('gateway'); dns=config.get('dns')
        if not all([ip, prefix, gateway, dns]): messagebox.showerror("설정 오류", "`config.txt`의 모든 항목을 확인하세요."); return

        if_index = self.active_interface_info['if_index']
        self.log(f"인터페이스 {if_index}에 설정 적용을 시작합니다..."); dns_str = ",".join([f"'{d.strip()}'" for d in dns.split(',')])
        
        self.run_ps_command(f"Remove-NetIPAddress -InterfaceIndex {if_index} -Confirm:$false; "
                            f"New-NetIPAddress -InterfaceIndex {if_index} -IPAddress {ip} -PrefixLength {prefix} -DefaultGateway {gateway}; "
                            f"Set-DnsClientServerAddress -InterfaceIndex {if_index} -ServerAddresses ({dns_str})")

        self.log("설정 적용 완료. 2초 후 정보를 새로고침합니다.")
        self.master.after(2000, self.get_and_backup_settings)
        messagebox.showinfo("성공", "파일의 설정으로 네트워크 정보를 변경했습니다.")

    def restore_original_settings(self):
        if not os.path.exists(self.network_backup_path): messagebox.showerror("오류", "복원할 백업 파일이 없습니다."); return
        with open(self.network_backup_path, "r", encoding='utf-8') as f: info = json.load(f)
        
        if_index=info.get('if_index'); ip=info.get('ip'); prefix=info.get('prefix_length'); gateway=info.get('gateway'); dns=info.get('dns')
        self.log(f"인터페이스 {if_index}의 설정을 백업된 상태로 복원합니다...")
        dns_str = ",".join([f"'{d.strip()}'" for d in dns]) if dns else ""
        
        ps_commands = f"Remove-NetIPAddress -InterfaceIndex {if_index} -Confirm:$false; "
        ps_commands += f"New-NetIPAddress -InterfaceIndex {if_index} -IPAddress {ip} -PrefixLength {prefix} "
        if gateway: ps_commands += f"-DefaultGateway {gateway}; "
        else: ps_commands += "; "
        if dns_str: ps_commands += f"Set-DnsClientServerAddress -InterfaceIndex {if_index} -ServerAddresses ({dns_str})"
        else: ps_commands += f"Set-DnsClientServerAddress -InterfaceIndex {if_index} -ResetServerAddresses"
        
        self.run_ps_command(ps_commands)
        self.log("복원 완료. 2초 후 정보를 새로고침합니다.")
        self.master.after(2000, self.get_and_backup_settings)
        messagebox.showinfo("성공", "원래의 네트워크 설정으로 복원했습니다.")

    # === 2. 윈도우 인증 탭 (정상 작동하던 코드) ===
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
        if len(new_key.strip()) != 29: messagebox.showerror("입력 오류", "유효한 제품 키 형식이 아닙니다."); return
        if self.apply_windows_key(new_key.strip()):
            config['Settings']['ProductKey'] = new_key.strip()
            with open(self.windows_config_path, 'w', encoding='utf-8') as f: config.write(f)
            messagebox.showinfo("성공", "윈도우 제품 키가 성공적으로 적용 및 저장되었습니다.")
        else: messagebox.showerror("실패", "제품 키 적용에 실패했습니다. 로그를 확인해주세요.")

    def get_win_partial_key(self):
        output = self.run_ps_command("(Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey")
        if output: return f"OEM KEY: ...{output[-5:]}"
        output = self.run_ps_command("(Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -ne $null -and $_.LicenseStatus -eq 1})[0].PartialProductKey")
        if output: return f"Current Key: ...{output}"
        return "확인 불가"

    def apply_windows_key(self, key):
        self.log(f"[윈도우] 제품 키 설치 시도: {key[:5]}...")
        output = self.run_ps_command(f"cscript.exe C:\\Windows\\System32\\slmgr.vbs /ipk {key}")
        if "성공" not in output: self.log(f"키 설치 실패: {output}"); return False
        self.log(f"키 설치 성공. 온라인 인증 시도...")
        self.run_ps_command("cscript.exe C:\\Windows\\System32\\slmgr.vbs /ato")
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()