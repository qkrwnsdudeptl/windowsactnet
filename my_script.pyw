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
        master.title("시스템 유틸리티 (PowerShell 최종 안정화)")
        master.geometry("500x700")

        try:
            self.script_dir = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            self.script_dir = os.path.dirname(sys.executable)

        self.network_config_path = os.path.join(self.script_dir, "config.txt")
        self.network_backup_path = os.path.join(self.script_dir, "backup_settings.json")
        self.windows_config_path = os.path.join(self.script_dir, "windows_key.ini")

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
        self.log("PowerShell 명령어 시간 제한(5초)을 적용했습니다.")
        self.master.protocol("WM_DELETE_WINDOW", self.cleanup_and_exit)

    def log(self, message):
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_area.see(tk.END)
    
    def cleanup_and_exit(self):
        if messagebox.askyesno("종료 확인", "프로그램을 종료하시겠습니까?"): self.master.destroy()
    
    # === 이 함수에 timeout 매개변수 추가 ===
    def run_ps_command(self, command, timeout=5): # 기본 타임아웃 5초
        full_command = ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive", "-Command", command]
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(full_command, check=True, capture_output=True, text=True, 
                                    encoding='utf-8', startupinfo=startupinfo, timeout=timeout) # timeout 적용
            output = result.stdout.strip()
            if not output and result.stderr.strip():
                if "Confirm" not in result.stderr and "Path" not in result.stderr :
                     self.log(f"PowerShell 정보(stderr): {result.stderr.strip()}")
            return output if output else result.stderr.strip()
        except subprocess.TimeoutExpired:
            self.log(f"PowerShell 오류: 명령어 실행 시간 초과 ({timeout}초). 명령어: {command[:100]}...")
            return f"PS_ERROR: Timeout ({timeout}s)"
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.strip() or e.stdout.strip() or f"명령 실행 실패 (코드: {e.returncode})"
            self.log(f"PowerShell 오류: {error_message}"); return f"PS_ERROR: {error_message}"
        except FileNotFoundError:
            self.log("PowerShell을 찾을 수 없습니다."); return "PS_ERROR: PowerShell not found."

    # === 1. 네트워크 탭 (PowerShell 기반) ===
    def create_network_widgets(self, parent_tab):
        self.active_interface_info = {}
        self.backup_settings_data = {}
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
        tk.Button(btn_frame, text="종료", command=self.cleanup_and_exit, bg="#FFDDDD").pack(fill=tk.X, padx=10, pady=(10, 5))
        self.create_default_config_if_not_exists()

    def create_default_config_if_not_exists(self):
        if not os.path.exists(self.network_config_path):
            with open(self.network_config_path, "w", encoding="utf-8") as f:
                f.write("# IP 주소를 입력하세요. (예: 192.168.0.100)\nip=\n\n"
                        "# 서브넷 마스크 길이를 숫자로 입력하세요. (예: 24는 255.255.255.0을 의미)\nsubnet_prefix=\n\n"
                        "# 기본 게이트웨이 주소를 입력하세요.\ngateway=\n\n"
                        "# DNS 서버 주소를 입력하세요. 여러 개일 경우 콤마(,)로 구분합니다.\ndns=\n")
            self.log(f"`{os.path.basename(self.network_config_path)}` 파일 생성")

    def prefix_to_subnet(self, prefix_length):
        if not isinstance(prefix_length, int) or not (0 <= prefix_length <= 32): return "N/A"
        try:
            mask_integer = (0xffffffff << (32 - prefix_length)) & 0xffffffff
            return f"{(mask_integer >> 24) & 0xff}.{(mask_integer >> 16) & 0xff}.{(mask_integer >> 8) & 0xff}.{mask_integer & 0xff}"
        except: return "N/A"

    # === 이 함수 내부의 PowerShell 명령어 실행 방식이 변경되었습니다 ===
    def get_and_backup_settings(self):
        self.log("PowerShell로 활성 네트워크 어댑터 인덱스를 가져옵니다...")
        ps_get_index_command = (
            "$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceType -eq 6 -or $_.InterfaceType -eq 71) } | Select-Object -First 1; "
            "if ($adapter) { $adapter.InterfaceIndex } else { Write-Host 'PS_ERROR: No suitable active adapter found' }"
        )
        if_index_output = self.run_ps_command(ps_get_index_command)

        if not if_index_output or if_index_output.startswith("PS_ERROR:"):
            messagebox.showerror("오류", f"활성 네트워크 어댑터 인덱스를 가져올 수 없습니다.\n로그: {if_index_output}"); self.log(f"어댑터 인덱스 가져오기 실패: {if_index_output}"); return
        
        try:
            if_index = int(if_index_output)
            self.log(f"활성 어댑터 인덱스 확인: {if_index}")
        except ValueError:
            messagebox.showerror("오류", f"유효하지 않은 어댑터 인덱스 값입니다: {if_index_output}"); self.log(f"어댑터 인덱스 값 오류: {if_index_output}"); return

        self.log(f"PowerShell로 인덱스 {if_index}의 상세 네트워크 정보를 가져옵니다...")
        ps_get_config_command = f"Get-NetIPConfiguration -InterfaceIndex {if_index} | Where-Object {{ $_.IPv4DefaultGateway -ne $null }} | Select-Object -First 1 | ConvertTo-Json -Depth 3"
        json_output = self.run_ps_command(ps_get_config_command)

        if not json_output or json_output.startswith("PS_ERROR:") or "Get-NetIPConfiguration" in json_output :
            messagebox.showerror("오류", f"상세 네트워크 정보를 가져올 수 없습니다.\n로그: {json_output[:200]}"); self.log(f"상세 정보 가져오기 실패: {json_output}"); return

        try:
            data = json.loads(json_output)
            ipv4_address_info_list = data.get('IPv4Address', [])
            ip_address, prefix_length = None, None
            if ipv4_address_info_list:
                preferred_ip_info = next((item for item in ipv4_address_info_list if item.get("AddressState") == "Preferred"), ipv4_address_info_list[0] if ipv4_address_info_list else None)
                if preferred_ip_info:
                    ip_address = preferred_ip_info.get('IPAddress'); prefix_length = preferred_ip_info.get('PrefixLength')

            dns_server_info_list = data.get('DNSServer', [])
            dns_servers = []
            if dns_server_info_list:
                 dns_servers_from_obj = dns_server_info_list[0].get('ServerAddresses', [])
                 dns_servers = [dns_servers_from_obj] if isinstance(dns_servers_from_obj, str) else dns_servers_from_obj

            self.active_interface_info = {
                'InterfaceIndex': data.get('InterfaceIndex'), 'InterfaceAlias': data.get('InterfaceAlias', "N/A"),
                'IPAddress': ip_address, 'PrefixLength': prefix_length,
                'DefaultGateway': data.get('IPv4DefaultGateway', {}).get('NextHopAddress'),
                'DNSServerAddresses': dns_servers
            }
            info = self.active_interface_info
            if not all([info['InterfaceIndex'], info['IPAddress'], info['PrefixLength'] is not None]):
                messagebox.showerror("오류", "핵심 정보(인덱스, IP, 서브넷 길이)를 찾지 못했습니다."); self.log(f"파싱 오류. 데이터: {info}"); return
            
            self.log(f"인터페이스: {info['InterfaceAlias']} (인덱스: {info['InterfaceIndex']})")
            self.ip_var.set(info['IPAddress']); self.subnet_var.set(self.prefix_to_subnet(info['PrefixLength']))
            self.gateway_var.set(info.get('DefaultGateway', 'N/A')); self.dns_var.set(", ".join(info['DNSServerAddresses']) if info['DNSServerAddresses'] else 'N/A')
            
            self.backup_settings_data = info.copy() 
            with open(self.network_backup_path, "w", encoding='utf-8') as f: json.dump(self.backup_settings_data, f, ensure_ascii=False, indent=4)
            self.log(f"설정 백업 완료: {os.path.basename(self.network_backup_path)}")
            self.btn_restore.config(state=tk.NORMAL)
            messagebox.showinfo("성공", "현재 네트워크 설정을 성공적으로 불러오고 백업했습니다.")
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as e:
            self.log(f"정보 분석 중 예외: {e}. JSON: {json_output[:500]}..."); messagebox.showerror("파싱 오류", f"정보 분석 중 오류:\n{e}")

    def apply_settings_from_config(self): # (이하 로직은 이전과 동일하게 유지, 필요시 run_ps_command timeout 조정)
        current_if_index = self.active_interface_info.get('InterfaceIndex')
        if not current_if_index: messagebox.showwarning("경고", "먼저 '1. 현재 설정 불러오기'를 실행하세요."); return
        try:
            with open(self.network_config_path, "r", encoding="utf-8") as f: config = dict(line.strip().split('=', 1) for line in f if '=' in line and not line.strip().startswith('#'))
        except FileNotFoundError: messagebox.showerror("오류", f"`{os.path.basename(self.network_config_path)}` 파일을 찾을 수 없습니다."); return
        ip=config.get('ip'); prefix_str=config.get('subnet_prefix'); gateway=config.get('gateway'); dns_config=config.get('dns')
        if not all([ip, prefix_str, gateway, dns_config]): messagebox.showerror("설정 오류", "`config.txt`의 모든 항목을 확인하세요."); return
        try: prefix = int(prefix_str); assert 0 <= prefix <= 32
        except (ValueError, AssertionError): messagebox.showerror("설정 오류", "subnet_prefix는 0에서 32 사이의 숫자여야 합니다."); return
        self.log(f"인터페이스 인덱스 {current_if_index}에 설정 적용을 시작합니다..."); dns_servers_to_set = [f"'{d.strip()}'" for d in dns_config.split(',') if d.strip()]; dns_str_for_ps = ",".join(dns_servers_to_set) if dns_servers_to_set else "$null"
        ps_clear_ip = f"$ErrorActionPreference = 'SilentlyContinue'; Get-NetIPAddress -InterfaceIndex {current_if_index} -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false; $ErrorActionPreference = 'Continue';"
        self.run_ps_command(ps_clear_ip)
        ps_set_ip = f"New-NetIPAddress -InterfaceIndex {current_if_index} -IPAddress {ip} -PrefixLength {prefix} -DefaultGateway {gateway}"
        result_ip = self.run_ps_command(ps_set_ip);
        if result_ip and ("PS_ERROR:" in result_ip or "Error" in result_ip or "오류" in result_ip): self.log(f"IP/게이트웨이 설정 실패: {result_ip}"); messagebox.showerror("오류", f"IP/게이트웨이 설정에 실패했습니다:\n{result_ip}"); return
        ps_set_dns = f"Set-DnsClientServerAddress -InterfaceIndex {current_if_index} -ServerAddresses ({dns_str_for_ps})"
        if dns_str_for_ps == "$null": ps_set_dns = f"Set-DnsClientServerAddress -InterfaceIndex {current_if_index} -ResetServerAddresses"
        result_dns = self.run_ps_command(ps_set_dns)
        if result_dns and ("PS_ERROR:" in result_dns or "Error" in result_dns or "오류" in result_dns): self.log(f"DNS 설정 실패: {result_dns}"); messagebox.showerror("오류", f"DNS 설정에 실패했습니다:\n{result_dns}"); return
        self.log("설정 적용 완료. 2초 후 정보를 새로고침합니다."); self.master.after(2000, self.get_and_backup_settings); messagebox.showinfo("성공", "파일의 설정으로 네트워크 정보를 변경했습니다.")

    def restore_original_settings(self): # (이하 로직은 이전과 동일하게 유지, 필요시 run_ps_command timeout 조정)
        if not self.backup_settings_data or not self.backup_settings_data.get('InterfaceIndex'): messagebox.showerror("오류", "복원할 백업 데이터가 없습니다."); return
        info = self.backup_settings_data; if_index=info.get('InterfaceIndex'); ip=info.get('IPAddress'); prefix=info.get('PrefixLength'); gateway=info.get('DefaultGateway'); dns_list=info.get('DNSServerAddresses', [])
        self.log(f"인터페이스 인덱스 {if_index}의 설정을 백업된 상태로 복원합니다..."); dns_str_for_ps = ",".join([f"'{d.strip()}'" for d in dns_list if d.strip()]) if dns_list else "$null"
        ps_clear_ip = f"$ErrorActionPreference = 'SilentlyContinue'; Get-NetIPAddress -InterfaceIndex {if_index} -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false; $ErrorActionPreference = 'Continue';"
        self.run_ps_command(ps_clear_ip)
        ps_restore_ip = f"New-NetIPAddress -InterfaceIndex {if_index} -IPAddress {ip} -PrefixLength {prefix}"
        if gateway: ps_restore_ip += f" -DefaultGateway {gateway}"
        result_ip = self.run_ps_command(ps_restore_ip)
        if result_ip and ("PS_ERROR:" in result_ip or "Error" in result_ip or "오류" in result_ip): self.log(f"IP/게이트웨이 복원 실패: {result_ip}"); messagebox.showerror("오류", f"IP/게이트웨이 복원에 실패했습니다:\n{result_ip}"); return
        ps_restore_dns = f"Set-DnsClientServerAddress -InterfaceIndex {if_index} -ServerAddresses ({dns_str_for_ps})"
        if dns_str_for_ps == "$null": ps_restore_dns = f"Set-DnsClientServerAddress -InterfaceIndex {if_index} -ResetServerAddresses"
        result_dns = self.run_ps_command(ps_restore_dns)
        if result_dns and ("PS_ERROR:" in result_dns or "Error" in result_dns or "오류" in result_dns): self.log(f"DNS 복원 실패: {result_dns}"); messagebox.showerror("오류", f"DNS 복원에 실패했습니다:\n{result_dns}"); return
        self.log("복원 완료. 2초 후 정보를 새로고침합니다."); self.master.after(2000, self.get_and_backup_settings); messagebox.showinfo("성공", "원래의 네트워크 설정으로 복원했습니다.")

    # === 2. 윈도우 인증 탭 ===
    def create_windows_widgets(self, parent_tab): # (이전과 동일)
        win_frame = ttk.LabelFrame(parent_tab, text=" 윈도우 정품 키 관리 "); win_frame.pack(fill=tk.X, padx=10, pady=10, expand=True)
        self.win_key_var = tk.StringVar(value="아래 버튼을 눌러 확인")
        center_frame = ttk.Frame(win_frame); center_frame.pack(expand=True)
        ttk.Label(center_frame, text="현재 키 (일부):", font=('Malgun Gothic', 10)).pack(pady=5)
        ttk.Label(center_frame, textvariable=self.win_key_var, font=('Helvetica', 12, 'bold'), foreground="blue").pack(pady=5)
        ttk.Button(parent_tab, text="윈도우 정품 인증 시작", command=self.run_windows_activation_flow).pack(fill=tk.X, padx=10, pady=20)

    def run_windows_activation_flow(self): # (이전과 동일, run_ps_command 사용)
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

    def get_win_partial_key(self): # (이전과 동일, run_ps_command 사용)
        self.log("[윈도우] 현재 윈도우 제품 키 정보를 가져옵니다...")
        ps_command_partial_key = ("(Get-CimInstance SoftwareLicensingProduct | "
                                  "Where-Object { $_.PartialProductKey -ne $null -and $_.LicenseStatus -eq 1} | "
                                  "Select-Object -First 1).PartialProductKey")
        output_partial = self.run_ps_command(ps_command_partial_key)
        if output_partial and "PS_ERROR:" not in output_partial and "PartialProductKey" not in output_partial :
            return f"...{output_partial}"
        ps_command_oem = "(Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey"
        output_oem = self.run_ps_command(ps_command_oem)
        if output_oem and "PS_ERROR:" not in output_oem and "OA3xOriginalProductKey" not in output_oem:
             return f"OEM: ...{output_oem[-5:]}"
        return "확인 불가"

    def apply_windows_key(self, key): # (이전과 동일, run_ps_command 사용)
        self.log(f"[윈도우] 제품 키 설치 시도: {key[:5]}...")
        result_ipk = self.run_ps_command(f"cscript.exe C:\\Windows\\System32\\slmgr.vbs /ipk {key}")
        if result_ipk is None or "PS_ERROR:" in result_ipk or \
           ("오류" in result_ipk or "Error" in result_ipk.lower()) and \
           ("성공" not in result_ipk and "successfully" not in result_ipk.lower()):
            self.log(f"[윈도우] 제품 키 설치 실패: {result_ipk}"); return False
        self.log(f"[윈도우] 제품 키 설치 성공 응답: {result_ipk}")
        result_ato = self.run_ps_command("cscript.exe C:\\Windows\\System32\\slmgr.vbs /ato")
        if result_ato: self.log(f"[윈도우] 정품 인증 시도 결과: {result_ato}")
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()