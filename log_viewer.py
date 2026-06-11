# -*- coding: utf-8 -*-
"""
Windows 日志与事件查看器 v1.0
功能：系统日志、安全日志、应用日志、登录记录、USB历史、文件改动、进程历史、网络连接、已安装程序、系统信息
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import json
import os
import sys
import datetime
import re
import ctypes

# ==================== 辅助函数 ====================

def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_powershell(cmd, timeout=30):
    """运行 PowerShell 命令并返回 JSON 结果"""
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
        return None
    except Exception as e:
        return None

def run_wevtutil(cmd, timeout=60):
    """运行 wevtutil 命令并返回结果"""
    try:
        p = subprocess.run(
            f"wevtutil {cmd}", shell=True, capture_output=True, text=True,
            timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW
        )
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
        return None
    except Exception as e:
        return None

def safe_str(s):
    """安全转换为字符串"""
    if s is None:
        return ""
    return str(s)

# ==================== 数据获取模块 ====================

class DataFetcher:
    """数据获取器 - 通过各种 Windows API 获取系统信息"""

    @staticmethod
    def get_system_events(count=500, date_str=""):
        """获取系统日志"""
        results = []
        try:
            if date_str:
                time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
            else:
                time_filter = "StartTime=(Get-Date).AddDays(-7)"
            ps_cmd = f'''
            $filter = @{{ LogName='System'; {time_filter} }}
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {count} -ErrorAction SilentlyContinue | ForEach-Object {{
                [PSCustomObject]@{{
                    Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    ID = $_.Id
                    Level = if($_.LevelDisplayName){{$_.LevelDisplayName}}else{{'未知'}}
                    Source = $_.ProviderName
                    Message = ($_.Message -replace '[\\r\\n]+',' ' -replace '\\s+',' ').Substring(0,[Math]::Min(300,($_.Message -replace '[\\r\\n]+',' ').Length))
                }}
            }}
            ConvertTo-Json @($events) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                results = json.loads(output)
        except:
            raw = run_wevtutil(f"qe System /c:{count} /rd:true /f:xml", timeout=60)
            if raw:
                results = DataFetcher._parse_wevtutil_xml(raw, "System")
        return results if isinstance(results, list) else []

    @staticmethod
    def get_security_events(count=500, date_str=""):
        """获取安全日志（登录/注销/权限等）"""
        results = []
        try:
            if date_str:
                time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
            else:
                time_filter = "StartTime=(Get-Date).AddDays(-7)"
            ps_cmd = f'''
            $filter = @{{ LogName='Security'; {time_filter} }}
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {count} -ErrorAction SilentlyContinue | ForEach-Object {{
                $msg = ($_.Message -replace '[\\r\\n]+',' ') -replace '\\s+',' '
                if($msg.Length -gt 300){{ $msg = $msg.Substring(0,300) }}
                [PSCustomObject]@{{
                    Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    ID = $_.Id
                    Level = if($_.LevelDisplayName){{$_.LevelDisplayName}}else{{'信息'}}
                    Task = $_.TaskDisplayName
                    Keyword = $_.KeywordsDisplayNames -join ','
                    Message = $msg
                }}
            }}
            ConvertTo-Json @($events) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                results = json.loads(output)
        except:
            pass
        return results if isinstance(results, list) else []

    @staticmethod
    def get_application_events(count=500, date_str=""):
        """获取应用程序日志"""
        results = []
        try:
            if date_str:
                time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
            else:
                time_filter = "StartTime=(Get-Date).AddDays(-7)"
            ps_cmd = f'''
            $filter = @{{ LogName='Application'; {time_filter} }}
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {count} -ErrorAction SilentlyContinue | ForEach-Object {{
                $msg = ($_.Message -replace '[\\r\\n]+',' ') -replace '\\s+',' '
                if($msg.Length -gt 300){{ $msg = $msg.Substring(0,300) }}
                [PSCustomObject]@{{
                    Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    ID = $_.Id
                    Level = if($_.LevelDisplayName){{$_.LevelDisplayName}}else{{'未知'}}
                    Source = $_.ProviderName
                    Message = $msg
                }}
            }}
            ConvertTo-Json @($events) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                results = json.loads(output)
        except:
            pass
        return results if isinstance(results, list) else []

    @staticmethod
    def get_login_history(count=500, date_str=""):
        """获取登录/注销历史"""
        results = []
        try:
            if date_str:
                time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
            else:
                time_filter = "StartTime=(Get-Date).AddDays(-30)"
            ps_cmd = f'''
            $filter = @{{ LogName='Security'; ID=4624,4634,4647,4672; {time_filter} }}
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {count} -ErrorAction SilentlyContinue | ForEach-Object {{
                $msg = $_.Message
                $user = ''
                $domain = ''
                $type = ''
                if($msg -match '账户名:\\s+(\\S+)'){{ $user = $Matches[1] }}
                if($msg -match '帐户域:\\s+(\\S+)'){{ $domain = $Matches[1] }}
                if($msg -match '登录类型:\\s+(\\S+)'){{ $type = $Matches[1] }}
                [PSCustomObject]@{{
                    Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    ID = $_.Id
                    User = $user
                    Domain = $domain
                    LoginType = $type
                    Action = switch($_.Id){{ 4624 {{'登录成功'}} 4634 {{'注销'}} 4647 {{'用户注销'}} 4672 {{'特权分配'}} default {{'其他'}} }}
                }}
            }}
            ConvertTo-Json @($events) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                results = json.loads(output)
        except:
            pass
        return results if isinstance(results, list) else []

    @staticmethod
    def get_usb_history():
        """获取 USB 设备连接历史"""
        results = []
        try:
            ps_cmd = '''
            $results = @()
            $paths = @(
                'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB',
                'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR'
            )
            foreach($path in $paths) {
                if(Test-Path $path) {
                    $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                    foreach($item in $items) {
                        $subItems = Get-ChildItem -Path $item.PSPath -ErrorAction SilentlyContinue
                        foreach($sub in $subItems) {
                            try {
                                $prop = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
                                $results += [PSCustomObject]@{
                                    DeviceID = $sub.PSChildName
                                    Name = if($prop.FriendlyName){$prop.FriendlyName}else{$item.PSChildName}
                                    ClassGUID = if($prop.ClassGUID){$prop.ClassGUID}else{''}
                                    Service = if($prop.Service){$prop.Service}else{''}
                                    Mfg = if($prop.Mfg){$prop.Mfg}else{''}
                                }
                            } catch {}
                        }
                    }
                }
            }
            ConvertTo-Json @($results) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_recent_files(date_str="", max_count=200):
        """获取最近修改的文件"""
        results = []
        try:
            if date_str:
                time_filter = (
                    f"$_.LastWriteTime -ge [datetime]'{date_str}' -and "
                    f"$_.LastWriteTime -lt [datetime]'{date_str}'.AddDays(1)"
                )
            else:
                time_filter = "$_.LastWriteTime -gt (Get-Date).AddDays(-3)"
            ps_cmd = f'''
            $results = @()
            $paths = @("$env:USERPROFILE\\Desktop", "$env:USERPROFILE\\Documents", "$env:USERPROFILE\\Downloads", "$env:TEMP")
            foreach($p in $paths) {{
                if(Test-Path $p) {{
                    $files = Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | 
                        Where-Object {{ {time_filter} }} |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 100
                    foreach($f in $files) {{
                        $results += [PSCustomObject]@{{
                            Path = $f.FullName
                            Name = $f.Name
                            LastModified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            SizeKB = [math]::Round($f.Length/1KB, 1)
                            Extension = $f.Extension
                        }}
                    }}
                }}
            }}
            ConvertTo-Json @($results[0..[Math]::Min({max_count-1},$results.Count-1)]) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_process_history(count=500, date_str=""):
        """获取进程执行历史（通过事件日志）"""
        results = []
        try:
            if date_str:
                time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
            else:
                time_filter = "StartTime=(Get-Date).AddDays(-7)"
            ps_cmd = f'''
            $filter = @{{ LogName='Security'; ID=4688; {time_filter} }}
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {count} -ErrorAction SilentlyContinue | ForEach-Object {{
                $msg = $_.Message
                $proc = ''
                $user = ''
                if($msg -match '新进程名称:\\s+(\\S+)'){{ $proc = $Matches[1] }}
                if($msg -match '使用者名称:\\s+(\\S+)'){{ $user = $Matches[1] }}
                [PSCustomObject]@{{
                    Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Process = $proc
                    User = $user
                }}
            }}
            ConvertTo-Json @($events) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_network_connections():
        """获取当前网络连接"""
        results = []
        try:
            ps_cmd = '''
            $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
                Where-Object { $_.State -eq 'Established' } |
                Select-Object -First 100 |
                ForEach-Object {
                    try { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { $proc = '' }
                    [PSCustomObject]@{
                        LocalAddress = "$($_.LocalAddress):$($_.LocalPort)"
                        RemoteAddress = "$($_.RemoteAddress):$($_.RemotePort)"
                        State = $_.State.ToString()
                        Process = $proc
                        PID = $_.OwningProcess
                    }
                }
            ConvertTo-Json @($conns) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_installed_software():
        """获取已安装的软件列表"""
        results = []
        try:
            ps_cmd = '''
            $results = @()
            $paths = @(
                'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
                'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
                'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
            )
            foreach($path in $paths) {
                if(Test-Path (Split-Path $path)) {
                    $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -and $_.DisplayName -ne '' } |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Name = $_.DisplayName
                                Version = $_.DisplayVersion
                                Publisher = $_.Publisher
                                InstallDate = $_.InstallDate
                                UninstallString = $_.UninstallString
                            }
                        }
                    $results += $items
                }
            }
            ConvertTo-Json @($results | Sort-Object Name -Unique) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_system_info():
        """获取系统基本信息"""
        info = {}
        try:
            ps_cmd = '''
            $os = Get-CimInstance Win32_OperatingSystem
            $cs = Get-CimInstance Win32_ComputerSystem
            $bios = Get-CimInstance Win32_BIOS
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            $uptime = (Get-Date) - $os.LastBootUpTime
            
            [PSCustomObject]@{
                Hostname = $cs.Name
                OS = $os.Caption
                Version = $os.Version
                Build = $os.BuildNumber
                Architecture = $os.OSArchitecture
                InstallDate = $os.InstallDate.ToString('yyyy-MM-dd')
                LastBoot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
                Uptime = "$($uptime.Days)天 $($uptime.Hours)小时 $($uptime.Minutes)分钟"
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                TotalRAM_GB = [math]::Round($cs.TotalPhysicalMemory/1GB, 1)
                CPU = $cpu.Name
                Cores = $cpu.NumberOfCores
                BIOS = $bios.SMBIOSBIOSVersion
                SerialNumber = $bios.SerialNumber
                CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            }
            ConvertTo-Json -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                info = json.loads(output)
        except:
            pass
        return info

    @staticmethod
    def get_scheduled_tasks():
        """获取计划任务"""
        results = []
        try:
            ps_cmd = '''
            $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
                Select-Object -First 100 |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.TaskName
                        Path = $_.TaskPath
                        State = $_.State.ToString()
                        Description = $_.Description
                        Trigger = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','
                    }
                }
            ConvertTo-Json @($tasks) -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_services():
        """获取服务状态"""
        results = []
        try:
            ps_cmd = '''
            Get-Service | Select-Object -First 200 |
                ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        DisplayName = $_.DisplayName
                        Status = $_.Status.ToString()
                        StartType = $_.StartType.ToString()
                    }
                } | ConvertTo-Json -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_disk_info():
        """获取磁盘信息"""
        results = []
        try:
            ps_cmd = '''
            Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
                ForEach-Object {
                    [PSCustomObject]@{
                        Drive = $_.DeviceID
                        Label = $_.VolumeName
                        FileSystem = $_.FileSystem
                        TotalGB = [math]::Round($_.Size/1GB, 1)
                        FreeGB = [math]::Round($_.FreeSpace/1GB, 1)
                        UsedPercent = [math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100, 1)
                    }
                } | ConvertTo-Json -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                raw = json.loads(output)
                results = raw if isinstance(raw, list) else []
        except:
            pass
        return results

    @staticmethod
    def get_anomaly_report(date_str=""):
        """综合异常检测报告 - 汇总所有可疑活动"""
        report = {
            "failed_logins": [],
            "recent_success_logins": [],
            "night_logins": [],
            "admin_logins": [],
            "system_crashes": [],
            "usb_devices": [],
            "recent_files": [],
            "active_network": [],
            "suspicious_services": [],
        }

        if date_str:
            login_time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
            crash_time_filter = f"StartTime='{date_str}T00:00:00'; EndTime='{date_str}T23:59:59'"
        else:
            login_time_filter = "StartTime=(Get-Date).AddDays(-14)"
            crash_time_filter = "StartTime=(Get-Date).AddDays(-14)"
        dt = date_str

        # 1. 获取登录记录
        try:
            ps_cmd = (
                "$filter = @{ LogName='Security'; ID=4624,4625,4634,4647,4672,4776; "
                + login_time_filter + " }\n"
                "$events = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {\n"
                "    $msg = $_.Message\n"
                "    $user = ''; $domain = ''; $type = ''; $workstation = ''\n"
                "    if($msg -match '帐户名:\\\\s+(\\\\S+)'){ $user = $Matches[1] }\n"
                "    if($msg -match '帐户域:\\\\s+(\\\\S+)'){ $domain = $Matches[1] }\n"
                "    if($msg -match '登录类型:\\\\s+(\\\\S+)'){ $type = $Matches[1] }\n"
                "    if($msg -match '工作站名称:\\\\s+(\\\\S+)'){ $workstation = $Matches[1] }\n"
                "    [PSCustomObject]@{\n"
                "        Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')\n"
                "        ID = $_.Id\n"
                "        User = $user\n"
                "        Domain = $domain\n"
                "        LoginType = $type\n"
                "        Workstation = $workstation\n"
                "    }\n"
                "}\n"
                "ConvertTo-Json @($events) -Compress"
            )
            output = run_powershell(ps_cmd, timeout=60)
            if output:
                data = json.loads(output)
                if isinstance(data, list):
                    for evt in data:
                        eid = int(evt.get('ID', 0))
                        if eid == 4625:
                            report["failed_logins"].append(evt)
                        elif eid == 4624:
                            report["recent_success_logins"].append(evt)
                            t = evt.get('LoginType', '')
                            if t == '10':
                                report["admin_logins"].append(evt)
                            ts = evt.get('Time', '')
                            if ts:
                                try:
                                    hour = int(ts[11:13])
                                    if hour >= 22 or hour < 6:
                                        report["night_logins"].append(evt)
                                except:
                                    pass
                        elif eid == 4672:
                            report["admin_logins"].append(evt)
        except:
            pass

        # 2. 系统崩溃/错误
        try:
            ps_cmd = (
                "$filter = @{ LogName='System'; ID=41,1001,6008; "
                + crash_time_filter + " }\n"
                "Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -ErrorAction SilentlyContinue |\n"
                "    ForEach-Object {\n"
                "        [PSCustomObject]@{\n"
                "            Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')\n"
                "            ID = $_.Id\n"
                "            Level = if($_.LevelDisplayName){$_.LevelDisplayName}else{'错误'}\n"
                "            Message = ($_.Message -replace '[\\r\\n]+',' ') -replace '\\s+',' '\n"
                "        }\n"
                "    } | ConvertTo-Json -Compress"
            )
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                data = json.loads(output)
                if isinstance(data, list):
                    report["system_crashes"] = data
        except:
            pass

        # 3. USB设备
        try:
            report["usb_devices"] = DataFetcher.get_usb_history()
        except:
            pass

        # 4. 最近文件
        try:
            report["recent_files"] = DataFetcher.get_recent_files(date_str=dt, max_count=50)
        except:
            pass

        # 5. 网络连接
        try:
            report["active_network"] = DataFetcher.get_network_connections()
        except:
            pass

        # 6. 可疑服务
        try:
            ps_cmd = '''
            Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State='Running'" |
                ForEach-Object {
                    $desc = if($_.Description){$_.Description}else{''}
                    [PSCustomObject]@{
                        Name = $_.Name
                        DisplayName = $_.DisplayName
                        Path = $_.PathName
                        Description = $desc.Substring(0, [Math]::Min(200, $desc.Length))
                    }
                } | ConvertTo-Json -Compress
            '''
            output = run_powershell(ps_cmd, timeout=30)
            if output:
                data = json.loads(output)
                if isinstance(data, list):
                    report["suspicious_services"] = data
        except:
            pass

        return report

    @staticmethod
    def _parse_wevtutil_xml(xml_data, log_type):
        """简单解析 wevtutil XML 输出（备用方案）"""
        results = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(f"<root>{xml_data}</root>")
            for event in root.findall('Event'):
                time_elem = event.find(".//TimeCreated")
                id_elem = event.find(".//EventID")
                level_elem = event.find(".//Level")
                provider = event.find(".//Provider")
                data_items = event.findall(".//Data")
                message = ' '.join([d.get('Name','') + ':' + (d.text or '') for d in data_items])
                
                results.append({
                    "Time": time_elem.get("SystemTime", "") if time_elem is not None else "",
                    "ID": id_elem.text if id_elem is not None else "",
                    "Level": level_elem.text if level_elem is not None else "",
                    "Source": provider.get("Name", "") if provider is not None else "",
                    "Message": message[:300]
                })
        except:
            pass
        return results

# ==================== 事件ID含义字典 ====================

EVENT_MEANINGS = {
    # Security Events
    4624: "✅ 账户登录成功",
    4625: "❌ 账户登录失败（密码错误？）",
    4634: "👋 账户注销",
    4647: "👋 用户主动注销",
    4648: "🔑 尝试使用显式凭据登录",
    4672: "⚡ 为新登录分配特殊权限",
    4688: "▶️ 新进程已创建",
    4689: "⏹️ 进程已终止",
    4720: "👤 创建了用户账户",
    4722: "✅ 启用了用户账户",
    4725: "🚫 禁用了用户账户",
    4726: "🗑️ 删除了用户账户",
    4732: "➕ 成员被添加到启用了安全性的本地组",
    4738: "✏️ 用户账户已更改",
    4740: "🔒 用户账户被锁定",
    4767: "🔓 用户账户已解锁",
    4798: "🔍 枚举了用户的本地组成员身份",
    4800: "🔒 工作站被锁定",
    4801: "🔓 工作站已解锁",
    4902: "📋 创建了每用户审核策略表",
    4907: "🔧 更改了对象的审核设置",
    5058: "🔐 密钥文件操作",
    5061: "🔑 加密操作",
    5140: "📁 访问了网络共享对象",
    5156: "🌐 Windows 筛选平台允许了连接",
    5157: "🚫 Windows 筛选平台阻止了连接",
    5158: "🌐 Windows 筛选平台允许了绑定",
    5379: "🔑 读取了已保存的凭据",
    
    # System Events
    41: "💥 系统意外关机（可能是断电/崩溃）",
    1001: "💻 系统故障记录（蓝屏诊断）",
    6005: "✅ 事件日志服务已启动",
    6006: "⏹️ 事件日志服务已停止",
    6008: "⚠️ 上一次系统关闭是意外的",
    6009: "ℹ️ 操作系统版本信息",
    6013: "⏱️ 系统运行时间",
    7001: "⚠️ 服务启动超时",
    7002: "⚠️ 服务启动失败",
    7030: "⚠️ 服务被标记为交互服务",
    7031: "💥 服务意外终止",
    7034: "💥 服务意外终止",
    7040: "🔧 服务启动类型已更改",
    7045: "🔧 系统中安装了新服务",
    10016: "⚠️ 应用程序权限问题（DCOM）",
    
    # Application Events
    1000: "💥 应用程序错误",
    1001: "💥 应用程序故障",
    1002: "⏸️ 应用程序挂起",
    11707: "🔧 产品安装操作完成",
    11708: "🔧 产品安装/卸载操作",
    11724: "🗑️ 产品卸载操作完成",
}

def get_event_meaning(event_id, default=""):
    """获取事件含义描述"""
    try:
        eid = int(event_id)
        return EVENT_MEANINGS.get(eid, default)
    except:
        return default

# ==================== GUI 应用 ====================

class LogViewerApp:
    """主应用程序"""

    def __init__(self, root):
        self.root = root
        self.root.title("Windows 日志与事件查看器 v1.0")
        self.root.geometry("1200x750")

        # 设置图标（可选）
        try:
            self.root.iconbitmap(default='')
        except:
            pass

        # 检查管理员权限
        if not is_admin():
            self._show_admin_warning()

        # 创建 UI
        self._create_widgets()

        # 绑定快捷键
        self.root.bind('<Control-f>', lambda e: self._focus_search())
        self.root.bind('<Control-r>', lambda e: self._refresh_current())

    def _show_admin_warning(self):
        """显示非管理员警告"""
        warning = tk.Toplevel(self.root)
        warning.title("权限提示")
        warning.geometry("450x180")
        warning.transient(self.root)
        warning.resizable(False, False)
        
        tk.Label(warning, text="⚠️ 建议以管理员身份运行", font=("微软雅黑", 12, "bold"), fg="orange").pack(pady=(20, 10))
        tk.Label(warning, text="部分功能（如安全日志、网络连接）需要管理员权限\n"
                              "才能获取完整信息。\n\n"
                              "您可以继续使用，但某些数据可能不完整。", 
                 font=("微软雅黑", 9), justify=tk.LEFT).pack(pady=5)
        
        btn = ttk.Button(warning, text="知道了，继续使用", command=warning.destroy)
        btn.pack(pady=10)
        btn.focus_set()

    def _create_widgets(self):
        """创建界面组件"""
        # 顶部工具栏
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        ttk.Label(toolbar, text="日志与事件查看器", font=("微软雅黑", 14, "bold")).pack(side=tk.LEFT, padx=5)

        # 日期范围选择
        ttk.Label(toolbar, text="选择日期:").pack(side=tk.LEFT, padx=(15, 3))
        self.date_var = tk.StringVar()
        # 生成最近30天日期列表
        today = datetime.date.today()
        weekdays_cn = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
        self.date_options = []
        self.date_value_map = {}  # "MM-DD 周X" -> "YYYY-MM-DD"
        for i in range(30):
            d = today - datetime.timedelta(days=i)
            label = d.strftime('%m-%d') + ' ' + weekdays_cn[d.weekday()]
            value = d.strftime('%Y-%m-%d')
            self.date_options.append(label)
            self.date_value_map[label] = value
        # 默认选今天
        default_label = today.strftime('%m-%d') + ' ' + weekdays_cn[today.weekday()]
        self.date_var.set(default_label)
        self.selected_date = self.date_value_map.get(default_label, today.strftime('%Y-%m-%d'))
        self.date_combo = ttk.Combobox(toolbar, textvariable=self.date_var,
                                        values=self.date_options, state="readonly", width=12)
        self.date_combo.pack(side=tk.LEFT, padx=3)
        self.date_combo.bind('<<ComboboxSelected>>', self._on_date_changed)

        # 默认显示的数据天数（兼容旧逻辑）
        self.date_days = 7

        # 搜索框
        ttk.Label(toolbar, text="搜索:").pack(side=tk.LEFT, padx=(15, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', self._on_search)

        ttk.Button(toolbar, text="清除", command=self._clear_search).pack(side=tk.LEFT, padx=2)

        # 刷新按钮
        self.refresh_btn = ttk.Button(toolbar, text="🔄 刷新当前页", command=self._refresh_current)
        self.refresh_btn.pack(side=tk.LEFT, padx=(15, 5))

        # 导出按钮
        ttk.Button(toolbar, text="📤 导出为CSV", command=self._export_csv).pack(side=tk.LEFT, padx=5)

        # 状态标签
        self.status_label = ttk.Label(toolbar, text="", foreground="gray")
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # 主内容区 - Notebook 标签页
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 定义所有标签页
        self.tabs = [
            ("� 异常检测", self._create_anomaly_tab),
            ("� 系统日志", self._create_system_tab),
            ("🔒 安全日志", self._create_security_tab),
            ("📱 应用日志", self._create_application_tab),
            ("👤 登录记录", self._create_login_tab),
            ("🔌 USB历史", self._create_usb_tab),
            ("📁 文件改动", self._create_files_tab),
            ("▶️ 进程历史", self._create_process_tab),
            ("🌐 网络连接", self._create_network_tab),
            ("📦 已装软件", self._create_software_tab),
            ("🖥️ 系统信息", self._create_sysinfo_tab),
        ]

        self.treeviews = {}  # 存储各标签页的 TreeView
        self.current_data = {}  # 存储当前数据用于搜索过滤

        for tab_name, create_func in self.tabs:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab_name)
            create_func(frame)

        # 绑定标签页切换事件
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_changed)

        # 底部状态栏
        self.status_bar = ttk.Label(self.root, text="就绪 | 点击各标签页加载数据 | Ctrl+F 搜索 | Ctrl+R 刷新", 
                                     relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_log_tab(self, parent, columns, widths, tag_name, fetch_func, *fetch_args, needs_days=True):
        """通用日志标签页创建"""
        # 控件区域
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text=f"共 0 条记录", font=("微软雅黑", 9)).pack(side=tk.LEFT)
        count_label = control_frame.winfo_children()[-1] if control_frame.winfo_children() else None

        # 使用 TreeView 显示数据
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5)

        # 滚动条
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                            yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)

        for col, width in zip(columns, widths):
            tree.heading(col, text=col, command=lambda c=col: self._sort_treeview(tree, c, False))
            tree.column(col, width=width, minwidth=50)

        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # 双击事件
        tree.bind('<Double-1>', lambda e, t=tree: self._show_detail(t))

        self.treeviews[tag_name] = tree

        # 加载数据
        self._load_data_async(fetch_func, tag_name, columns, count_label, needs_days, *fetch_args)

    def _create_system_tab(self, parent):
        columns = ["时间", "事件ID", "级别", "来源", "含义", "详细信息"]
        widths = [150, 70, 80, 120, 200, 400]
        self._create_log_tab(parent, columns, widths, "system", DataFetcher.get_system_events)

    def _create_security_tab(self, parent):
        columns = ["时间", "事件ID", "级别", "任务类别", "关键字", "含义", "详细信息"]
        widths = [150, 70, 80, 100, 100, 200, 400]
        self._create_log_tab(parent, columns, widths, "security", DataFetcher.get_security_events)

    def _create_application_tab(self, parent):
        columns = ["时间", "事件ID", "级别", "来源", "含义", "详细信息"]
        widths = [150, 70, 80, 120, 200, 400]
        self._create_log_tab(parent, columns, widths, "application", DataFetcher.get_application_events)

    def _create_login_tab(self, parent):
        columns = ["时间", "事件ID", "操作", "用户名", "域", "登录类型"]
        widths = [150, 70, 100, 150, 150, 100]
        self._create_log_tab(parent, columns, widths, "login", DataFetcher.get_login_history)

    def _create_usb_tab(self, parent):
        columns = ["设备ID", "设备名称", "类GUID", "服务", "制造商"]
        widths = [200, 250, 150, 100, 200]
        self._create_log_tab(parent, columns, widths, "usb", DataFetcher.get_usb_history, needs_days=False)

    def _create_files_tab(self, parent):
        columns = ["修改时间", "文件名", "路径", "大小(KB)", "类型"]
        widths = [150, 200, 350, 80, 80]
        self._create_log_tab(parent, columns, widths, "files", DataFetcher.get_recent_files)

    def _create_process_tab(self, parent):
        columns = ["时间", "进程路径", "用户名"]
        widths = [150, 500, 200]
        self._create_log_tab(parent, columns, widths, "process", DataFetcher.get_process_history)

    def _create_network_tab(self, parent):
        columns = ["本地地址", "远程地址", "状态", "进程", "PID"]
        widths = [200, 300, 100, 150, 80]
        self._create_log_tab(parent, columns, widths, "network", DataFetcher.get_network_connections, needs_days=False)

    def _create_software_tab(self, parent):
        columns = ["软件名称", "版本", "发行商", "安装日期"]
        widths = [350, 120, 250, 120]
        self._create_log_tab(parent, columns, widths, "software", DataFetcher.get_installed_software, needs_days=False)

    def _create_anomaly_tab(self, parent):
        """异常检测标签页 - 综合安全分析"""
        self.anomaly_text = scrolledtext.ScrolledText(parent, font=("Consolas", 10), wrap=tk.WORD)
        self.anomaly_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self._show_loading(self.anomaly_text, "🔍 异常检测报告")
        self._load_anomaly()

    def _create_sysinfo_tab(self, parent):
        """系统信息标签页 - 使用 Text 显示"""
        self.sysinfo_text = scrolledtext.ScrolledText(parent, font=("Consolas", 10), wrap=tk.WORD)
        self.sysinfo_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self._show_loading(self.sysinfo_text, "🖥️ 系统信息")
        self._load_sysinfo()

    def _show_loading(self, text_widget, title, step=""):
        """在文本区域显示加载提示"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, "\n\n\n\n")
        text_widget.insert(tk.END, f"         ⏳  {title}\n\n")
        text_widget.insert(tk.END, "         ┌──────────────────────────────────────┐\n")
        text_widget.insert(tk.END, "         │                                      │\n")
        text_widget.insert(tk.END, "         │        正在收集数据，请稍候...        │\n")
        text_widget.insert(tk.END, "         │                                      │\n")
        text_widget.insert(tk.END, "         └──────────────────────────────────────┘\n")
        if step:
            text_widget.insert(tk.END, f"\n         ▸ {step}\n")
        text_widget.insert(tk.END, "\n\n         💡 提示：低配电脑加载可能稍慢，数据量越大越久")
        text_widget.config(state=tk.DISABLED)

    def _load_data_async(self, fetch_func, tag_name, columns, count_label, needs_days=True, *args):
        """异步加载数据"""
        # 立即在 TreeView 中显示加载提示
        tree = self.treeviews.get(tag_name)
        if tree:
            for item in tree.get_children():
                tree.delete(item)
            loading_cols = list(columns)
            loading_vals = ["⏳ 正在加载..."] * len(columns)
            # 第一列放醒目提示
            loading_vals[0] = "⏳ 正在加载数据，请稍候..."
            loading_vals[-1] = "💡 低配电脑可能稍慢，请耐心等待"
            tree.insert('', 'end', values=loading_vals, tags=('loading',))
            tree.tag_configure('loading', foreground='#0066CC')
        if count_label:
            count_label.config(text="⏳ 正在加载...")

        def do_fetch():
            self.root.after(0, lambda: self.status_label.config(text="⏳ 正在加载数据...", foreground="blue"))
            try:
                if needs_days:
                    if args:
                        data = fetch_func(date_str=self.selected_date, *args)
                    else:
                        data = fetch_func(date_str=self.selected_date)
                else:
                    if args:
                        data = fetch_func(*args)
                    else:
                        data = fetch_func()
                self.root.after(0, lambda: self._populate_tree(tag_name, columns, data, count_label))
                self.root.after(0, lambda: self.status_label.config(text="✅ 加载完成", foreground="green"))
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(text=f"❌ 加载失败: {str(e)[:50]}", foreground="red"))

        thread = threading.Thread(target=do_fetch, daemon=True)
        thread.start()

    def _populate_tree(self, tag_name, columns, data, count_label):
        """填充 TreeView 数据"""
        tree = self.treeviews.get(tag_name)
        if not tree:
            return

        # 清空
        for item in tree.get_children():
            tree.delete(item)

        if not data:
            tree.insert('', 'end', values=["(无数据)"] * len(columns))
            if count_label:
                count_label.config(text="共 0 条记录")
            return

        # 存储原始数据用于搜索
        self.current_data[tag_name] = data

        # 批量插入
        for i, item in enumerate(data):
            values = self._extract_values(item, columns)
            # 为不同级别设置颜色标签
            tags = []
            level = values[2] if len(values) > 2 else ""
            if "错误" in str(level) or "Error" in str(level) or "失败" in str(level):
                tags.append('error')
            elif "警告" in str(level) or "Warning" in str(level):
                tags.append('warning')
            elif "信息" in str(level) or "Information" in str(level):
                tags.append('info')

            tree.insert('', 'end', values=values, tags=tags)

        # 设置颜色
        tree.tag_configure('error', foreground='red')
        tree.tag_configure('warning', foreground='orange')
        tree.tag_configure('info', foreground='gray')

        if count_label:
            count_label.config(text=f"共 {len(data)} 条记录")

    def _extract_values(self, item, columns):
        """从数据项提取值，添加事件含义"""
        values = []
        for col in columns:
            key_map = {
                "时间": "Time",
                "事件ID": "ID",
                "级别": "Level",
                "来源": "Source",
                "详细信息": "Message",
                "任务类别": "Task",
                "关键字": "Keyword",
                "含义": "__meaning__",
                "操作": "Action",
                "用户名": "User",
                "域": "Domain",
                "登录类型": "LoginType",
                "设备ID": "DeviceID",
                "设备名称": "Name",
                "类GUID": "ClassGUID",
                "服务": "Service",
                "制造商": "Mfg",
                "修改时间": "LastModified",
                "文件名": "Name",
                "路径": "Path",
                "大小(KB)": "SizeKB",
                "类型": "Extension",
                "进程路径": "Process",
                "本地地址": "LocalAddress",
                "远程地址": "RemoteAddress",
                "状态": "State",
                "进程": "Process",
                "PID": "PID",
                "软件名称": "Name",
                "版本": "Version",
                "发行商": "Publisher",
                "安装日期": "InstallDate",
            }
            key = key_map.get(col, "")
            if key == "__meaning__":
                event_id = item.get("ID", "")
                values.append(get_event_meaning(event_id, ""))
            elif key == "Process" and col == "进程路径":
                values.append(item.get("Process", ""))
            elif key:
                values.append(safe_str(item.get(key, "")))
            else:
                values.append("")
        return values

    def _show_detail(self, tree):
        """显示详细信息弹窗"""
        selection = tree.selection()
        if not selection:
            return
        item = tree.item(selection[0])
        values = item['values']
        
        detail = tk.Toplevel(self.root)
        detail.title("详细信息")
        detail.geometry("700x400")
        detail.transient(self.root)
        
        text = scrolledtext.ScrolledText(detail, font=("Consolas", 10), wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = tree['columns']
        for col, val in zip(columns, values):
            text.insert(tk.END, f"【{col}】\n{val}\n\n")
        text.config(state=tk.DISABLED)

    def _load_anomaly(self):
        """加载异常检测报告"""
        LOGIN_TYPE_MAP = {
            "2": "💻 本地控制台登录",
            "3": "🌐 网络登录（共享访问）",
            "4": "📋 批处理登录",
            "5": "⚙️ 服务账户登录",
            "7": "🔓 屏幕解锁",
            "10": "🖥️ 远程桌面登录",
            "11": "🔑 缓存凭据登录",
        }

        def do_fetch():
            steps = [
                "🔑 正在查询登录记录...",
                "💥 正在查询系统崩溃事件...",
                "🔌 正在查询 USB 设备记录...",
                "📁 正在扫描最近文件变动...",
                "🌐 正在检查网络连接...",
                "⚙️ 正在检查可疑服务...",
            ]
            step_idx = [0]  # 用列表包装以在闭包中修改

            def update_step():
                if step_idx[0] < len(steps):
                    self._show_loading(self.anomaly_text, "🔍 异常检测报告", steps[step_idx[0]])
                    step_idx[0] += 1
                    # 每300ms推进一步，直到所有步骤显示完
                    if step_idx[0] < len(steps):
                        self.root.after(300, update_step)

            # 显示初始加载状态
            self.root.after(0, update_step)
            self.root.after(0, lambda: self.status_label.config(
                text="⏳ 正在收集异常检测数据...", foreground="blue"))

            # 后台执行实际查询
            report = DataFetcher.get_anomaly_report(date_str=self.selected_date)
            self.root.after(0, lambda: self._show_loading(
                self.anomaly_text, "🔍 异常检测报告", "📊 正在生成报告..."))
            self.root.after(0, lambda: self.status_label.config(
                text="📊 正在生成异常检测报告...", foreground="blue"))

            def update_ui():
                txt = self.anomaly_text
                txt.config(state=tk.NORMAL)
                txt.delete(1.0, tk.END)

                # 计算风险分数
                risk_score = 0
                risk_items = []

                # ============ 第一部分：总览面板 ============
                txt.insert(tk.END, "╔" + "═" * 58 + "╗\n")
                txt.insert(tk.END, "║" + "  🔍  系 统 安 全 异 常 检 测 报 告".center(56) + "║\n")
                now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                txt.insert(tk.END, "║" + f"  生成时间: {now_str}".ljust(58) + "║\n")
                txt.insert(tk.END, "╚" + "═" * 58 + "╝\n\n")

                # ---------- 风险评分 ----------
                failed_count = len(report.get("failed_logins", []))
                night_count = len(report.get("night_logins", []))
                remote_count = len(report.get("admin_logins", []))
                crash_count = len(report.get("system_crashes", []))
                usb_count = len(report.get("usb_devices", []))
                file_count = len(report.get("recent_files", []))
                net_count = len(report.get("active_network", []))

                if failed_count > 5:
                    risk_score += 30
                    risk_items.append(f"⚠️  {failed_count} 次登录失败尝试")
                elif failed_count > 0:
                    risk_score += 10
                    risk_items.append(f"⚡ {failed_count} 次登录失败尝试")

                if night_count > 0:
                    risk_score += 20
                    risk_items.append(f"🌙 {night_count} 次深夜/凌晨登录")

                if remote_count > 0:
                    risk_score += 15
                    risk_items.append(f"🖥️ {remote_count} 次远程登录")

                if crash_count > 0:
                    risk_score += 15
                    risk_items.append(f"💥 {crash_count} 次系统崩溃/异常关机")

                if net_count > 20:
                    risk_score += 5

                # 风险等级
                if risk_score >= 60:
                    level_text = "🔴 高风险 - 强烈建议您仔细审查以下所有项目！"
                    level_tag = 'risk_high'
                elif risk_score >= 30:
                    level_text = "🟡 中等风险 - 存在值得关注的异常活动"
                    level_tag = 'risk_med'
                elif risk_score >= 10:
                    level_text = "🟢 低风险 - 有少量异常，建议关注"
                    level_tag = 'risk_low'
                else:
                    level_text = "✅ 未检测到明显异常"
                    level_tag = 'risk_ok'

                txt.insert(tk.END, f"  【风险评估】{level_text}\n")
                txt.insert(tk.END, f"  风险评分: {risk_score}/100\n\n")
                if risk_items:
                    txt.insert(tk.END, "  发现的可疑项:\n")
                    for item in risk_items:
                        txt.insert(tk.END, f"    {item}\n")
                txt.insert(tk.END, "\n")

                # ============ 第二部分：登录活动分析 ============
                txt.insert(tk.END, "─" * 60 + "\n")
                txt.insert(tk.END, f"  🔑 一、登录活动分析（{self.selected_date}）\n")
                txt.insert(tk.END, "─" * 60 + "\n\n")

                # 成功登录
                success_logins = report.get("recent_success_logins", [])
                if success_logins:
                    txt.insert(tk.END, f"  ▸ 成功登录: 共 {len(success_logins)} 次\n")
                    # 统计每个用户
                    user_counts = {}
                    for s in success_logins:
                        u = s.get('User', '?')
                        user_counts[u] = user_counts.get(u, 0) + 1
                    for u, c in user_counts.items():
                        txt.insert(tk.END, f"      {u}: {c} 次\n")
                    # 显示最近5条
                    txt.insert(tk.END, "\n  最近登录记录:\n")
                    for s in success_logins[:8]:
                        lt = s.get('LoginType', '?')
                        lt_desc = LOGIN_TYPE_MAP.get(lt, f"类型{lt}")
                        ws = s.get('Workstation', '')
                        ws_info = f" 来源:{ws}" if ws else ""
                        txt.insert(tk.END, f"      {s.get('Time','?')} | {s.get('User','?')} | {lt_desc}{ws_info}\n")
                else:
                    txt.insert(tk.END, "  ▸ 成功登录: (无数据，可能日志服务未开启或权限不足)\n")

                # 失败登录 - 最可疑
                failed_logins = report.get("failed_logins", [])
                txt.insert(tk.END, f"\n  ▸ 登录失败: 共 {len(failed_logins)} 次 {('⚠️ 有人可能在尝试破解密码！' if len(failed_logins) > 3 else '')}\n")
                if failed_logins:
                    fail_users = {}
                    for f in failed_logins:
                        u = f.get('User', '?')
                        fail_users[u] = fail_users.get(u, 0) + 1
                    for u, c in fail_users.items():
                        txt.insert(tk.END, f"      目标账户: {u} - 失败 {c} 次\n")
                    txt.insert(tk.END, "\n  最近失败记录:\n")
                    for f in failed_logins[:5]:
                        ws = f.get('Workstation', '')
                        ws_info = f" 来源:{ws}" if ws else ""
                        txt.insert(tk.END, f"      {f.get('Time','?')} | 尝试登录: {f.get('User','?')}{ws_info}\n")

                # 深夜登录
                night_logins = report.get("night_logins", [])
                if night_logins:
                    txt.insert(tk.END, f"\n  ▸ 🌙 深夜登录 (22:00-06:00): {len(night_logins)} 次 (非常可疑！)\n")
                    for n in night_logins[:5]:
                        lt = n.get('LoginType', '?')
                        lt_desc = LOGIN_TYPE_MAP.get(lt, f"类型{lt}")
                        txt.insert(tk.END, f"      {n.get('Time','?')} | {n.get('User','?')} | {lt_desc}\n")

                # 远程登录
                remote_logins = report.get("admin_logins", [])
                if remote_logins:
                    txt.insert(tk.END, f"\n  ▸ 🖥️ 远程桌面/特权登录: {len(remote_logins)} 次\n")
                    for r in remote_logins[:5]:
                        lt = r.get('LoginType', '?')
                        lt_desc = LOGIN_TYPE_MAP.get(lt, f"类型{lt}")
                        txt.insert(tk.END, f"      {r.get('Time','?')} | {r.get('User','?')} | {lt_desc}\n")

                # ============ 第三部分：系统异常事件 ============
                txt.insert(tk.END, "\n" + "─" * 60 + "\n")
                txt.insert(tk.END, f"  💥 二、系统异常事件（{self.selected_date}）\n")
                txt.insert(tk.END, "─" * 60 + "\n\n")

                crashes = report.get("system_crashes", [])
                if crashes:
                    CRASH_MEANING = {
                        "41": "系统意外重启（断电/强制关机/蓝屏）",
                        "1001": "系统故障记录（蓝屏诊断）",
                        "6008": "上一次系统关闭是意外的（非正常关机）",
                    }
                    txt.insert(tk.END, f"  共 {len(crashes)} 次异常事件:\n\n")
                    for c in crashes[:10]:
                        eid_str = str(c.get('ID', '?'))
                        meaning = CRASH_MEANING.get(eid_str, get_event_meaning(eid_str, ''))
                        txt.insert(tk.END, f"  [{eid_str}] {c.get('Time','?')} - {meaning}\n")
                else:
                    txt.insert(tk.END, "  ✅ 未发现系统异常事件\n")

                # ============ 第四部分：USB 设备记录 ============
                txt.insert(tk.END, "\n" + "─" * 60 + "\n")
                txt.insert(tk.END, "  🔌 三、USB 设备连接记录\n")
                txt.insert(tk.END, "─" * 60 + "\n\n")

                usb = report.get("usb_devices", [])
                if usb:
                    txt.insert(tk.END, f"  历史上连接过 {len(usb)} 个 USB 设备:\n\n")
                    for u in usb[:20]:
                        name = u.get('Name', u.get('DeviceID', '未知设备'))
                        mfg = u.get('Mfg', '')
                        mfg_info = f" [{mfg}]" if mfg else ""
                        dev_id = u.get('DeviceID', '')[:30]
                        txt.insert(tk.END, f"  • {name}{mfg_info}\n")
                        if dev_id:
                            txt.insert(tk.END, f"    ID: {dev_id}\n")
                else:
                    txt.insert(tk.END, "  (无数据)\n")

                # ============ 第五部分：最近文件变动 ============
                txt.insert(tk.END, "\n" + "─" * 60 + "\n")
                txt.insert(tk.END, f"  📁 四、最近文件变动（{self.selected_date}）\n")
                txt.insert(tk.END, "─" * 60 + "\n\n")

                files = report.get("recent_files", [])
                if files:
                    txt.insert(tk.END, f"  {self.selected_date}共有 {len(files)} 个文件发生过修改:\n\n")
                    for f_item in files[:15]:
                        name = f_item.get('Name', '?')
                        mtime = f_item.get('LastModified', '?')
                        path = f_item.get('Path', '?')
                        txt.insert(tk.END, f"  {mtime} | {name}\n")
                        txt.insert(tk.END, f"           {path}\n")
                else:
                    txt.insert(tk.END, "  (无数据)\n")

                # ============ 第六部分：网络连接 ============
                txt.insert(tk.END, "\n" + "─" * 60 + "\n")
                txt.insert(tk.END, "  🌐 五、当前活跃网络连接\n")
                txt.insert(tk.END, "─" * 60 + "\n\n")

                net = report.get("active_network", [])
                if net:
                    txt.insert(tk.END, f"  当前 {len(net)} 个活跃连接:\n\n")
                    # 统计外部连接
                    external = [n for n in net if not str(n.get('RemoteAddress', '')).startswith(('127.', '192.168.', '10.', '172.16', '172.17'))]
                    if external:
                        txt.insert(tk.END, f"  ⚠️ 其中 {len(external)} 个连接指向外部地址:\n")
                        for n in external[:10]:
                            proc = n.get('Process', '?')
                            remote = n.get('RemoteAddress', '?')
                            txt.insert(tk.END, f"  → {remote} (进程: {proc})\n")
                    # 显示其他连接
                    local_net = [n for n in net if n not in external]
                    for n in local_net[:5]:
                        proc = n.get('Process', '?')
                        remote = n.get('RemoteAddress', '?')
                        txt.insert(tk.END, f"  → {remote} (进程: {proc})\n")
                else:
                    txt.insert(tk.END, "  (无数据，可能需要管理员权限)\n")

                # ============ 第七部分：建议 ============
                txt.insert(tk.END, "\n" + "─" * 60 + "\n")
                txt.insert(tk.END, "  💡 六、安全建议\n")
                txt.insert(tk.END, "─" * 60 + "\n\n")

                if risk_score >= 60:
                    txt.insert(tk.END, "  1. 立即修改您的 Windows 登录密码\n")
                    txt.insert(tk.END, "  2. 检查是否有不明远程连接\n")
                    txt.insert(tk.END, "  3. 检查是否安装了不明软件\n")
                    txt.insert(tk.END, "  4. 运行杀毒软件全盘扫描\n")
                    txt.insert(tk.END, "  5. 确认 USB 设备列表中是否有不认识的设备\n")
                elif risk_score >= 30:
                    txt.insert(tk.END, "  1. 确认深夜登录是否为您本人的操作\n")
                    txt.insert(tk.END, "  2. 检查登录失败记录，确认是否有异常\n")
                    txt.insert(tk.END, "  3. 定期更换密码以提高安全性\n")
                else:
                    txt.insert(tk.END, "  ✅ 当前未发现明显异常\n")
                    txt.insert(tk.END, "  建议定期查看本报告，保持安全意识\n")
                    txt.insert(tk.END, "  • 离开电脑时按 Win+L 锁定屏幕\n")
                    txt.insert(tk.END, "  • 不要将密码告诉他人\n")

                txt.insert(tk.END, "\n" + "═" * 60 + "\n")
                txt.insert(tk.END, "  报告结束 | 双击其他标签页可查看详细原始数据\n")
                txt.insert(tk.END, "═" * 60 + "\n")

                # 样式标记
                txt.tag_configure('risk_high', foreground='red', font=('Consolas', 11, 'bold'))
                txt.tag_configure('risk_med', foreground='orange', font=('Consolas', 10, 'bold'))
                txt.tag_configure('risk_low', foreground='#8B8000', font=('Consolas', 10, 'bold'))
                txt.tag_configure('risk_ok', foreground='green', font=('Consolas', 10, 'bold'))

                # 插入风险标签
                txt.insert(tk.END, "")  # dummy
                start = "1.0"
                while True:
                    pos = txt.search("🔴 高风险", start, tk.END)
                    if not pos:
                        break
                    end = f"{pos}+14c"
                    txt.tag_add('risk_high', pos, end)
                    start = end
                start = "1.0"
                while True:
                    pos = txt.search("🟡 中等风险", start, tk.END)
                    if not pos:
                        break
                    end = f"{pos}+14c"
                    txt.tag_add('risk_med', pos, end)
                    start = end
                start = "1.0"
                while True:
                    pos = txt.search("🟢 低风险", start, tk.END)
                    if not pos:
                        break
                    end = f"{pos}+13c"
                    txt.tag_add('risk_low', pos, end)
                    start = end
                start = "1.0"
                while True:
                    pos = txt.search("✅ 未检测到明显异常", start, tk.END)
                    if not pos:
                        break
                    end = f"{pos}+14c"
                    txt.tag_add('risk_ok', pos, end)
                    start = end

                txt.config(state=tk.DISABLED)
                self.status_label.config(text="✅ 异常检测完成", foreground="green")

            self.root.after(0, update_ui)

        thread = threading.Thread(target=do_fetch, daemon=True)
        thread.start()

    def _load_sysinfo(self):
        """加载系统信息到文本区域"""
        def do_fetch():
            self.root.after(0, lambda: self.status_label.config(text="⏳ 正在加载系统信息...", foreground="blue"))
            
            info = DataFetcher.get_system_info()
            disk = DataFetcher.get_disk_info()
            tasks = DataFetcher.get_scheduled_tasks()
            services = DataFetcher.get_services()

            def update_ui():
                self.sysinfo_text.config(state=tk.NORMAL)
                self.sysinfo_text.delete(1.0, tk.END)
                
                # 系统信息
                if info:
                    self.sysinfo_text.insert(tk.END, "═" * 60 + "\n")
                    self.sysinfo_text.insert(tk.END, "  🖥️  系统基本信息\n")
                    self.sysinfo_text.insert(tk.END, "═" * 60 + "\n")
                    for key, val in info.items():
                        label = {
                            "Hostname": "主机名", "OS": "操作系统", "Version": "版本号",
                            "Build": "构建号", "Architecture": "系统架构",
                            "InstallDate": "安装日期", "LastBoot": "最后启动",
                            "Uptime": "运行时间", "Manufacturer": "制造商", "Model": "型号",
                            "TotalRAM_GB": "总内存(GB)", "CPU": "处理器",
                            "Cores": "核心数", "BIOS": "BIOS版本",
                            "SerialNumber": "序列号", "CurrentUser": "当前用户"
                        }.get(key, key)
                        self.sysinfo_text.insert(tk.END, f"  {label:12s}: {val}\n")
                
                # 磁盘信息
                if disk:
                    self.sysinfo_text.insert(tk.END, "\n" + "═" * 60 + "\n")
                    self.sysinfo_text.insert(tk.END, "  💾 磁盘信息\n")
                    self.sysinfo_text.insert(tk.END, "═" * 60 + "\n")
                    for d in disk:
                        self.sysinfo_text.insert(tk.END, 
                            f"  {safe_str(d.get('Drive','')):5s} {safe_str(d.get('Label','')):15s} "
                            f"总容量: {safe_str(d.get('TotalGB','')):>7s} GB  "
                            f"已用: {safe_str(d.get('UsedPercent',''))}%\n")

                # 计划任务
                if tasks:
                    self.sysinfo_text.insert(tk.END, "\n" + "═" * 60 + "\n")
                    self.sysinfo_text.insert(tk.END, f"  📅 计划任务（共 {len(tasks)} 个活跃任务）\n")
                    self.sysinfo_text.insert(tk.END, "═" * 60 + "\n")
                    for t in tasks[:50]:
                        self.sysinfo_text.insert(tk.END, 
                            f"  [{safe_str(t.get('State',''))}] {safe_str(t.get('Path',''))}{safe_str(t.get('Name',''))}\n")

                # 服务状态
                if services:
                    self.sysinfo_text.insert(tk.END, "\n" + "═" * 60 + "\n")
                    self.sysinfo_text.insert(tk.END, f"  ⚙️ 服务状态（共 {len(services)} 个）\n")
                    self.sysinfo_text.insert(tk.END, "═" * 60 + "\n")
                    running = [s for s in services if s.get('Status') == 'Running']
                    stopped = [s for s in services if s.get('Status') == 'Stopped']
                    self.sysinfo_text.insert(tk.END, f"  运行中: {len(running)} | 已停止: {len(stopped)}\n\n")
                    for s in services[:50]:
                        status_icon = "🟢" if s.get('Status') == 'Running' else "🔴"
                        self.sysinfo_text.insert(tk.END,
                            f"  {status_icon} {safe_str(s.get('DisplayName',''))[:50]}\n"
                            f"     状态: {safe_str(s.get('Status',''))} | 启动类型: {safe_str(s.get('StartType',''))}\n")

                self.sysinfo_text.config(state=tk.DISABLED)
                self.status_label.config(text="✅ 系统信息加载完成", foreground="green")

            self.root.after(0, update_ui)

        thread = threading.Thread(target=do_fetch, daemon=True)
        thread.start()

    def _on_date_changed(self, event=None):
        """日期范围变更"""
        selected = self.date_var.get()
        self.selected_date = self.date_value_map.get(selected, datetime.date.today().strftime('%Y-%m-%d'))
        self.status_bar.config(text=f"已选择日期: {self.selected_date} | 正在刷新...")
        # 自动刷新当前页
        self._refresh_current()

    def _on_tab_changed(self, event):
        """标签页切换事件"""
        current = self.notebook.select()
        tab_text = self.notebook.tab(current, "text")
        self.status_bar.config(text=f"当前: {tab_text} | Ctrl+F 搜索 | Ctrl+R 刷新")

    def _on_search(self, event=None):
        """搜索过滤"""
        query = self.search_var.get().lower()
        current_tab = self.notebook.select()
        
        for tag_name, tree in self.treeviews.items():
            tab_widget = tree.master.master.master  # 获取 tab frame
            if str(tab_widget) == str(self.notebook.nametowidget(current_tab)):
                data = self.current_data.get(tag_name, [])
                
                # 清空
                for item in tree.get_children():
                    tree.delete(item)

                if not query:
                    # 恢复全部数据
                    for item in data:
                        values = self._extract_values(item, tree['columns'])
                        tree.insert('', 'end', values=values)
                    return

                # 过滤
                count = 0
                for item in data:
                    values = self._extract_values(item, tree['columns'])
                    if any(query in str(v).lower() for v in values):
                        tree.insert('', 'end', values=values)
                        count += 1

                self.status_bar.config(text=f"搜索 '{query}' - 匹配 {count} 条记录")
                break

    def _clear_search(self):
        """清除搜索"""
        self.search_var.set("")
        self._on_search()

    def _focus_search(self):
        """聚焦搜索框"""
        self.search_entry.focus_set()

    def _refresh_current(self):
        """刷新当前标签页"""
        current = self.notebook.select()
        tab_text = self.notebook.tab(current, "text")
        
        refresh_map = {
            "� 异常检测": ("anomaly", self._load_anomaly),
            "� 系统日志": ("system", DataFetcher.get_system_events),
            "🔒 安全日志": ("security", DataFetcher.get_security_events),
            "📱 应用日志": ("application", DataFetcher.get_application_events),
            "👤 登录记录": ("login", DataFetcher.get_login_history),
            "🔌 USB历史": ("usb", DataFetcher.get_usb_history),
            "📁 文件改动": ("files", DataFetcher.get_recent_files),
            "▶️ 进程历史": ("process", DataFetcher.get_process_history),
            "🌐 网络连接": ("network", DataFetcher.get_network_connections),
            "📦 已装软件": ("software", DataFetcher.get_installed_software),
            "🖥️ 系统信息": ("sysinfo", self._load_sysinfo),
        }

        # 不需要日期参数的标签
        no_days_tags = {"usb", "network", "software", "sysinfo"}

        if tab_text in refresh_map:
            tag, func = refresh_map[tab_text]
            if tag in ("sysinfo", "anomaly"):
                func()
            else:
                tree = self.treeviews[tag]
                columns = tree['columns']
                # 找 count_label
                parent = tree.master.master
                count_label = None
                for child in parent.winfo_children():
                    if isinstance(child, ttk.Frame):
                        for c in child.winfo_children():
                            if isinstance(c, ttk.Label):
                                count_label = c
                                break
                needs_days = tag not in no_days_tags
                self._load_data_async(func, tag, columns, count_label, needs_days)

    def _sort_treeview(self, tree, col, reverse):
        """排序 TreeView"""
        try:
            data = [(tree.set(child, col), child) for child in tree.get_children('')]
            # 尝试数值排序
            try:
                data.sort(key=lambda x: float(x[0]) if x[0] else 0, reverse=reverse)
            except:
                data.sort(key=lambda x: x[0].lower(), reverse=reverse)
            
            for idx, (_, child) in enumerate(data):
                tree.move(child, '', idx)
            
            tree.heading(col, command=lambda: self._sort_treeview(tree, col, not reverse))
        except:
            pass

    def _export_csv(self):
        """导出当前数据为 CSV"""
        current = self.notebook.select()
        tab_text = self.notebook.tab(current, "text")
        
        # 找到对应数据
        export_map = {
            "📋 系统日志": "system",
            "🔒 安全日志": "security",
            "📱 应用日志": "application",
            "👤 登录记录": "login",
            "🔌 USB历史": "usb",
            "📁 文件改动": "files",
            "▶️ 进程历史": "process",
            "🌐 网络连接": "network",
            "📦 已装软件": "software",
        }

        import csv
        from tkinter import filedialog

        if tab_text in export_map:
            tag = export_map[tab_text]
            data = self.current_data.get(tag, [])
            tree = self.treeviews.get(tag)
            if not tree or not data:
                messagebox.showwarning("导出失败", "没有数据可导出")
                return
            
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
                initialfile=f"{tag}_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            if filepath:
                try:
                    columns = tree['columns']
                    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                        writer = csv.writer(f)
                        writer.writerow(columns)
                        for item in data:
                            writer.writerow(self._extract_values(item, columns))
                    messagebox.showinfo("导出成功", f"数据已导出到:\n{filepath}")
                    os.startfile(os.path.dirname(filepath))
                except Exception as e:
                    messagebox.showerror("导出失败", str(e))
        elif tab_text in ("🖥️ 系统信息", "🔍 异常检测"):
            prefix = "anomaly" if "异常" in tab_text else "system_info"
            content = self.anomaly_text.get(1.0, tk.END) if "异常" in tab_text else self.sysinfo_text.get(1.0, tk.END)
            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                initialfile=f"{prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filepath:
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                    messagebox.showinfo("导出成功", f"数据已导出到:\n{filepath}")
                    os.startfile(os.path.dirname(filepath))
                except Exception as e:
                    messagebox.showerror("导出失败", str(e))

# ==================== 主入口 ====================

def main():
    root = tk.Tk()

    # 设置样式
    style = ttk.Style()
    style.theme_use('clam')
    
    # 配置字体
    default_font = ("微软雅黑", 9)
    root.option_add('*Font', default_font)
    
    # Treeview 样式
    style.configure("Treeview", font=("微软雅黑", 9), rowheight=22)
    style.configure("Treeview.Heading", font=("微软雅黑", 9, "bold"))
    
    app = LogViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
