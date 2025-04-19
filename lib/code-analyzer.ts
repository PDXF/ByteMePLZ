// Regular expressions for detecting Discord webhooks and suspicious connections
const DISCORD_WEBHOOK_PATTERNS = [
  // Discord webhook URLs
  /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/(\d+)\/([A-Za-z0-9.\-_]+)/g,
  /https:\/\/(?:ptb\.|canary\.)?discord\.com\/api\/v\d+\/webhooks\/(\d+)\/([A-Za-z0-9.\-_]+)/g,
  // Discord webhook variables or strings
  /webhook_url\s*=\s*["']https:\/\/discord/g,
  /WEBHOOK_URL\s*=\s*["']https:\/\/discord/g,
  /webhook\s*=\s*["']https:\/\/discord/g,
]

// Malware behavior patterns
const MALWARE_BEHAVIORS = [
  // Keyloggers
  {
    name: "KeyGhost - Keylogger",
    description: "Code that captures keyboard input, often using SetWindowsHookEx or similar methods",
    patterns: [
      /SetWindowsHookEx\s*\(\s*WH_KEYBOARD/g,
      /keyboard_hook|keylogger|keystroke|GetAsyncKeyState/gi,
      /pynput\.keyboard|keyboard\.on_press/g,
      /InputEvent\.KEY_PRESSED/g,
    ],
    severity: "high",
    languages: ["cpp", "python", "java", "csharp"],
  },
  // Remote shells
  {
    name: "GhostShell - Hidden Reverse Shell",
    description: "Code that establishes a reverse shell connection to a remote server",
    patterns: [
      /socket\s*\.\s*connect\s*$$\s*$$\s*["']\w+["']\s*,\s*\d+\s*$$\s*$$/g,
      /reverse_shell|bind_shell|backdoor/gi,
      /subprocess\.Popen\s*\(\s*\[["'](?:bash|cmd|powershell)["']/g,
      /new\s+Socket\s*$$\s*["']\w+["']\s*,\s*\d+\s*$$/g,
    ],
    severity: "high",
    languages: ["python", "powershell", "bash", "cpp", "java"],
  },
  // Discord abuse
  {
    name: "InstaRAT - Discord API Abuse",
    description: "Code that uses Discord API for command and control or data exfiltration",
    patterns: [
      /discord\.(?:py|js|webhook)/g,
      /discord_webhook|discordwebhook/gi,
      /requests\.post\s*\(\s*["']https:\/\/discord/g,
      /fetch\s*\(\s*["']https:\/\/discord/g,
    ],
    severity: "high",
    languages: ["python", "javascript", "powershell"],
  },
  // Screen capture
  {
    name: "ScreenPeek - Screen Capture",
    description: "Code that captures screenshots, potentially for spying",
    patterns: [
      /screenshot|screen_capture|capture_screen/gi,
      /pyautogui\.screenshot/g,
      /ImageGrab\.grab/g,
      /Robot\s*$$\s*$$\.createScreenCapture/g,
      /time\.sleep\s*$$\s*[1-9]\d*\s*$$|Thread\.sleep\s*$$\s*\d+\s*$$/g,
    ],
    severity: "medium",
    languages: ["python", "java", "csharp", "javascript"],
  },
  // Webcam access
  {
    name: "CamCreep - Webcam Spy",
    description: "Code that accesses the webcam without clear user consent",
    patterns: [
      /webcam|camera_capture|cv2\.VideoCapture/gi,
      /getUserMedia\s*\(\s*\{.*?video/g,
      /openCV|opencv/gi,
      /navigator\.mediaDevices/g,
    ],
    severity: "high",
    languages: ["python", "javascript", "cpp", "java"],
  },
  // Audio capture
  {
    name: "MicSniff - Audio Capture",
    description: "Code that records audio from the microphone",
    patterns: [
      /microphone|audio_capture|record_audio/gi,
      /pyaudio\.PyAudio/g,
      /AudioRecord|AudioCapture/g,
      /getUserMedia\s*\(\s*\{.*?audio/g,
    ],
    severity: "high",
    languages: ["python", "javascript", "java", "csharp"],
  },
  // Discord token theft
  {
    name: "TokenSnatch - Discord Token Theft",
    description: "Code that attempts to steal Discord tokens from local storage",
    patterns: [
      /discord.*?token|token.*?discord/gi,
      /LocalStorage.*?discord/g,
      /appdata.*?discord/gi,
      /roaming.*?discord/gi,
    ],
    severity: "high",
    languages: ["javascript", "python", "powershell"],
  },
  // Password stealing
  {
    name: "PassSniff - Password Theft",
    description: "Code that attempts to extract passwords from browsers or the system",
    patterns: [
      /password|credential|login/gi,
      /chrome.*?password|firefox.*?password/gi,
      /sqlite.*?login/gi,
      /os\.getenv\s*$$\s*["']USERPROFILE["']\s*$$/g,
    ],
    severity: "high",
    languages: ["python", "javascript", "powershell", "cpp"],
  },
  // Memory dumping
  {
    name: "CredDump32 - Memory Extraction",
    description: "Code that attempts to extract sensitive data from memory",
    patterns: [
      /lsass|minidump|MiniDumpWriteDump/gi,
      /process.*?memory|memory.*?dump/gi,
      /OpenProcess\s*\(\s*PROCESS_/g,
      /ReadProcessMemory/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp", "powershell"],
  },
  // Dropper behavior
  {
    name: "DropMeBaby - Malware Dropper",
    description: "Code that downloads and executes additional payloads",
    patterns: [
      /download.*?execute|execute.*?download/gi,
      /wget|curl|Invoke-WebRequest|DownloadFile/g,
      /temp.*?\.exe|%temp%/gi,
      /Process\.Start\s*\(\s*["'].*?\.exe["']/g,
    ],
    severity: "high",
    languages: ["batch", "powershell", "python", "csharp"],
  },
  // File encryption (ransomware)
  {
    name: "FileCrypter - Ransomware Behavior",
    description: "Code that encrypts files, potentially for ransomware",
    patterns: [
      /encrypt.*?file|file.*?encrypt/gi,
      /AES|RSA|Crypto|cipher/g,
      /\.encrypt\s*\(|Cipher\./g,
      /ransom|payment|bitcoin|wallet/gi,
    ],
    severity: "high",
    languages: ["python", "java", "csharp", "javascript"],
  },
  // Obfuscation
  {
    name: "XorDropper - Obfuscation Techniques",
    description: "Code that uses obfuscation to hide its true purpose",
    patterns: [
      /xor|base64|rot13|encode|decode/gi,
      /eval\s*\(|exec\s*\(/g,
      /chr\s*$$\s*\d+\s*$$|String\.fromCharCode/g,
      /\\x[0-9a-f]{2}/gi,
    ],
    severity: "medium",
    languages: ["python", "javascript", "powershell", "batch"],
  },
  // Clipboard manipulation
  {
    name: "ClipSteal - Clipboard Attack",
    description: "Code that monitors or modifies the clipboard",
    patterns: [
      /clipboard|clip_board|GetClipboardData/gi,
      /pyperclip|clipboard\.get|clipboard\.set/g,
      /Clipboard\.GetText|Clipboard\.SetText/g,
      /navigator\.clipboard/g,
    ],
    severity: "medium",
    languages: ["python", "javascript", "csharp", "cpp"],
  },
  // USB infection
  {
    name: "AutoRunUSB - USB Spreader",
    description: "Code that attempts to spread via USB drives",
    patterns: [
      /autorun\.inf|autorun|usb.*?drive/gi,
      /DriveInfo\.GetDrives/g,
      /removable.*?drive|drive.*?removable/gi,
      /wmic\s+logicaldisk/g,
    ],
    severity: "high",
    languages: ["batch", "csharp", "python", "powershell"],
  },
  // Browser history theft
  {
    name: "WebSpy - Browser History Theft",
    description: "Code that extracts browser history or cookies",
    patterns: [
      /history|cookie|browser.*?data/gi,
      /chrome.*?history|firefox.*?history/gi,
      /sqlite.*?places\.sqlite/g,
      /AppData.*?Google.*?Chrome/g,
    ],
    severity: "medium",
    languages: ["python", "javascript", "powershell"],
  },
  // Memory scanning
  {
    name: "RAMScan - Memory Scanning",
    description: "Code that scans memory for sensitive data patterns like credit card numbers",
    patterns: [
      /memory.*?scan|scan.*?memory/gi,
      /credit.*?card|card.*?number/gi,
      /regex.*?search|pattern.*?match/gi,
      /ReadProcessMemory|VirtualQueryEx/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp", "python"],
  },
  // Persistence mechanisms
  {
    name: "RegBackdoor - Registry Persistence",
    description: "Code that modifies registry for persistence",
    patterns: [
      /registry|regedit|reg\s+add/gi,
      /HKEY_LOCAL_MACHINE.*?Run|HKEY_CURRENT_USER.*?Run/gi,
      /HKLM|HKCU|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/g,
      /Registry\.SetValue/g,
    ],
    severity: "high",
    languages: ["powershell", "batch", "csharp", "cpp"],
  },
  // Scheduled tasks
  {
    name: "TaskPersister - Scheduled Task Creation",
    description: "Code that creates scheduled tasks for persistence",
    patterns: [
      /schtasks|scheduled.*?task|task.*?scheduler/gi,
      /cron|crontab|at\s+command/gi,
      /TaskScheduler|ScheduledTask/g,
      /TASK_CREATE/g,
    ],
    severity: "high",
    languages: ["batch", "powershell", "csharp", "python"],
  },
  // WMI abuse
  {
    name: "WMIExec - WMI Abuse",
    description: "Code that uses WMI for execution or persistence",
    patterns: [
      /WMI|wmic|Win32_Process/gi,
      /ManagementObject|ManagementClass/g,
      /Invoke-WmiMethod|Get-WmiObject/g,
      /SELECT\s+\*\s+FROM\s+Win32_/gi,
    ],
    severity: "medium",
    languages: ["powershell", "csharp", "batch"],
  },
  // Anti-analysis techniques
  {
    name: "VMDetector - Anti-VM Techniques",
    description: "Code that attempts to detect virtual machines or sandboxes",
    patterns: [
      /vmware|virtualbox|virtual.*?machine|sandbox/gi,
      /check.*?vm|detect.*?vm/gi,
      /hypervisor|hyper-v|qemu|kvm/gi,
      /GetSystemFirmwareTable/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp", "powershell", "python"],
  },
  // Process injection
  {
    name: "RemoteThreader - Process Injection",
    description: "Code that injects into other processes",
    patterns: [
      /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory/g,
      /process.*?inject|inject.*?process/gi,
      /OpenProcess\s*\(\s*PROCESS_/g,
      /memoryapi|memory_basic_information/gi,
    ],
    severity: "high",
    languages: ["cpp", "csharp"],
  },
  // DNS tunneling
  {
    name: "DNSMessenger - DNS Tunneling",
    description: "Code that uses DNS for command and control or data exfiltration",
    patterns: [
      /dns.*?tunnel|tunnel.*?dns/gi,
      /dns.*?query|query.*?dns/gi,
      /nslookup|dig\s+command|Resolve-DnsName/g,
      /TXT.*?record|record.*?TXT/gi,
    ],
    severity: "high",
    languages: ["python", "powershell", "bash"],
  },
  // Named pipes
  {
    name: "PipeTalker - Named Pipes",
    description: "Code that uses named pipes for inter-process communication",
    patterns: [
      /named.*?pipe|pipe.*?name/gi,
      /CreateNamedPipe|ConnectNamedPipe/g,
      /\\\\.\\pipe\\/g,
      /NamedPipeClientStream|NamedPipeServerStream/g,
    ],
    severity: "medium",
    languages: ["cpp", "csharp", "powershell"],
  },
  // Event log tampering
  {
    name: "EventLoggerKiller - Log Tampering",
    description: "Code that disables or clears event logs",
    patterns: [
      /event.*?log.*?clear|clear.*?event.*?log/gi,
      /wevtutil\s+cl|Clear-EventLog/g,
      /EventLog\.Clear/g,
      /event.*?log.*?disable|disable.*?event.*?log/gi,
    ],
    severity: "high",
    languages: ["powershell", "batch", "csharp"],
  },
  // ARP spoofing
  {
    name: "ARPSpoofer - ARP Poisoning",
    description: "Code that performs ARP spoofing for MITM attacks",
    patterns: [
      /arp.*?spoof|spoof.*?arp/gi,
      /arp.*?poison|poison.*?arp/gi,
      /scapy\.ARP|scapy\.send/g,
      /arpspoof|ettercap/g,
    ],
    severity: "high",
    languages: ["python", "bash"],
  },
  // Self-deletion
  {
    name: "SelfDestruct - Self-Deletion",
    description: "Code that deletes itself after execution",
    patterns: [
      /self.*?delete|delete.*?self/gi,
      /batch.*?delete|delete.*?batch/gi,
      /del\s+%0|del\s+"%~f0"/g,
      /os\.remove\s*$$\s*__file__\s*$$/g,
    ],
    severity: "medium",
    languages: ["batch", "python", "powershell"],
  },
  // Steganography
  {
    name: "PngPayload - Steganography",
    description: "Code that hides data in images or other files",
    patterns: [
      /steg(?:o|ano)(?:graphy)?/gi,
      /hide.*?data|data.*?hide/gi,
      /lsb.*?image|image.*?lsb/gi,
      /PIL\.Image|cv2\.imread/g,
    ],
    severity: "medium",
    languages: ["python", "java", "cpp"],
  },
  // Fileless malware
  {
    name: "MemoryOnly - Fileless Malware",
    description: "Code that operates entirely in memory without writing to disk",
    patterns: [
      /fileless|memory.*?only/gi,
      /IEX\s*$$\s*New-Object\s+Net\.WebClient\s*$$\.DownloadString/g,
      /eval\s*\(\s*download/gi,
      /reflective.*?load|load.*?reflective/gi,
    ],
    severity: "high",
    languages: ["powershell", "javascript"],
  },
  // Additional malware types
  {
    name: "ShadowCopy - Volume Shadow Copy Deletion",
    description: "Code that deletes volume shadow copies to prevent recovery",
    patterns: [
      /vssadmin\s+delete\s+shadows/gi,
      /wmic\s+shadowcopy\s+delete/gi,
      /Win32_ShadowCopy/gi,
      /Delete.*?Shadow/gi,
    ],
    severity: "high",
    languages: ["batch", "powershell", "csharp"],
  },
  {
    name: "CronInject - Crontab Manipulation",
    description: "Code that modifies crontab for persistence on Unix systems",
    patterns: [/crontab\s+-e/g, /\/etc\/cron\./g, /append.*?crontab|crontab.*?append/gi, /write.*?cron|cron.*?write/gi],
    severity: "high",
    languages: ["python", "bash", "ruby"],
  },
  {
    name: "SudoStealer - Sudo Credential Theft",
    description: "Code that attempts to steal sudo credentials on Unix systems",
    patterns: [/\/etc\/sudoers/g, /sudo\s+-S/g, /SUDO_ASKPASS/g, /sudo.*?password|password.*?sudo/gi],
    severity: "high",
    languages: ["bash", "python", "ruby"],
  },
  {
    name: "SSHBackdoor - SSH Key Manipulation",
    description: "Code that manipulates SSH keys for unauthorized access",
    patterns: [/\.ssh\/authorized_keys/g, /ssh-keygen/g, /id_rsa|id_dsa|id_ecdsa/g, /ssh.*?key|key.*?ssh/gi],
    severity: "high",
    languages: ["bash", "python", "ruby"],
  },
  {
    name: "CertThief - Certificate Theft",
    description: "Code that extracts or manipulates SSL/TLS certificates",
    patterns: [
      /certificate.*?store|store.*?certificate/gi,
      /X509Certificate|X509Store/g,
      /certmgr|certutil/g,
      /\.pfx|\.p12|\.crt|\.pem/g,
    ],
    severity: "high",
    languages: ["csharp", "powershell", "cpp"],
  },
  {
    name: "BrowserPivot - Browser Session Hijacking",
    description: "Code that attempts to hijack browser sessions",
    patterns: [
      /cookie.*?theft|theft.*?cookie/gi,
      /session.*?hijack|hijack.*?session/gi,
      /browser.*?profile|profile.*?browser/gi,
      /chrome.*?session|firefox.*?session/gi,
    ],
    severity: "high",
    languages: ["python", "javascript", "ruby"],
  },
  {
    name: "DomainHarvester - Domain Credential Harvesting",
    description: "Code that attempts to harvest domain credentials",
    patterns: [
      /LDAP.*?query|query.*?LDAP/gi,
      /domain.*?controller|controller.*?domain/gi,
      /kerberos.*?ticket|ticket.*?kerberos/gi,
      /mimikatz|sekurlsa/gi,
    ],
    severity: "high",
    languages: ["powershell", "csharp", "cpp"],
  },
  {
    name: "SysmonWiper - Sysmon Log Deletion",
    description: "Code that attempts to disable or delete Sysmon logs",
    patterns: [
      /Sysmon.*?log|log.*?Sysmon/gi,
      /uninstall.*?sysmon|sysmon.*?uninstall/gi,
      /Microsoft-Windows-Sysmon/g,
      /sc\s+delete\s+Sysmon/g,
    ],
    severity: "high",
    languages: ["powershell", "batch"],
  },
  {
    name: "DefenderBypass - Antivirus Bypass",
    description: "Code that attempts to bypass or disable Windows Defender",
    patterns: [
      /defender.*?bypass|bypass.*?defender/gi,
      /disable.*?defender|defender.*?disable/gi,
      /Set-MpPreference/g,
      /Add-MpPreference/g,
    ],
    severity: "high",
    languages: ["powershell", "batch", "csharp"],
  },
  {
    name: "FirewallDisabler - Firewall Manipulation",
    description: "Code that disables or modifies firewall settings",
    patterns: [
      /firewall.*?disable|disable.*?firewall/gi,
      /netsh\s+advfirewall/g,
      /Set-NetFirewallProfile/g,
      /iptables\s+-F/g,
    ],
    severity: "high",
    languages: ["powershell", "batch", "bash"],
  },
  {
    name: "UACBypass - UAC Bypass Techniques",
    description: "Code that attempts to bypass User Account Control",
    patterns: [
      /UAC.*?bypass|bypass.*?UAC/gi,
      /eventvwr|fodhelper|sdclt/g,
      /ConsentPromptBehaviorAdmin/g,
      /IEInstal|RunAs|ShellExecute.*?runas/gi,
    ],
    severity: "high",
    languages: ["powershell", "batch", "csharp"],
  },
  {
    name: "CredentialVault - Windows Credential Vault Access",
    description: "Code that attempts to access the Windows Credential Vault",
    patterns: [
      /credential.*?vault|vault.*?credential/gi,
      /CredRead|CredEnum|CredWrite/g,
      /vaultcli|VaultEnumerateItems/g,
      /dpapi.*?master/gi,
    ],
    severity: "high",
    languages: ["cpp", "csharp", "powershell"],
  },
  {
    name: "TokenImpersonator - Token Impersonation",
    description: "Code that performs token impersonation or theft",
    patterns: [
      /token.*?impersonation|impersonation.*?token/gi,
      /DuplicateToken|ImpersonateLoggedOnUser/g,
      /SeImpersonatePrivilege/g,
      /GetTokenInformation/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp"],
  },
  {
    name: "ProcessHollower - Process Hollowing",
    description: "Code that performs process hollowing to hide malicious code",
    patterns: [
      /process.*?hollow|hollow.*?process/gi,
      /ZwUnmapViewOfSection|NtUnmapViewOfSection/g,
      /WriteProcessMemory.*?GetThreadContext/g,
      /SetThreadContext|ResumeThread/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp"],
  },
  {
    name: "DLLHijacker - DLL Hijacking",
    description: "Code that performs DLL hijacking or side-loading",
    patterns: [
      /dll.*?hijack|hijack.*?dll/gi,
      /LoadLibrary|GetProcAddress/g,
      /dll.*?search|search.*?dll/gi,
      /PATH.*?dll|dll.*?PATH/gi,
    ],
    severity: "high",
    languages: ["cpp", "csharp", "powershell"],
  },
  {
    name: "AtomBomber - Atom Bombing Technique",
    description: "Code that uses atom bombing for code injection",
    patterns: [/atom.*?bomb|bomb.*?atom/gi, /GlobalAddAtom|GlobalGetAtomName/g, /QueueUserAPC/g, /NtQueueApcThread/g],
    severity: "high",
    languages: ["cpp"],
  },
  {
    name: "ThreadHijacker - Thread Hijacking",
    description: "Code that hijacks threads for code execution",
    patterns: [
      /thread.*?hijack|hijack.*?thread/gi,
      /SuspendThread|SetThreadContext/g,
      /GetThreadContext|ResumeThread/g,
      /CreateToolhelp32Snapshot.*?Thread32/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp"],
  },
  {
    name: "StackSpoofer - Stack Spoofing",
    description: "Code that manipulates the call stack to evade detection",
    patterns: [
      /stack.*?spoof|spoof.*?stack/gi,
      /RtlCaptureStackBackTrace/g,
      /SetThreadStackGuarantee/g,
      /call.*?stack.*?manipulat/gi,
    ],
    severity: "high",
    languages: ["cpp"],
  },
  {
    name: "HeapSpray - Heap Spraying",
    description: "Code that performs heap spraying for exploits",
    patterns: [
      /heap.*?spray|spray.*?heap/gi,
      /VirtualAlloc.*?MEM_COMMIT/g,
      /NtAllocateVirtualMemory/g,
      /RtlAllocateHeap/g,
    ],
    severity: "high",
    languages: ["cpp", "javascript"],
  },
  {
    name: "ROPChain - Return-Oriented Programming",
    description: "Code that uses ROP chains for exploitation",
    patterns: [
      /ROP.*?chain|chain.*?ROP/gi,
      /return.*?oriented.*?programming/gi,
      /gadget.*?address|address.*?gadget/gi,
      /stack.*?pivot|pivot.*?stack/gi,
    ],
    severity: "high",
    languages: ["cpp", "python"],
  },
  {
    name: "CodeCave - Code Cave Injection",
    description: "Code that injects into code caves of executables",
    patterns: [
      /code.*?cave|cave.*?code/gi,
      /section.*?append|append.*?section/gi,
      /PE.*?inject|inject.*?PE/gi,
      /IMAGE_NT_HEADERS|IMAGE_SECTION_HEADER/g,
    ],
    severity: "high",
    languages: ["cpp", "python"],
  },
  {
    name: "BootkitInstaller - Bootkit Installation",
    description: "Code that installs a bootkit for persistence",
    patterns: [
      /bootkit|boot.*?sector/gi,
      /MBR|VBR|GPT/g,
      /BOOTMGR|NTLDR/g,
      /disk.*?write.*?sector|sector.*?write.*?disk/gi,
    ],
    severity: "high",
    languages: ["cpp", "csharp"],
  },
  {
    name: "KernelDriver - Malicious Kernel Driver",
    description: "Code that installs or loads a kernel driver",
    patterns: [
      /kernel.*?driver|driver.*?kernel/gi,
      /ZwLoadDriver|NtLoadDriver/g,
      /DriverEntry|DRIVER_OBJECT/g,
      /SCM.*?driver|driver.*?SCM/gi,
    ],
    severity: "high",
    languages: ["cpp", "csharp"],
  },
  {
    name: "ETWBypass - ETW Bypass",
    description: "Code that bypasses Event Tracing for Windows",
    patterns: [
      /ETW.*?bypass|bypass.*?ETW/gi,
      /EtwEventWrite|EtwEventRegister/g,
      /patch.*?ETW|ETW.*?patch/gi,
      /NtTraceEvent/g,
    ],
    severity: "high",
    languages: ["cpp", "csharp", "powershell"],
  },
  {
    name: "AMSIPatcher - AMSI Bypass",
    description: "Code that bypasses Antimalware Scan Interface",
    patterns: [
      /AMSI.*?bypass|bypass.*?AMSI/gi,
      /AmsiScanBuffer|AmsiInitialize/g,
      /patch.*?AMSI|AMSI.*?patch/gi,
      /amsi\.dll/g,
    ],
    severity: "high",
    languages: ["powershell", "csharp", "cpp"],
  },
  {
    name: "ScriptBlockLogger - Script Block Logging Bypass",
    description: "Code that bypasses PowerShell Script Block Logging",
    patterns: [
      /ScriptBlock.*?logging|logging.*?ScriptBlock/gi,
      /bypass.*?scriptblock|scriptblock.*?bypass/gi,
      /PowerShell.*?ETW|ETW.*?PowerShell/gi,
      /Reflection\.Assembly/g,
    ],
    severity: "high",
    languages: ["powershell"],
  },
  {
    name: "SysMon - Sysmon Evasion",
    description: "Code that attempts to evade Sysmon monitoring",
    patterns: [
      /Sysmon.*?evade|evade.*?Sysmon/gi,
      /Sysmon.*?bypass|bypass.*?Sysmon/gi,
      /EventID.*?1|EventID.*?3|EventID.*?7/g,
      /Microsoft-Windows-Sysmon/g,
    ],
    severity: "high",
    languages: ["powershell", "batch", "cpp"],
  },
  {
    name: "AppLockerBypass - AppLocker Bypass",
    description: "Code that attempts to bypass AppLocker policies",
    patterns: [
      /AppLocker.*?bypass|bypass.*?AppLocker/gi,
      /regsvr32|rundll32|installutil/g,
      /msdt|mshta|regasm|regsvcs/g,
      /trusted.*?folder|folder.*?trusted/gi,
    ],
    severity: "high",
    languages: ["powershell", "batch", "csharp"],
  },
  {
    name: "DeviceGuardBypass - Device Guard Bypass",
    description: "Code that attempts to bypass Device Guard",
    patterns: [
      /DeviceGuard.*?bypass|bypass.*?DeviceGuard/gi,
      /UMCI.*?bypass|bypass.*?UMCI/gi,
      /WDAC.*?bypass|bypass.*?WDAC/gi,
      /ConstrainedLanguage.*?bypass|bypass.*?ConstrainedLanguage/gi,
    ],
    severity: "high",
    languages: ["powershell", "csharp"],
  },
  {
    name: "CryptoMiner - Cryptocurrency Mining",
    description: "Code that performs cryptocurrency mining",
    patterns: [
      /crypto.*?min(?:e|er|ing)|min(?:e|er|ing).*?crypto/gi,
      /monero|bitcoin|ethereum|xmrig/gi,
      /stratum\+tcp/g,
      /hashrate|mining.*?pool|pool.*?mining/gi,
    ],
    severity: "high",
    languages: ["python", "javascript", "cpp", "batch"],
  },
  {
    name: "SkidLingo - Script Kiddie Terminology",
    description: "Code containing script kiddie terminology and edgy hacker slang",
    patterns: [
      /1337|l33t|leet/gi,
      /h[a4]xx?[o0]r/gi,
      /h[a4]ck[e3]r/gi,
      /crypt[e3]r/gi,
      /pwn(?:ed|age|z)/gi,
      /n[o0]{2}b|sk[i1]d|script\s*k[i1]dd[i1]e/gi,
    ],
    severity: "low",
    languages: ["python", "javascript", "powershell", "batch", "cpp", "csharp", "java"],
  },
  {
    name: "MemeVirus - Joke/Prank Malware",
    description: "Code containing references to joke or prank malware",
    patterns: [
      /troll|prank|joke/gi,
      /meme|funny|lol|rofl|lmao/gi,
      /rickroll|rick\s*roll|never\s*gonna\s*give\s*you\s*up/gi,
      /jumpscare|scare|boo/gi,
      /fake\s*(?:virus|malware|trojan|worm|ransomware)/gi,
    ],
    severity: "low",
    languages: ["python", "javascript", "powershell", "batch", "cpp", "csharp", "java"],
  },
  {
    name: "SkidTool - Script Kiddie Tool References",
    description: "Code containing references to tools commonly used by script kiddies",
    patterns: [
      /metasploit|msfconsole|msfvenom/gi,
      /kali\s*linux|parrot\s*os|backbox/gi,
      /nmap|zenmap|masscan/gi,
      /sqlmap|sqlninja|havij/gi,
      /hydra|medusa|brutus/gi,
    ],
    severity: "medium",
    languages: ["python", "javascript", "powershell", "batch", "cpp", "csharp", "java"],
  },
]

// Suspicious imports by language
const SUSPICIOUS_IMPORTS = {
  python: [
    { pattern: /import\s+socket/g, description: "Network communication" },
    { pattern: /import\s+subprocess/g, description: "Process execution" },
    { pattern: /import\s+os/g, description: "OS interaction" },
    { pattern: /import\s+sys/g, description: "System access" },
    { pattern: /import\s+requests/g, description: "HTTP requests" },
    { pattern: /import\s+pyautogui/g, description: "Screen/keyboard automation" },
    { pattern: /import\s+pynput/g, description: "Keyboard/mouse monitoring" },
    { pattern: /import\s+PIL/g, description: "Image processing" },
    { pattern: /import\s+cv2/g, description: "Computer vision/webcam" },
    { pattern: /import\s+pyaudio/g, description: "Audio recording" },
    { pattern: /import\s+ctypes/g, description: "Low-level C access" },
    { pattern: /import\s+win32api|import\s+win32con/g, description: "Windows API access" },
    { pattern: /import\s+winreg/g, description: "Registry access" },
    { pattern: /import\s+base64/g, description: "Data encoding" },
    { pattern: /import\s+cryptography|import\s+Crypto/g, description: "Cryptography" },
    { pattern: /import\s+pyHook/g, description: "Keyboard/mouse hooks" },
    { pattern: /import\s+sqlite3/g, description: "Database access" },
    { pattern: /import\s+discord/g, description: "Discord API" },
    { pattern: /import\s+scapy/g, description: "Network packet manipulation" },
    { pattern: /import\s+psutil/g, description: "Process monitoring" },
  ],
  java: [
    { pattern: /import\s+java\.net\./g, description: "Network communication" },
    { pattern: /import\s+java\.io\./g, description: "File I/O" },
    { pattern: /import\s+java\.lang\.Runtime/g, description: "Process execution" },
    { pattern: /import\s+java\.awt\.Robot/g, description: "Screen/keyboard automation" },
    { pattern: /import\s+javax\.sound\.sampled/g, description: "Audio recording" },
    { pattern: /import\s+java\.util\.Base64/g, description: "Data encoding" },
    { pattern: /import\s+javax\.crypto/g, description: "Cryptography" },
    { pattern: /import\s+java\.sql/g, description: "Database access" },
    { pattern: /import\s+com\.sun\./g, description: "Low-level system access" },
    { pattern: /import\s+java\.lang\.reflect/g, description: "Reflection" },
    { pattern: /import\s+java\.security/g, description: "Security operations" },
  ],
  cpp: [
    { pattern: /#include\s+<windows\.h>/g, description: "Windows API" },
    { pattern: /#include\s+<winsock2\.h>/g, description: "Network communication" },
    { pattern: /#include\s+<tlhelp32\.h>/g, description: "Process enumeration" },
    { pattern: /#include\s+<wininet\.h>/g, description: "Internet access" },
    { pattern: /#include\s+<psapi\.h>/g, description: "Process information" },
    { pattern: /#include\s+<winreg\.h>/g, description: "Registry access" },
    { pattern: /#include\s+<crypt32\.h>/g, description: "Cryptography" },
    { pattern: /#include\s+<shlwapi\.h>/g, description: "Shell utilities" },
    { pattern: /#include\s+<shlobj\.h>/g, description: "Shell objects" },
    { pattern: /#include\s+<dbghelp\.h>/g, description: "Debug helpers" },
  ],
  javascript: [
    { pattern: /require\s*$$\s*['"]child_process['"]\s*$$/g, description: "Process execution" },
    { pattern: /require\s*$$\s*['"]fs['"]\s*$$/g, description: "File system access" },
    { pattern: /require\s*$$\s*['"]http['"]\s*$$/g, description: "HTTP requests" },
    { pattern: /require\s*$$\s*['"]https['"]\s*$$/g, description: "HTTPS requests" },
    { pattern: /require\s*$$\s*['"]net['"]\s*$$/g, description: "Network access" },
    { pattern: /require\s*$$\s*['"]crypto['"]\s*$$/g, description: "Cryptography" },
    { pattern: /require\s*$$\s*['"]os['"]\s*$$/g, description: "OS information" },
    { pattern: /require\s*$$\s*['"]path['"]\s*$$/g, description: "Path manipulation" },
    { pattern: /require\s*$$\s*['"]dns['"]\s*$$/g, description: "DNS operations" },
    { pattern: /require\s*$$\s*['"]discord\.js['"]\s*$$/g, description: "Discord API" },
    { pattern: /fetch\s*\(/g, description: "Network requests" },
    { pattern: /XMLHttpRequest/g, description: "Network requests" },
    { pattern: /eval\s*\(/g, description: "Dynamic code execution" },
    { pattern: /document\.cookie/g, description: "Cookie access" },
    { pattern: /localStorage/g, description: "Local storage access" },
  ],
  powershell: [
    { pattern: /Invoke-Expression|IEX/g, description: "Dynamic code execution" },
    { pattern: /Invoke-WebRequest|wget|curl/g, description: "Network requests" },
    { pattern: /New-Object\s+Net\.WebClient/g, description: "Network client" },
    { pattern: /Start-Process|Invoke-Command/g, description: "Process execution" },
    { pattern: /Get-WmiObject|Invoke-WmiMethod/g, description: "WMI operations" },
    { pattern: /Get-Process|Stop-Process/g, description: "Process manipulation" },
    { pattern: /Get-Content|Set-Content/g, description: "File operations" },
    { pattern: /Get-ItemProperty|Set-ItemProperty/g, description: "Registry operations" },
    { pattern: /ConvertTo-SecureString|ConvertFrom-SecureString/g, description: "Credential handling" },
    { pattern: /Add-Type/g, description: "Loading .NET code" },
    { pattern: /Out-String/g, description: "String manipulation" },
    { pattern: /Get-Credential/g, description: "Credential access" },
    { pattern: /schtasks/g, description: "Scheduled tasks" },
    { pattern: /reg\s+add|reg\s+delete/g, description: "Registry manipulation" },
    { pattern: /netsh|ipconfig|route/g, description: "Network configuration" },
  ],
  batch: [
    { pattern: /net\s+user/g, description: "User account manipulation" },
    { pattern: /net\s+localgroup/g, description: "Group manipulation" },
    { pattern: /reg\s+add|reg\s+delete/g, description: "Registry manipulation" },
    { pattern: /schtasks/g, description: "Scheduled tasks" },
    { pattern: /attrib/g, description: "File attribute manipulation" },
    { pattern: /netsh/g, description: "Network configuration" },
    { pattern: /taskkill/g, description: "Process termination" },
    { pattern: /wmic/g, description: "WMI operations" },
    { pattern: /powershell\s+-/g, description: "PowerShell execution" },
    { pattern: /del\s+\/f|rmdir\s+\/s/g, description: "File deletion" },
    { pattern: /icacls/g, description: "Permission manipulation" },
    { pattern: /sc\s+create|sc\s+config/g, description: "Service manipulation" },
    { pattern: /start\s+\/b/g, description: "Background process" },
    { pattern: /assoc/g, description: "File association" },
    { pattern: /ftype/g, description: "File type association" },
  ],
  vbscript: [
    { pattern: /CreateObject\s*$$\s*["']WScript\.Shell["']\s*$$/g, description: "Shell access" },
    { pattern: /CreateObject\s*$$\s*["']Scripting\.FileSystemObject["']\s*$$/g, description: "File system access" },
    { pattern: /CreateObject\s*$$\s*["']MSXML2\.XMLHTTP["']\s*$$/g, description: "Network requests" },
    { pattern: /CreateObject\s*$$\s*["']ADODB\.Stream["']\s*$$/g, description: "Binary file handling" },
    { pattern: /CreateObject\s*$$\s*["']WScript\.Network["']\s*$$/g, description: "Network access" },
    { pattern: /Shell\s*\(/g, description: "Command execution" },
    { pattern: /Run\s*\(/g, description: "Process execution" },
    { pattern: /RegRead|RegWrite/g, description: "Registry operations" },
    { pattern: /GetObject\s*\(\s*["']winmgmts:/g, description: "WMI operations" },
    { pattern: /Base64/g, description: "Data encoding" },
  ],
}

// Network connection patterns
const SUSPICIOUS_CONNECTION_PATTERNS = {
  python: [
    // HTTP requests
    /requests\.(?:get|post|put|delete)\s*\(\s*["']http/g,
    /urllib\.request\.urlopen\s*\(\s*["']http/g,
    /http\.client\.HTTPConnection\s*\(\s*["']/g,
    // Socket connections
    /socket\s*\.\s*socket\s*$$\s*.*?\s*$$.*?\.connect\s*\(\s*\(["'](.*?)["']\s*,\s*(\d+)/g,
    // Subprocess calls
    /subprocess\.(?:Popen|call|run)\s*\(\s*\[?["']/g,
    // File operations that might be suspicious
    /open\s*\(\s*["'].*\.(?:exe|dll|bat|sh|ps1)["']\s*,\s*["']w/g,
  ],
  java: [
    // HTTP connections
    /HttpURLConnection|URL\s*\(\s*["']http/g,
    /new\s+Socket\s*\(\s*["'](.*?)["']\s*,\s*(\d+)/g,
    // Process execution
    /Runtime\.getRuntime$$$$\.exec\s*\(\s*["']/g,
    /ProcessBuilder\s*\(\s*(?:Arrays\.asList\s*\(\s*)?["']/g,
    // File operations
    /new\s+FileOutputStream\s*\(\s*["'].*\.(?:exe|dll|bat|sh|ps1)["']/g,
  ],
  cpp: [
    // Socket connections
    /socket\s*$$\s*.*?\s*$$/g,
    /connect\s*$$\s*.*?,\s*\(struct sockaddr\s*\*$$/g,
    // HTTP requests
    /curl_easy_setopt\s*\(\s*.*,\s*CURLOPT_URL\s*,\s*["']/g,
    // Process execution
    /system\s*\(\s*["']/g,
    /popen\s*\(\s*["']/g,
    // File operations
    /fopen\s*\(\s*["'].*\.(?:exe|dll|bat|sh|ps1)["']\s*,\s*["']w/g,
  ],
  javascript: [
    // HTTP requests
    /fetch\s*\(\s*["']http/g,
    /XMLHttpRequest/g,
    /\.ajax\s*\(\s*\{/g,
    // WebSockets
    /new\s+WebSocket\s*\(\s*["']ws/g,
    // Process execution
    /child_process\.exec\s*\(\s*["']/g,
    /child_process\.spawn\s*\(\s*["']/g,
  ],
  powershell: [
    // HTTP requests
    /Invoke-WebRequest\s+/g,
    /Invoke-RestMethod\s+/g,
    /\[Net\.WebClient\]/g,
    // Process execution
    /Start-Process\s+/g,
    /Invoke-Expression\s+/g,
    /Invoke-Command\s+/g,
  ],
  batch: [
    // Network commands
    /ping\s+/g,
    /netstat\s+/g,
    /nslookup\s+/g,
    // Process execution
    /start\s+/g,
    /call\s+/g,
    /cmd\s+\/c\s+/g,
  ],
  vbscript: [
    // HTTP requests
    /MSXML2\.XMLHTTP/g,
    /WinHttp\.WinHttpRequest/g,
    // Process execution
    /WScript\.Shell.*?\.Run/g,
    /WScript\.Shell.*?\.Exec/g,
    // File operations
    /ADODB\.Stream/g,
  ],
}

// Patterns for skid level detection
const SKID_PATTERNS = {
  cringeComments: [
    /\/\/\s*(?:1337|l33t|elite|pr0|h4x|h4x0r|hax0r|hacker|skid|noob|n00b|pwn|pwned|owned|0wned)/gi,
    /\/\*\s*(?:1337|l33t|elite|pr0|h4x|h4x0r|hax0r|hacker|skid|noob|n00b|pwn|pwned|owned|0wned).*?\*\//gi,
    /#\s*(?:1337|l33t|elite|pr0|h4x|h4x0r|hax0r|hacker|skid|noob|n00b|pwn|pwned|owned|0wned)/gi,
    /(?:\/\/|\/\*|#)\s*(?:made by|coded by|created by|written by|brought to you by).*?(?:hacker|hax0r|h4x0r)/gi,
    /(?:\/\/|\/\*|#)\s*(?:don't|do not|dont)\s*(?:skid|steal|copy|leak|share)/gi,
    /(?:\/\/|\/\*|#)\s*(?:this|the)\s*(?:code|script|tool|program)\s*(?:is|was)\s*(?:made|created|written|coded)\s*(?:by|from)\s*(?:me|myself|us|our team)/gi,
    /(?:\/\/|\/\*|#)\s*(?:use|using)\s*(?:this|the)\s*(?:code|script|tool|program)\s*(?:at your own risk|responsibly)/gi,
    /(?:\/\/|\/\*|#)\s*(?:i am not|we are not|not)\s*(?:responsible|liable|accountable)/gi,
    /(?:\/\/|\/\*|#)\s*(?:for educational purposes only|educational purposes|for education only)/gi,
    /(?:\/\/|\/\*|#)\s*(?:undetectable|undetected|fud|fully undetectable|bypass|bypasses|bypassing)/gi,
    /(?:\/\/|\/\*|#)\s*(?:v\d+\.\d+|version\s*\d+\.\d+)/gi,
    /(?:\/\/|\/\*|#)\s*(?:copyright|©|copyrighted|all rights reserved)/gi,
    /(?:\/\/|\/\*|#)\s*(?:join|follow|subscribe|discord|telegram|youtube)/gi,
  ],
  hardcodedPaths: [
    /(?:C:\\Users\\.*?\\)/g,
    /(?:\/home\/.*?\/)/g,
    /(?:%APPDATA%|%LOCALAPPDATA%|%TEMP%|%USERPROFILE%)/g,
    /(?:\.\.\/\.\.\/\.\.\/)/g,
    /(?:Desktop|Documents|Downloads|Pictures|Videos)/g,
  ],
  copyPastePatterns: [
    /TODO|FIXME|NOTE|XXX|HACK/g,
    /stackoverflow|github|pastebin|hastebin/gi,
    /copied from|based on|inspired by/gi,
    /\/\/\s*(?:code|script|function|method)\s*(?:from|by)/gi,
    /\/\/\s*(?:source|reference|credit):/gi,
  ],
}

// Function to analyze code for malware indicators
export async function analyzeCode(code: string, language: string, fileName = "") {
  // Find Discord webhooks
  const webhooks: string[] = []
  for (const pattern of DISCORD_WEBHOOK_PATTERNS) {
    const matches = [...code.matchAll(pattern)]
    for (const match of matches) {
      webhooks.push(match[0])
    }
  }

  // Find suspicious connections
  const connections: string[] = []
  const connectionPatterns =
    SUSPICIOUS_CONNECTION_PATTERNS[language as keyof typeof SUSPICIOUS_CONNECTION_PATTERNS] || []

  for (const pattern of connectionPatterns) {
    const matches = [...code.matchAll(pattern)]
    for (const match of matches) {
      connections.push(match[0])
    }
  }

  // Find suspicious imports
  const suspiciousImports: string[] = []
  const importPatterns = SUSPICIOUS_IMPORTS[language as keyof typeof SUSPICIOUS_IMPORTS] || []

  for (const { pattern, description } of importPatterns) {
    const matches = [...code.matchAll(pattern)]
    for (const match of matches) {
      suspiciousImports.push(`${match[0]} - ${description}`)
    }
  }

  // Detect malicious behaviors
  const detectedBehaviors: Array<{
    name: string
    description: string
    severity: "low" | "medium" | "high"
    confidence: number
    matches: string[]
  }> = []

  for (const behavior of MALWARE_BEHAVIORS) {
    if (!behavior.languages.includes(language)) continue

    const matches: string[] = []
    let matchCount = 0
    const totalPatterns = behavior.patterns.length

    for (const pattern of behavior.patterns) {
      const patternMatches = [...code.matchAll(pattern)]
      if (patternMatches.length > 0) {
        matchCount++
        for (const match of patternMatches) {
          matches.push(match[0])
        }
      }
    }

    // Calculate confidence based on how many patterns matched
    if (matches.length > 0) {
      const confidence = Math.round((matchCount / totalPatterns) * 100)
      detectedBehaviors.push({
        name: behavior.name,
        description: behavior.description,
        severity: behavior.severity as "low" | "medium" | "high",
        confidence: confidence,
        matches: [...new Set(matches)], // Remove duplicates
      })
    }
  }

  // Calculate a comprehensive malware score based on findings
  let malwareScore = 0

  // Count unique detection types
  const detectionTypes = new Set<string>()
  detectedBehaviors.forEach((behavior) => {
    detectionTypes.add(behavior.name.split(" - ")[0]) // Use the base name before the dash
  })

  // Discord webhooks are suspicious
  if (webhooks.length > 0) {
    malwareScore += 15 + Math.min(webhooks.length * 3, 15)
    detectionTypes.add("DiscordWebhook")
  }

  // Suspicious connections add to the score
  if (connections.length > 0) {
    malwareScore += 10 + Math.min(connections.length * 2, 10)
    detectionTypes.add("SuspiciousConnection")
  }

  // Suspicious imports add to the score
  if (suspiciousImports.length > 0) {
    malwareScore += Math.min(suspiciousImports.length, 15)
    detectionTypes.add("SuspiciousImport")
  }

  // Detected behaviors significantly impact the score
  // But we'll adjust based on unique detection types
  for (const behavior of detectedBehaviors) {
    const severityMultiplier = behavior.severity === "high" ? 1.2 : behavior.severity === "medium" ? 0.8 : 0.5
    malwareScore += Math.round((behavior.confidence / 100) * 10 * severityMultiplier)
  }

  // Check for obfuscation techniques
  const obfuscationScore = checkForObfuscation(code, language)
  malwareScore += obfuscationScore
  if (obfuscationScore > 0) {
    detectionTypes.add("Obfuscation")
  }

  // Adjust score based on number of unique detection types
  // Only go high if there are more than 5 types of detections
  if (detectionTypes.size > 5) {
    malwareScore = Math.min(Math.max(malwareScore, 75), 100) // Ensure at least 75, max 100
  } else if (detectionTypes.size > 3) {
    malwareScore = Math.min(Math.max(malwareScore, 50), 74) // Ensure at least 50, max 74
  } else if (detectionTypes.size > 1) {
    malwareScore = Math.min(Math.max(malwareScore, 25), 49) // Ensure at least 25, max 49
  } else {
    malwareScore = Math.min(malwareScore, 24) // Cap at 24 if only one detection type
  }

  // Determine file type from name or language
  let fileType = language
  if (fileName) {
    const extension = fileName.split(".").pop()?.toLowerCase() || ""
    if (extension) {
      fileType = extension
    }
  }

  // Simulate server processing time
  await new Promise((resolve) => setTimeout(resolve, 800))

  return {
    webhooks: [...new Set(webhooks)], // Remove duplicates
    connections: [...new Set(connections)], // Remove duplicates
    suspiciousImports: [...new Set(suspiciousImports)], // Remove duplicates
    detectedBehaviors: detectedBehaviors.sort((a, b) => {
      // Sort by severity first (high to low)
      const severityOrder = { high: 3, medium: 2, low: 1 }
      const severityDiff =
        severityOrder[b.severity as keyof typeof severityOrder] - severityOrder[a.severity as keyof severityOrder]

      if (severityDiff !== 0) return severityDiff

      // Then by confidence (high to low)
      return b.confidence - a.confidence
    }),
    malwareScore,
    fileType,
    detectionCount: detectionTypes.size,
  }
}

// Function to analyze skid level
export async function analyzeSkidLevel(code: string, language: string) {
  let skidScore = 0
  const cringeComments: string[] = []
  const hardcodedPaths: string[] = []
  const copyPastePatterns: string[] = []

  // Check for cringe comments
  for (const pattern of SKID_PATTERNS.cringeComments) {
    const matches = [...code.matchAll(pattern)]
    for (const match of matches) {
      cringeComments.push(match[0].trim())
      skidScore += 5
    }
  }

  // Check for hardcoded paths
  for (const pattern of SKID_PATTERNS.hardcodedPaths) {
    const matches = [...code.matchAll(pattern)]
    for (const match of matches) {
      hardcodedPaths.push(match[0])
      skidScore += 3
    }
  }

  // Check for copy-paste patterns
  for (const pattern of SKID_PATTERNS.copyPastePatterns) {
    const matches = [...code.matchAll(pattern)]
    for (const match of matches) {
      copyPastePatterns.push(match[0].trim())
      skidScore += 2
    }
  }

  // Count Discord webhooks
  const webhookCount = [
    ...code.matchAll(/https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/(\d+)\/([A-Za-z0-9.\-_]+)/g),
  ].length
  skidScore += webhookCount * 4

  // Check for inconsistent code style
  const indentationStyles = new Set()
  const lines = code.split("\n")
  for (const line of lines) {
    if (line.startsWith("  ")) indentationStyles.add(2)
    if (line.startsWith("    ")) indentationStyles.add(4)
    if (line.startsWith("\t")) indentationStyles.add("tab")
  }
  if (indentationStyles.size > 1) {
    skidScore += 10
    copyPastePatterns.push("Inconsistent indentation style")
  }

  // Check for variable naming inconsistency
  const camelCaseVars = [...code.matchAll(/\b[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*\b/g)].length
  const snake_case_vars = [...code.matchAll(/\b[a-z][a-z0-9]*_[a-z0-9_]*\b/g)].length
  if (camelCaseVars > 0 && snake_case_vars > 0) {
    skidScore += 8
    copyPastePatterns.push("Mixed variable naming conventions")
  }

  // Check for excessive use of global variables
  const globalVars = [...code.matchAll(/\bglobal\s+[a-zA-Z0-9_]+/g)].length
  skidScore += globalVars * 2

  // Cap the score at 100
  skidScore = Math.min(skidScore, 100)

  // Determine skid level
  let skidLevel: "Script Kiddie Apprentice" | "Intermediate Skid" | "Advanced Skid" | "Master Skid" | "1337 h4x0r"
  let advice: string

  if (skidScore >= 80) {
    skidLevel = "1337 h4x0r"
    advice =
      "Wow, this code is peak script kiddie material! It's practically screaming 'I learned to code from YouTube tutorials and hacking forums'. The excessive use of hacker slang, inconsistent coding style, and hardcoded paths suggest this was cobbled together from various sources without understanding how it works."
  } else if (skidScore >= 60) {
    skidLevel = "Master Skid"
    advice =
      "This code shows all the hallmarks of script kiddie work. Multiple Discord webhooks, cringe comments, and inconsistent coding practices suggest it was copied from multiple sources. Consider learning proper programming principles instead of copying code."
  } else if (skidScore >= 40) {
    skidLevel = "Advanced Skid"
    advice =
      "This code has several red flags typical of script kiddie work. The mix of coding styles and suspicious patterns suggests limited understanding of what the code actually does."
  } else if (skidScore >= 20) {
    skidLevel = "Intermediate Skid"
    advice =
      "There are some concerning patterns in this code that suggest copy-pasting from tutorials or forums. Consider taking time to understand the fundamentals of programming."
  } else {
    skidLevel = "Script Kiddie Apprentice"
    advice =
      "This code shows minimal script kiddie tendencies. It's relatively clean, but there's still room for improvement in coding practices."
  }

  // Simulate server processing time
  await new Promise((resolve) => setTimeout(resolve, 800))

  return {
    skidScore,
    cringeComments: [...new Set(cringeComments)],
    webhookCount,
    hardcodedPaths: [...new Set(hardcodedPaths)],
    copyPastePatterns: [...new Set(copyPastePatterns)],
    skidLevel,
    advice,
  }
}

// Helper function to check for code obfuscation
function checkForObfuscation(code: string, language: string): number {
  let score = 0

  // Check for encoded strings
  const base64Patterns = [
    /[A-Za-z0-9+/]{20,}={0,2}/g, // Base64
    /[A-Fa-f0-9]{10,}/g, // Hex
  ]

  for (const pattern of base64Patterns) {
    const matches = [...code.matchAll(pattern)]
    score += Math.min(matches.length * 2, 10)
  }

  // Check for string manipulation/concatenation to hide strings
  const stringConcatPatterns = [
    /['"][^'"]*['"]\s*\+\s*['"][^'"]*['"]/g, // "a" + "b"
    /String\.fromCharCode\s*\(/g, // String.fromCharCode()
    /\\x[0-9a-f]{2}/gi, // \x00 hex escapes
    /\\u[0-9a-f]{4}/gi, // \u0000 unicode escapes
  ]

  for (const pattern of stringConcatPatterns) {
    const matches = [...code.matchAll(pattern)]
    score += Math.min(matches.length, 10)
  }

  // Check for eval or equivalent
  const evalPatterns = [
    /eval\s*\(/g, // JavaScript eval
    /exec\s*\(/g, // Python exec
    /Function\s*\(\s*['"]return/g, // new Function()
    /setTimeout\s*\(\s*['"][^'"]+['"]/g, // setTimeout with string
    /setInterval\s*\(\s*['"][^'"]+['"]/g, // setInterval with string
  ]

  for (const pattern of evalPatterns) {
    const matches = [...code.matchAll(pattern)]
    score += Math.min(matches.length * 5, 20)
  }

  return Math.min(score, 30) // Cap at 30 points
}
