"""Kali 工具库语义搜索 — Qdrant 向量检索 + 内置关键词降级"""

import json
import logging
import re
import hashlib
import time
from typing import Optional

logger = logging.getLogger(__name__)

#  ═══════════════════════════════════════════════════════════
#  配置
#  ═══════════════════════════════════════════════════════════

QDRANT_URL = "http://yunjing-qdrant:6333"
COLLECTION_NAME = "kali_tools"
EMBED_DIM = 1024  # BGE-large-zh
BGE_URL = "http://yunjing-bge:8000"

#  ═══════════════════════════════════════════════════════════
#  内置 Kali 工具元数据（200+ 常用工具,按类别分组）
#  当 Qdrant 不可用时作为关键词降级搜索用
#  ═══════════════════════════════════════════════════════════

KALI_TOOLS = [
    # ─── 信息收集 / OSINT ────────────────────────────
    {"name": "nmap", "description": "网络探测和安全扫描器,支持端口扫描、服务版本检测、操作系统识别,支持NSE脚本扩展", "category": "信息收集/端口扫描", "command": "nmap", "usage": "nmap -sV -sC target"},
    {"name": "masscan", "description": "大规模端口扫描器,比nmap更快,适合扫描整个互联网或大规模网段", "category": "信息收集/端口扫描", "command": "masscan", "usage": "masscan -p1-65535 --rate=1000 target"},
    {"name": "zmap", "description": "互联网级网络扫描器,单线程可扫描整个IPv4地址空间", "category": "信息收集/端口扫描", "command": "zmap", "usage": "zmap -p 443 -M icmp_echo -o results.csv"},
    {"name": "unicornscan", "description": "分布式端口扫描器,支持异步TCP扫描和自定义扫描模式", "category": "信息收集/端口扫描", "command": "unicornscan", "usage": "unicornscan -i eth0 target:1-65535"},
    {"name": "dnsrecon", "description": "DNS枚举和侦察工具,支持子域名爆破、SRV记录枚举、区域传输", "category": "信息收集/DNS", "command": "dnsrecon", "usage": "dnsrecon -d example.com -t brt"},
    {"name": "dnsenum", "description": "DNS枚举工具,支持字典爆破、反向查找、区域传输、WHOIS查询", "category": "信息收集/DNS", "command": "dnsenum", "usage": "dnsenum example.com"},
    {"name": "fierce", "description": "DNS子域名发现工具,支持递归查询和字典爆破", "category": "信息收集/DNS", "command": "fierce", "usage": "fierce --domain example.com"},
    {"name": "theharvester", "description": "从搜索引擎收集电子邮件、子域名、IP等信息", "category": "信息收集/OSINT", "command": "theharvester", "usage": "theharvester -d example.com -b google"},
    {"name": "sublist3r", "description": "快速子域名枚举工具,使用搜索引擎和多数据源", "category": "信息收集/子域名", "command": "sublist3r", "usage": "sublist3r -d example.com"},
    {"name": "amass", "description": "OWASP子域名枚举工具,支持被动和主动收集,集成大量数据源", "category": "信息收集/子域名", "command": "amass", "usage": "amass enum -d example.com"},
    {"name": "subfinder", "description": "快速被动子域名枚举工具,支持多个API数据源", "category": "信息收集/子域名", "command": "subfinder", "usage": "subfinder -d example.com"},
    {"name": "whois", "description": "域名注册信息查询工具", "category": "信息收集/OSINT", "command": "whois", "usage": "whois example.com"},
    {"name": "dmitry", "description": "Deepmagic信息收集工具,支持WHOIS、DNS、子域名、端口扫描", "category": "信息收集/OSINT", "command": "dmitry", "usage": "dmitry -winse example.com"},
    {"name": "recon-ng", "description": "Web侦察框架,提供模块化的信息收集接口", "category": "信息收集/OSINT", "command": "recon-ng", "usage": "recon-ng -r recon_script"},
    {"name": "spiderfoot", "description": "自动化OSINT框架,支持200+数据源", "category": "信息收集/OSINT", "command": "spiderfoot", "usage": "spiderfoot -s target -o html"},
    {"name": "maltego", "description": "图形化情报分析工具,用于发现和分析实体间的关系", "category": "信息收集/OSINT", "command": "maltego", "usage": "maltego"},
    {"name": "shodan", "description": "Shodan搜索API客户端,搜索联网设备和服务", "category": "信息收集/OSINT", "command": "shodan", "usage": "shodan search 'apache'"},
    {"name": "whatweb", "description": "Web技术栈指纹识别,识别CMS、Web服务器、JavaScript库等", "category": "信息收集/WEB指纹", "command": "whatweb", "usage": "whatweb example.com"},
    {"name": "wappalyzer", "description": "Web技术识别工具,通过HTTP响应头和HTML分析识别技术栈", "category": "信息收集/WEB指纹", "command": "wappalyzer", "usage": "wappalyzer https://example.com"},
    {"name": "wafw00f", "description": "Web应用防火墙(WAF)指纹识别和检测工具", "category": "信息收集/WEB指纹", "command": "wafw00f", "usage": "wafw00f example.com"},
    {"name": "urlcrazy", "description": "域名变体生成和DNS记录检查工具,用于发现域名抢注", "category": "信息收集/OSINT", "command": "urlcrazy", "usage": "urlcrazy -p example.com"},

    # ─── WEB 扫描 ────────────────────────────────────
    {"name": "gobuster", "description": "多线程目录/文件爆破工具,支持目录、DNS、vhost、S3枚举模式。常用于网站后台扫描和Web路径发现", "category": "Web扫描/目录爆破", "command": "gobuster", "usage": "gobuster dir -u https://target -w wordlist.txt"},
    {"name": "dirb", "description": "基于字典的Web目录爆破工具,用于发现网站后台、隐藏路径和管理页面", "category": "Web扫描/目录爆破", "command": "dirb", "usage": "dirb https://target wordlist.txt"},
    {"name": "dirsearch", "description": "高级Web路径扫描器,支持递归扫描、多线程、多种响应过滤,适用于网站目录枚举和后台发现", "category": "Web扫描/目录爆破", "command": "dirsearch", "usage": "dirsearch -u https://target"},
    {"name": "ffuf", "description": "快速Web模糊测试工具,支持目录发现、参数模糊、vhost枚举和网站后台扫描", "category": "Web扫描/模糊测试", "command": "ffuf", "usage": "ffuf -u https://target/FUZZ -w wordlist.txt"},
    {"name": "wfuzz", "description": "Web应用模糊测试工具,支持参数爆破、目录发现、身份绕过", "category": "Web扫描/模糊测试", "command": "wfuzz", "usage": "wfuzz -w wordlist.txt https://target/FUZZ"},
    {"name": "nikto", "description": "Web服务器扫描器,检测潜在危险文件、过时版本、配置问题", "category": "Web扫描/漏洞扫描", "command": "nikto", "usage": "nikto -h https://target"},
    {"name": "golismero", "description": "Web安全扫描框架,集成多种扫描插件", "category": "Web扫描/综合", "command": "golismero", "usage": "golismero scan https://target"},
    {"name": "wapiti", "description": "Web漏洞扫描器,支持SQL注入、XSS、文件包含等检测", "category": "Web扫描/漏洞扫描", "command": "wapiti", "usage": "wapiti -u https://target"},
    {"name": "skipfish", "description": "主动Web应用安全侦察工具,生成站点地图和安全报告", "category": "Web扫描/漏洞扫描", "command": "skipfish", "usage": "skipfish -o report_dir https://target"},
    {"name": "arachni", "description": "Web应用安全扫描框架,支持AJAX、多态化、分布式扫描", "category": "Web扫描/综合", "command": "arachni", "usage": "arachni https://target"},
    {"name": "xsser", "description": "跨站脚本(XSS)检测和利用框架,支持多种注入类型和绕过技术", "category": "Web扫描/XSS", "command": "xsser", "usage": "xsser -u https://target/?q=test"},
    {"name": "sqlmap", "description": "自动SQL注入检测和利用工具,支持多种数据库和注入技术", "category": "Web扫描/SQL注入", "command": "sqlmap", "usage": "sqlmap -u 'https://target/page?id=1' --batch"},
    {"name": "jSQL", "description": "Java SQL注入工具,提供图形化界面进行SQL注入测试", "category": "Web扫描/SQL注入", "command": "jsql", "usage": "jsql -u 'https://target/page?id=1'"},
    {"name": "sslyze", "description": "SSL/TLS配置安全扫描工具,检测证书、密码套件和协议支持", "category": "Web扫描/SSL", "command": "sslyze", "usage": "sslyze target.com"},
    {"name": "testssl", "description": "SSL/TLS安全测试工具,检测CVE漏洞、弱密码套件和配置问题", "category": "Web扫描/SSL", "command": "testssl", "usage": "testssl target.com:443"},
    {"name": "cmsmap", "description": "CMS安全扫描框架,支持WordPress、Joomla、Drupal等", "category": "Web扫描/CMS", "command": "cmsmap", "usage": "cmsmap https://target/wp-login.php"},
    {"name": "wpscan", "description": "WordPress安全扫描器,检测插件漏洞、弱密码、主题问题", "category": "Web扫描/CMS", "command": "wpscan", "usage": "wpscan --url https://target"},
    {"name": "joomscan", "description": "Joomla安全扫描器,检测已知漏洞和配置问题", "category": "Web扫描/CMS", "command": "joomscan", "usage": "joomscan -u https://target"},
    {"name": "droopescan", "description": "Drupal安全扫描器,检测版本漏洞和配置问题", "category": "Web扫描/CMS", "command": "droopescan", "usage": "droopescan scan drupal -u https://target"},
    {"name": "wpsc", "description": "WordPress配置安全检查工具", "category": "Web扫描/CMS", "command": "wpsc", "usage": "wpsc https://target"},

    # ─── 漏洞扫描 ────────────────────────────────────
    {"name": "nuclei", "description": "基于YAML模板的快速漏洞扫描器,支持数千种漏洞检测模板", "category": "漏洞扫描/通用", "command": "nuclei", "usage": "nuclei -u https://target -t cves/"},
    {"name": "openvas", "description": "开源漏洞扫描系统,提供全面的漏洞管理和评估(Greenbone)", "category": "漏洞扫描/综合", "command": "openvas", "usage": "gvm-cli --host target"},
    {"name": "nexstalk", "description": "网络漏洞扫描器", "category": "漏洞扫描/通用", "command": "nexstalk", "usage": "nexstalk --target target"},
    {"name": "lynis", "description": "Linux/Unix系统安全审计工具,检查系统加固、配置和漏洞", "category": "漏洞扫描/系统审计", "command": "lynis", "usage": "lynis audit system"},
    {"name": "chkrootkit", "description": "Rootkit检测工具,检查系统是否被植入后门或Rootkit", "category": "漏洞扫描/系统审计", "command": "chkrootkit", "usage": "chkrootkit"},
    {"name": "rkhunter", "description": "Rootkit Hunter,检测Rootkit、后门和本地漏洞", "category": "漏洞扫描/系统审计", "command": "rkhunter", "usage": "rkhunter --check"},
    {"name": "tiger", "description": "系统安全审计工具,检查密码策略、文件权限、网络配置等", "category": "漏洞扫描/系统审计", "command": "tiger", "usage": "tiger"},
    {"name": "vulnhub", "description": "本地漏洞数据库和扫描器", "category": "漏洞扫描/通用", "command": "vulnhub", "usage": "vulnhub --search apache"},

    # ─── 暴力破解 / 密码审计 ─────────────────────────
    {"name": "hydra", "description": "网络登录破解工具,支持多种协议(FTP、SSH、HTTP、SMB、MySQL等)", "category": "暴力破解/在线", "command": "hydra", "usage": "hydra -l admin -P pass.txt ssh://target"},
    {"name": "medusa", "description": "并行网络登录破解工具,支持多线程和多协议", "category": "暴力破解/在线", "command": "medusa", "usage": "medusa -h target -u admin -P pass.txt -M ssh"},
    {"name": "ncrack", "description": "高精度网络认证破解工具,支持SSH、RDP、FTP、Telnet等", "category": "暴力破解/在线", "command": "ncrack", "usage": "ncrack -u admin -P pass.txt ssh://target"},
    {"name": "crowbar", "description": "暴力破解工具,支持SSH密钥、VNC、OpenVPN等协议", "category": "暴力破解/在线", "command": "crowbar", "usage": "crowbar -b sshkey -k id_rsa -t target"},
    {"name": "john", "description": "John the Ripper,离线密码破解工具,支持多种哈希算法", "category": "暴力破解/离线", "command": "john", "usage": "john --wordlist=rockyou.txt hash.txt"},
    {"name": "hashcat", "description": "GPU加速密码破解工具,支持几乎所有哈希类型和攻击模式", "category": "暴力破解/离线", "command": "hashcat", "usage": "hashcat -m 0 -a 0 hash.txt rockyou.txt"},
    {"name": "hashid", "description": "哈希类型识别工具,根据格式判断哈希算法", "category": "暴力破解/辅助", "command": "hashid", "usage": "hashid '$2y$10$...'"},
    {"name": "hash-identifier", "description": "哈希类型识别工具,通过特征识别哈希算法", "category": "暴力破解/辅助", "command": "hash-identifier", "usage": "hash-identifier"},
    {"name": "cewl", "description": "从目标网站生成自定义密码字典,可爬取页面提取关键词", "category": "暴力破解/字典生成", "command": "cewl", "usage": "cewl https://target -w custom_wordlist.txt"},
    {"name": "crunch", "description": "自定义密码字典生成器,支持组合、字符集和模式", "category": "暴力破解/字典生成", "command": "crunch", "usage": "crunch 8 10 abc123 -o wordlist.txt"},
    {"name": "wordlists", "description": "Kali预装密码字典库(/usr/share/wordlists),包含rockyou等多语言字典", "category": "暴力破解/字典", "command": "wordlists", "usage": "ls /usr/share/wordlists/"},
    {"name": "rsmangler", "description": "基于规则的密码字典变异工具,生成变体组合", "category": "暴力破解/字典生成", "command": "rsmangler", "usage": "rsmangler -f wordlist.txt -o mutated.txt"},

    # ─── 漏洞利用 ────────────────────────────────────
    {"name": "metasploit", "description": "渗透测试框架,提供漏洞利用、payload生成、后渗透等全套工具链", "category": "漏洞利用/框架", "command": "msfconsole", "usage": "msfconsole -q"},
    {"name": "searchsploit", "description": "Exploit-DB本地搜索工具,快速查找公开漏洞利用代码", "category": "漏洞利用/搜索", "command": "searchsploit", "usage": "searchsploit apache 2.2"},
    {"name": "exploitdb", "description": "Exploit Database离线副本,包含大量历史漏洞利用代码", "category": "漏洞利用/数据库", "command": "exploitdb", "usage": "searchsploit -m exploit_id"},
    {"name": "beef", "description": "浏览器利用框架,用于客户端渗透测试和XSS利用", "category": "漏洞利用/Web", "command": "beef", "usage": "beef-xss"},
    {"name": "yersinia", "description": "二层网络协议漏洞利用工具,支持STP、CDP、DTP等协议攻击", "category": "漏洞利用/网络", "command": "yersinia", "usage": "yersinia -I"},
    {"name": "cisco-auditing-tool", "description": "Cisco设备安全审计和漏洞利用工具", "category": "漏洞利用/网络设备", "command": "cisco-auditing-tool", "usage": "cisco-auditing-tool target"},
    {"name": "snmpcheck", "description": "SNMP协议审计工具,用于获取设备信息和配置", "category": "漏洞利用/网络设备", "command": "snmpcheck", "usage": "snmpcheck -t target"},
    {"name": "armitage", "description": "Metasploit图形化前端,简化攻击管理和团队协作", "category": "漏洞利用/框架", "command": "armitage", "usage": "armitage"},

    # ─── Web 应用测试 ───────────────────────────────
    {"name": "burpsuite", "description": "Web应用安全测试综合平台,包含代理、扫描器、repeater和intruder", "category": "Web应用/综合", "command": "burpsuite", "usage": "burpsuite"},
    {"name": "zap", "description": "OWASP ZAP Web安全扫描代理,自动发现Web漏洞", "category": "Web应用/综合", "command": "zap", "usage": "zap.sh"},
    {"name": "proxychains", "description": "代理链工具,支持通过多级代理转发TCP连接", "category": "Web应用/代理", "command": "proxychains", "usage": "proxychains nmap target"},
    {"name": "torsocks", "description": "Tor网络代理工具,通过Tor匿名网络转发流量", "category": "Web应用/代理", "command": "torsocks", "usage": "torsocks curl https://target"},
    {"name": "curl", "description": "命令行HTTP客户端,支持多种协议和请求构造", "category": "Web应用/通用", "command": "curl", "usage": "curl -X POST -d 'data' https://target"},
    {"name": "httpie", "description": "人性化HTTP客户端,彩色输出和简洁语法", "category": "Web应用/通用", "command": "httpie", "usage": "http POST https://target key=value"},
    {"name": "postman", "description": "API开发和测试平台(CLI: newman)", "category": "Web应用/通用", "command": "postman", "usage": "postman"},

    # ─── 网络工具 ────────────────────────────────────
    {"name": "netcat", "description": "TCP/IP瑞士军刀,支持端口扫描、文件传输、反向Shell等", "category": "网络工具/通用", "command": "nc", "usage": "nc -lvnp 4444"},
    {"name": "socat", "description": "多功能网络工具,支持端口转发、SSL、代理和文件传输", "category": "网络工具/通用", "command": "socat", "usage": "socat TCP-LISTEN:8080,fork TCP:target:80"},
    {"name": "ncat", "description": "Nmap版本的netcat,支持SSL、代理和连接保持", "category": "网络工具/通用", "command": "ncat", "usage": "ncat -lvnp 4444"},
    {"name": "tcpdump", "description": "命令行网络抓包分析工具,支持BPF过滤器和多种输出格式", "category": "网络工具/抓包", "command": "tcpdump", "usage": "tcpdump -i eth0 port 80"},
    {"name": "wireshark", "description": "图形化网络协议分析工具,支持数百种协议解析(CLI: tshark)", "category": "网络工具/抓包", "command": "tshark", "usage": "tshark -i eth0 -w capture.pcap"},
    {"name": "ettercap", "description": "中间人攻击框架,支持ARP欺骗、DNS欺骗和流量嗅探", "category": "网络工具/中间人", "command": "ettercap", "usage": "ettercap -T -M arp /target//"},
    {"name": "bettercap", "description": "现代MITM攻击框架,支持网络嗅探、欺骗、凭据抓取", "category": "网络工具/中间人", "command": "bettercap", "usage": "bettercap -eval 'net.probe on'"},
    {"name": "responder", "description": "LLMNR/NBT-NS/mDNS欺骗工具,用于捕获Windows网络凭据", "category": "网络工具/中间人", "command": "responder", "usage": "responder -I eth0"},
    {"name": "arp-scan", "description": "ARP扫描工具,快速发现局域网活动主机", "category": "网络工具/发现", "command": "arp-scan", "usage": "arp-scan --localnet"},
    {"name": "nbtscan", "description": "NetBIOS网络扫描工具,发现Windows主机和共享资源", "category": "网络工具/发现", "command": "nbtscan", "usage": "nbtscan 192.168.1.0/24"},
    {"name": "netdiscover", "description": "主动/被动ARP侦察工具,用于网络资产发现", "category": "网络工具/发现", "command": "netdiscover", "usage": "netdiscover -r 192.168.1.0/24"},
    {"name": "wireshark-dumpcap", "description": "Wireshark命令行抓包工具,用于长期数据捕获", "category": "网络工具/抓包", "command": "dumpcap", "usage": "dumpcap -i eth0 -w capture.pcap"},
    {"name": "airodump-ng", "description": "802.11无线网络数据包捕获和扫描工具(aircrack-ng套件)", "category": "网络工具/无线", "command": "airodump-ng", "usage": "airodump-ng wlan0"},
    {"name": "aireplay-ng", "description": "无线网络数据包注入工具,用于ARP重放和解认证攻击", "category": "网络工具/无线", "command": "aireplay-ng", "usage": "aireplay-ng -0 5 -a AP_MAC wlan0"},
    {"name": "aircrack-ng", "description": "WEP/WPA/WPA2无线安全密码破解工具,用于无线网络安全审计和WiFi密码恢复", "category": "网络工具/无线", "command": "aircrack-ng", "usage": "aircrack-ng -w wordlist.txt capture.cap"},
    {"name": "kismet", "description": "无线网络检测器和入侵检测系统,支持GPS定位", "category": "网络工具/无线", "command": "kismet", "usage": "kismet"},

    # ─── Windows / AD 安全 ───────────────────────────
    {"name": "impacket", "description": "Python网络协议工具集合,支持SMB/WMI/LDAP等Windows协议攻击,常用于内网渗透和横向移动", "category": "AD安全/综合", "command": "impacket", "usage": "impacket-smbexec domain/user:pass@target"},
    {"name": "smbclient", "description": "SMB/CIFS客户端,用于文件共享访问和枚举", "category": "AD安全/SMB", "command": "smbclient", "usage": "smbclient -L //target"},
    {"name": "smbmap", "description": "SMB共享枚举工具,支持递归列出共享和权限检查", "category": "AD安全/SMB", "command": "smbmap", "usage": "smbmap -H target"},
    {"name": "enum4linux", "description": "Windows/Samba枚举工具,通过SMB/RPC获取用户、共享和策略信息", "category": "AD安全/枚举", "command": "enum4linux", "usage": "enum4linux -a target"},
    {"name": "enum4linux-ng", "description": "enum4linux升级版,支持更多LDAP/SMB枚举和JSON输出", "category": "AD安全/枚举", "command": "enum4linux-ng", "usage": "enum4linux-ng -A target"},
    {"name": "ldapdomaindump", "description": "LDAP域信息导出工具,用于内网信息收集", "category": "AD安全/LDAP", "command": "ldapdomaindump", "usage": "ldapdomaindump ldap://target -u domain\\user"},
    {"name": "ldapsearch", "description": "LDAP搜索命令行工具,用于查询目录服务信息", "category": "AD安全/LDAP", "command": "ldapsearch", "usage": "ldapsearch -x -H ldap://target -b dc=domain,dc=com"},
    {"name": "bloodhound", "description": "Active Directory关系图分析工具,用于发现权限提升路径", "category": "AD安全/分析", "command": "bloodhound-python", "usage": "bloodhound-python -d domain.local -u user -p pass -c All"},
    {"name": "bloodhound.py", "description": "BloodHound的Python数据收集器,收集AD域信息", "category": "AD安全/分析", "command": "bloodhound.py", "usage": "bloodhound.py -d domain.local -u user -p pass -ns target"},
    {"name": "kerbrute", "description": "Kerberos预认证爆破工具,用于域用户枚举和密码猜测", "category": "AD安全/Kerberos", "command": "kerbrute", "usage": "kerbrute userenum -d domain.local userlist.txt target"},
    {"name": "impacket-secretsdump", "description": "impacket套件中的凭据转储工具,支持DCSync和SAM提取", "category": "AD安全/凭据", "command": "secretsdump", "usage": "impacket-secretsdump domain/user:pass@target"},
    {"name": "impacket-GetNPUsers", "description": "AS-REP Roasting攻击工具,获取无预认证用户的TGT哈希", "category": "AD安全/Kerberos", "command": "GetNPUsers", "usage": "impacket-GetNPUsers domain.local/ -usersfile users.txt"},
    {"name": "impacket-GetUserSPNs", "description": "Kerberoasting攻击工具,请求服务票据并破解服务账户密码", "category": "AD安全/Kerberos", "command": "GetUserSPNs", "usage": "impacket-GetUserSPNs domain.local/user:pass -request"},
    {"name": "impacket-psexec", "description": "PsExec的Python实现,通过SMB在远程Windows系统执行命令", "category": "AD安全/执行", "command": "psexec", "usage": "impacket-psexec domain/user:pass@target"},
    {"name": "impacket-wmiexec", "description": "通过WMI在远程Windows系统执行命令(无需文件上传)", "category": "AD安全/执行", "command": "wmiexec", "usage": "impacket-wmiexec domain/user:pass@target"},
    {"name": "impacket-smbexec", "description": "通过SMB在远程Windows系统执行命令", "category": "AD安全/执行", "command": "smbexec", "usage": "impacket-smbexec domain/user:pass@target"},
    {"name": "impacket-atexec", "description": "通过Windows任务计划程序在远程系统执行命令", "category": "AD安全/执行", "command": "atexec", "usage": "impacket-atexec domain/user:pass@target"},
    {"name": "impacket-dpapi", "description": "Windows DPAPI凭据解密工具", "category": "AD安全/凭据", "command": "dpapi", "usage": "impacket-dpapi masterkey -file mk.txt"},
    {"name": "crackmapexec", "description": "后渗透工具套件,支持SMB/WMI/LDAP/WinRM协议的攻击和枚举,内网渗透和横向移动必备工具", "category": "AD安全/综合", "command": "crackmapexec", "usage": "crackmapexec smb target -u user -p pass"},
    {"name": "netexec", "description": "crackmapexec的继任者,支持SMB/WMI/LDAP/WinRM/FTP/SSH,内网渗透和横向移动常用工具", "category": "AD安全/综合", "command": "netexec", "usage": "netexec smb target -u user -p pass"},
    {"name": "evil-winrm", "description": "WinRM远程管理Shell工具,用于Windows远程连接", "category": "AD安全/执行", "command": "evil-winrm", "usage": "evil-winrm -i target -u user -p pass"},
    {"name": "mimikatz", "description": "Windows凭据提取工具,可获取明文密码、哈希和Kerberos票据", "category": "AD安全/凭据", "command": "mimikatz", "usage": "mimikatz 'privilege::debug' 'sekurlsa::logonpasswords'"},
    {"name": "pypykatz", "description": "Mimikatz的Python实现,跨平台凭据提取", "category": "AD安全/凭据", "command": "pypykatz", "usage": "pypykatz lsa minidump lsass.dmp"},

    # ─── 后渗透 / 权限维持 ───────────────────────────
    {"name": "powershell", "description": "Windows PowerShell,用于脚本执行和后渗透操作", "category": "后渗透/通用", "command": "pwsh", "usage": "powershell -Exec Bypass -File script.ps1"},
    {"name": "powersploit", "description": "PowerShell后渗透框架,包含信息收集、权限提升和横向移动模块", "category": "后渗透/PowerShell", "command": "powersploit", "usage": "Import-Module PowerSploit"},
    {"name": "empire", "description": "PowerShell后渗透代理框架,支持模块化攻击和C2通信", "category": "后渗透/框架", "command": "empire", "usage": "empire"},
    {"name": "cobaltstrike", "description": "商业化后渗透平台,支持C2通信、漏洞利用和团队协作", "category": "后渗透/框架", "command": "cobaltstrike", "usage": "teamserver ip password"},
    {"name": "metasploit-payloads", "description": "Metasploit框架中的payload生成工具集", "category": "后渗透/Payload", "command": "msfvenom", "usage": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=port"},
    {"name": "msfvenom", "description": "Metasploit payload生成器,支持多种格式和编码器", "category": "后渗透/Payload", "command": "msfvenom", "usage": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f exe"},
    {"name": "shellter", "description": "动态Shellcode注入工具,用于免杀payload生成", "category": "后渗透/免杀", "command": "shellter", "usage": "shellter"},
    {"name": "veil", "description": "免杀payload生成框架,生成绕过杀毒软件的可执行文件", "category": "后渗透/免杀", "command": "veil", "usage": "veil"},
    {"name": "upx", "description": "可执行文件压缩工具,用于免杀压缩payload", "category": "后渗透/免杀", "command": "upx", "usage": "upx -9 payload.exe"},
    {"name": "chisel", "description": "基于HTTP的隧道工具,支持内网穿透和代理", "category": "后渗透/隧道", "command": "chisel", "usage": "chisel server -p 8080 --reverse"},
    {"name": "ligolo-ng", "description": "轻量级内网穿透工具,支持多级代理", "category": "后渗透/隧道", "command": "ligolo-ng", "usage": "ligolo-ng -listen 0.0.0.0:8080"},
    {"name": "sshuttle", "description": "通过SSH的VPN代理工具,无需客户端配置即可转发流量", "category": "后渗透/隧道", "command": "sshuttle", "usage": "sshuttle -r user@target 10.0.0.0/8"},
    {"name": "stunnel", "description": "SSL隧道包装工具,用于加密任意TCP连接", "category": "后渗透/隧道", "command": "stunnel", "usage": "stunnel stunnel.conf"},
    {"name": "proxytunnel", "description": "HTTP代理隧道工具,通过CONNECT方法建立TCP连接", "category": "后渗透/隧道", "command": "proxytunnel", "usage": "proxytunnel -p proxy:8080 -d target:80"},

    # ─── 逆向工程 ────────────────────────────────────
    {"name": "gdb", "description": "GNU调试器,支持二进制调试、反汇编和内存分析", "category": "逆向工程/调试", "command": "gdb", "usage": "gdb -q ./binary"},
    {"name": "radare2", "description": "高级二进制分析框架,支持反汇编、调试和逆向工程", "category": "逆向工程/分析", "command": "r2", "usage": "r2 ./binary"},
    {"name": "ghidra", "description": "NSA开源逆向工程框架,支持反编译、分析和脚本插件", "category": "逆向工程/分析", "command": "ghidra", "usage": "ghidra"},
    {"name": "ida", "description": "IDA Pro/Free反汇编器和调试器(仅free版本在Kali)", "category": "逆向工程/分析", "command": "ida", "usage": "ida"},
    {"name": "apktool", "description": "APK逆向工具,反编译和重打包Android应用", "category": "逆向工程/Android", "command": "apktool", "usage": "apktool d app.apk"},
    {"name": "dex2jar", "description": "Android DEX/APK转换为JAR工具,配合JD-GUI使用", "category": "逆向工程/Android", "command": "d2j-dex2jar", "usage": "d2j-dex2jar app.apk"},
    {"name": "jadx", "description": "DEX到Java反编译器,支持GUI和命令行模式", "category": "逆向工程/Android", "command": "jadx", "usage": "jadx -d output app.apk"},
    {"name": "ollydbg", "description": "Windows 32位调试器,用于用户级代码调试(仅x86)", "category": "逆向工程/调试", "command": "ollydbg", "usage": "ollydbg"},
    {"name": "x64dbg", "description": "Windows 64位调试器,类似OllyDbg但支持x64", "category": "逆向工程/调试", "command": "x64dbg", "usage": "x64dbg"},
    {"name": "strings", "description": "提取二进制文件中的可打印字符串", "category": "逆向工程/通用", "command": "strings", "usage": "strings binary | grep -i password"},
    {"name": "objdump", "description": "GNU二进制文件分析工具,显示段、符号表和反汇编", "category": "逆向工程/分析", "command": "objdump", "usage": "objdump -d binary"},
    {"name": "strace", "description": "系统调用跟踪工具,监控进程与内核的交互", "category": "逆向工程/动态分析", "command": "strace", "usage": "strace -f -e trace=open,read,write ./binary"},
    {"name": "ltrace", "description": "库调用跟踪工具,监控程序调用的外部库函数", "category": "逆向工程/动态分析", "command": "ltrace", "usage": "ltrace ./binary"},
    {"name": "binwalk", "description": "固件分析工具,识别和提取嵌入式固件中的文件", "category": "逆向工程/固件", "command": "binwalk", "usage": "binwalk firmware.bin"},
    {"name": "foremost", "description": "数据恢复工具,基于文件头签名恢复已删除文件", "category": "逆向工程/取证", "command": "foremost", "usage": "foremost -i disk_image.dd -o output/"},

    # ─── 取证 ────────────────────────────────────────
    {"name": "autopsy", "description": "数字取证平台,提供GUI分析磁盘镜像和文件系统", "category": "取证/综合", "command": "autopsy", "usage": "autopsy"},
    {"name": "sleuthkit", "description": "磁盘取证命令行工具集,支持文件系统分析和恢复", "category": "取证/文件系统", "command": "tsk_recover", "usage": "tsk_recover -e disk.dd output/"},
    {"name": "volatility", "description": "内存取证框架,分析RAM转储文件提取进程、网络连接和凭据", "category": "取证/内存", "command": "volatility", "usage": "volatility -f mem.dmp imageinfo"},
    {"name": "volatility3", "description": "Volatility v3,支持Windows/Linux/macOS内存分析", "category": "取证/内存", "command": "vol", "usage": "vol -f mem.dmp windows.info"},
    {"name": "bulk_extractor", "description": "高速数字取证工具,从磁盘镜像中批量提取结构化数据", "category": "取证/数据提取", "command": "bulk_extractor", "usage": "bulk_extractor -o output/ disk.dd"},
    {"name": "guymager", "description": "磁盘镜像获取工具(GUI),支持DD、E01和AFF格式", "category": "取证/镜像", "command": "guymager", "usage": "guymager"},
    {"name": "ddrescue", "description": "数据恢复工具,从损坏的存储设备中复制数据", "category": "取证/恢复", "command": "ddrescue", "usage": "ddrescue -d /dev/sdb image.dd logfile"},
    {"name": "scalpel", "description": "基于文件雕刻的数据恢复工具,不依赖文件系统", "category": "取证/恢复", "command": "scalpel", "usage": "scalpel disk.dd -o output/"},
    {"name": "testdisk", "description": "数据恢复和分区恢复工具,支持恢复已删除分区", "category": "取证/恢复", "command": "testdisk", "usage": "testdisk /dev/sdb"},
    {"name": "photorec", "description": "文件恢复工具,从存储介质恢复已删除文件(照片、文档等)", "category": "取证/恢复", "command": "photorec", "usage": "photorec /dev/sdb"},
    {"name": "exiftool", "description": "读写文件元数据(EXIF/IPTC/XMP)的工具,用于图片信息收集", "category": "取证/元数据", "command": "exiftool", "usage": "exiftool image.jpg"},

    # ─── 嗅探 / 欺骗 ────────────────────────────────
    {"name": "driftnet", "description": "从网络流量中捕获和显示图片的工具", "category": "嗅探/图片", "command": "driftnet", "usage": "driftnet -i eth0"},
    {"name": "urlsnarf", "description": "从网络流量中提取HTTP请求URL的工具", "category": "嗅探/HTTP", "command": "urlsnarf", "usage": "urlsnarf -i eth0"},
    {"name": "msgsnarf", "description": "从网络流量中提取即时消息的工具", "category": "嗅探/消息", "command": "msgsnarf", "usage": "msgsnarf -i eth0"},
    {"name": "tcpxtract", "description": "基于文件签名的网络流量文件提取工具", "category": "嗅探/文件提取", "command": "tcpxtract", "usage": "tcpxtract -f capture.pcap"},
    {"name": "chaosreader", "description": "网络会话分析工具,从pcap文件中提取文件和数据", "category": "嗅探/分析", "command": "chaosreader", "usage": "chaosreader capture.pcap"},
    {"name": "isr-ssltrip", "description": "SSL剥离攻击工具,降级HTTPS到HTTP", "category": "嗅探/中间人", "command": "ssltrip", "usage": "ssltrip"},
    {"name": "dsniff", "description": "网络嗅探工具集合,包含arpspoof、dnsspoof、webspy等", "category": "嗅探/综合", "command": "dsniff", "usage": "dsniff -i eth0"},
    {"name": "arpspoof", "description": "ARP欺骗工具,用于局域网的中间人攻击", "category": "嗅探/ARP", "command": "arpspoof", "usage": "arpspoof -i eth0 -t target gateway"},
    {"name": "dnsspoof", "description": "DNS欺骗工具,伪造DNS响应将流量重定向", "category": "嗅探/DNS", "command": "dnsspoof", "usage": "dnsspoof -i eth0 -f hosts.txt"},
    {"name": "mitmproxy", "description": "交互式HTTPS中间人代理,用于Web流量调试和修改", "category": "嗅探/代理", "command": "mitmproxy", "usage": "mitmproxy --mode transparent"},
    {"name": "sslstrip", "description": "HTTPS降级攻击工具,将TLS连接降级到HTTP", "category": "嗅探/中间人", "command": "sslstrip", "usage": "sslstrip -l 8080"},

    # ─── 数据库测试 ──────────────────────────────────
    {"name": "sqldict", "description": "SQL注入字典生成工具,用于模糊测试参数", "category": "数据库/SQL注入", "command": "sqldict", "usage": "sqldict"},
    {"name": "sqlsus", "description": "SQL注入辅助工具,支持自动检测和利用", "category": "数据库/SQL注入", "command": "sqlsus", "usage": "sqlsus -u 'https://target/page?id=1'"},
    {"name": "sqlninja", "description": "Microsoft SQL Server注入利用工具", "category": "数据库/SQL注入", "command": "sqlninja", "usage": "sqlninja -m http -u 'https://target/page?id=1'"},
    {"name": "dbdatools", "description": "数据库数据提取和分析工具集", "category": "数据库/通用", "command": "dbdatools", "usage": "dbdatools"},

    # ─── 无线安全 ────────────────────────────────────
    {"name": "aircrack-ng-suite", "description": "完整无线安全审计套件,含捕获、注入、破解全套工具", "category": "无线/综合", "command": "aircrack-ng", "usage": "aircrack-ng -w wordlist capture.cap"},
    {"name": "reaver", "description": "WPS PIN攻击工具,暴力破解WPS注册码", "category": "无线/WPS", "command": "reaver", "usage": "reaver -i wlan0 -b BSSID -c channel"},
    {"name": "bully", "description": "改进版WPS暴力破解工具,比Reaver更稳定", "category": "无线/WPS", "command": "bully", "usage": "bully wlan0 -b BSSID"},
    {"name": "cowpatty", "description": "WPA/WPA2预共享密钥破解工具,使用预计算哈希加速", "category": "无线/WPA", "command": "cowpatty", "usage": "cowpatty -r capture.cap -s ssid -d hash_file"},
    {"name": "pyrit", "description": "GPU加速的WPA/WPA2预计算表生成和破解工具", "category": "无线/WPA", "command": "pyrit", "usage": "pyrit -r capture.cap attack_passthrough"},
    {"name": "airgeddon", "description": "无线安全审计多合一脚本,集成多种攻击模式", "category": "无线/综合", "command": "airgeddon", "usage": "airgeddon"},
    {"name": "wifite", "description": "自动化无线网络审计工具,支持WEP/WPA/WPS攻击", "category": "无线/综合", "command": "wifite", "usage": "wifite"},
    {"name": "fluxion", "description": "社会工程学无线攻击工具,克隆合法AP诱导用户输入密码", "category": "无线/社会工程", "command": "fluxion", "usage": "fluxion"},
    {"name": "mdk3", "description": "无线网络DoS攻击工具,支持多种干扰模式", "category": "无线/DoS", "command": "mdk3", "usage": "mdk3 wlan0 a -a BSSID"},
    {"name": "hostapd-wpe", "description": "恶意AP工具,用于捕获WPA Enterprise凭据(PEAP/EAP)", "category": "无线/企业", "command": "hostapd-wpe", "usage": "hostapd-wpe hostapd-wpe.conf"},
    {"name": "eaphammer", "description": "邪恶双胞胎AP攻击框架,针对WPA-Enterprise网络", "category": "无线/企业", "command": "eaphammer", "usage": "eaphammer -i wlan0 --essid target"},

    # ─── 社会工程 ────────────────────────────────────
    {"name": "setoolkit", "description": "社会工程攻击工具包,支持钓鱼、恶意USB、Web攻击等", "category": "社会工程/综合", "command": "setoolkit", "usage": "setoolkit"},
    {"name": "gophish", "description": "开源钓鱼攻击框架,支持邮件模板、目标管理和报告", "category": "社会工程/钓鱼", "command": "gophish", "usage": "gophish"},
    {"name": "king-phisher", "description": "钓鱼攻击工具包,支持邮件发送和凭据收集", "category": "社会工程/钓鱼", "command": "king-phisher", "usage": "king-phisher"},
    {"name": "maltego-identity", "description": "Maltego身份识别模块,分析社交媒体实体关系", "category": "社会工程/OSINT", "command": "maltego", "usage": "maltego"},
    {"name": "legion", "description": "自动化社会工程信息收集框架", "category": "社会工程/OSINT", "command": "legion", "usage": "legion"},

    # ─── 密码管理 ────────────────────────────────────
    {"name": "keepassxc", "description": "密码管理器(KeePassXC),安全的凭据存储和自动填充", "category": "密码管理/存储", "command": "keepassxc", "usage": "keepassxc"},
    {"name": "gnupg", "description": "GNU隐私卫士,用于加密、签名和密钥管理", "category": "密码管理/加密", "command": "gpg", "usage": "gpg --encrypt --recipient user file"},

    # ─── 服务扫描 ────────────────────────────────────
    {"name": "httpx", "description": "HTTP探测和发现工具,检测存活Web服务器并收集响应信息", "category": "服务扫描/HTTP", "command": "httpx", "usage": "httpx -l urls.txt -title -status-code"},
    {"name": "httprobe", "description": "HTTP/HTTPS探测工具,验证域名是否存活", "category": "服务扫描/HTTP", "command": "httprobe", "usage": "cat domains.txt | httprobe"},
    {"name": "naabu", "description": "快速端口扫描器,Go语言实现,支持SYN和Connect扫描", "category": "服务扫描/端口", "command": "naabu", "usage": "naabu -host target -p 1-1000"},
    {"name": "rustscan", "description": "超快端口扫描器,基于Rust实现,可配合nmap使用", "category": "服务扫描/端口", "command": "rustscan", "usage": "rustscan -a target -r 1-65535"},
    {"name": "katana", "description": "Web爬虫和URL发现工具,支持被动和主动爬取网站页面、表单和API端点", "category": "服务扫描/爬虫", "command": "katana", "usage": "katana -u https://target"},
    {"name": "gospider", "description": "Go语言Web爬虫,支持站点地图、链接和表单发现", "category": "服务扫描/爬虫", "command": "gospider", "usage": "gospider -s https://target"},
    {"name": "haktrails", "description": "SecurityTrails API客户端,用于子域名和DNS数据查询", "category": "信息收集/子域名", "command": "haktrails", "usage": "haktrails subdomains example.com"},

    # ─── 云安全 ──────────────────────────────────────
    {"name": "cloudlist", "description": "云资产发现工具,支持AWS/Azure/GCP等云平台", "category": "云安全/资产发现", "command": "cloudlist", "usage": "cloudlist -p aws -vpc-id vpc-xxx"},
    {"name": "s3scanner", "description": "S3存储桶发现和权限审计工具", "category": "云安全/S3", "command": "s3scanner", "usage": "s3scanner -bucket names.txt"},
    {"name": "cloud_enum", "description": "多云平台资源枚举工具,支持AWS/Azure/GCP/DigitalOcean", "category": "云安全/枚举", "command": "cloud_enum", "usage": "cloud_enum -k target"},
    {"name": "pacu", "description": "AWS利用框架,支持IAM权限提升、后渗透和数据提取", "category": "云安全/AWS", "command": "pacu", "usage": "pacu"},
    {"name": "scoutsuite", "description": "多云安全审计框架,支持AWS/Azure/GCP/Oracle", "category": "云安全/审计", "command": "scout", "usage": "scout aws --profile default"},

    # ─── Web 应用防火墙 / 绕过 ───────────────────────
    {"name": "wafw00f-web", "description": "WAF检测与指纹识别工具,识别40+种WAF产品", "category": "WAF/检测", "command": "wafw00f", "usage": "wafw00f https://target"},
    {"name": "nmap-nse-scripts", "description": "Nmap NSE脚本库,包含600+脚本用于漏洞检测和服务发现", "category": "NSE/综合", "command": "nmap", "usage": "nmap --script=vuln target"},
    {"name": "payloadsallthethings", "description": "Web渗透测试payload集合,包含SQL注入、XSS、命令注入等", "category": "Payload/综合", "command": "payloadsallthethings", "usage": "cat PayloadsAllTheThings/SQL Injection/"},

    # ─── 代码审计 ────────────────────────────────────
    {"name": "semgrep", "description": "静态代码分析工具,支持自定义规则查找安全漏洞", "category": "代码审计/静态分析", "command": "semgrep", "usage": "semgrep --config=auto src/"},
    {"name": "bandit", "description": "Python代码安全审计工具,检测常见漏洞模式", "category": "代码审计/Python", "command": "bandit", "usage": "bandit -r app/"},
    {"name": "flawfinder", "description": "C/C++代码安全审计工具,统计安全风险并评级", "category": "代码审计/C", "command": "flawfinder", "usage": "flawfinder src/"},
    {"name": "nikto-web", "description": "Web服务器安全扫描器", "category": "代码审计/Web", "command": "nikto", "usage": "nikto -h target"},
    {"name": "brakeman", "description": "Ruby on Rails安全审计工具,检测Web漏洞", "category": "代码审计/Ruby", "command": "brakeman", "usage": "brakeman app/"},

    # ─── 硬件 / 物理安全 ────────────────────────────
    {"name": "killerbee", "description": "ZigBee/IEEE 802.15.4无线协议安全测试框架", "category": "硬件/ZigBee", "command": "killerbee", "usage": "zbid -i wlan0"},
    {"name": "bluetoothctl", "description": "蓝牙协议控制和管理工具(Linux BlueZ)", "category": "硬件/蓝牙", "command": "bluetoothctl", "usage": "bluetoothctl scan on"},
    {"name": "bettercap-bt", "description": "BetterCap的蓝牙模块,支持BT/BLE嗅探和欺骗", "category": "硬件/蓝牙", "command": "bettercap", "usage": "bettercap -eval 'ble.recon on'"},
    {"name": "hcitool", "description": "蓝牙设备配置和扫描工具", "category": "硬件/蓝牙", "command": "hcitool", "usage": "hcitool scan"},
    {"name": "nfc-list", "description": "NFC/RFID读卡器工具,读取和写入NFC标签", "category": "硬件/NFC", "command": "nfc-list", "usage": "nfc-list"},
    {"name": "mfoc", "description": "MIFARE Classic NFC卡破解工具", "category": "硬件/NFC", "command": "mfoc", "usage": "mfoc -O card.dump"},
    {"name": "mfcuk", "description": "MIFARE Classic认证漏洞利用工具", "category": "硬件/NFC", "command": "mfcuk", "usage": "mfcuk -C -R -s 0x10"},

    # ─── 渗透测试辅助 ───────────────────────────────
    {"name": "proxychains4", "description": "新版代理链工具,支持SOCKS4/5和HTTP代理", "category": "辅助/代理", "command": "proxychains4", "usage": "proxychains4 nmap target"},
    {"name": "socat-ng", "description": "socat网络工具,支持SSL/TLS封装", "category": "辅助/网络", "command": "socat", "usage": "socat TCP-LISTEN:80,fork TCP:target:80"},
    {"name": "nmap-parse-output", "description": "nmap XML输出解析工具", "category": "辅助/解析", "command": "nmap-parse-output", "usage": "nmap-parse-output scan.xml"},
    {"name": "jq", "description": "JSON命令行处理器,用于解析和转换JSON数据", "category": "辅助/数据处理", "command": "jq", "usage": "jq '.results[] | {ip: .ip}' output.json"},
    {"name": "yq", "description": "YAML/JSON/XML命令行处理器", "category": "辅助/数据处理", "command": "yq", "usage": "yq e '.name' values.yaml"},
    {"name": "p7zip-full", "description": "文件压缩和解压工具", "category": "辅助/压缩", "command": "7z", "usage": "7z x archive.7z"},
    {"name": "xclip", "description": "命令行剪贴板工具", "category": "辅助/剪贴板", "command": "xclip", "usage": "cat file | xclip -selection clipboard"},
    {"name": "tmux", "description": "终端复用器,支持多窗口和会话管理", "category": "辅助/终端", "command": "tmux", "usage": "tmux new -s session_name"},
    {"name": "screen", "description": "终端多路复用器,支持分离和重新连接会话", "category": "辅助/终端", "command": "screen", "usage": "screen -S session_name"},
    {"name": "rlwrap", "description": "readline wrapper,为没有历史功能的命令行提供行编辑", "category": "辅助/终端", "command": "rlwrap", "usage": "rlwrap nc -lvnp 4444"},
    {"name": "ncat-ssl", "description": "带SSL支持的ncat", "category": "辅助/网络", "command": "ncat", "usage": "ncat --ssl -lvnp 4444"},
    {"name": "vim", "description": "文本编辑器", "category": "辅助/编辑", "command": "vim", "usage": "vim file.txt"},
    {"name": "nano", "description": "简单文本编辑器", "category": "辅助/编辑", "command": "nano", "usage": "nano file.txt"},

    # ─── 报告生成 ────────────────────────────────────
    {"name": "dradis", "description": "协作式安全报告生成框架,支持多种导入格式", "category": "报告/框架", "command": "dradis", "usage": "dradis"},
    {"name": "faraday", "description": "渗透测试自动化管理平台,集成工具输出和报告", "category": "报告/管理", "command": "faraday", "usage": "faraday"},
    {"name": "cherrytree", "description": "笔记管理工具,支持层级组织和代码片段", "category": "报告/笔记", "command": "cherrytree", "usage": "cherrytree"},
    {"name": "pandoc", "description": "文档格式转换工具,支持Markdown到PDF/HTML/DOCX等", "category": "报告/转换", "command": "pandoc", "usage": "pandoc report.md -o report.pdf"},
]

# 构建搜索索引: (工具名称和描述中的关键词) → 工具列表
_KEYWORD_INDEX = {}  # lazy init


def _build_keyword_index():
    """构建关键词倒排索引"""
    index = {}
    for i, tool in enumerate(KALI_TOOLS):
        text = f"{tool['name']} {tool['description']} {tool['category']} {tool.get('usage','')}"
        # 提取中英文关键词
        words = set()
        # 英文单词
        for w in re.findall(r'[a-zA-Z][a-zA-Z0-9._-]{2,}', text):
            words.add(w.lower())
        # 中文短语 (2+字符)
        for w in re.findall(r'[\u4e00-\u9fff]{2,}', text):
            words.add(w)
        for word in words:
            if word not in index:
                index[word] = []
            index[word].append(i)
    return index


def _get_qdrant_client():
    """Lazy qdrant client (only imported when needed)"""
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.http import models as qdrant_models
        return QdrantClient, qdrant_models
    except ImportError:
        return None, None


def _get_bge_embedding(text: str) -> Optional[list[float]]:
    """通过 BGE 服务获取 embedding"""
    import httpx
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{BGE_URL}/embed",
                json={"text": text, "normalize": True},
            )
            resp.raise_for_status()
            return resp.json().get("vector")
    except Exception as e:
        logger.debug(f"[KaliSearch] BGE 服务不可用: {e}")
        return None


def _keyword_search(query: str, limit: int = 5) -> list[dict]:
    """关键词降级搜索 — 基于内置工具元数据

    支持:
      - 精确关键词匹配 (索引)
      - 中文短语子串匹配 (fallback)
      - 英文单词匹配
    """
    global _KEYWORD_INDEX
    if not _KEYWORD_INDEX:
        _KEYWORD_INDEX = _build_keyword_index()

    # 提取查询关键词
    query_words = set()
    for w in re.findall(r'[a-zA-Z][a-zA-Z0-9._-]{2,}', query):
        query_words.add(w.lower())
    for w in re.findall(r'[\u4e00-\u9fff]{2,}', query):
        query_words.add(w)

    if not query_words:
        return KALI_TOOLS[:limit]

    # 分数: 匹配到的关键词数 + 中文子串匹配加分
    scores = {}
    for word in query_words:
        # 精确索引匹配
        for idx in _KEYWORD_INDEX.get(word, []):
            scores[idx] = scores.get(idx, 0) + 2  # 精确匹配权重高

        # 中文子串匹配: 查询中的短中文词可能被完整短语包含
        if len(word) >= 2 and re.match(r'[\u4e00-\u9fff]', word):
            for index_word, tool_indices in _KEYWORD_INDEX.items():
                if word in index_word:
                    for idx in tool_indices:
                        if idx not in scores:
                            scores[idx] = scores.get(idx, 0) + 1
                        else:
                            pass  # 精确匹配已加分

    if not scores:
        # 兜底: 全文简单文本搜索（精确短语匹配）
        query_lower = query.lower()
        for idx, tool in enumerate(KALI_TOOLS):
            text = f"{tool['name']} {tool['description']} {tool['category']}".lower()
            if query_lower in text:
                scores[idx] = scores.get(idx, 0) + 1

    if not scores:
        # 更深兜底: 中文查询拆分为 2-gram 子串匹配
        cn_chars = re.findall(r'[\u4e00-\u9fff]', query)
        if len(cn_chars) >= 2:
            bigrams = set()
            for i in range(len(cn_chars) - 1):
                bigrams.add(cn_chars[i] + cn_chars[i+1])
            # 也拆成单个中文词的组合（2-4字滑动窗口）
            for window_size in (4, 3, 2):
                for i in range(len(cn_chars) - window_size + 1):
                    bigrams.add(''.join(cn_chars[i:i+window_size]))
            for idx, tool in enumerate(KALI_TOOLS):
                text = f"{tool['name']} {tool['description']} {tool['category']}"
                match_count = sum(1 for bg in bigrams if bg in text)
                if match_count >= 2:
                    scores[idx] = scores.get(idx, 0) + match_count

    if not scores:
        return []

    # 按分数排序
    ranked = sorted(scores.items(), key=lambda x: -x[1])[:limit]
    return [KALI_TOOLS[idx] for idx, _ in ranked]


def get_kali_tool(name: str) -> Optional[dict]:
    """通过工具名称精确查找工具信息"""
    for tool in KALI_TOOLS:
        if tool["name"] == name:
            return tool
        # 也匹配 command
        if tool.get("command") == name:
            return tool
    return None


def search_kali_tools(query: str, limit: int = 5) -> list[dict]:
    """语义搜索 Kali 工具，返回最匹配的 tool 列表

    流程:
      1. 尝试 Qdrant 向量搜索 (需 BGE + Qdrant 服务可用)
      2. 尝试 Qdrant 全文搜索
      3. 降级到内置关键词搜索

    Args:
        query: 搜索查询（中文/英文）
        limit: 返回结果数量上限

    Returns:
        匹配的工具列表, 每项含 name, description, category, command, usage
    """
    if not query or not query.strip():
        return KALI_TOOLS[:limit]

    query = query.strip()

    # ── 优先: Qdrant 语义搜索 ──
    try:
        QdrantClient, qmodels = _get_qdrant_client()
        if QdrantClient is not None:
            client = QdrantClient(url=QDRANT_URL)
            # 检查集合是否存在
            collections = client.get_collections().collections
            if any(c.name == COLLECTION_NAME for c in collections):
                # 尝试获取 BGE embedding
                vector = _get_bge_embedding(query)
                if vector:
                    results = client.query_points(
                        collection_name=COLLECTION_NAME,
                        query=vector,
                        limit=limit,
                        with_payload=True,
                        score_threshold=0.5,
                    )
                    if results.points:
                        return [
                            {
                                "name": p.payload.get("name", ""),
                                "description": p.payload.get("description", ""),
                                "category": p.payload.get("category", ""),
                                "command": p.payload.get("command", ""),
                                "usage": p.payload.get("usage", ""),
                                "score": p.score,
                            }
                            for p in results.points
                            if p.payload
                        ]
    except Exception as e:
        logger.debug(f"[KaliSearch] Qdrant 语义搜索失败: {e}")

    # ── 降级: 内置关键词搜索 ──
    return _keyword_search(query, limit=limit)


#  ═══════════════════════════════════════════════════════════
#  初始化: 可选的自动索引写入
#  ═══════════════════════════════════════════════════════════

def ensure_kali_tools_collection(force: bool = False) -> bool:
    """确保 Qdrant kali_tools 集合存在，并将内置工具数据写入

    Args:
        force: 是否强制重建（覆盖已有数据）

    Returns:
        是否成功
    """
    try:
        QdrantClient, qmodels = _get_qdrant_client()
        if QdrantClient is None:
            logger.warning("[KaliSearch] qdrant-client 未安装, 使用内置搜索")
            return False

        client = QdrantClient(url=QDRANT_URL)

        # 检查集合是否存在
        collections = client.get_collections().collections
        exists = any(c.name == COLLECTION_NAME for c in collections)

        if not exists:
            client.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=qmodels.VectorParams(
                    size=EMBED_DIM,
                    distance=qmodels.Distance.COSINE,
                ),
            )
            logger.info(f"[KaliSearch] 创建 kali_tools 集合")
            force = True  # 新集合需要写入数据

        if not force:
            # 检查是否已有数据
            count = client.count(collection_name=COLLECTION_NAME)
            if count.count > 0:
                logger.info(f"[KaliSearch] 集合已有 {count.count} 条数据, 跳过写入")
                return True

        # ── 批量写入工具数据 ──
        points = []
        for i, tool in enumerate(KALI_TOOLS):
            text = f"{tool['name']}: {tool['description']} 类别: {tool['category']}"
            point_id = (hash(tool["name"]) & 0x7FFFFFFFFFFFFFFF)

            # 尝试获取 BGE embedding
            vector = _get_bge_embedding(text)
            if vector is None:
                # 没有 BGE 服务时使用零向量（Qdrant 要求非空）
                vector = [0.0] * EMBED_DIM

            points.append(qmodels.PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "name": tool["name"],
                    "description": tool["description"],
                    "category": tool["category"],
                    "command": tool.get("command", tool["name"]),
                    "usage": tool.get("usage", ""),
                    "text": text,
                }
            ))

        # 分批写入（每批 100 条）
        batch_size = 100
        for start in range(0, len(points), batch_size):
            batch = points[start:start + batch_size]
            client.upsert(
                collection_name=COLLECTION_NAME,
                points=batch,
                wait=True,
            )
            logger.info(f"[KaliSearch] 写入 {start+len(batch)}/{len(points)} 条工具数据")

        # 为 text 字段创建全文索引
        try:
            client.create_payload_index(
                collection_name=COLLECTION_NAME,
                field_name="text",
                field_schema=qmodels.PayloadSchemaType.TEXT,
            )
        except Exception:
            pass

        logger.info(f"[KaliSearch] ✅ 工具库索引完成: {len(points)} 条")
        return True

    except Exception as e:
        logger.warning(f"[KaliSearch] Qdrant 初始化失败: {e}")
        return False
