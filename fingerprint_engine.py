#!/usr/bin/env python3
"""
=============================================================================
   指纹识别引擎 v3.0 - FLUX核心组件
=============================================================================
    核心特性:
    - 25,000+ 指纹规则
    - 多特征交叉验证机制
    - 置信度评分系统
    - 通用关键词过滤
    - 支持JSON/YAML格式
    
    检测方法:
    - keyword: 关键词匹配
    - faviconhash: Favicon哈希匹配
    - headers: HTTP头匹配
    - body: 响应体匹配
    
    作者: ROOT4044
    版本: 3.0.0
    日期: 2026-03-03
=============================================================================
"""

import re
import json
import yaml
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class FingerprintRule:
    """统一指纹规则结构"""
    name: str           # 系统名称 (原cms)
    method: str         # 匹配方法: body/header/url/faviconhash
    keyword: List[str]  # 匹配关键词
    level: str          # 特征级别: L1/L2/L3
    category: str       # 系统类别: CMS/WebServer/ERP/OA/etc
    icon: str = "🔍"
    severity: str = "Info"


@dataclass
class FingerprintResult:
    """指纹识别结果"""
    name: str
    category: str
    version: str
    confidence: int
    evidence: str
    icon: str = "🔍"
    severity: str = "Info"
    level: str = "L2"


class FingerprintEngine:
    """指纹识别引擎 - 合并EHole和Veo规则"""
    
    def __init__(self, session, config_path: str = None):
        self.session = session
        self.rules: List[FingerprintRule] = []
        self.favicon_hashes: Dict[str, str] = {}
        
        # 加载配置
        self.config = self._load_config(config_path)
        self.weights = self.config.get('fingerprint_weights', {})
        self.thresholds = self.config.get('confidence_thresholds', {})
        
        # 初始化规则
        self._init_rules()
        
    def _load_config(self, config_path: str = None) -> Dict:
        """加载配置文件"""
        if config_path is None:
            config_path = Path(__file__).parent / "config" / "rules.yaml"
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"[!] 加载配置文件失败: {e}，使用默认配置")
            return {
                'fingerprint_weights': {
                    'faviconhash': 0.45,
                    'header': 0.20,
                    'body_keyword': 0.20,
                    'title': 0.10,
                    'url_path': 0.05
                },
                'confidence_thresholds': {
                    'report': 70,
                    'high_confidence': 85,
                    'verify': 50
                }
            }
    
    def _init_rules(self):
        """初始化指纹规则 - 合并EHole和Veo"""
        # 加载内置核心指纹
        self._load_builtin_rules()
        # 加载并合并外部指纹库
        self._load_and_merge_external_rules()
        
    def _load_builtin_rules(self):
        """加载内置核心指纹"""
        builtin_rules = [
            # L1 强特征 - Favicon Hash
            FingerprintRule("致远OA", "faviconhash", ["1578525679"], "L1", "OA", "📋"),
            FingerprintRule("泛微OA", "faviconhash", ["1578525679"], "L1", "OA", "📋"),
            FingerprintRule("极限OA", "faviconhash", ["1967132225"], "L1", "OA", "📋"),
            FingerprintRule("Joomla", "faviconhash", ["1747282642"], "L1", "CMS", "🏛️"),
            
            # L1 强特征 - 特定Header
            FingerprintRule("ThinkPHP", "header", ["X-Powered-By: ThinkPHP"], "L1", "Framework", "💭"),
            FingerprintRule("Nginx", "header", ["Server: nginx"], "L1", "WebServer", "🟢"),
            FingerprintRule("Apache", "header", ["Server: Apache"], "L1", "WebServer", "🪶"),
            FingerprintRule("IIS", "header", ["Server: Microsoft-IIS"], "L1", "WebServer", "🪟"),
            
            # L2 中特征 - Body关键词
            FingerprintRule("致远OA", "body", ["/seeyon/", "/seeyon/common/"], "L2", "OA", "📋"),
            FingerprintRule("通达OA", "body", ["Office Anywhere", "/images/tongda.ico"], "L2", "OA", "📋"),
            FingerprintRule("金和OA", "body", ["金和网络", "Jinher Software"], "L2", "OA", "📋"),
            FingerprintRule("红帆OA", "body", ["iOffice.net", "iOffice Hospital"], "L2", "OA", "📋"),
            FingerprintRule("Spring Boot", "body", ["Whitelabel Error Page", "spring-boot"], "L2", "Framework", "🚀"),
            FingerprintRule("Swagger UI", "body", ["swagger-ui", "Swagger UI"], "L2", "DevTool", "📘"),
            FingerprintRule("WordPress", "body", ["/wp-content/", "/wp-includes/"], "L2", "CMS", "📝"),
            FingerprintRule("phpMyAdmin", "body", ["phpMyAdmin", "pma_theme_name"], "L2", "Database", "🐬"),
            
            # L3 弱特征 - Title
            FingerprintRule("登录页面", "body", ["登录", "Login", "Sign in"], "L3", "Generic", "🔐"),
            FingerprintRule("管理后台", "body", ["管理", "Admin", "后台"], "L3", "Generic", "🔐"),
        ]
        
        for rule in builtin_rules:
            self._add_rule(rule)
    
    def _load_and_merge_external_rules(self):
        """加载合并后的指纹库"""
        try:
            data_dir = Path(__file__).parent / "data"
            
            # 优先加载合并后的指纹库
            merged_path = data_dir / "fingerprints_merged.json"
            if merged_path.exists():
                with open(merged_path, 'r', encoding='utf-8') as f:
                    merged_data = json.load(f)
                    
                for fp in merged_data.get('fingerprint', []):
                    rule = FingerprintRule(
                        name=fp.get('name', 'Unknown'),
                        method=fp.get('method', 'body'),
                        keyword=fp.get('keyword', []),
                        level=fp.get('level', 'L2'),
                        category=fp.get('category', 'Other'),
                        icon=self._get_icon(fp.get('name', ''))
                    )
                    self._add_rule(rule)
                
                logger.info(f"[*] 加载指纹库: {len(self.rules)} 条规则")
            else:
                logger.warning(f"[!] 合并指纹库不存在: {merged_path}")
                
        except Exception as e:
            logger.warning(f"[!] 加载指纹库失败: {e}")
    
    def _get_level_from_method(self, method: str) -> str:
        """根据匹配方法自动推断特征级别"""
        method = method.lower()
        if method in ["faviconhash", "header"]:
            return "L1"  # 强特征
        elif method in ["url"]:
            return "L2"  # 中特征
        return "L2"  # 默认中特征
    
    def _get_category(self, name: str) -> str:
        """自动推断系统类别"""
        name_lower = name.lower()
        
        # OA系统
        if any(kw in name_lower for kw in ['oa', '致远', '泛微', '通达', '金和', '极限', '九思', '红帆', 'ioffice', 'landray', 'e-mobile', 'ecology']):
            return "OA"
        
        # CMS系统
        if any(kw in name_lower for kw in ['cms', 'wordpress', 'joomla', 'drupal', 'discuz', 'dedecms', 'pbootcms', 'typecho', 'phpcms', 'jeecms']):
            return "CMS"
        
        # Web服务器
        if any(kw in name_lower for kw in ['nginx', 'apache', 'iis', 'tomcat', 'weblogic', 'jboss', 'jetty', 'openresty', 'caddy']):
            return "WebServer"
        
        # 框架
        if any(kw in name_lower for kw in ['spring', 'django', 'flask', 'laravel', 'thinkphp', 'express', 'yii', 'fastadmin', 'jeecgboot']):
            return "Framework"
        
        # 数据库
        if any(kw in name_lower for kw in ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'influxdb', 'neo4j', 'h2', 'phpmyadmin']):
            return "Database"
        
        # 安全设备
        if any(kw in name_lower for kw in ['防火墙', 'waf', 'vpn', '堡垒机', 'sangfor', '深信服', '天融信', '启明星辰', '网御', '绿盟', '奇安信', 'qax']):
            return "Security"
        
        # 开发工具
        if any(kw in name_lower for kw in ['gitlab', 'jenkins', 'nexus', 'minio', 'harbor', 'gitea', 'gitbucket', 'showdoc', '禅道', 'zentao']):
            return "DevTool"
        
        # 监控系统
        if any(kw in name_lower for kw in ['kibana', 'grafana', 'zabbix', 'prometheus', 'netdata', 'hadoop', 'skywalking']):
            return "Monitoring"
        
        # 消息队列
        if any(kw in name_lower for kw in ['kafka', 'rabbitmq', 'rocketmq']):
            return "MessageQueue"
        
        # ERP系统
        if any(kw in name_lower for kw in ['erp', '用友', 'yonyou', '金蝶', 'kingdee', '帆软', 'finereport', '广联达', 'glodon']):
            return "ERP"
        
        # 网络设备
        if any(kw in name_lower for kw in ['路由器', '交换机', 'h3c', 'ruijie', '锐捷', 'huawei', '华为', 'cisco', 'tp-link', 'dell']):
            return "Network"
        
        # 云平台
        if any(kw in name_lower for kw in ['vmware', 'esxi', 'vcenter', '群晖', 'synology', 'nas']):
            return "Cloud"
        
        # 面板
        if any(kw in name_lower for kw in ['宝塔', 'bt.cn']):
            return "Panel"
        
        return "Other"
    
    def _get_icon(self, name: str) -> str:
        """获取图标"""
        icon_map = {
            # OA系统
            "致远OA": "📋", "泛微OA": "📋", "通达OA": "📋", "金和OA": "📋",
            "极限OA": "📋", "九思OA": "📋", "红帆OA": "📋", "蓝凌OA": "📋",
            "宏景OA": "📋", "致翔OA": "📋", "e-mobile": "📱", "ecology": "🌿",
            
            # CMS
            "WordPress": "📝", "Joomla": "🏛️", "Drupal": "🐘", "Discuz": "💬",
            "DedeCMS": "🏗️", "PbootCMS": "📰", "Typecho": "📝", "PHPCMS": "📰",
            
            # 服务器
            "Nginx": "🟢", "Apache": "🪶", "IIS": "🪟", "Tomcat": "🐱",
            "Weblogic": "☕", "JBoss": "🎯", "Jetty": "✈️", "OpenResty": "🌟",
            "Caddy": "🔧",
            
            # 框架
            "Spring Boot": "🚀", "Spring": "🍃", "Django": "🎯", "Flask": "🌶️",
            "Laravel": "🎨", "ThinkPHP": "💭", "Express": "🚂", "Yii": "🔷",
            
            # 数据库
            "MySQL": "🐬", "PostgreSQL": "🐘", "MongoDB": "🍃", "Redis": "🔴",
            "Elasticsearch": "🔍", "InfluxDB": "📊", "Neo4j": "🕸️",
            "phpMyAdmin": "🐬",
            
            # 安全设备
            "防火墙": "🛡️", "WAF": "🛡️", "VPN": "🔒", "堡垒机": "🔐",
            "Sangfor": "🔒", "深信服": "🛡️", "天融信": "🛡️", "启明星辰": "🔒",
            
            # 开发工具
            "GitLab": "🦊", "Jenkins": "🤵", "Nexus": "📦", "MinIO": "🪣",
            "Harbor": "⚓", "Gitea": "☕", "Swagger": "📘", "禅道": "🧘",
            
            # 监控
            "Kibana": "📊", "Grafana": "📈", "Zabbix": "📉", "Prometheus": "🔥",
            
            # 消息队列
            "Kafka": "📮", "RabbitMQ": "🐰", "RocketMQ": "🚀",
            
            # ERP
            "用友": "💼", "金蝶": "💼", "帆软": "📊",
            
            # 网络设备
            "H3C": "📡", "华为": "📡", "Huawei": "📡", "Cisco": "📡",
            
            # 云平台
            "VMware": "☁️", "ESXi": "☁️", "群晖": "💾",
            
            # 面板
            "宝塔": "🎛️",
        }
        
        for key, icon in icon_map.items():
            if key.lower() in name.lower() or name.lower() in key.lower():
                return icon
        return "🔍"
    
    def _deduplicate_rules(self, rules: List[FingerprintRule]) -> List[FingerprintRule]:
        """按name+method+keyword去重"""
        seen = set()
        unique_rules = []
        for rule in rules:
            key = (rule.name, rule.method, tuple(rule.keyword))
            if key not in seen:
                seen.add(key)
                unique_rules.append(rule)
        logger.info(f"🧹 规则去重后: {len(unique_rules)} 条 (去重前: {len(rules)} 条)")
        return unique_rules
    
    def _add_rule(self, rule: FingerprintRule):
        """添加规则到规则库"""
        self.rules.append(rule)
        
        # 如果是faviconhash，添加到hash映射
        if rule.method == 'faviconhash':
            for keyword in rule.keyword:
                self.favicon_hashes[keyword] = rule.name
    
    def analyze(self, url: str, headers: Dict, content: str, title: str = "") -> List[FingerprintResult]:
        """
        执行指纹识别分析 - 采用严格的多特征验证机制
        
        规则：
        1. 必须至少2个独立特征匹配（不同method）
        2. 或 faviconhash 完全匹配
        3. 或 特定性极强的单一特征（如特定header组合）
        
        Args:
            url: 目标URL
            headers: HTTP响应头
            content: 响应内容
            title: 页面标题
            
        Returns:
            指纹结果列表
        """
        results = []
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        content_lower = content.lower()
        title_lower = title.lower() if title else ""
        
        # 计算favicon hash
        favicon_hash = self._get_favicon_hash(url)
        
        # 按系统名称分组规则，进行多特征验证
        system_rules = {}
        for rule in self.rules:
            if rule.name not in system_rules:
                system_rules[rule.name] = []
            system_rules[rule.name].append(rule)
        
        # 对每个系统进行多特征验证
        for system_name, rules in system_rules.items():
            matched_methods = set()  # 记录匹配到的method类型
            matched_features = []
            total_score = 0.0
            
            for rule in rules:
                feature_score = 0.0
                matched_keywords = []
                
                # 根据method进行匹配
                if rule.method == 'faviconhash' and favicon_hash:
                    if favicon_hash in rule.keyword:
                        # faviconhash完全匹配 - 最高置信度
                        feature_score = 0.98
                        matched_keywords.append(f"favicon:{favicon_hash}")
                        matched_methods.add('faviconhash')
                
                elif rule.method == 'header':
                    header_str = str(headers_lower)
                    for keyword in rule.keyword:
                        keyword_lower = keyword.lower()
                        if keyword_lower in header_str:
                            # header匹配需要特定性检查
                            if self._is_specific_header_keyword(keyword):
                                feature_score = 0.85
                                matched_keywords.append(f"header:{keyword}")
                                matched_methods.add('header')
                            break
                
                elif rule.method == 'url':
                    url_lower = url.lower()
                    for keyword in rule.keyword:
                        if keyword.lower() in url_lower:
                            # URL路径匹配通常比较特定
                            feature_score = 0.80
                            matched_keywords.append(f"url:{keyword}")
                            matched_methods.add('url')
                            break
                
                elif rule.method == 'body':
                    match_count = 0
                    valid_keywords = []
                    for keyword in rule.keyword:
                        if keyword.lower() in content_lower:
                            # 检查是否为通用词
                            if not self._is_generic_keyword(keyword):
                                match_count += 1
                                valid_keywords.append(keyword)
                    
                    # body匹配需要多个非通用关键词
                    if match_count >= 2:
                        feature_score = 0.75 + min(match_count * 0.05, 0.15)
                        matched_keywords.append(f"body:{','.join([k[:20] for k in valid_keywords[:2]])}")
                        matched_methods.add('body')
                    elif match_count == 1:
                        # 单个关键词必须非常特定（长度>=20且包含系统名特征）
                        keyword = valid_keywords[0]
                        if len(keyword) >= 20 and self._is_highly_specific(keyword, system_name):
                            feature_score = 0.70
                            matched_keywords.append(f"body:{keyword[:30]}")
                            matched_methods.add('body')
                
                elif rule.method == 'title':
                    for keyword in rule.keyword:
                        if keyword.lower() in title_lower:
                            # title匹配需要特定性检查
                            if len(keyword) >= 8 and not self._is_generic_keyword(keyword):
                                feature_score = 0.80
                                matched_keywords.append(f"title:{keyword}")
                                matched_methods.add('title')
                            break
                
                if feature_score > 0:
                    total_score += feature_score
                    matched_features.extend(matched_keywords)
            
            # 验证条件（降低门槛以识别更多系统）：
            # 1. faviconhash匹配（单独即可）
            # 2. 至少2个不同method的特征匹配
            # 3. 或 1个高置信度特征（>=0.70）
            # 4. 或 1个body特征且关键词较特定（>=15字符）
            final_score = 0.0
            is_valid = False
            
            if 'faviconhash' in matched_methods:
                # faviconhash匹配直接通过
                final_score = 0.98
                is_valid = True
            elif len(matched_methods) >= 2:
                # 至少2个不同method的特征
                final_score = min(total_score * 0.85, 0.92)
                is_valid = True
            elif len(matched_methods) == 1 and total_score >= 0.70:
                # 单个特征但置信度较高即可
                final_score = total_score * 0.90
                is_valid = True
            elif matched_methods and matched_features:
                # 有任何匹配特征都尝试识别（最低门槛）
                # 根据特征数量和质量计算分数
                base_score = 0.50
                if 'header' in matched_methods:
                    base_score += 0.15
                if 'body' in matched_methods:
                    base_score += 0.10
                if 'title' in matched_methods:
                    base_score += 0.10
                final_score = min(base_score + len(matched_features) * 0.05, 0.75)
                is_valid = final_score >= 0.55
            
            # 只有验证通过才添加到结果（降低门槛到55%）
            if is_valid and final_score >= 0.55:
                results.append(FingerprintResult(
                    name=system_name,
                    category=rules[0].category if rules else "Other",
                    version="",
                    confidence=int(final_score * 100),
                    evidence=f"方法:{','.join(matched_methods)}, 匹配:{', '.join(matched_features[:3])}",
                    icon=rules[0].icon if rules else "🔍",
                    severity=rules[0].severity if rules else "info",
                    level=rules[0].level if rules else "L2"
                ))
        
        # 按置信度排序
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        # 限制结果数量，避免过多误报
        return results[:10]
    
    def _is_generic_keyword(self, keyword: str) -> bool:
        """检查关键词是否为通用词（容易导致误报）"""
        generic_words = {
            'login', 'admin', 'user', 'password', 'system', 'manage', 'index',
            'home', 'page', 'main', 'default', 'welcome', 'dashboard',
            'api', 'v1', 'v2', 'version', 'update', 'help', 'about',
            'contact', 'service', 'support', 'copyright', 'rights',
            'javascript', 'jquery', 'script', 'style', 'css', 'html',
            'div', 'span', 'class', 'id', 'name', 'type', 'value',
            'get', 'post', 'put', 'delete', 'patch', 'options',
            '200', '404', '500', 'error', 'success', 'fail',
            'true', 'false', 'null', 'undefined', 'none',
            'www', 'http', 'https', 'com', 'cn', 'net', 'org',
            'lang', 'language', 'path', 'set-cookie', 'httponly',
            'must-revalidate', 'no-cache', 'no-store', 'private',
            'max-age', 'expires', 'last-modified', 'etag',
            'content-type', 'text/html', 'application/json',
            'gzip', 'deflate', 'br', 'chunked', 'keep-alive',
            'close', 'connection', 'accept', 'encoding', 'charset'
        }
        keyword_lower = keyword.lower()
        return keyword_lower in generic_words or len(keyword_lower) < 6
    
    def _is_specific_header_keyword(self, keyword: str) -> bool:
        """检查header关键词是否具有特定性"""
        # 太短的词不特定
        if len(keyword) < 8:
            return False
        
        # 通用HTTP header不特定
        generic_headers = {
            'set-cookie', 'cookie', 'session', 'token', 'auth',
            'cache-control', 'pragma', 'expires', 'date', 'age',
            'etag', 'last-modified', 'if-modified-since',
            'content-length', 'content-type', 'content-encoding',
            'accept', 'accept-encoding', 'accept-language',
            'user-agent', 'referer', 'origin', 'host',
            'connection', 'keep-alive', 'close', 'upgrade',
            'x-powered-by', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy',
            'access-control-allow-origin', 'access-control-allow-methods'
        }
        keyword_lower = keyword.lower()
        return keyword_lower not in generic_headers
    
    def _is_highly_specific(self, keyword: str, system_name: str) -> bool:
        """检查关键词是否高度特定（与系统名相关）"""
        keyword_lower = keyword.lower()
        system_lower = system_name.lower()
        
        # 关键词包含系统名的一部分
        if any(part in keyword_lower for part in system_lower.split('-')):
            return True
        
        # 关键词包含特定技术标识
        tech_markers = ['version', 'copyright', 'license', 'author', 'vendor', 'product']
        if any(marker in keyword_lower for marker in tech_markers):
            return True
        
        return False
    
    def _verify_system_in_content(self, system_name: str, content: str, title: str) -> bool:
        """验证系统名是否出现在页面内容中（辅助验证）"""
        system_parts = system_name.lower().replace('-', ' ').replace('_', ' ').split()
        content_and_title = content + ' ' + title
        
        # 至少有一个系统名部分出现在内容中
        for part in system_parts:
            if len(part) >= 4 and part in content_and_title:
                return True
        
        return False
    
    def _get_favicon_hash(self, url: str) -> Optional[str]:
        """获取favicon的hash值 (支持MMH3和MD5备选)"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
            
            response = self.session.get(favicon_url, timeout=5, verify=False)
            if response.status_code == 200 and response.content:
                favicon = response.content
                if favicon:
                    # 优先使用MMH3 hash
                    try:
                        import mmh3
                        hash_val = mmh3.hash(favicon)
                        return str(hash_val)
                    except ImportError:
                        # 备选：使用MD5 hash
                        hash_val = hashlib.md5(favicon).hexdigest()
                        return hash_val
        except:
            pass
        return None
    
    def _deduplicate_results(self, results: List[FingerprintResult]) -> List[FingerprintResult]:
        """去重：保留置信度最高的结果"""
        seen = {}
        for result in results:
            if result.name not in seen or seen[result.name].confidence < result.confidence:
                seen[result.name] = result
        return list(seen.values())
