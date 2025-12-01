#!/usr/bin/env python3
"""
anirss-openlist-sync遗漏检测与删除功能
用于检测anirss本地已下载但openlist云端缺失的文件，并提供删除anirss遗漏文件的能力
"""

import requests
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import configparser
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class Config:
    """配置管理类"""
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or 'config.ini'
        self.default_config = {
            'anirss_url': 'http://localhost:8080',
            'openlist_url': 'http://localhost:3000',
            'openlist_username': 'admin',
            'openlist_password': 'password',
            'qbit_url': 'http://localhost:8080',
            'qbit_username': '',
            'qbit_password': '',
            'qbit_max_age_hours': 24,
            'log_level': 'INFO',
            'log_max_bytes': 10485760,  # 10MB
            'log_backup_count': 3,
            'thread_pool_size': 4,
            'skip_ova': True,
            'detect': True,
            'delete': False,
            'report': False
        }
        self.config = self.default_config.copy()
        self._load_config()
    
    def _load_config(self) -> None:
        """加载配置文件"""
        if os.path.exists(self.config_file):
            config_parser = configparser.ConfigParser()
            config_parser.read(self.config_file, encoding='utf-8')
            
            # 读取配置
            if 'anirss' in config_parser:
                self.config['anirss_url'] = config_parser['anirss'].get('url', self.default_config['anirss_url'])
            
            if 'openlist' in config_parser:
                self.config['openlist_url'] = config_parser['openlist'].get('url', self.default_config['openlist_url'])
                self.config['openlist_username'] = config_parser['openlist'].get('username', self.default_config['openlist_username'])
                self.config['openlist_password'] = config_parser['openlist'].get('password', self.default_config['openlist_password'])
            
            if 'qbit' in config_parser:
                self.config['qbit_url'] = config_parser['qbit'].get('url', self.default_config['qbit_url'])
                self.config['qbit_username'] = config_parser['qbit'].get('username', self.default_config['qbit_username'])
                self.config['qbit_password'] = config_parser['qbit'].get('password', self.default_config['qbit_password'])
                self.config['qbit_max_age_hours'] = config_parser['qbit'].getint('max_age_hours', self.default_config['qbit_max_age_hours'])
            
            if 'operation' in config_parser:
                self.config['detect'] = config_parser['operation'].getboolean('detect', self.default_config['detect'])
                self.config['delete'] = config_parser['operation'].getboolean('delete', self.default_config['delete'])
                self.config['report'] = config_parser['operation'].getboolean('report', self.default_config['report'])
                self.config['skip_ova'] = config_parser['operation'].getboolean('skip_ova', self.default_config['skip_ova'])
                self.config['thread_pool_size'] = config_parser['operation'].getint('thread_pool_size', self.default_config['thread_pool_size'])
            
            if 'log' in config_parser:
                self.config['log_level'] = config_parser['log'].get('level', self.default_config['log_level']).upper()
                self.config['log_max_bytes'] = config_parser['log'].getint('max_bytes', self.default_config['log_max_bytes'])
                self.config['log_backup_count'] = config_parser['log'].getint('backup_count', self.default_config['log_backup_count'])
        else:
            self._generate_default_config()
    
    def _generate_default_config(self) -> None:
        """生成默认配置文件"""
        default_config_ini = """# anirss-openlist-sync 配置文件

[anirss]
# anirss API地址
url = http://localhost:8080

[openlist]
# openlist API地址
url = http://localhost:3000
# openlist用户名
username = admin
# openlist密码
password = password

[qbit]
# qbit API地址
url = http://localhost:8080
# qbit用户名（可选）
username =
# qbit密码（可选）
password =
# 种子添加超过多少小时后删除（默认24小时）
max_age_hours = 24

[operation]
# 执行遗漏检测 (true/false)
detect = true
# 执行删除操作 (true/false)
delete = false
# 生成详细报告 (true/false)
report = false
# 跳过剧场版 (true/false)
skip_ova = true
# 线程池大小（默认4）
thread_pool_size = 4

[log]
# 日志等级 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
level = INFO
# 日志文件最大大小 (字节，默认10MB)
max_bytes = 10485760
# 日志备份数量 (默认3个)
backup_count = 3
"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            f.write(default_config_ini)
        logger.info(f"已生成默认配置文件: {self.config_file}")
    
    def update(self, **kwargs) -> None:
        """更新配置"""
        self.config.update(kwargs)
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        return self.config.get(key, default)


def setup_logging(config: Config) -> None:
    """配置日志"""
    # 获取日志配置
    log_level = getattr(logging, config.get('log_level'), logging.INFO)
    log_max_bytes = config.get('log_max_bytes')
    log_backup_count = config.get('log_backup_count')
    
    # 清除现有处理器
    logger.handlers.clear()
    
    # 设置日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # 文件处理器 - 支持日志滚动
    file_handler = RotatingFileHandler(
        'anirss-openlist-sync.log',
        maxBytes=log_max_bytes,
        backupCount=log_backup_count,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)
    
    # 控制台处理器
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(log_level)
    
    # 添加处理器
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.setLevel(log_level)
    
    logger.info("任务开始")


class AnirssAPI:
    """anirss API调用类"""
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def get_anime_list(self) -> List[Dict[str, Any]]:
        """获取所有番剧信息"""
        try:
            url = f'{self.base_url}/api/ani'
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get('data', []) if data.get('code') == 200 else []
        except Exception as e:
            logger.error(f"获取番剧列表异常: {str(e)}")
            return []
    
    def get_download_status(self, anime_id: str, anime_info: Dict[str, Any]) -> Dict[str, Any]:
        """获取单个番剧的下载情况"""
        try:
            url = f'{self.base_url}/api/items'
            response = requests.post(url, json=anime_info, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get('data', {}) if data.get('code') == 200 else {}
        except Exception as e:
            logger.error(f"获取番剧{anime_id}下载状态异常: {str(e)}")
            return {}
    
    def delete_torrent(self, anime_id: str, info_hash: str) -> bool:
        """删除本地种子"""
        try:
            url = f'{self.base_url}/api/torrent?id={anime_id}&infoHash={info_hash}'
            response = requests.delete(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            if data.get('code') == 200:
                logger.info(f"成功删除种子: {anime_id} - {info_hash}")
                return True
            logger.error(f"删除种子{anime_id} - {info_hash}失败: {data.get('message')}")
            return False
        except Exception as e:
            logger.error(f"删除种子{anime_id} - {info_hash}异常: {str(e)}")
            return False


class QbitAPI:
    """qbit API调用类"""
    def __init__(self, base_url: str, username: str = '', password: str = ''):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.cookies = None
    
    def login(self) -> bool:
        """登录qbit"""
        try:
            url = f'{self.base_url}/api/v2/auth/login'
            payload = {'username': self.username, 'password': self.password}
            response = requests.post(url, data=payload, timeout=30)
            response.raise_for_status()
            
            if response.text == 'Ok.':
                self.cookies = response.cookies
                return True
            return False
        except Exception as e:
            logger.error(f"qbit登录异常: {str(e)}")
            return False
    
    def _request(self, endpoint: str, method: str = 'get', **kwargs) -> Any:
        """发送qbit API请求"""
        if not self.cookies and not self.login():
            return None
        
        url = f'{self.base_url}/api/v2/{endpoint}'
        try:
            response = requests.request(method, url, cookies=self.cookies, timeout=30, **kwargs)
            response.raise_for_status()
            return response.json() if response.text else None
        except Exception as e:
            logger.error(f"qbit API请求异常: {str(e)}")
            return None
    
    def get_torrent(self, info_hash: str) -> Optional[Dict[str, Any]]:
        """根据info_hash获取种子信息"""
        endpoint = f'torrents/info?hash={info_hash}'
        torrents = self._request(endpoint)
        return torrents[0] if torrents and len(torrents) > 0 else None
    
    def is_torrent_active(self, info_hash: str) -> bool:
        """检查种子是否正在下载"""
        torrent = self.get_torrent(info_hash)
        if not torrent:
            return False
        status = torrent.get('state')
        active_states = ['downloading', 'stalledDL', 'checkingDL', 'queuedDL']
        return status in active_states
    
    def delete_torrent(self, info_hash: str, delete_files: bool = True) -> bool:
        """删除qbit种子，可选删除本地文件"""
        try:
            endpoint = 'torrents/delete'
            params = {
                'hashes': info_hash,
                'deleteFiles': 'true' if delete_files else 'false'
            }
            result = self._request(endpoint, method='post', params=params)
            return result is not None
        except Exception as e:
            logger.error(f"qbit种子异常: {str(e)}")
            return False
    
    def should_delete_torrent(self, info_hash: str, max_age_hours: int = 24) -> bool:
        """判断是否应该删除种子"""
        torrent = self.get_torrent(info_hash)
        
        if not torrent:
            return True
        
        status = torrent.get('state')
        active_states = ['downloading', 'stalledDL', 'checkingDL', 'queuedDL']
        
        if status not in active_states:
            return False
        
        download_speed = torrent.get('dlspeed', 0)
        
        if download_speed > 0:
            return False
        
        added_time = torrent.get('added_on', 0)
        current_time = time.time()
        
        age_hours = (current_time - added_time) / 3600
        
        return age_hours > max_age_hours


class OpenlistAPI:
    """openlist API调用类"""
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.token = None
    
    def get_jwt_token(self) -> Optional[str]:
        """获取JWT令牌"""
        try:
            url = f'{self.base_url}/api/auth/login'
            payload = {'username': self.username, 'password': self.password}
            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            if data.get('code') == 200:
                self.token = data.get('data', {}).get('token')
                return self.token
            logger.error(f"获取令牌失败: {data.get('message')}")
            return None
        except Exception as e:
            logger.error(f"获取令牌异常: {str(e)}")
            return None
    
    def get_file_list(self, path: str) -> List[Dict[str, Any]]:
        """获取指定路径的文件列表"""
        if not self.token:
            self.get_jwt_token()
        
        try:
            return self._request_file_list(path)
        except Exception as e:
            logger.error(f"获取文件列表异常: {str(e)}")
            return []
    
    def _request_file_list(self, path: str) -> List[Dict[str, Any]]:
        """发送文件列表请求"""
        url = f'{self.base_url}/api/fs/list'
        headers = {'Authorization': f'{self.token}', 'Content-Type': 'application/json'}
        payload = {'path': path, 'password': '', 'refresh': False, 'page': 1, 'per_page': 1000}
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # 检查token是否失效
        if data.get('code') == 401 and 'token' in str(data.get('message')).lower():
            self.token = None
            self.get_jwt_token()
            headers['Authorization'] = f'{self.token}'
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        return data.get('data', {}).get('content', []) if data.get('code') == 200 else []
    
    def get_upload_tasks(self) -> List[Dict[str, Any]]:
        """获取未完成的上传任务"""
        if not self.token:
            self.get_jwt_token()
        
        try:
            return self._request_upload_tasks()
        except Exception as e:
            logger.error(f"获取上传任务异常: {str(e)}")
            return []
    
    def _request_upload_tasks(self) -> List[Dict[str, Any]]:
        """发送上传任务请求"""
        url = f'{self.base_url}/api/task/upload/undone'
        headers = {'Authorization': f'{self.token}'}
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # 检查token是否失效
        if data.get('code') == 401 and 'token' in str(data.get('message')).lower():
            self.token = None
            self.get_jwt_token()
            headers['Authorization'] = f'{self.token}'
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        
        return data.get('data', []) if data.get('code') == 200 else []


class MissingDetector:
    """遗漏检测类"""
    def __init__(self, anirss_api: AnirssAPI, openlist_api: OpenlistAPI, skip_ova: bool = True, thread_pool_size: int = 4):
        self.anirss_api = anirss_api
        self.openlist_api = openlist_api
        self.skip_ova = skip_ova
        self.thread_pool_size = thread_pool_size
    
    def detect_missing_files(self) -> List[Dict[str, Any]]:
        """检测遗漏文件"""
        missing_files = []
        logger.debug("开始获取番剧列表")
        anime_list = self.anirss_api.get_anime_list()
        logger.debug(f"获取到 {len(anime_list)} 个番剧")
        
        # 过滤掉电影
        filtered_anime_list = [
            anime for anime in anime_list 
            if not (self.skip_ova and anime.get('ova', False))
        ]
        logger.debug(f"过滤后剩余 {len(filtered_anime_list)} 个番剧")
        
        # 使用线程池检测番剧
        with ThreadPoolExecutor(max_workers=self.thread_pool_size) as executor:
            logger.info(f"多线程运行: {self.thread_pool_size}")
            
            # 提交检测任务
            futures = {
                executor.submit(self._detect_missing_for_anime, anime): anime
                for anime in filtered_anime_list
            }
            
            # 收集检测结果
            for future in as_completed(futures):
                anime = futures[future]
                try:
                    result = future.result()
                    missing_files.extend(result)
                    logger.debug(f"完成番剧检测: {anime.get('title')}")
                except Exception as e:
                    logger.error(f"检测番剧异常: {anime.get('title')} - {str(e)}")
        
        logger.info(f"检测完成，共发现 {len(missing_files)} 个遗漏文件")
        return missing_files
    
    def _detect_missing_for_anime(self, anime: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测单个番剧的遗漏文件"""
        missing_files = []
        anime_id = anime.get('id')
        title = anime.get('title')
        logger.debug(f"处理番剧: {title}")
        
        download_status = self.anirss_api.get_download_status(anime_id, anime)
        items = download_status.get('items', [])
        
        alist_path = self._process_alist_path(anime)
        openlist_file_prefixes = self._get_openlist_file_prefixes(alist_path)
        
        for item in items:
            if item.get('local'):
                missing_file = self._check_missing_file(item, anime, openlist_file_prefixes)
                if missing_file:
                    missing_files.append(missing_file)
        
        return missing_files
    
    def _process_alist_path(self, anime: Dict[str, Any]) -> str:
        """处理alistPath，替换变量"""
        alist_path = anime.get('alistPath', '')
        if alist_path:
            alist_path = alist_path.replace('${title}', anime.get('title', ''))
            alist_path = alist_path.replace('${season}', str(anime.get('season', 1)))
        return alist_path
    
    def _get_openlist_file_prefixes(self, alist_path: str) -> set:
        """获取openlist文件前缀集合"""
        logger.debug(f"获取openlist文件列表，路径: {alist_path}")
        openlist_files = self.openlist_api.get_file_list(alist_path)
        logger.debug(f"获取到 {len(openlist_files)} 个文件")
        openlist_file_prefixes = set()
        
        for file in openlist_files:
            if not file.get('is_dir'):
                file_name = file.get('name', '')
                file_prefix = file_name.rsplit('.', 1)[0] if '.' in file_name else file_name
                openlist_file_prefixes.add(file_prefix)
        
        logger.debug(f"提取到 {len(openlist_file_prefixes)} 个文件前缀")
        return openlist_file_prefixes
    
    def _check_missing_file(self, item: Dict[str, Any], anime: Dict[str, Any], openlist_file_prefixes: set) -> Optional[Dict[str, Any]]:
        """检查单个文件是否遗漏"""
        re_name = item.get('reName')
        if re_name not in openlist_file_prefixes:
            missing_file = {
                'anime_id': anime.get('id'),
                'title': anime.get('title'),
                'episode': item.get('episode'),
                're_name': re_name,
                'info_hash': item.get('infoHash'),
                'alist_path': self._process_alist_path(anime),
                'local': item.get('local')
            }
            logger.warning(f"发现遗漏文件: {anime.get('title')} - {re_name}")
            return missing_file
        return None
    
    def generate_report(self, missing_files: List[Dict[str, Any]]) -> None:
        """生成遗漏文件报告"""
        report = {'total_missing': len(missing_files), 'missing_files': missing_files}
        with open('missing_files_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)


class MissingDeleter:
    """遗漏文件删除类"""
    def __init__(self, anirss_api: AnirssAPI, qbit_api: QbitAPI, openlist_api: OpenlistAPI, max_age_hours: int = 24):
        self.anirss_api = anirss_api
        self.qbit_api = qbit_api
        self.openlist_api = openlist_api
        self.max_age_hours = max_age_hours
    
    def delete_missing_files(self, missing_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """删除遗漏文件"""
        result = {'total': len(missing_files), 'success': 0, 'failed': 0, 'skipped': 0, 'details': []}
        
        for file_info in missing_files:
            self._process_delete(file_info, result)
        
        return result
    
    def _process_delete(self, file_info: Dict[str, Any], result: Dict[str, Any]) -> None:
        """处理单个文件的删除"""
        anime_id = file_info.get('anime_id')
        info_hash = file_info.get('info_hash')
        local = file_info.get('local', False)
        title = file_info.get('title')
        re_name = file_info.get('re_name')
        
        if not local:
            self._handle_skip(file_info, result, reason='本地不存在')
            return
        
        torrent = self.qbit_api.get_torrent(info_hash)
        
        if not self.qbit_api.should_delete_torrent(info_hash, self.max_age_hours):
            self._handle_skip(file_info, result, reason='qbit正在下载')
            return

        openlist_tasks = self.openlist_api.get_upload_tasks()
        
        if self._check_related_openlist_task(file_info, openlist_tasks):
            self._handle_skip(file_info, result, reason='openlist正在上传')
            return
        
        try:
            if not torrent:
                logger.info(f"删除anirss: {title} - {re_name}")
                if self.anirss_api.delete_torrent(anime_id, info_hash):
                    self._record_deleted_torrent(f"{title} - {re_name}")
                    self._handle_success(file_info, result)
                else:
                    self._handle_failure(file_info, result)
            else:
                logger.info(f"种子在qbit中，删除qbit种子并删除anirss种子: {title} - {re_name}")
                if self.qbit_api.delete_torrent(info_hash, delete_files=True):
                    if self.anirss_api.delete_torrent(anime_id, info_hash):
                        self._record_deleted_torrent(f"{title} - {re_name}")
                        self._handle_success(file_info, result)
                    else:
                        self._handle_failure(file_info, result)
                else:
                    self._handle_failure(file_info, result)
        except Exception as e:
            logger.error(f"删除种子异常: {str(e)}")
            self._handle_failure(file_info, result)
    
    def _check_related_openlist_task(self, file_info: Dict[str, Any], tasks: List[Dict[str, Any]]) -> bool:
        """检查是否存在相关的openlist任务"""
        title = file_info.get('title')
        re_name = file_info.get('re_name')
        
        for task in tasks:
            task_name = task.get('name', '')
            if title in task_name or re_name in task_name:
                logger.info(f"发现相关openlist任务: {task_name}")
                return True
        
        return False
    
    def _record_deleted_torrent(self, torrent_name: str) -> None:
        """将删除的种子名称写入文件"""
        with open('deleted_torrents.txt', 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {torrent_name}\n")
    
    def _handle_skip(self, file_info: Dict[str, Any], result: Dict[str, Any], reason: str) -> None:
        """处理跳过删除"""
        result['skipped'] += 1
        result['details'].append({
            'status': 'skipped',
            'title': file_info.get('title'),
            're_name': file_info.get('re_name'),
            'message': f'{reason}，跳过删除'
        })
        logger.info(f"跳过删除: {file_info.get('title')} - {file_info.get('re_name')}（{reason}）")
    
    def _handle_success(self, file_info: Dict[str, Any], result: Dict[str, Any]) -> None:
        """处理删除成功"""
        result['success'] += 1
        result['details'].append({
            'status': 'success',
            'title': file_info.get('title'),
            're_name': file_info.get('re_name'),
            'message': '删除成功'
        })
    
    def _handle_failure(self, file_info: Dict[str, Any], result: Dict[str, Any]) -> None:
        """处理删除失败"""
        result['failed'] += 1
        result['details'].append({
            'status': 'failed',
            'title': file_info.get('title'),
            're_name': file_info.get('re_name'),
            'message': '删除失败'
        })
    
    def generate_delete_report(self, delete_result: Dict[str, Any]) -> None:
        """生成删除操作报告"""
        with open('delete_report.json', 'w', encoding='utf-8') as f:
            json.dump(delete_result, f, ensure_ascii=False, indent=2)
        logger.info(f"删除操作完成: 成功{delete_result['success']}个，失败{delete_result['failed']}个，跳过{delete_result['skipped']}个")


class SyncManager:
    """同步管理器"""
    def __init__(self, config: Config):
        self.config = config
        self._init_apis()
    
    def _init_apis(self) -> None:
        """初始化API客户端"""
        self.anirss_api = AnirssAPI(self.config.get('anirss_url'))
        self.openlist_api = OpenlistAPI(
            self.config.get('openlist_url'),
            self.config.get('openlist_username'),
            self.config.get('openlist_password')
        )
        self.qbit_api = QbitAPI(
            self.config.get('qbit_url'),
            self.config.get('qbit_username'),
            self.config.get('qbit_password')
        )
        self.detector = MissingDetector(
            self.anirss_api, 
            self.openlist_api, 
            self.config.get('skip_ova'),
            self.config.get('thread_pool_size')
        )
        self.deleter = MissingDeleter(
            self.anirss_api, 
            self.qbit_api, 
            self.openlist_api,
            self.config.get('qbit_max_age_hours')
        )
    
    def run(self) -> None:
        """执行同步操作"""
        missing_files = self.detector.detect_missing_files()
        
        if self.config.get('report'):
            self.detector.generate_report(missing_files)
        
        if self.config.get('delete') and missing_files:
            delete_result = self.deleter.delete_missing_files(missing_files)
            if self.config.get('report'):
                self.deleter.generate_delete_report(delete_result)
    
    def run_default_detect(self) -> None:
        """执行默认检测操作"""
        logger.info("未指定操作，默认执行检测")
        missing_files = self.detector.detect_missing_files()
        if self.config.get('report'):
            self.detector.generate_report(missing_files)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='anirss-openlist-sync遗漏检测与删除工具')
    parser.add_argument('--detect', action='store_true', help='仅执行遗漏检测')
    parser.add_argument('--delete', action='store_true', help='执行遗漏检测并删除文件')
    parser.add_argument('--report', action='store_true', help='生成详细报告')
    parser.add_argument('--config', type=str, help='指定配置文件路径')
    parser.add_argument('--anirss-url', type=str, help='anirss API地址')
    parser.add_argument('--openlist-url', type=str, help='openlist API地址')
    parser.add_argument('--openlist-username', type=str, help='openlist用户名')
    parser.add_argument('--openlist-password', type=str, help='openlist密码')
    
    args = parser.parse_args()
    
    # 初始化配置
    config = Config(args.config)
    
    # 配置日志
    setup_logging(config)
    
    # 合并命令行参数到配置
    config.update(
        detect=args.detect or config.get('detect'),
        delete=args.delete or config.get('delete'),
        report=args.report or config.get('report'),
        anirss_url=args.anirss_url or config.get('anirss_url'),
        openlist_url=args.openlist_url or config.get('openlist_url'),
        openlist_username=args.openlist_username or config.get('openlist_username'),
        openlist_password=args.openlist_password or config.get('openlist_password')
    )
    
    # 执行同步操作
    sync_manager = SyncManager(config)
    if config.get('detect') or config.get('delete'):
        sync_manager.run()
    else:
        sync_manager.run_default_detect()
    
    logger.info("操作完成")


if __name__ == '__main__':
    main()
