#!/usr/bin/env python3

"""
NoDPI
=====
Версия 4.0 – поддержка WebSocket, улучшенный контроль инжекции.
"""

import argparse
import asyncio
import logging
import os
import random
import socket
import ssl
import sys
import textwrap
import time
import traceback

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from urllib.error import URLError
from urllib.request import urlopen, Request

if sys.platform == "win32":
    import winreg

try:
    from active_bypass import ActiveBypassEngine, SCAPY_AVAILABLE as ACTIVE_BYPASS_AVAILABLE
except ImportError:
    ActiveBypassEngine = None
    ACTIVE_BYPASS_AVAILABLE = False

__version__ = "4.0.0"

os.system("")

def log_to_file(msg: str):
    try:
        with open("inject.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} - {msg}\n")
    except:
        pass


# ---------- Интерфейсы ----------
class IBlacklistManager(ABC):
    @abstractmethod
    def is_blocked(self, domain: str) -> bool:
        pass
    @abstractmethod
    async def check_domain(self, domain: bytes) -> None:
        pass

class ILogger(ABC):
    @abstractmethod
    def log_access(self, message: str) -> None:
        pass
    @abstractmethod
    def log_error(self, message: str) -> None:
        pass
    @abstractmethod
    def info(self, message: str) -> None:
        pass
    @abstractmethod
    def error(self, message: str) -> None:
        pass

class IStatistics(ABC):
    @abstractmethod
    def increment_total_connections(self) -> None:
        pass
    @abstractmethod
    def increment_allowed_connections(self) -> None:
        pass
    @abstractmethod
    def increment_blocked_connections(self) -> None:
        pass
    @abstractmethod
    def increment_error_connections(self) -> None:
        pass
    @abstractmethod
    def update_traffic(self, incoming: int, outgoing: int) -> None:
        pass
    @abstractmethod
    def update_speeds(self) -> None:
        pass
    @abstractmethod
    def get_stats_display(self) -> str:
        pass

class IConnectionHandler(ABC):
    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        pass

class IAutostartManager(ABC):
    @staticmethod
    @abstractmethod
    def manage_autostart(action: str) -> None:
        pass


# ---------- Классы ----------
class ConnectionInfo:
    def __init__(self, src_ip: str, dst_domain: str, dst_ip: str, dst_port: int,
                 protocol: str, method: str, should_fragment: bool, is_websocket: bool = False):
        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol      # 'TCP' или 'UDP'
        self.method = method
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0
        self.should_fragment = should_fragment
        self.is_websocket = is_websocket
        self.out_packets = 0
        self.bytes_sent = 0  # для cutoff


class ProxyConfig:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 8881
        self.out_host = None
        self.blacklist_file = "blacklist.txt"
        self.methods = ["random"]
        self.fake_sni = "www.google.com"
        self.repeat_delay = 100
        self.domain_matching = "strict"
        self.log_access_file = None
        self.log_error_file = None
        self.no_blacklist = False
        self.auto_blacklist = False
        self.quiet = False
        self.stream_frag_min = 0
        self.stream_frag_max = 0
        self.reverse_frag = False
        self.active_bypass = False
        self.inject_fake = 0
        self.fake_ttl = 3

        # Новые параметры
        self.dpi_desync_repeats = 0
        self.dpi_desync_autottl = False
        self.dpi_desync_start = 0
        self.dpi_desync_cutoff = 0
        self.dpi_desync_fooling = "none"
        self.filter_udp = ""           # диапазон портов, например "50000-50099"
        self.filter_l7 = ""             # список сигнатур через запятую, например "discord,stun"
        self.dpi_desync_mode = "split"  # split, multisplit, fakedsplit
        self.dpi_desync_split_pos = "1" # позиция разреза (байт или midsld)
        self.dpi_desync_websocket = "normal"  # bypass, normal, aggressive

        # Старые (совместимость)
        self.packet_disorder = False
        self.modify_seq = True
        self.sniff_interface = None


class FileBlacklistManager(IBlacklistManager):
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.blacklist_file = self.config.blacklist_file
        self.blocked: List[str] = []
        self.load_blacklist()

    def load_blacklist(self) -> None:
        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"File {self.blacklist_file} not found")
        with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line.strip()) < 2 or line.strip()[0] == '#':
                    continue
                self.blocked.append(line.strip().lower().replace('www.', ''))

    def is_blocked(self, domain: str) -> bool:
        domain = domain.replace('www.', '')
        if self.config.domain_matching == "loose":
            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return True
        if domain in self.blocked:
            return True
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.blocked:
                return True
        return False

    async def check_domain(self, domain: bytes) -> None:
        pass


class AutoBlacklistManager(IBlacklistManager):
    def __init__(self, config: ProxyConfig):
        self.blacklist_file = config.blacklist_file
        self.blocked: List[str] = []
        self.whitelist: List[str] = []
    def is_blocked(self, domain: str) -> bool:
        return domain in self.blocked
    async def check_domain(self, domain: bytes) -> None:
        domain_str = domain.decode()
        if domain_str in self.blocked or domain_str in self.whitelist:
            return
        try:
            req = Request(f"https://{domain_str}", headers={"User-Agent": "Mozilla/5.0"})
            context = ssl._create_unverified_context()
            with urlopen(req, timeout=4, context=context):
                self.whitelist.append(domain_str)
        except URLError as e:
            reason = str(e.reason)
            if "handshake operation timed out" in reason:
                self.blocked.append(domain_str)
                with open(self.blacklist_file, "a", encoding="utf-8") as f:
                    f.write(domain_str + "\n")


class NoBlacklistManager(IBlacklistManager):
    def is_blocked(self, domain: str) -> bool:
        return True
    async def check_domain(self, domain: bytes) -> None:
        pass


class ProxyLogger(ILogger):
    def __init__(self, log_access_file: Optional[str], log_error_file: Optional[str], quiet: bool = False):
        self.quiet = quiet
        self.logger = logging.getLogger(__name__)
        self.error_counter_callback = None
        self.setup_logging(log_access_file, log_error_file)

    def setup_logging(self, log_access_file: Optional[str], log_error_file: Optional[str]) -> None:
        class ErrorCounterHandler(logging.FileHandler):
            def __init__(self, counter_callback, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.counter_callback = counter_callback
            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    self.counter_callback()
                super().emit(record)

        if log_error_file:
            error_handler = ErrorCounterHandler(self.increment_errors, log_error_file, encoding="utf-8")
            error_handler.setFormatter(logging.Formatter("[%(asctime)s][%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S"))
            error_handler.setLevel(logging.ERROR)
            error_handler.addFilter(lambda record: record.levelno == logging.ERROR)
        else:
            error_handler = logging.NullHandler()

        if log_access_file:
            access_handler = logging.FileHandler(log_access_file, encoding="utf-8")
            access_handler.setFormatter(logging.Formatter("%(message)s"))
            access_handler.setLevel(logging.INFO)
            access_handler.addFilter(lambda record: record.levelno == logging.INFO)
        else:
            access_handler = logging.NullHandler()

        self.logger.propagate = False
        self.logger.handlers = []
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(access_handler)

    def set_error_counter_callback(self, callback):
        self.error_counter_callback = callback
    def increment_errors(self) -> None:
        if self.error_counter_callback:
            self.error_counter_callback()
    def log_access(self, message: str) -> None:
        self.logger.info(message)
    def log_error(self, message: str) -> None:
        self.logger.error(message)
    def info(self, *args, **kwargs) -> None:
        if not self.quiet:
            print(*args, **kwargs)
    def error(self, *args, **kwargs) -> None:
        if not self.quiet:
            print(*args, **kwargs)


class Statistics(IStatistics):
    def __init__(self):
        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0
        self.errors_connections = 0
        self.traffic_in = 0
        self.traffic_out = 0
        self.last_traffic_in = 0
        self.last_traffic_out = 0
        self.speed_in = 0
        self.speed_out = 0
        self.average_speed_in = (0, 1)
        self.average_speed_out = (0, 1)
        self.last_time = None

    def increment_total_connections(self) -> None:
        self.total_connections += 1
    def increment_allowed_connections(self) -> None:
        self.allowed_connections += 1
    def increment_blocked_connections(self) -> None:
        self.blocked_connections += 1
    def increment_error_connections(self) -> None:
        self.errors_connections += 1
    def update_traffic(self, incoming: int, outgoing: int) -> None:
        self.traffic_in += incoming
        self.traffic_out += outgoing
    def update_speeds(self) -> None:
        current_time = time.time()
        if self.last_time is not None:
            time_diff = current_time - self.last_time
            if time_diff > 0:
                self.speed_in = (self.traffic_in - self.last_traffic_in) * 8 / time_diff
                self.speed_out = (self.traffic_out - self.last_traffic_out) * 8 / time_diff
                if self.speed_in > 0:
                    self.average_speed_in = (self.average_speed_in[0] + self.speed_in, self.average_speed_in[1] + 1)
                if self.speed_out > 0:
                    self.average_speed_out = (self.average_speed_out[0] + self.speed_out, self.average_speed_out[1] + 1)
        self.last_traffic_in = self.traffic_in
        self.last_traffic_out = self.traffic_out
        self.last_time = current_time
    def get_stats_display(self) -> str:
        col_width = 30
        conns_stat = f"\033[97mTotal: \033[93m{self.total_connections}\033[0m".ljust(col_width) + \
                     "\033[97m| " + f"\033[97mMiss: \033[96m{self.allowed_connections}\033[0m".ljust(col_width) + \
                     "\033[97m| " + f"\033[97mUnblock: \033[92m{self.blocked_connections}\033[0m".ljust(col_width) + \
                     "\033[97m| " f"\033[97mErrors: \033[91m{self.errors_connections}\033[0m".ljust(col_width)
        traffic_stat = f"\033[97mTotal: \033[96m{self.format_size(self.traffic_out + self.traffic_in)}\033[0m".ljust(col_width) + \
                       "\033[97m| " + f"\033[97mDL: \033[96m{self.format_size(self.traffic_in)}\033[0m".ljust(col_width) + \
                       "\033[97m| " + f"\033[97mUL: \033[96m{self.format_size(self.traffic_out)}\033[0m".ljust(col_width) + "\033[97m| "
        avg_speed_in = self.average_speed_in[0] / self.average_speed_in[1] if self.average_speed_in[1] > 0 else 0
        avg_speed_out = self.average_speed_out[0] / self.average_speed_out[1] if self.average_speed_out[1] > 0 else 0
        speed_stat = f"\033[97mDL: \033[96m{self.format_speed(self.speed_in)}\033[0m".ljust(col_width) + \
                     "\033[97m| " + f"\033[97mUL: \033[96m{self.format_speed(self.speed_out)}\033[0m".ljust(col_width) + \
                     "\033[97m| " + f"\033[97mAVG DL: \033[96m{self.format_speed(avg_speed_in)}\033[0m".ljust(col_width) + \
                     "\033[97m| " + f"\033[97mAVG UL: \033[96m{self.format_speed(avg_speed_out)}\033[0m".ljust(col_width)
        title = "STATISTICS"
        top_border = f"\033[92m{'═' * 36} {title} {'═' * 36}\033[0m"
        line_conns = f"\033[92m   {'Conns'.ljust(8)}:\033[0m {conns_stat}\033[0m"
        line_traffic = f"\033[92m   {'Traffic'.ljust(8)}:\033[0m {traffic_stat}\033[0m"
        line_speed = f"\033[92m   {'Speed'.ljust(8)}:\033[0m {speed_stat}\033[0m"
        bottom_border = f"\033[92m{'═' * (36*2+len(title)+2)}\033[0m"
        return f"{top_border}\n{line_conns}\n{line_traffic}\n{line_speed}\n{bottom_border}"
    @staticmethod
    def format_size(size: int) -> str:
        units = ["B", "KB", "MB", "GB"]
        unit = 0
        size_float = float(size)
        while size_float >= 1024 and unit < len(units) - 1:
            size_float /= 1024
            unit += 1
        return f"{size_float:.1f} {units[unit]}"
    @staticmethod
    def format_speed(speed_bps: float) -> str:
        if speed_bps <= 0:
            return "0 b/s"
        units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
        unit = 0
        speed = speed_bps
        while speed >= 1000 and unit < len(units) - 1:
            speed /= 1000
            unit += 1
        return f"{speed:.0f} {units[unit]}"


class FragmentedWriter:
    def __init__(self, writer: asyncio.StreamWriter, min_size: int, max_size: int):
        self._writer = writer
        self.min_size = min_size
        self.max_size = max_size
    def write(self, data: bytes):
        pos = 0
        while pos < len(data):
            frag_size = random.randint(self.min_size, min(self.max_size, len(data) - pos))
            self._writer.write(data[pos:pos+frag_size])
            pos += frag_size
    async def drain(self):
        await self._writer.drain()
    def is_closing(self):
        return self._writer.is_closing()
    def close(self):
        self._writer.close()
    async def wait_closed(self):
        await self._writer.wait_closed()


class ConnectionHandler:
    def __init__(self, config: ProxyConfig, blacklist_manager: IBlacklistManager,
                 statistics: IStatistics, logger: ILogger):
        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.out_host = self.config.out_host
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()
        self.active_engine = None
        self.udp_transport = None

        # Парсинг фильтров
        self.udp_port_range = None
        if config.filter_udp:
            try:
                parts = config.filter_udp.split('-')
                if len(parts) == 2:
                    self.udp_port_range = (int(parts[0]), int(parts[1]))
            except:
                pass
        self.l7_signatures = [s.strip().encode() for s in config.filter_l7.split(',') if s.strip()] if config.filter_l7 else []

    # --- TCP обработка ---
    async def handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await reader.read(4096)  # читаем больше для анализа WebSocket
            if not http_data:
                writer.close()
                return
            method, host, port = self._parse_http_request(http_data)
            domain_str = host.decode()
            should_fragment = self.blacklist_manager.is_blocked(domain_str)
            conn_key = (client_ip, client_port)

            # Определяем, является ли запрос WebSocket-апгрейдом
            is_websocket = self._is_websocket_upgrade(http_data)

            # Резолвим IP
            try:
                dst_ip = socket.gethostbyname(domain_str)
            except:
                dst_ip = domain_str

            conn_info = ConnectionInfo(client_ip, domain_str, dst_ip, port, "TCP",
                                       method.decode(), should_fragment, is_websocket)

            # Если это WebSocket и выбран режим bypass, отключаем фрагментацию и инжекцию
            if is_websocket and self.config.dpi_desync_websocket == "bypass":
                conn_info.should_fragment = False
                log_to_file(f"WebSocket connection from {client_ip}:{client_port} to {domain_str} – bypassing fragmentation")

            if method == b"CONNECT" and isinstance(self.blacklist_manager, AutoBlacklistManager):
                await self.blacklist_manager.check_domain(host)

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            self.statistics.update_traffic(0, len(http_data))
            conn_info.traffic_out += len(http_data)

            if method == b"CONNECT":
                await self._handle_https_connection(reader, writer, host, port, conn_key, conn_info)
            else:
                await self._handle_http_connection(reader, writer, http_data, host, port, conn_key, conn_info)
        except Exception:
            await self._handle_connection_error(writer, conn_key)

    def _parse_http_request(self, http_data: bytes) -> Tuple[bytes, bytes, int]:
        headers = http_data.split(b"\r\n")
        first_line = headers[0].split(b" ")
        method = first_line[0]
        url = first_line[1]
        if method == b"CONNECT":
            host_port = url.split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            host_header = next((h for h in headers if h.startswith(b"Host: ")), None)
            if not host_header:
                raise ValueError("Missing Host header")
            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80
        return method, host, port

    def _is_websocket_upgrade(self, http_data: bytes) -> bool:
        """Проверяет, содержит ли запрос заголовок Upgrade: websocket."""
        headers = http_data.split(b"\r\n")
        for h in headers:
            if h.lower().startswith(b"upgrade:") and b"websocket" in h.lower():
                return True
        return False

    async def _handle_https_connection(self, reader, writer, host, port, conn_key, conn_info):
        response_size = len(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.statistics.update_traffic(response_size, 0)
        conn_info.traffic_in += response_size
        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port, local_addr=(self.out_host, 0) if self.out_host else None)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._handle_initial_tls_data(reader, remote_writer, host, conn_info)
        await self._setup_tcp_piping(reader, writer, remote_reader, remote_writer, conn_key, conn_info.should_fragment)

    async def _handle_http_connection(self, reader, writer, http_data, host, port, conn_key, conn_info):
        http_data = self._modify_http_request(http_data)
        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port, local_addr=(self.out_host, 0) if self.out_host else None)
        remote_writer.write(http_data)
        await remote_writer.drain()
        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()
        await self._setup_tcp_piping(reader, writer, remote_reader, remote_writer, conn_key, conn_info.should_fragment)

    def _modify_http_request(self, data: bytes) -> bytes:
        # Здесь можно добавить hostcase, hostdot и т.д., для краткости оставим как есть
        return data

    def _extract_sni_position(self, data):
        i = 0
        while i < len(data) - 8:
            if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
                ext_len = data[i+3]
                server_name_list_len = data[i+5]
                server_name_len = data[i+8]
                if ext_len - server_name_list_len == 2 and server_name_list_len - server_name_len == 3:
                    sni_start = i + 9
                    sni_end = sni_start + server_name_len
                    return sni_start, sni_end
            i += 1
        return None

    def _create_fake_tls_record(self, data: bytes) -> bytes:
        header = bytes([0x16, 0x03, 0x03, (len(data) >> 8) & 0xFF, len(data) & 0xFF])
        return header + data

    async def _repeat_first_fragment(self, writer: asyncio.StreamWriter, fragment: bytes, delay_ms: int):
        await asyncio.sleep(delay_ms / 1000)
        try:
            if not writer.is_closing():
                writer.write(fragment)
                await writer.drain()
        except:
            pass

    async def _handle_initial_tls_data(self, reader, writer, host, conn_info):
        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            self.logger.log_error(f"{host.decode()} : {traceback.format_exc()}")
            return
        should_fragment = conn_info.should_fragment
        if not should_fragment:
            combined = head + data
            writer.write(combined)
            await writer.drain()
            self.statistics.update_traffic(0, len(combined))
            conn_info.traffic_out += len(combined)
            self.statistics.increment_total_connections()
            self.statistics.increment_allowed_connections()
            return
        fragments = []
        methods = self.config.methods
        if 'faketls' in methods:
            fake_data = os.urandom(random.randint(32, 128))
            fake_record = self._create_fake_tls_record(fake_data)
            fragments.append(fake_record)
        if 'snifake' in methods:
            fake_data = b"\x16\x03\x03" + os.urandom(100)
            fragments.append(fake_data)
        if 'random' in methods:
            host_end = data.find(b"\x00")
            if host_end != -1:
                part_data = bytes.fromhex("160304") + (host_end + 1).to_bytes(2, "big") + data[: host_end + 1]
                fragments.append(part_data)
                remaining = data[host_end + 1:]
            else:
                remaining = data
            while remaining:
                chunk_len = min(random.randint(50, 200), len(remaining))
                part_data = bytes.fromhex("160304") + chunk_len.to_bytes(2, "big") + remaining[:chunk_len]
                fragments.append(part_data)
                remaining = remaining[chunk_len:]
        elif 'sni' in methods:
            sni_pos = self._extract_sni_position(data)
            if sni_pos:
                part_start = data[: sni_pos[0]]
                sni_data = data[sni_pos[0] : sni_pos[1]]
                part_end = data[sni_pos[1]:]
                middle = (len(sni_data) + 1) // 2
                fragments.append(bytes.fromhex("160304") + len(part_start).to_bytes(2, "big") + part_start)
                fragments.append(bytes.fromhex("160304") + len(sni_data[:middle]).to_bytes(2, "big") + sni_data[:middle])
                fragments.append(bytes.fromhex("160304") + len(sni_data[middle:]).to_bytes(2, "big") + sni_data[middle:])
                fragments.append(bytes.fromhex("160304") + len(part_end).to_bytes(2, "big") + part_end)
            else:
                full = self._create_fake_tls_record(head + data)
                fragments.append(full)
        else:
            full = self._create_fake_tls_record(head + data)
            fragments.append(full)
        if 'multidisorder' in methods and len(fragments) > 1:
            random.shuffle(fragments)
        if self.config.reverse_frag:
            fragments.reverse()
        for frag in fragments:
            writer.write(frag)
            await writer.drain()
            self.statistics.update_traffic(0, len(frag))
            conn_info.traffic_out += len(frag)
        if 'repeat' in methods and fragments:
            asyncio.create_task(self._repeat_first_fragment(writer, fragments[0], self.config.repeat_delay))
        self.statistics.increment_total_connections()
        self.statistics.increment_blocked_connections()

    async def _setup_tcp_piping(self, client_reader, client_writer, remote_reader, remote_writer, conn_key, should_fragment):
        async with self.tasks_lock:
            self.tasks.extend([
                asyncio.create_task(self._pipe_tcp(client_reader, remote_writer, "out", conn_key, should_fragment)),
                asyncio.create_task(self._pipe_tcp(remote_reader, client_writer, "in", conn_key, should_fragment)),
            ])

    async def _pipe_tcp(self, reader, writer, direction, conn_key, should_fragment):
        if direction == 'out' and should_fragment and self.config.stream_frag_min > 0:
            writer = FragmentedWriter(writer, self.config.stream_frag_min, self.config.stream_frag_max)
        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(1500)
                if not data:
                    break
                if direction == "out":
                    self.statistics.update_traffic(0, len(data))
                else:
                    self.statistics.update_traffic(len(data), 0)
                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            conn_info.traffic_out += len(data)
                            conn_info.bytes_sent += len(data)
                        else:
                            conn_info.traffic_in += len(data)
                writer.write(data)
                await writer.drain()

                # Активный обход для TCP
                if (direction == 'out' and
                    self.active_engine and
                    self.config.inject_fake > 0 and
                    should_fragment and
                    conn_info):

                    # Если это WebSocket и режим bypass, не инжектим
                    if conn_info.is_websocket and self.config.dpi_desync_websocket == "bypass":
                        continue

                    # Проверка start и cutoff
                    if conn_info.out_packets < self.config.dpi_desync_start:
                        pass
                    elif self.config.dpi_desync_cutoff > 0 and conn_info.bytes_sent > self.config.dpi_desync_cutoff:
                        # превысили лимит – больше не применяем обход к этому соединению
                        pass
                    else:
                        conn_info.out_packets += 1
                        if conn_info.out_packets % self.config.inject_fake == 0:
                            sockname = writer.get_extra_info('sockname')
                            src_port = sockname[1] if sockname else 0

                            ttl = self.config.fake_ttl
                            if self.config.dpi_desync_autottl and self.active_engine:
                                ttl = self.active_engine.get_optimal_ttl()

                            log_to_file(f"TCP out packet for {conn_info.dst_ip}, triggering inject")
                            try:
                                self.active_engine.inject_fake(
                                    src_ip=conn_info.src_ip,
                                    dst_ip=conn_info.dst_ip,
                                    src_port=src_port,
                                    dst_port=conn_info.dst_port,
                                    seq=random.randint(1000, 1000000),
                                    ack=0,
                                    window=64240,
                                    protocol='TCP',
                                    repeats=self.config.dpi_desync_repeats,
                                    fooling=self.config.dpi_desync_fooling,
                                    ttl=ttl
                                )
                            except Exception as e:
                                self.logger.log_error(f"Inject error: {e}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            conn_info = self.active_connections.get(conn_key)
            domain = conn_info.dst_domain if conn_info else "unknown"
            self.logger.log_error(f"{domain} : {traceback.format_exc()}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(f"{conn_info.start_time} {conn_info.src_ip} {conn_info.method} {conn_info.dst_domain} {conn_info.traffic_in} {conn_info.traffic_out}")

    # --- UDP обработка (оставлена как заглушка) ---
    async def handle_udp(self):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPProtocol(self),
            local_addr=(self.config.host, self.config.port)
        )
        self.udp_transport = transport
        self.logger.info(f"UDP proxy listening on {self.config.host}:{self.config.port}")
        return transport

    def udp_datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Заглушка – для полноценного UDP-прокси нужен перехват пакетов
        pass

    async def _handle_connection_error(self, writer, conn_key):
        try:
            error_response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
            writer.write(error_response)
            await writer.drain()
            self.statistics.update_traffic(len(error_response), 0)
        except:
            pass
        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)
        self.statistics.increment_total_connections()
        self.statistics.increment_error_connections()
        if conn_info:
            self.logger.log_error(f"{conn_info.dst_domain} : {traceback.format_exc()}")
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

    async def cleanup_tasks(self) -> None:
        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: ConnectionHandler):
        self.handler = handler
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        self.handler.udp_datagram_received(data, addr)


class ProxyServer:
    def __init__(self, config: ProxyConfig, blacklist_manager: IBlacklistManager,
                 statistics: IStatistics, logger: ILogger):
        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(config, blacklist_manager, statistics, logger)
        self.tcp_server = None
        self.udp_transport = None
        self.active_engine = None
        logger.set_error_counter_callback(statistics.increment_error_connections)

    def print_banner(self) -> None:
        self.logger.info("\033]0;NoDPI\007")
        if sys.platform == "win32":
            os.system("mode con: lines=35")
        console_width = os.get_terminal_size().columns
        disclaimer = """DISCLAIMER. The developer and/or supplier of this software shall not be liable for any loss or damage, including but not limited to direct, indirect, incidental, punitive or consequential damages arising out of the use of or inability to use this software, even if the developer or supplier has been advised of the possibility of such damages. The developer and/or supplier of this software shall not be liable for any legal consequences arising out of the use of this software. This includes, but is not limited to, violation of laws, rules or regulations, as well as any claims or suits arising out of the use of this software. The user is solely responsible for compliance with all applicable laws and regulations when using this software."""
        wrapped_text = textwrap.TextWrapper(width=70).wrap(disclaimer)
        left_padding = (console_width - 76) // 2
        self.logger.info("\n\n\n")
        self.logger.info("\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m")
        for line in wrapped_text:
            padded_line = line.ljust(70)
            self.logger.info("\033[91m" + " " * left_padding + "║ " + padded_line + " ║" + "\033[0m")
        self.logger.info("\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m")
        time.sleep(1)
        self.logger.info('\033[2J\033[H')
        self.logger.info("""
\033[92m ██████   █████          ██████████   ███████████  █████
░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
 ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
 ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
 ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
 ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
 █████  ░░█████░░██████  ██████████   █████        █████
░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """)
        self.logger.info(f"\033[92mVersion: {__version__}".center(50))
        self.logger.info("\033[97m" + "Enjoy watching! / Наслаждайтесь просмотром!".center(50))
        self.logger.info("\n")
        self.logger.info(f"\033[92m[INFO]:\033[97m Proxy is running on {self.config.host}:{self.config.port} (TCP+UDP)")
        self.logger.info(f"\033[92m[INFO]:\033[97m Selected methods: {', '.join(self.config.methods)}")
        if self.config.fake_sni:
            self.logger.info(f"\033[92m[INFO]:\033[97m Fake SNI: {self.config.fake_sni}")
        if self.config.repeat_delay:
            self.logger.info(f"\033[92m[INFO]:\033[97m Repeat delay: {self.config.repeat_delay} ms")
        if self.config.stream_frag_min > 0:
            self.logger.info(f"\033[92m[INFO]:\033[97m Stream fragmentation: {self.config.stream_frag_min}-{self.config.stream_frag_max} bytes")
        if self.config.reverse_frag:
            self.logger.info("\033[92m[INFO]:\033[97m Reverse fragmentation enabled for ClientHello")
        if self.config.active_bypass:
            self.logger.info("\033[92m[INFO]:\033[97m Active DPI bypass: ENABLED (injection mode)")
            if self.config.inject_fake > 0:
                self.logger.info(f"\033[92m[INFO]:\033[97m   Fake packet injection: every {self.config.inject_fake} packets, TTL={self.config.fake_ttl}")
            if self.config.dpi_desync_repeats > 0:
                self.logger.info(f"\033[92m[INFO]:\033[97m   Repeats: {self.config.dpi_desync_repeats}")
            if self.config.dpi_desync_fooling != "none":
                self.logger.info(f"\033[92m[INFO]:\033[97m   Fooling: {self.config.dpi_desync_fooling}")
            if self.config.dpi_desync_autottl:
                self.logger.info("\033[92m[INFO]:\033[97m   Auto TTL enabled")
            if self.config.dpi_desync_start > 0:
                self.logger.info(f"\033[92m[INFO]:\033[97m   Start after {self.config.dpi_desync_start} packets")
            if self.config.dpi_desync_cutoff > 0:
                self.logger.info(f"\033[92m[INFO]:\033[97m   Cutoff after {self.config.dpi_desync_cutoff} bytes")
            if self.config.filter_udp:
                self.logger.info(f"\033[92m[INFO]:\033[97m   UDP port filter: {self.config.filter_udp}")
            if self.config.filter_l7:
                self.logger.info(f"\033[92m[INFO]:\033[97m   L7 filter: {self.config.filter_l7}")
            if self.config.dpi_desync_mode != "split":
                self.logger.info(f"\033[92m[INFO]:\033[97m   Desync mode: {self.config.dpi_desync_mode}, split pos: {self.config.dpi_desync_split_pos}")
            if self.config.dpi_desync_websocket:
                self.logger.info(f"\033[92m[INFO]:\033[97m   WebSocket mode: {self.config.dpi_desync_websocket}")
        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info("\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking.")
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info("\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.logger.info(f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blacklist_manager.blocked)} domains")
            self.logger.info(f"\033[92m[INFO]:\033[97m Path to blacklist: '{self.config.blacklist_file}'")
        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.config.log_error_file}'")
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Error logging is disabled")
        if self.config.log_access_file:
            self.logger.info(f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.config.log_access_file}'")
        else:
            self.logger.info("\033[92m[INFO]:\033[97m Access logging is disabled")
        self.logger.info("")
        self.logger.info("\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice")
        self.logger.info("")

    async def display_stats(self) -> None:
        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                stats_display = self.statistics.get_stats_display()
                print(stats_display)
                print("\033[5A", end="")

    async def run(self) -> None:
        if not self.config.quiet:
            self.print_banner()
        try:
            # TCP server
            self.tcp_server = await asyncio.start_server(
                self.connection_handler.handle_tcp_connection,
                self.config.host,
                self.config.port
            )
            # UDP server (если нужен)
            if self.config.filter_udp or self.config.filter_l7:
                await self.connection_handler.handle_udp()
        except OSError as e:
            self.logger.error(f"\033[91m[ERROR]: Failed to start proxy: {e}\033[0m")
            sys.exit(1)

        if self.config.active_bypass:
            if not ACTIVE_BYPASS_AVAILABLE or ActiveBypassEngine is None:
                self.logger.error("\033[91m[ERROR]: Active bypass requested but Scapy is not available. Please install scapy.\033[0m")
                sys.exit(1)
            blacklisted_domains = set(self.blacklist_manager.blocked) if hasattr(self.blacklist_manager, 'blocked') else set()
            self.active_engine = ActiveBypassEngine(
                proxy_host=self.config.host,
                proxy_port=self.config.port,
                blacklisted_domains=blacklisted_domains,
                dns_resolver=socket.gethostbyname,
                inject_fake=self.config.inject_fake,
                fake_ttl=self.config.fake_ttl,
                repeats=self.config.dpi_desync_repeats,
                fooling=self.config.dpi_desync_fooling,
                autottl=self.config.dpi_desync_autottl
            )
            self.active_engine.start()
            self.connection_handler.active_engine = self.active_engine
            self.logger.info("\033[92m[INFO]:\033[97m Active DPI bypass engine started (injection mode)")

        if not self.config.quiet:
            asyncio.create_task(self.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())
        await self.tcp_server.serve_forever()

    async def shutdown(self) -> None:
        if self.active_engine:
            self.active_engine.stop()
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
        if self.connection_handler.udp_transport:
            self.connection_handler.udp_transport.close()
        for task in self.connection_handler.tasks:
            task.cancel()


class BlacklistManagerFactory:
    @staticmethod
    def create(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
        if config.no_blacklist:
            return NoBlacklistManager()
        if config.auto_blacklist:
            return AutoBlacklistManager(config)
        try:
            return FileBlacklistManager(config)
        except FileNotFoundError as e:
            logger.error(f"\033[91m[ERROR]: {e}\033[0m")
            sys.exit(1)


class ConfigLoader:
    @staticmethod
    def load_from_args(args) -> ProxyConfig:
        config = ProxyConfig()
        config.host = args.host
        config.port = args.port
        config.out_host = args.out_host
        config.blacklist_file = args.blacklist
        config.methods = [m.strip() for m in args.method.split('+')] if args.method else ['random']
        config.fake_sni = args.fake_sni
        config.repeat_delay = args.repeat_delay
        config.domain_matching = args.domain_matching
        config.log_access_file = args.log_access
        config.log_error_file = args.log_error
        config.no_blacklist = args.no_blacklist
        config.auto_blacklist = args.autoblacklist
        config.quiet = args.quiet
        if args.stream_frag_size:
            try:
                min_s, max_s = map(int, args.stream_frag_size.split('-'))
                config.stream_frag_min = min_s
                config.stream_frag_max = max_s
            except ValueError:
                print("Неверный формат --stream-frag-size. Используйте мин-макс, например 50-150")
                sys.exit(1)
        config.reverse_frag = args.reverse_frag
        config.active_bypass = args.active_dpi_bypass
        config.inject_fake = args.inject_fake
        config.fake_ttl = args.fake_ttl
        config.packet_disorder = args.packet_disorder
        config.modify_seq = args.modify_seq
        config.sniff_interface = args.interface

        # Новые параметры
        config.dpi_desync_repeats = args.dpi_desync_repeats
        config.dpi_desync_autottl = args.dpi_desync_autottl
        config.dpi_desync_start = args.dpi_desync_start
        config.dpi_desync_cutoff = args.dpi_desync_cutoff
        config.dpi_desync_fooling = args.dpi_desync_fooling
        config.filter_udp = args.filter_udp
        config.filter_l7 = args.filter_l7
        config.dpi_desync_mode = args.dpi_desync_mode
        config.dpi_desync_split_pos = args.dpi_desync_split_pos
        config.dpi_desync_websocket = args.dpi_desync_websocket
        return config


class WindowsAutostartManager(IAutostartManager):
    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        app_name = "NoDPIProxy"
        exe_path = sys.executable
        try:
            key = winreg.HKEY_CURRENT_USER
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            if action == "install":
                with winreg.OpenKey(key, reg_path, 0, winreg.KEY_WRITE) as regkey:
                    winreg.SetValueEx(regkey, app_name, 0, winreg.REG_SZ,
                                      f'"{exe_path}" --blacklist "{os.path.dirname(exe_path)}/blacklist.txt"')
                print(f"\033[92m[INFO]:\033[97m Added to autostart: {exe_path}")
            elif action == "uninstall":
                try:
                    with winreg.OpenKey(key, reg_path, 0, winreg.KEY_WRITE) as regkey:
                        winreg.DeleteValue(regkey, app_name)
                    print("\033[92m[INFO]:\033[97m Removed from autostart")
                except FileNotFoundError:
                    print("\033[91m[ERROR]: Not found in autostart\033[0m")
        except PermissionError:
            print("\033[91m[ERROR]: Access denied. Run as administrator\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")


class LinuxAutostartManager(IAutostartManager):
    @staticmethod
    def manage_autostart(action: str = "install") -> None:
        app_name = "NoDPIProxy"
        exec_path = sys.executable
        if action == "install":
            try:
                autostart_dir = Path.home() / ".config" / "autostart"
                autostart_dir.mkdir(parents=True, exist_ok=True)
                desktop_file = autostart_dir / f"{app_name}.desktop"
                desktop_content = ("[Desktop Entry]\nType=Application\nName={app_name}\nExec={exec_path} --blacklist '{os.path.dirname(exec_path)}/blacklist.txt'\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true")
                with open(desktop_file, "w", encoding="utf-8") as f:
                    f.write(desktop_content)
                print(f"\033[92m[INFO]:\033[97m Added to autostart: {exe_path}")
            except Exception as e:
                print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")
        elif action == "uninstall":
            autostart_dir = Path.home() / ".config" / "autostart"
            desktop_file = autostart_dir / f"{app_name}.desktop"
            if desktop_file.exists():
                try:
                    desktop_file.unlink()
                    print("\033[92m[INFO]:\033[97m Removed from autostart")
                except Exception as e:
                    print(f"\033[91m[ERROR]: Autostart operation failed: {e}\033[0m")


class ProxyApplication:
    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8881)
        parser.add_argument("--out-host")
        bl_group = parser.add_mutually_exclusive_group()
        bl_group.add_argument("--blacklist", default="blacklist.txt")
        bl_group.add_argument("--no-blacklist", action="store_true")
        bl_group.add_argument("--autoblacklist", action="store_true")
        parser.add_argument("--method", default="random", help="Methods: random, sni, ...")
        parser.add_argument("--fake-sni", default="www.google.com")
        parser.add_argument("--repeat-delay", type=int, default=100)
        parser.add_argument("--domain-matching", default="strict", choices=["loose","strict"])
        parser.add_argument("--log-access")
        parser.add_argument("--log-error")
        parser.add_argument("-q","--quiet", action="store_true")
        parser.add_argument("--install", action="store_true")
        parser.add_argument("--uninstall", action="store_true")
        parser.add_argument("--stream-frag-size", help="min-max")
        parser.add_argument("--reverse-frag", action="store_true")
        parser.add_argument("--active-dpi-bypass", action="store_true", help="Enable active injection")
        parser.add_argument("--inject-fake", type=int, default=0, help="Inject fake packet every N packets")
        parser.add_argument("--fake-ttl", type=int, default=3, help="TTL for fake packets")
        parser.add_argument("--packet-disorder", action="store_true")
        parser.add_argument("--modify-seq", action="store_true", default=True)
        parser.add_argument("--interface", help="not used")

        # Новые параметры
        parser.add_argument("--dpi-desync-repeats", type=int, default=0, help="Repeats count")
        parser.add_argument("--dpi-desync-autottl", action="store_true", help="Auto TTL")
        parser.add_argument("--dpi-desync-start", type=int, default=0, help="Start after N packets")
        parser.add_argument("--dpi-desync-cutoff", type=int, default=0, help="Cutoff after N bytes")
        parser.add_argument("--dpi-desync-fooling", default="none", choices=["none", "md5sig", "badseq", "badsum", "ts", "md5sig,badseq"], help="Fooling methods")
        parser.add_argument("--filter-udp", default="", help="UDP port range, e.g. 50000-50099")
        parser.add_argument("--filter-l7", default="", help="L7 signatures, comma separated, e.g. discord,stun")
        parser.add_argument("--dpi-desync-mode", default="split", choices=["split", "multisplit", "fakedsplit"], help="Desync mode")
        parser.add_argument("--dpi-desync-split-pos", default="1", help="Split position: byte number or 'midsld'")
        parser.add_argument("--dpi-desync-websocket", default="normal", choices=["bypass", "normal", "aggressive"], help="WebSocket handling")
        return parser.parse_args()

    @classmethod
    async def run(cls):
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
        args = cls.parse_args()
        if args.install or args.uninstall:
            if getattr(sys, "frozen", False):
                if args.install:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("install")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("install")
                elif args.uninstall:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("uninstall")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("uninstall")
                sys.exit(0)
            else:
                print("\033[91m[ERROR]: Autostart works only in executable version\033[0m")
                sys.exit(1)
        config = ConfigLoader.load_from_args(args)
        logger = ProxyLogger(config.log_access_file, config.log_error_file, config.quiet)
        blacklist_manager = BlacklistManagerFactory.create(config, logger)
        statistics = Statistics()
        logger.set_error_counter_callback(statistics.increment_error_connections)
        proxy = ProxyServer(config, blacklist_manager, statistics, logger)
        try:
            await proxy.run()
        except asyncio.CancelledError:
            await proxy.shutdown()
            logger.info("\n"*6 + "\033[92m[INFO]:\033[97m Shutting down proxy...")
            try:
                if sys.platform == "win32":
                    os.system("mode con: lines=3000")
                sys.exit(0)
            except asyncio.CancelledError:
                pass

if __name__ == "__main__":
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass