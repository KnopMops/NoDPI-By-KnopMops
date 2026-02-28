#!/usr/bin/env python3
"""
Active DPI bypass engine - расширенная версия с поддержкой repeats, fooling, autottl.
"""

import os
import random
import socket
import threading
import time
from typing import Set, Optional, Callable
from datetime import datetime

try:
    from scapy.all import send, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

def log_to_file(msg: str):
    try:
        with open("inject.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} - {msg}\n")
    except:
        pass

def log_console(msg: str):
    print(f"[BYPASS] {msg}")


class ActiveBypassEngine:
    def __init__(
        self,
        proxy_host: str = '127.0.0.1',
        proxy_port: int = 8881,
        blacklisted_domains: Set[str] = None,
        dns_resolver: Callable[[str], str] = None,
        inject_fake: int = 0,
        fake_ttl: int = 3,
        repeats: int = 0,
        fooling: str = "none",
        autottl: bool = False,
        **kwargs
    ):
        log_to_file("ActiveBypassEngine.__init__ started")
        log_console("ActiveBypassEngine.__init__ started")
        if not SCAPY_AVAILABLE:
            log_to_file("Scapy not available")
            log_console("Scapy not available")
            raise ImportError("Scapy is not installed. Please install scapy.")

        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.blacklisted_domains = blacklisted_domains or set()
        self.dns_resolver = dns_resolver or socket.gethostbyname
        self.inject_fake_freq = inject_fake
        self.fake_ttl = fake_ttl
        self.repeats = repeats
        self.fooling = fooling
        self.autottl = autottl
        self.optimal_ttl = fake_ttl  # по умолчанию

        self.blacklisted_ips: Set[str] = set()
        self._resolve_blacklisted_domains()

        if self.autottl:
            self._determine_optimal_ttl()

        log_to_file(f"ActiveBypassEngine.__init__ finished, blacklisted IPs: {self.blacklisted_ips}")
        log_console(f"ActiveBypassEngine.__init__ finished, blacklisted IPs: {self.blacklisted_ips}")

    def _resolve_blacklisted_domains(self):
        for domain in self.blacklisted_domains:
            try:
                ip = self.dns_resolver(domain)
                self.blacklisted_ips.add(ip)
                log_to_file(f"Resolved {domain} -> {ip}")
                log_console(f"Resolved {domain} -> {ip}")
            except Exception as e:
                log_to_file(f"Failed to resolve {domain}: {e}")
                log_console(f"Failed to resolve {domain}: {e}")

    def _determine_optimal_ttl(self):
        """Простой алгоритм определения оптимального TTL."""
        test_target = "8.8.8.8"
        log_console("AutoTTL: probing for optimal TTL...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(1)
        for ttl in range(3, 20):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            try:
                sock.sendto(b"probe", (test_target, 53))
                sock.recvfrom(1024)
                log_console(f"AutoTTL: TTL {ttl} reached target")
                self.optimal_ttl = ttl
                break
            except socket.timeout:
                log_console(f"AutoTTL: TTL {ttl} timed out")
                self.optimal_ttl = ttl
                break
            except Exception:
                pass
        sock.close()
        log_console(f"AutoTTL: selected TTL = {self.optimal_ttl}")

    def get_optimal_ttl(self):
        return self.optimal_ttl

    def start(self):
        log_to_file("ActiveBypassEngine.start() called")
        log_console("ActiveBypassEngine.start() called")

    def stop(self):
        log_to_file("ActiveBypassEngine.stop() called")
        log_console("ActiveBypassEngine.stop() called")

    def should_bypass(self, dst_ip: str) -> bool:
        result = dst_ip in self.blacklisted_ips
        log_to_file(f"should_bypass({dst_ip}) -> {result}")
        return result

    def inject_fake(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int = None, ack: int = 0, window: int = 64240,
                     protocol: str = 'TCP', repeats: int = None, fooling: str = None, ttl: int = None):
        if repeats is None:
            repeats = self.repeats
        if fooling is None:
            fooling = self.fooling
        if ttl is None:
            ttl = self.optimal_ttl if self.autottl else self.fake_ttl

        log_to_file(f"inject_fake ENTERED: src={src_ip}:{src_port} dst={dst_ip}:{dst_port} proto={protocol} repeats={repeats} fooling={fooling}")

        if not self.should_bypass(dst_ip):
            log_to_file("inject_fake: dst_ip not in blacklist, skipping")
            return

        ip = IP(src=src_ip, dst=dst_ip, ttl=ttl)
        fake_data = os.urandom(random.randint(20, 100))

        if protocol == 'TCP':
            if seq is None:
                seq = random.randint(1000, 1000000)
            tcp = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack,
                      flags="A", window=window)
            if 'md5sig' in fooling:
                tcp = tcp / Raw(b'\x13\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            if 'badseq' in fooling:
                tcp.seq += 1000000
            if 'ts' in fooling:
                tcp = tcp / Raw(b'\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00')
            pkt = ip / tcp / fake_data
        else:  # UDP
            udp = UDP(sport=src_port, dport=dst_port)
            pkt = ip / udp / fake_data

        log_to_file(f"Generating fake {protocol} packet, TTL={ttl}")

        for i in range(repeats + 1):
            try:
                send(pkt, verbose=False)
                log_to_file(f"FAKE {protocol} packet sent (copy {i+1}) to {dst_ip}:{dst_port}")
                print(f"[INJECT] Fake {protocol} to {dst_ip}:{dst_port} TTL={ttl} copy {i+1}")
                if i < repeats:
                    time.sleep(0.001)
            except Exception as e:
                log_to_file(f"FAILED to inject fake {protocol} packet: {e}")
                print(f"[ERROR] Failed to inject fake {protocol}: {e}")