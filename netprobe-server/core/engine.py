"""
NetProbe Core Engine
All network operations - runs in threads, reports via callbacks
"""
import socket
import struct
import time
import threading
import subprocess
import platform
import os
import sys
import select
import random
import queue
import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Optional, List, Dict
from datetime import datetime

OS = platform.system()  # 'Linux', 'Windows', 'Darwin'

# Suppress the black console window that Windows shows for every subprocess.
# Pass **_HIDE to every subprocess.Popen / run / check_output call.
_HIDE = {'creationflags': 0x08000000} if OS == 'Windows' else {}

# ─────────────────────────────────────────────
# iperf3 binary resolver
# ─────────────────────────────────────────────

def find_iperf3() -> Optional[str]:
    """
    Find iperf3 binary. Search order:
    1. Extracted from frozen PyInstaller bundle (_MEIPASS)
    2. Same directory as the running script/exe
    3. System PATH
    Returns full path string or None.
    """
    exe_name = 'iperf3.exe' if OS == 'Windows' else 'iperf3'

    # 1. PyInstaller frozen bundle
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidate = os.path.join(meipass, exe_name)
        if os.path.isfile(candidate):
            return candidate

    # 2. Next to the script / exe
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
        # Also check project root (one level up from core/)
        base_root = os.path.dirname(base)
        candidate = os.path.join(base_root, exe_name)
        if os.path.isfile(candidate):
            return candidate

    candidate = os.path.join(base, exe_name)
    if os.path.isfile(candidate):
        return candidate

    # 3. System PATH
    import shutil
    return shutil.which('iperf3')


@dataclass
class PingResult:
    host: str
    ip: str
    seq: int
    rtt_ms: float        # -1 = timeout
    ttl: int = 0
    timestamp: float = field(default_factory=time.time)

@dataclass
class HopResult:
    hop: int
    ip: str
    hostname: str
    rtts: List[float]    # 3 probes; -1 = no response
    loss_pct: float = 0.0

@dataclass
class MTRRow:
    hop: int
    ip: str
    hostname: str
    sent: int = 0
    loss_pct: float = 0.0
    last_ms: float = 0.0
    avg_ms: float = 0.0
    best_ms: float = 999999.0
    worst_ms: float = 0.0
    stdev_ms: float = 0.0
    _rtts: List[float] = field(default_factory=list)

    def update(self, rtt: float):
        self.sent += 1
        if rtt < 0:
            self.loss_pct = (self.sent - len(self._rtts)) / self.sent * 100
            return
        self._rtts.append(rtt)
        self.last_ms = rtt
        self.best_ms = min(self.best_ms, rtt)
        self.worst_ms = max(self.worst_ms, rtt)
        self.avg_ms = sum(self._rtts) / len(self._rtts)
        self.loss_pct = (self.sent - len(self._rtts)) / self.sent * 100
        if len(self._rtts) > 1:
            mean = self.avg_ms
            self.stdev_ms = (sum((x - mean)**2 for x in self._rtts) / len(self._rtts)) ** 0.5

@dataclass
class PortResult:
    host: str
    port: int
    state: str           # 'open', 'closed', 'filtered'
    service: str = ''
    banner: str = ''
    rtt_ms: float = 0.0

@dataclass
class DNSResult:
    query: str
    record_type: str
    answers: List[str]
    nameserver: str = ''
    rtt_ms: float = 0.0
    error: str = ''

@dataclass
class ARPEntry:
    ip: str
    mac: str
    hostname: str = ''
    vendor: str = ''
    interface: str = ''

@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    flags: str = ''
    info: str = ''

# ─────────────────────────────────────────────
# ICMP helpers (cross-platform raw socket)
# ─────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i+1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def _build_icmp_echo(pid: int, seq: int) -> bytes:
    pid = pid & 0xFFFF
    seq = seq & 0x7FFF  # keep within signed short range to be safe
    header = struct.pack('bbHHH', 8, 0, 0, pid, seq)
    payload = b'NetProbe' * 4
    chk = _checksum(header + payload)
    header = struct.pack('bbHHH', 8, 0, chk, pid, seq)
    return header + payload

def _icmp_ping(host: str, seq: int, timeout: float = 2.0, ttl: int = 64) -> PingResult:
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return PingResult(host=host, ip='', seq=seq, rtt_ms=-1)

    pid = os.getpid() & 0xFFFF

    try:
        if OS == 'Windows':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.settimeout(timeout)
    except PermissionError:
        # Fall back to subprocess ping if no raw socket permission
        return _subprocess_ping(host, seq)

    packet = _build_icmp_echo(pid, seq)
    t_send = time.perf_counter()
    sock.sendto(packet, (ip, 1))

    try:
        while True:
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                sock.close()
                return PingResult(host=host, ip=ip, seq=seq, rtt_ms=-1)
            raw, addr = sock.recvfrom(1024)
            t_recv = time.perf_counter()
            # parse ICMP
            ip_header_len = (raw[0] & 0xF) * 4
            icmp_data = raw[ip_header_len:]
            icmp_type, _, _, recv_pid, recv_seq = struct.unpack('bbHHh', icmp_data[:8])
            ip_ttl = raw[8]
            if icmp_type == 0 and recv_pid == pid and recv_seq == seq:
                rtt = (t_recv - t_send) * 1000
                sock.close()
                return PingResult(host=host, ip=ip, seq=seq, rtt_ms=round(rtt, 3), ttl=ip_ttl)
            elif icmp_type == 11:  # TTL exceeded - still count as response for traceroute
                rtt = (t_recv - t_send) * 1000
                sock.close()
                return PingResult(host=host, ip=addr[0], seq=seq, rtt_ms=round(rtt, 3), ttl=ip_ttl)
    except (socket.timeout, OSError):
        sock.close()
        return PingResult(host=host, ip=ip, seq=seq, rtt_ms=-1)

def _subprocess_ping(host: str, seq: int) -> PingResult:
    """Fallback ping using system ping command"""
    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host
    try:
        if OS == 'Windows':
            cmd = ['ping', '-n', '1', '-w', '2000', host]
        else:
            cmd = ['ping', '-c', '1', '-W', '2', host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, **_HIDE)
        output = result.stdout
        # parse time= from output
        import re
        m = re.search(r'time[=<]([\d.]+)\s*ms', output, re.IGNORECASE)
        if m:
            return PingResult(host=host, ip=ip, seq=seq, rtt_ms=float(m.group(1)))
    except Exception:
        pass
    return PingResult(host=host, ip=ip, seq=seq, rtt_ms=-1)

# ─────────────────────────────────────────────
# Ping Monitor (continuous)
# ─────────────────────────────────────────────

class PingMonitor:
    def __init__(self, host: str, interval: float = 1.0, callback: Callable = None):
        self.host = host
        self.interval = interval
        self.callback = callback
        self._stop = threading.Event()
        self._thread = None
        self.results: List[PingResult] = []

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        seq = 0
        while not self._stop.is_set():
            r = _icmp_ping(self.host, seq)
            self.results.append(r)
            if self.callback:
                self.callback(r)
            seq += 1
            self._stop.wait(self.interval)

# ─────────────────────────────────────────────
# Traceroute
# ─────────────────────────────────────────────



def traceroute(host: str, max_hops: int = 30, probes: int = 3,
               timeout: float = 2.0, callback: Callable = None) -> List[HopResult]:
    """Single traceroute run. Uses subprocess on Windows, raw sockets on Linux."""
    # Windows: always use subprocess tracert — raw socket dual-socket approach
    # doesn't work reliably on Windows due to how ICMP receive works
    if OS == 'Windows':
        return _subprocess_traceroute(host, max_hops, callback)

    # Linux/Mac: raw socket approach
    try:
        dest_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return []

    results = []
    pid = os.getpid() & 0xFFFF

    for ttl in range(1, max_hops + 1):
        rtts = []
        hop_ip = None

        for probe in range(probes):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                sock.settimeout(timeout)

                seq = (ttl * 100 + probe) & 0xFFFF
                packet = _build_icmp_echo(pid, seq)
                t_send = time.perf_counter()
                sock.sendto(packet, (dest_ip, 1))

                try:
                    raw, addr = sock.recvfrom(1024)
                    t_recv = time.perf_counter()
                    ip_header_len = (raw[0] & 0xF) * 4
                    icmp_type = raw[ip_header_len]
                    if icmp_type in (0, 11):
                        hop_ip = addr[0]
                        rtts.append(round((t_recv - t_send) * 1000, 3))
                    else:
                        rtts.append(-1)
                except socket.timeout:
                    rtts.append(-1)
                finally:
                    sock.close()
            except PermissionError:
                return _subprocess_traceroute(host, max_hops, callback)

        hostname = hop_ip or '*'
        if hop_ip and hop_ip != '*':
            try:
                hostname = socket.gethostbyaddr(hop_ip)[0]
            except:
                hostname = hop_ip

        valid_rtts = [r for r in rtts if r >= 0]
        loss = (probes - len(valid_rtts)) / probes * 100
        hop = HopResult(hop=ttl, ip=hop_ip or '*', hostname=hostname,
                        rtts=rtts, loss_pct=loss)
        results.append(hop)
        if callback:
            callback(hop)

        if hop_ip == dest_ip:
            break

    return results


def _subprocess_traceroute(host: str, max_hops: int, callback: Callable) -> List[HopResult]:
    """Traceroute using system command - primary path on Windows"""
    import re
    results = []
    if OS == 'Windows':
        cmd = ['tracert', '-d', '-h', str(max_hops), '-w', '2000', host]
    else:
        cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', '2', host]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding='utf-8', errors='replace', **_HIDE)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            if OS == 'Windows':
                # Windows tracert lines look like:
                #   1    <1 ms    <1 ms    <1 ms  192.168.1.1
                #   2     *        *        *     Request timed out.
                #  12    14 ms    13 ms    14 ms  8.8.8.8
                hop_match = re.match(r'^\s*(\d+)', line)
                if not hop_match:
                    continue
                hop_n = int(hop_match.group(1))

                # Extract all RTT values (handles <1 ms and N ms)
                rtt_matches = re.findall(r'[<]?(\d+)\s*ms', line)
                rtts = [float(r) for r in rtt_matches]

                # Count * timeouts
                star_count = line.count('*')
                while len(rtts) + star_count < 3:
                    star_count += 1
                # Fill missing with -1
                while len(rtts) < 3:
                    rtts.append(-1)

                # Extract IP address (last thing on the line that looks like an IP)
                ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                ip = ip_matches[-1] if ip_matches else '*'

                # All stars = timeout hop
                if not ip_matches and star_count >= 3:
                    ip = '*'
                    rtts = [-1, -1, -1]

                loss = rtts.count(-1) / 3 * 100
                hop = HopResult(hop=hop_n, ip=ip, hostname=ip, rtts=rtts[:3], loss_pct=loss)
                results.append(hop)
                if callback:
                    callback(hop)

                # Stop if we reached the destination
                if ip != '*' and ip == socket.gethostbyname(host):
                    break

            else:
                # Linux traceroute
                m = re.match(r'^\s*(\d+)\s+', line)
                if not m:
                    continue
                hop_n = int(m.group(1))
                ip_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                ip = ip_match[0] if ip_match else '*'
                rtt_match = re.findall(r'([\d.]+)\s*ms', line)
                rtts = [float(r) for r in rtt_match] if rtt_match else [-1, -1, -1]
                while len(rtts) < 3:
                    rtts.append(-1)
                loss = rtts.count(-1) / 3 * 100
                hop = HopResult(hop=hop_n, ip=ip, hostname=ip, rtts=rtts[:3], loss_pct=loss)
                results.append(hop)
                if callback:
                    callback(hop)

    except Exception:
        pass
    return results


# ─────────────────────────────────────────────
# MTR (continuous traceroute)
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# IPerf3 Client (uses bundled/system iperf3 binary)
# ─────────────────────────────────────────────

class IPerf3Client:
    """
    Runs iperf3 as a subprocess. Supports both TCP and UDP.
    Parses iperf3 JSON output for reliable cross-version parsing.
    """
    def __init__(self, host: str, port: int = 5201, duration: int = 10,
                 protocol: str = 'tcp', streams: int = 1,
                 callback: Callable = None):
        self.host = host
        self.port = port
        self.duration = duration
        self.protocol = protocol  # 'tcp' or 'udp'
        self.streams = streams
        self.callback = callback
        self._proc = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _run(self):
        import re, json

        iperf3_path = find_iperf3()
        if not iperf3_path:
            if self.callback:
                self.callback({
                    'event': 'error',
                    'message': 'iperf3 not found. Place iperf3.exe next to NetProbe.exe or install it.'
                })
            return

        cmd = [
            iperf3_path,
            '-c', self.host,
            '-p', str(self.port),
            '-t', str(self.duration),
            '-P', str(self.streams),
            '--forceflush',
            '-f', 'm',   # megabits
        ]
        if self.protocol == 'udp':
            cmd += ['-u', '-b', '0']  # unlimited bandwidth UDP

        if self.callback:
            self.callback({'event': 'connected', 'host': self.host,
                           'iperf3': iperf3_path})

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,  # line-buffered
                **_HIDE
            )

            while True:
                line = self._proc.stdout.readline()
                if not line:
                    break
                if self._stop.is_set():
                    break
                line = line.strip()
                if not line:
                    continue

                # iperf3 interval lines:
                # [  5]   0.00-1.01   sec  92.6 MBytes   766 Mbits/sec
                # [SUM]   0.00-1.00   sec   112 MBytes   941 Mbits/sec
                interval = re.search(
                    r'\[\s*\S+\]\s+([\d.]+)-([\d.]+)\s+sec\s+'
                    r'[\d.]+\s+\S+\s+([\d.]+)\s+Mbits/sec',
                    line
                )
                if interval and 'sender' not in line and 'receiver' not in line:
                    t_start = float(interval.group(1))
                    t_end   = float(interval.group(2))
                    mbps    = float(interval.group(3))
                    elapsed = t_end

                    if self.callback:
                        self.callback({
                            'event': 'progress',
                            'mbps': round(mbps, 2),
                            'bytes': 0,
                            'elapsed': round(elapsed, 1),
                            'interval': f'{t_start:.2f}-{t_end:.2f}s'
                        })

                # Final summary lines contain 'sender' or 'receiver'
                if ('sender' in line or 'receiver' in line):
                    summary = re.search(r'([\d.]+)\s+Mbits/sec', line)
                    if summary:
                        mbps = float(summary.group(1))
                        role = 'sender' if 'sender' in line else 'receiver'
                        if self.callback:
                            self.callback({
                                'event': 'done',
                                'mbps': round(mbps, 2),
                                'bytes': 0,
                                'duration': self.duration,
                                'role': role
                            })

            stderr_out = self._proc.stderr.read() if self._proc.stderr else ''
            ret = self._proc.wait()
            if ret != 0 and not self._stop.is_set():
                msg = stderr_out.strip() or f'iperf3 exited with code {ret}'
                if self.callback:
                    self.callback({'event': 'error', 'message': msg})

        except FileNotFoundError:
            if self.callback:
                self.callback({'event': 'error',
                               'message': f'Cannot execute iperf3 at: {iperf3_path}'})
        except Exception as e:
            if self.callback:
                self.callback({'event': 'error', 'message': str(e)})




class MTRMonitor:
    def __init__(self, host: str, interval: float = 1.0, max_hops: int = 30,
                 callback: Callable = None):
        self.host = host
        self.interval = interval
        self.max_hops = max_hops
        self.callback = callback
        self._stop = threading.Event()
        self._thread = None
        self.rows: Dict[int, MTRRow] = {}  # hop -> MTRRow
        self._lock = threading.Lock()

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def get_rows(self) -> List[MTRRow]:
        with self._lock:
            return list(self.rows.values())

    def _run(self):
        # On Windows, use repeated tracert passes for MTR
        if OS == 'Windows':
            self._run_windows()
            return

        # Linux/Mac: raw socket per-TTL probing
        pid = os.getpid() & 0xFFFF
        seq = 0
        try:
            dest_ip = socket.gethostbyname(self.host)
        except:
            return

        while not self._stop.is_set():
            for ttl in range(1, self.max_hops + 1):
                if self._stop.is_set():
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    sock.settimeout(1.0)

                    packet = _build_icmp_echo(pid, seq % 65535)
                    t_send = time.perf_counter()
                    sock.sendto(packet, (dest_ip, 1))
                    seq += 1

                    hop_ip = None
                    rtt = -1.0
                    try:
                        raw, addr = sock.recvfrom(1024)
                        t_recv = time.perf_counter()
                        ip_header_len = (raw[0] & 0xF) * 4
                        icmp_type = raw[ip_header_len]
                        if icmp_type in (0, 11):
                            hop_ip = addr[0]
                            rtt = round((t_recv - t_send) * 1000, 3)
                    except socket.timeout:
                        pass
                    finally:
                        sock.close()

                    with self._lock:
                        if ttl not in self.rows:
                            hostname = hop_ip or '*'
                            if hop_ip:
                                try:
                                    hostname = socket.gethostbyaddr(hop_ip)[0]
                                except:
                                    hostname = hop_ip
                            self.rows[ttl] = MTRRow(hop=ttl, ip=hop_ip or '*', hostname=hostname)
                        self.rows[ttl].update(rtt)
                        if hop_ip:
                            self.rows[ttl].ip = hop_ip

                    if self.callback:
                        self.callback(dict(self.rows))

                    if hop_ip == dest_ip:
                        break

                except PermissionError:
                    self._run_subprocess()
                    return

            self._stop.wait(self.interval)

    def _run_windows(self):
        """Windows MTR: run repeated tracert passes, accumulate stats per hop"""
        import re
        try:
            dest_ip = socket.gethostbyname(self.host)
        except:
            dest_ip = self.host

        while not self._stop.is_set():
            cmd = ['tracert', '-d', '-h', str(self.max_hops), '-w', '2000', self.host]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, encoding='utf-8', errors='replace', **_HIDE)
                for line in proc.stdout:
                    if self._stop.is_set():
                        proc.terminate()
                        break
                    line = line.strip()
                    hop_match = re.match(r'^\s*(\d+)', line)
                    if not hop_match:
                        continue
                    hop_n = int(hop_match.group(1))

                    rtt_matches = re.findall(r'[<]?(\d+)\s*ms', line)
                    rtts = [float(r) for r in rtt_matches]
                    ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    ip = ip_matches[-1] if ip_matches else '*'

                    # Use average RTT of the probes, or -1 if all timed out
                    if rtts:
                        rtt = sum(rtts) / len(rtts)
                    else:
                        rtt = -1.0

                    with self._lock:
                        if hop_n not in self.rows:
                            self.rows[hop_n] = MTRRow(hop=hop_n, ip=ip, hostname=ip)
                        self.rows[hop_n].update(rtt)
                        if ip != '*':
                            self.rows[hop_n].ip = ip
                            self.rows[hop_n].hostname = ip

                    if self.callback:
                        self.callback(dict(self.rows))

            except Exception:
                pass

            self._stop.wait(self.interval)


    def _run_subprocess(self):
        """Fallback MTR via mtr command if available"""
        if OS == 'Windows':
            return
        try:
            subprocess.run(['mtr', '--version'], capture_output=True, **_HIDE)
        except FileNotFoundError:
            return

        cmd = ['mtr', '--report', '--report-cycles', '1', '--no-dns',
               '--interval', str(self.interval), self.host]
        while not self._stop.is_set():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, **_HIDE)
                import re
                for line in result.stdout.split('\n'):
                    m = re.match(r'\s*(\d+)\.\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)', line)
                    if m:
                        hop_n = int(m.group(1))
                        with self._lock:
                            row = self.rows.get(hop_n, MTRRow(hop=hop_n, ip=m.group(2), hostname=m.group(2)))
                            row.loss_pct = float(m.group(3))
                            row.sent = int(m.group(4))
                            row.last_ms = float(m.group(5))
                            row.avg_ms = float(m.group(6))
                            row.best_ms = float(m.group(7))
                            row.worst_ms = float(m.group(8))
                            row.stdev_ms = float(m.group(9))
                            self.rows[hop_n] = row
                        if self.callback:
                            self.callback(dict(self.rows))
            except Exception:
                pass
            self._stop.wait(self.interval)

# ─────────────────────────────────────────────
# Port Scanner
# ─────────────────────────────────────────────

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    161: 'SNMP', 162: 'SNMP-Trap', 389: 'LDAP', 636: 'LDAPS',
    1433: 'MSSQL', 1521: 'Oracle', 5900: 'VNC', 9200: 'Elasticsearch'
}

def port_scan(host: str, ports: List[int], timeout: float = 1.0,
              threads: int = 50, callback: Callable = None) -> List[PortResult]:
    results = []
    results_lock = threading.Lock()
    port_queue = queue.Queue()

    for p in ports:
        port_queue.put(p)

    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host

    def worker():
        while True:
            try:
                port = port_queue.get_nowait()
            except queue.Empty:
                break
            t0 = time.perf_counter()
            banner = ''
            rtt    = 0.0
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                err = sock.connect_ex((ip, port))
                rtt = (time.perf_counter() - t0) * 1000
                if err == 0:
                    state = 'open'
                    # Try banner grab
                    try:
                        sock.settimeout(0.5)
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(256).decode('utf-8', errors='replace').strip()[:100]
                    except:
                        pass
                else:
                    state = 'closed'
                sock.close()
            except socket.timeout:
                state = 'filtered'
                rtt = timeout * 1000
            except Exception:
                state = 'filtered'
                rtt = 0

            r = PortResult(host=ip, port=port, state=state,
                           service=COMMON_PORTS.get(port, ''), banner=banner, rtt_ms=round(rtt, 2))
            with results_lock:
                results.append(r)
            if callback:
                callback(r)
            port_queue.task_done()

    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

    return sorted(results, key=lambda x: x.port)

# ─────────────────────────────────────────────
# DNS Analysis
# ─────────────────────────────────────────────

def dns_lookup(host: str, record_types: List[str] = None, callback: Callable = None) -> List[DNSResult]:
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    results = []
    try:
        import dns.resolver
        for rtype in record_types:
            t0 = time.perf_counter()
            try:
                answers = dns.resolver.resolve(host, rtype)
                rtt = (time.perf_counter() - t0) * 1000
                ans_list = [str(r) for r in answers]
                r = DNSResult(query=host, record_type=rtype, answers=ans_list,
                              rtt_ms=round(rtt, 2))
            except Exception as e:
                r = DNSResult(query=host, record_type=rtype, answers=[], error=str(e))
            results.append(r)
            if callback:
                callback(r)
    except ImportError:
        # Fallback: basic A/AAAA lookup via socket
        for rtype in ['A']:
            t0 = time.perf_counter()
            try:
                infos = socket.getaddrinfo(host, None)
                rtt = (time.perf_counter() - t0) * 1000
                ips = list(set(i[4][0] for i in infos))
                r = DNSResult(query=host, record_type='A', answers=ips, rtt_ms=round(rtt, 2))
            except Exception as e:
                r = DNSResult(query=host, record_type='A', answers=[], error=str(e))
            results.append(r)
            if callback:
                callback(r)

        # Reverse lookup
        try:
            ip = socket.gethostbyname(host)
            hostname = socket.gethostbyaddr(ip)[0]
            r = DNSResult(query=ip, record_type='PTR', answers=[hostname])
            results.append(r)
            if callback:
                callback(r)
        except:
            pass

    return results

# ─────────────────────────────────────────────
# ARP / Layer 2 Scanner
# ─────────────────────────────────────────────

def get_local_interfaces() -> List[Dict]:
    interfaces = []
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    interfaces.append({
                        'name': name,
                        'ip': addr.address,
                        'netmask': addr.netmask or '255.255.255.0'
                    })
    except ImportError:
        # Fallback
        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
            interfaces.append({'name': 'default', 'ip': ip, 'netmask': '255.255.255.0'})
        except:
            pass
    return interfaces

def arp_scan(network: str, callback: Callable = None) -> List[ARPEntry]:
    """Scan a subnet for hosts using ARP (requires scapy or fallback to arp -a)"""
    results = []

    # Try scapy first
    try:
        from scapy.all import ARP, Ether, srp
        arp = ARP(pdst=network)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether / arp
        answered, _ = srp(packet, timeout=3, verbose=False)
        for sent, received in answered:
            hostname = '*'
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except:
                pass
            entry = ARPEntry(ip=received.psrc, mac=received.hwsrc, hostname=hostname)
            results.append(entry)
            if callback:
                callback(entry)
        return results
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: parse system ARP cache + ping sweep
    results = _arp_cache_parse(callback)
    return results

def _arp_cache_parse(callback: Callable = None) -> List[ARPEntry]:
    """Parse system ARP table"""
    import re
    results = []
    try:
        if OS == 'Windows':
            out = subprocess.check_output(['arp', '-a'], text=True, **_HIDE)
            for line in out.split('\n'):
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([\w-]{17})', line)
                if m:
                    entry = ARPEntry(ip=m.group(1), mac=m.group(2))
                    results.append(entry)
                    if callback:
                        callback(entry)
        else:
            out = subprocess.check_output(['arp', '-n'], text=True, stderr=subprocess.DEVNULL, **_HIDE)
            for line in out.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 3 and ':' in parts[2]:
                    entry = ARPEntry(ip=parts[0], mac=parts[2],
                                     interface=parts[-1] if len(parts) > 4 else '')
                    results.append(entry)
                    if callback:
                        callback(entry)
    except Exception:
        pass
    return results

def ping_sweep(network: str, callback: Callable = None) -> List[str]:
    """Fast ping sweep of a /24 subnet"""
    live_hosts = []
    lock = threading.Lock()

    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 256:
            hosts = hosts[:256]
    except ValueError:
        return live_hosts

    def check_host(ip_str):
        r = _icmp_ping(ip_str, random.randint(0, 32767), timeout=0.5)
        if r.rtt_ms >= 0:
            with lock:
                live_hosts.append(ip_str)
            if callback:
                callback(ip_str)

    threads = []
    for h in hosts:
        t = threading.Thread(target=check_host, args=(str(h),), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) % 50 == 0:
            for th in threads:
                th.join(timeout=2)
            threads = []
    for th in threads:
        th.join(timeout=2)

    return live_hosts

# ─────────────────────────────────────────────
# Bandwidth Test (iperf3-style TCP throughput)
# ─────────────────────────────────────────────

class BandwidthServer:
    def __init__(self, port: int = 5201, callback: Callable = None):
        self.port = port
        self.callback = callback
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _serve(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(('0.0.0.0', self.port))
            srv.listen(5)
            srv.settimeout(1.0)
            if self.callback:
                self.callback({'event': 'listening', 'port': self.port})
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
            srv.close()
        except Exception as e:
            if self.callback:
                self.callback({'event': 'error', 'message': str(e)})

    def _handle(self, conn, addr):
        total = 0
        t_start = time.perf_counter()
        t_last = t_start
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                total += len(data)
                now = time.perf_counter()
                if now - t_last >= 0.5:
                    elapsed = now - t_start
                    mbps = (total * 8) / (elapsed * 1_000_000)
                    if self.callback:
                        self.callback({'event': 'progress', 'bytes': total,
                                       'mbps': round(mbps, 2), 'client': addr[0]})
                    t_last = now
        finally:
            elapsed = time.perf_counter() - t_start
            if elapsed > 0:
                mbps = (total * 8) / (elapsed * 1_000_000)
                if self.callback:
                    self.callback({'event': 'done', 'bytes': total,
                                   'mbps': round(mbps, 2), 'duration': round(elapsed, 2)})
            conn.close()

class BandwidthClient:
    def __init__(self, host: str, port: int = 5201, duration: float = 10.0,
                 callback: Callable = None):
        self.host = host
        self.port = port
        self.duration = duration
        self.callback = callback
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        CHUNK = 128 * 1024  # 128KB chunks
        payload = b'X' * CHUNK
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            if self.callback:
                self.callback({'event': 'connected', 'host': self.host})

            total = 0
            t_start = time.perf_counter()
            t_last = t_start

            while not self._stop.is_set():
                elapsed = time.perf_counter() - t_start
                if elapsed >= self.duration:
                    break
                try:
                    sent = sock.send(payload)
                    total += sent
                except OSError:
                    break

                now = time.perf_counter()
                if now - t_last >= 0.5:
                    interval_elapsed = now - t_start
                    mbps = (total * 8) / (interval_elapsed * 1_000_000)
                    if self.callback:
                        self.callback({'event': 'progress', 'bytes': total,
                                       'mbps': round(mbps, 2),
                                       'elapsed': round(interval_elapsed, 1)})
                    t_last = now

            sock.close()
            total_elapsed = time.perf_counter() - t_start
            if total_elapsed > 0:
                mbps = (total * 8) / (total_elapsed * 1_000_000)
                if self.callback:
                    self.callback({'event': 'done', 'bytes': total,
                                   'mbps': round(mbps, 2), 'duration': round(total_elapsed, 2)})
        except Exception as e:
            if self.callback:
                self.callback({'event': 'error', 'message': str(e)})

# ─────────────────────────────────────────────
# Packet Capture (L4-L6 inspection)
# ─────────────────────────────────────────────

PROTOCOLS = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF'}

TCP_FLAGS = {
    0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
    0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR'
}

class PacketCapture:
    def __init__(self, filter_host: str = '', filter_port: int = 0,
                 callback: Callable = None, max_packets: int = 1000):
        self.filter_host = filter_host
        self.filter_port = filter_port
        self.callback = callback
        self.max_packets = max_packets
        self._stop = threading.Event()
        self._thread = None
        self.packets: List[PacketInfo] = []

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._capture, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _capture(self):
        # Try scapy first (best option)
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
            def pkt_handler(pkt):
                if self._stop.is_set():
                    return
                if IP not in pkt:
                    return
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto_num = pkt[IP].proto
                proto = PROTOCOLS.get(proto_num, str(proto_num))

                if self.filter_host and self.filter_host not in (src, dst):
                    return

                info = PacketInfo(
                    timestamp=time.time(),
                    src_ip=src, dst_ip=dst,
                    protocol=proto, length=len(pkt)
                )

                if TCP in pkt:
                    info.src_port = pkt[TCP].sport
                    info.dst_port = pkt[TCP].dport
                    flags_val = pkt[TCP].flags
                    info.flags = '+'.join(v for k, v in TCP_FLAGS.items() if flags_val & k)
                    if self.filter_port and self.filter_port not in (info.src_port, info.dst_port):
                        return
                elif UDP in pkt:
                    info.src_port = pkt[UDP].sport
                    info.dst_port = pkt[UDP].dport
                    if self.filter_port and self.filter_port not in (info.src_port, info.dst_port):
                        return

                self.packets.append(info)
                if len(self.packets) > self.max_packets:
                    self.packets = self.packets[-self.max_packets:]
                if self.callback:
                    self.callback(info)

            sniff(prn=pkt_handler, store=False,
                  stop_filter=lambda x: self._stop.is_set())
            return
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: raw socket capture (Linux/Windows)
        self._raw_capture()

    def _raw_capture(self):
        try:
            if OS == 'Windows':
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            sock.settimeout(0.5)

            while not self._stop.is_set():
                try:
                    raw, _ = sock.recvfrom(65535)
                    info = self._parse_raw(raw)
                    if info:
                        self.packets.append(info)
                        if len(self.packets) > self.max_packets:
                            self.packets = self.packets[-self.max_packets:]
                        if self.callback:
                            self.callback(info)
                except socket.timeout:
                    continue
                except Exception:
                    break

            if OS == 'Windows':
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
            sock.close()
        except PermissionError:
            if self.callback:
                self.callback(PacketInfo(
                    timestamp=time.time(), src_ip='ERROR', dst_ip='ERROR',
                    protocol='PERM', info='Requires root/admin for packet capture'
                ))

    def _parse_raw(self, raw: bytes) -> Optional[PacketInfo]:
        try:
            # Ethernet frame (Linux AF_PACKET) - skip 14 byte ethernet header
            if OS != 'Windows' and len(raw) > 14:
                eth_type = struct.unpack('!H', raw[12:14])[0]
                if eth_type != 0x0800:  # Only IPv4
                    return None
                raw = raw[14:]

            if len(raw) < 20:
                return None

            ver_ihl = raw[0]
            ihl = (ver_ihl & 0xF) * 4
            proto_num = raw[9]
            src_ip = socket.inet_ntoa(raw[12:16])
            dst_ip = socket.inet_ntoa(raw[16:20])
            proto = PROTOCOLS.get(proto_num, str(proto_num))
            total_len = struct.unpack('!H', raw[2:4])[0]

            info = PacketInfo(timestamp=time.time(), src_ip=src_ip, dst_ip=dst_ip,
                              protocol=proto, length=total_len)

            if self.filter_host and self.filter_host not in (src_ip, dst_ip):
                return None

            if proto_num == 6 and len(raw) >= ihl + 20:  # TCP
                tcp = raw[ihl:]
                info.src_port = struct.unpack('!H', tcp[0:2])[0]
                info.dst_port = struct.unpack('!H', tcp[2:4])[0]
                flags = tcp[13]
                info.flags = '+'.join(v for k, v in TCP_FLAGS.items() if flags & k)
            elif proto_num == 17 and len(raw) >= ihl + 8:  # UDP
                udp = raw[ihl:]
                info.src_port = struct.unpack('!H', udp[0:2])[0]
                info.dst_port = struct.unpack('!H', udp[2:4])[0]

            if self.filter_port and self.filter_port not in (info.src_port, info.dst_port):
                return None

            return info
        except Exception:
            return None

# ─────────────────────────────────────────────
# External Ping Monitor (multi-target)
# ─────────────────────────────────────────────

class ExternalMonitor:
    """Manages multiple persistent ping monitors with MTR capability"""
    def __init__(self, callback: Callable = None):
        self.callback = callback
        self._monitors: Dict[str, PingMonitor] = {}
        self._mtr_monitors: Dict[str, MTRMonitor] = {}
        self._lock = threading.Lock()

    def add_target(self, host: str, interval: float = 5.0, run_mtr: bool = False):
        with self._lock:
            if host in self._monitors:
                return False
            pm = PingMonitor(host, interval=interval,
                             callback=lambda r: self._on_ping(host, r))
            pm.start()
            self._monitors[host] = pm
            if run_mtr:
                mtr = MTRMonitor(host, interval=interval,
                                 callback=lambda rows: self._on_mtr(host, rows))
                mtr.start()
                self._mtr_monitors[host] = mtr
        return True

    def remove_target(self, host: str):
        with self._lock:
            if host in self._monitors:
                self._monitors[host].stop()
                del self._monitors[host]
            if host in self._mtr_monitors:
                self._mtr_monitors[host].stop()
                del self._mtr_monitors[host]

    def get_targets(self) -> List[str]:
        with self._lock:
            return list(self._monitors.keys())

    def get_stats(self, host: str) -> Dict:
        with self._lock:
            pm = self._monitors.get(host)
            if not pm:
                return {}
            results = pm.results[-100:]  # last 100 pings
            if not results:
                return {}
            valid = [r for r in results if r.rtt_ms >= 0]
            lost = len(results) - len(valid)
            return {
                'host': host,
                'sent': len(results),
                'received': len(valid),
                'loss_pct': round(lost / len(results) * 100, 1) if results else 0,
                'min_ms': round(min(r.rtt_ms for r in valid), 2) if valid else 0,
                'max_ms': round(max(r.rtt_ms for r in valid), 2) if valid else 0,
                'avg_ms': round(sum(r.rtt_ms for r in valid) / len(valid), 2) if valid else 0,
                'last_ms': valid[-1].rtt_ms if valid else -1,
                'last_results': [(r.rtt_ms, r.timestamp) for r in results[-60:]],
                'mtr_rows': [vars(row) for row in
                             (self._mtr_monitors[host].get_rows() if host in self._mtr_monitors else [])]
            }

    def stop_all(self):
        with self._lock:
            for pm in self._monitors.values():
                pm.stop()
            for mtr in self._mtr_monitors.values():
                mtr.stop()

    def _on_ping(self, host, result):
        if self.callback:
            self.callback('ping', host, result)

    def _on_mtr(self, host, rows):
        if self.callback:
            self.callback('mtr', host, rows)


# ─────────────────────────────────────────────
# ASN / Carrier Lookup (Team Cymru DNS)
# ─────────────────────────────────────────────

_asn_cache: Dict[str, str] = {}
_asn_cache_lock = threading.Lock()

def asn_lookup(ip: str) -> str:
    """
    Look up ASN + org name for an IP using Team Cymru DNS.
    Returns string like 'AS7018 AT&T' or '' on failure.
    Results are cached in memory for the session.
    Private/reserved IPs return 'Private' immediately.
    """
    if not ip or ip == '*':
        return ''

    # Check cache first
    with _asn_cache_lock:
        if ip in _asn_cache:
            return _asn_cache[ip]

    # Skip private/reserved ranges immediately
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            with _asn_cache_lock:
                _asn_cache[ip] = 'Private'
            return 'Private'
    except ValueError:
        return ''

    result = _cymru_lookup(ip)

    with _asn_cache_lock:
        _asn_cache[ip] = result

    return result


def _cymru_lookup(ip: str) -> str:
    """
    Query Team Cymru's DNS service for ASN info.
    Constructs reversed IP query to origin.asn.cymru.com
    TXT record returns: 'ASN | prefix | country | registry | date'
    Peer TXT record returns: 'ASN | org name'
    """
    try:
        # Reverse the IP for DNS query
        # e.g. 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
        parts = ip.split('.')
        if len(parts) != 4:
            return ''
        reversed_ip = '.'.join(reversed(parts))
        origin_query = f'{reversed_ip}.origin.asn.cymru.com'

        # Use dnspython if available (more reliable)
        try:
            import dns.resolver
            answers = dns.resolver.resolve(origin_query, 'TXT', lifetime=3.0)
            for rdata in answers:
                txt = str(rdata).strip('"').strip()
                # Format: "ASN | prefix | country | registry | date"
                asn_part = txt.split('|')[0].strip()
                if asn_part:
                    asn_num = asn_part.split()[0].strip()
                    # Now look up the org name
                    org = _cymru_asn_org(asn_num)
                    return f'AS{asn_num} {org}'.strip()
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: raw DNS query via socket (no dnspython needed)
        return _cymru_raw_dns(ip, reversed_ip)

    except Exception:
        return ''


def _cymru_asn_org(asn_num: str) -> str:
    """Look up org name for an ASN number via Cymru DNS"""
    try:
        import dns.resolver
        query = f'AS{asn_num}.asn.cymru.com'
        answers = dns.resolver.resolve(query, 'TXT', lifetime=3.0)
        for rdata in answers:
            txt = str(rdata).strip('"').strip()
            # Format: "ASN | country | registry | date | org name"
            parts = txt.split('|')
            if len(parts) >= 5:
                return parts[-1].strip()
    except Exception:
        pass
    return ''


def _cymru_raw_dns(ip: str, reversed_ip: str) -> str:
    """
    Fallback ASN lookup using subprocess nslookup/dig
    when dnspython is not available.
    """
    try:
        query = f'{reversed_ip}.origin.asn.cymru.com'
        if OS == 'Windows':
            cmd = ['nslookup', '-type=TXT', query]
        else:
            cmd = ['dig', '+short', 'TXT', query]

        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=5, encoding='utf-8', errors='replace', **_HIDE)
        output = result.stdout

        import re
        # Find ASN number in output
        m = re.search(r'"(\d+)\s*\|', output)
        if m:
            asn_num = m.group(1)
            # Try to get org name too
            if OS == 'Windows':
                cmd2 = ['nslookup', '-type=TXT', f'AS{asn_num}.asn.cymru.com']
            else:
                cmd2 = ['dig', '+short', 'TXT', f'AS{asn_num}.asn.cymru.com']

            result2 = subprocess.run(cmd2, capture_output=True, text=True,
                                     timeout=5, encoding='utf-8', errors='replace', **_HIDE)
            # Last pipe-separated field is org name
            parts = result2.stdout.split('|')
            org = parts[-1].strip().strip('"').strip() if len(parts) >= 5 else ''
            return f'AS{asn_num} {org}'.strip()
    except Exception:
        pass
    return ''


def asn_lookup_batch(ips: List[str], callback: Callable = None) -> Dict[str, str]:
    """
    Look up ASN for a list of IPs concurrently.
    Calls callback(ip, asn_str) as each result comes in.
    Returns dict of {ip: asn_str}
    """
    results = {}
    results_lock = threading.Lock()

    def lookup_one(ip):
        asn = asn_lookup(ip)
        with results_lock:
            results[ip] = asn
        if callback:
            callback(ip, asn)

    threads = []
    for ip in ips:
        if ip and ip != '*':
            t = threading.Thread(target=lookup_one, args=(ip,), daemon=True)
            t.start()
            threads.append(t)

    for t in threads:
        t.join(timeout=5)

    return results


# ─────────────────────────────────────────────
# GeoIP Lookup  (ip-api.com — free, no key)
# ─────────────────────────────────────────────

@dataclass
class GeoIPResult:
    ip: str
    country: str = ''
    country_code: str = ''
    city: str = ''
    region: str = ''
    org: str = ''
    lat: float = 0.0
    lon: float = 0.0
    error: str = ''

    def short(self) -> str:
        """Compact display string for table cells."""
        if self.error or not self.country_code:
            return ''
        parts = [self.country_code]
        if self.city:
            parts.append(self.city)
        return ', '.join(parts)


_geoip_cache: Dict[str, GeoIPResult] = {}
_geoip_lock = threading.Lock()


def geoip_lookup(ip: str) -> GeoIPResult:
    """GeoIP lookup via ip-api.com (free tier). Results cached per session."""
    with _geoip_lock:
        if ip in _geoip_cache:
            return _geoip_cache[ip]

    result = GeoIPResult(ip=ip)
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            result.country = 'Private'
            with _geoip_lock:
                _geoip_cache[ip] = result
            return result
    except ValueError:
        result.error = 'Invalid IP'
        return result

    try:
        import urllib.request
        import json as _json
        url = (f'http://ip-api.com/json/{ip}'
               f'?fields=country,countryCode,city,regionName,org,lat,lon,status,message')
        req = urllib.request.Request(url, headers={'User-Agent': 'NetProbe/1.1'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        if data.get('status') == 'success':
            result.country      = data.get('country', '')
            result.country_code = data.get('countryCode', '')
            result.city         = data.get('city', '')
            result.region       = data.get('regionName', '')
            result.org          = data.get('org', '')
            result.lat          = float(data.get('lat', 0))
            result.lon          = float(data.get('lon', 0))
        else:
            result.error = data.get('message', 'lookup failed')
    except Exception as e:
        result.error = str(e)

    with _geoip_lock:
        _geoip_cache[ip] = result
    return result


def geoip_lookup_batch(ips: List[str], callback: Callable = None) -> Dict[str, GeoIPResult]:
    """Concurrent GeoIP lookups. Calls callback(ip, GeoIPResult) as each completes."""
    results: Dict[str, GeoIPResult] = {}
    lock = threading.Lock()

    def _one(ip):
        geo = geoip_lookup(ip)
        with lock:
            results[ip] = geo
        if callback:
            callback(ip, geo)

    threads = [threading.Thread(target=_one, args=(ip,), daemon=True)
               for ip in ips if ip and ip != '*']
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=6)
    return results


# ─────────────────────────────────────────────
# SSL / TLS Inspector
# ─────────────────────────────────────────────

@dataclass
class SSLInfo:
    host: str
    port: int
    subject_cn: str = ''
    subject: str = ''
    issuer: str = ''
    version: str = ''
    cipher: str = ''
    not_before: str = ''
    not_after: str = ''
    san: List[str] = field(default_factory=list)
    days_remaining: int = 0
    expired: bool = False
    verified: bool = False
    error: str = ''


def _extract_cert_dict(cert: dict, info: SSLInfo):
    """Parse ssl.getpeercert() decoded dict into SSLInfo fields."""
    for field_list in cert.get('subject', []):
        for key, val in field_list:
            if key == 'commonName':
                info.subject_cn = val
    info.subject = '; '.join(
        f'{k}={v}' for fl in cert.get('subject', []) for k, v in fl)
    info.issuer = '; '.join(
        f'{k}={v}' for fl in cert.get('issuer', []) for k, v in fl)
    info.not_before = cert.get('notBefore', '')
    info.not_after  = cert.get('notAfter', '')
    if info.not_after:
        try:
            from datetime import datetime as _dt, timezone as _tz
            expire = _dt.strptime(info.not_after, '%b %d %H:%M:%S %Y %Z')
            now_naive = _dt.now(_tz.utc).replace(tzinfo=None)
            info.days_remaining = (expire - now_naive).days
            info.expired = info.days_remaining < 0
        except Exception:
            pass
    info.san = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']


def _parse_der_cert(der: bytes, info: SSLInfo):
    """Extract cert fields from raw DER bytes — tries cryptography lib, then openssl CLI."""
    try:
        from cryptography import x509 as _cx509
        from cryptography.hazmat.backends import default_backend as _backend
        import datetime as _dmod
        cert = _cx509.load_der_x509_certificate(der, _backend())
        cn_attrs = cert.subject.get_attributes_for_oid(_cx509.NameOID.COMMON_NAME)
        info.subject_cn = cn_attrs[0].value if cn_attrs else ''
        info.subject    = cert.subject.rfc4514_string()
        info.issuer     = cert.issuer.rfc4514_string()
        try:
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
        except AttributeError:
            nb = cert.not_valid_before.replace(tzinfo=_dmod.timezone.utc)
            na = cert.not_valid_after.replace(tzinfo=_dmod.timezone.utc)
        info.not_before = str(nb)
        info.not_after  = str(na)
        now = _dmod.datetime.now(_dmod.timezone.utc)
        info.days_remaining = (na - now).days
        info.expired = info.days_remaining < 0
        try:
            san_ext = cert.extensions.get_extension_for_class(_cx509.SubjectAlternativeName)
            info.san = san_ext.value.get_values_for_type(_cx509.DNSName)
        except Exception:
            pass
        return
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: openssl subprocess
    try:
        import ssl as _ssl_mod
        import re as _re
        pem = _ssl_mod.DER_cert_to_PEM_cert(der)
        res = subprocess.run(['openssl', 'x509', '-text', '-noout'],
                             input=pem, capture_output=True, text=True, timeout=5, **_HIDE)
        out = res.stdout
        m = _re.search(r'Subject:.*?CN\s*=\s*([^\n,/]+)', out)
        if m:
            info.subject_cn = m.group(1).strip()
        m = _re.search(r'Issuer:.*?O\s*=\s*([^\n,/]+)', out)
        if m:
            info.issuer = m.group(1).strip()
        m = _re.search(r'Not Before\s*:\s*([^\n]+)', out)
        if m:
            info.not_before = m.group(1).strip()
        m = _re.search(r'Not After\s*:\s*([^\n]+)', out)
        if m:
            info.not_after = m.group(1).strip()
            try:
                from datetime import datetime as _dt, timezone as _tz
                expire = _dt.strptime(info.not_after.strip(), '%b %d %H:%M:%S %Y %Z')
                now_naive = _dt.now(_tz.utc).replace(tzinfo=None)
                info.days_remaining = (expire - now_naive).days
                info.expired = info.days_remaining < 0
            except Exception:
                pass
        dns_names = _re.findall(r'DNS:([^\s,]+)', out)
        if dns_names:
            info.san = dns_names
    except Exception:
        pass


def ssl_inspect(host: str, port: int = 443, timeout: float = 10.0) -> SSLInfo:
    """Inspect SSL/TLS certificate and connection parameters for host:port."""
    import ssl as _ssl
    info = SSLInfo(host=host, port=port)
    try:
        # Step 1 — unverified connect: get cipher/version + raw DER cert
        ctx_bare = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx_bare.check_hostname = False
        ctx_bare.verify_mode = _ssl.CERT_NONE
        der = None
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx_bare.wrap_socket(raw, server_hostname=host) as s:
                info.version = s.version() or ''
                c = s.cipher()
                info.cipher = f'{c[0]} / {c[1]}' if c else ''
                der = s.getpeercert(binary_form=True)

        # Step 2 — verified connect: get decoded cert dict
        try:
            ctx_v = _ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx_v.wrap_socket(raw, server_hostname=host) as s:
                    _extract_cert_dict(s.getpeercert(), info)
                    info.verified = True
        except _ssl.SSLCertVerificationError as e:
            info.error = f'Verification failed: {e.reason}'
            if der:
                _parse_der_cert(der, info)
        except Exception:
            if der:
                _parse_der_cert(der, info)

    except Exception as e:
        info.error = str(e)
    return info


# ─────────────────────────────────────────────
# HTTP Probe
# ─────────────────────────────────────────────

@dataclass
class HTTPResult:
    url: str
    final_url: str = ''
    status_code: int = 0
    status_text: str = ''
    ttfb_ms: float = 0.0
    total_ms: float = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    server: str = ''
    content_type: str = ''
    error: str = ''


def http_probe(url: str, method: str = 'GET', follow_redirects: bool = True,
               timeout: float = 10.0) -> HTTPResult:
    """Probe an HTTP/HTTPS URL — returns timing, status, headers, redirect chain."""
    import urllib.request
    import urllib.error

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = HTTPResult(url=url)
    redirect_chain: List[str] = []
    t_start = time.perf_counter()

    try:
        class _RedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                redirect_chain.append(f'{code} → {newurl}')
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        opener = urllib.request.build_opener(
            _RedirectHandler if follow_redirects else urllib.request.BaseHandler)
        req = urllib.request.Request(
            url, method=method, headers={'User-Agent': 'NetProbe/1.1'})

        with opener.open(req, timeout=timeout) as resp:
            result.ttfb_ms      = round((time.perf_counter() - t_start) * 1000, 2)
            result.status_code  = resp.status
            result.status_text  = resp.reason or ''
            result.final_url    = resp.url or url
            result.redirect_chain = redirect_chain
            hdrs                = dict(resp.headers)
            result.headers      = hdrs
            result.server       = hdrs.get('Server', hdrs.get('server', ''))
            result.content_type = hdrs.get('Content-Type', hdrs.get('content-type', ''))
            cl = hdrs.get('Content-Length', hdrs.get('content-length', ''))
            if cl:
                try:
                    result.content_length = int(cl)
                except ValueError:
                    pass
            resp.read(4096)  # consume body (limited)

    except urllib.error.HTTPError as e:
        result.status_code = e.code
        result.status_text = e.reason or ''
        result.ttfb_ms     = round((time.perf_counter() - t_start) * 1000, 2)
        result.headers     = dict(e.headers) if e.headers else {}
        result.server      = result.headers.get('Server', '')
    except Exception as e:
        result.error = str(e)

    result.total_ms = round((time.perf_counter() - t_start) * 1000, 2)
    if not result.ttfb_ms:
        result.ttfb_ms = result.total_ms
    return result


# ─────────────────────────────────────────────
# WHOIS Lookup  (raw socket port 43)
# ─────────────────────────────────────────────

_WHOIS_TLDS: Dict[str, str] = {
    '.com': 'whois.verisign-grs.com', '.net': 'whois.verisign-grs.com',
    '.org': 'whois.pir.org',          '.edu': 'whois.educause.edu',
    '.gov': 'whois.dotgov.gov',       '.io':  'whois.iana.org',
    '.co':  'whois.iana.org',         '.uk':  'whois.nic.uk',
    '.de':  'whois.denic.de',         '.fr':  'whois.nic.fr',
    '.au':  'whois.auda.org.au',      '.ca':  'whois.cira.ca',
    '.jp':  'whois.jprs.jp',
}


def _whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall(f'{query}\r\n'.encode())
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk.decode('utf-8', errors='replace'))
            return ''.join(chunks)
    except Exception as e:
        return f'; Error querying {server}: {e}\n'


def whois_lookup(target: str) -> str:
    """Return raw WHOIS text for a domain or IP. Auto-selects the right server."""
    import re as _re
    target = target.strip()
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        text = _whois_query('whois.iana.org', target)
        for line in text.split('\n'):
            if line.lower().startswith('refer:'):
                server = line.split(':', 1)[1].strip()
                if server:
                    detail = _whois_query(server, target)
                    return detail + '\n\n;; --- IANA referral ---\n' + text
        return text
    else:
        parts = target.lower().split('.')
        tld = ('.' + parts[-1]) if len(parts) > 1 else ''
        server = _WHOIS_TLDS.get(tld, 'whois.iana.org')
        text = _whois_query(server, target)
        # Follow registrar WHOIS referral if present
        for line in text.split('\n'):
            if _re.match(r'(?i)(registrar\s+)?whois\s+server:', line):
                ref = line.split(':', 1)[1].strip().lower()
                if ref and ref != server and '.' in ref:
                    detail = _whois_query(ref, target)
                    return detail + f'\n\n;; --- {server} response ---\n' + text
        return text


# ─────────────────────────────────────────────
# Wake-on-LAN
# ─────────────────────────────────────────────

def wake_on_lan(mac: str, broadcast: str = '255.255.255.255', port: int = 9) -> bool:
    """Send a WoL magic packet (6×0xFF + target MAC×16) via UDP broadcast."""
    clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    if len(clean) != 12 or not all(c in '0123456789ABCDEF' for c in clean):
        raise ValueError(f'Invalid MAC address: {mac}')
    magic = b'\xFF' * 6 + bytes.fromhex(clean) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic, (broadcast, port))
    return True


# ─────────────────────────────────────────────
# UDP Port Probe  (basic — open|filtered or closed)
# ─────────────────────────────────────────────

def udp_port_scan(host: str, ports: List[int], timeout: float = 1.5,
                  callback: Callable = None) -> List[PortResult]:
    """
    Basic UDP port scan. Without raw-socket ICMP access the best we can say
    is 'open|filtered' (no response) or 'closed' (ICMP unreachable received).
    """
    results: List[PortResult] = []
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    for port in ports:
        t0 = time.perf_counter()
        state = 'open|filtered'
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(timeout)
            udp.sendto(b'\x00' * 4, (ip, port))
            try:
                udp.recv(512)
                state = 'open'
            except socket.timeout:
                state = 'open|filtered'
            except ConnectionResetError:
                state = 'closed'
            finally:
                udp.close()
        except Exception:
            state = 'unknown'
        rtt = (time.perf_counter() - t0) * 1000
        r = PortResult(host=ip, port=port, state=state,
                       service=COMMON_PORTS.get(port, ''), rtt_ms=round(rtt, 2))
        results.append(r)
        if callback:
            callback(r)
    return results


# ─────────────────────────────────────────────
# DNS-over-HTTPS comparison
# ─────────────────────────────────────────────

def doh_lookup(domain: str, record_type: str = 'A') -> Dict:
    """
    Query Google DoH and Cloudflare DoH for a domain/record type.
    Returns {'google': [...answers], 'cloudflare': [...answers], 'error': str}
    """
    import urllib.request
    import json as _json

    result: Dict = {'google': [], 'cloudflare': [], 'error': ''}

    def _query(url: str):
        try:
            req = urllib.request.Request(
                url,
                headers={'accept': 'application/dns-json',
                         'User-Agent': 'NetProbe/1.1'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read().decode())
            return [a['data'] for a in data.get('Answer', [])]
        except Exception as e:
            return [f'Error: {e}']

    g_url  = f'https://dns.google/resolve?name={domain}&type={record_type}'
    cf_url = (f'https://cloudflare-dns.com/dns-query'
              f'?name={domain}&type={record_type}')

    result['google']      = _query(g_url)
    result['cloudflare']  = _query(cf_url)
    return result



# ─────────────────────────────────────────────────────────────────
# Netstat snapshot
# ─────────────────────────────────────────────────────────────────

@dataclass
class NetstatEntry:
    proto:       str = ''
    local_addr:  str = ''
    local_port:  int = 0
    remote_addr: str = ''
    remote_port: int = 0
    state:       str = ''
    pid:         int = 0
    process:     str = ''


def _netstat_subprocess() -> List['NetstatEntry']:
    """Fallback: parse netstat -an output."""
    import subprocess, re
    entries: List[NetstatEntry] = []
    try:
        out = subprocess.check_output(
            ['netstat', '-ano'], text=True,
            stderr=subprocess.DEVNULL, timeout=10, **_HIDE)
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            proto = parts[0].upper()
            if proto not in ('TCP', 'UDP', 'TCP6', 'UDP6'):
                continue
            def _split(s: str):
                if s.startswith('['):
                    m = re.match(r'\[(.+)\]:(\d+)$', s)
                    return (m.group(1), int(m.group(2))) if m else (s, 0)
                if ':' in s:
                    h, p = s.rsplit(':', 1)
                    return h, int(p) if p.isdigit() else 0
                return s, 0
            la, lp = _split(parts[1]) if len(parts) > 1 else ('', 0)
            if proto.startswith('TCP') and len(parts) >= 4:
                ra, rp = _split(parts[2])
                state = parts[3]
                pid   = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
            else:
                ra, rp, state = '', 0, ''
                pid = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
            entries.append(NetstatEntry(
                proto=proto, local_addr=la, local_port=lp,
                remote_addr=ra, remote_port=rp, state=state, pid=pid))
    except Exception:
        pass
    return entries


def netstat_snapshot() -> List[NetstatEntry]:
    """Return current network connections; uses psutil if available."""
    import socket as _socket
    try:
        import psutil
        _PROTO = {
            (_socket.AF_INET,  _socket.SOCK_STREAM): 'TCP',
            (_socket.AF_INET6, _socket.SOCK_STREAM): 'TCP6',
            (_socket.AF_INET,  _socket.SOCK_DGRAM):  'UDP',
            (_socket.AF_INET6, _socket.SOCK_DGRAM):  'UDP6',
        }
        entries: List[NetstatEntry] = []
        for conn in psutil.net_connections(kind='all'):
            proc = ''
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid).name()
                except Exception:
                    pass
            proto = _PROTO.get((conn.family, conn.type), 'OTHER')
            la = conn.laddr.ip   if conn.laddr else ''
            lp = conn.laddr.port if conn.laddr else 0
            ra = conn.raddr.ip   if conn.raddr else ''
            rp = conn.raddr.port if conn.raddr else 0
            entries.append(NetstatEntry(
                proto=proto, local_addr=la, local_port=lp,
                remote_addr=ra, remote_port=rp,
                state=conn.status or '', pid=conn.pid or 0, process=proc))
        return entries
    except ImportError:
        return _netstat_subprocess()
