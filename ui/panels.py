"""
NetProbe Tab Panels
Each tool gets its own panel class.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import time
import socket

from .theme import *
from .widgets import (CardFrame, LabeledEntry, ScrolledText,
                      DarkTreeview, MiniGraph, RTTGraph, run_in_thread)
from core import (PingMonitor, MTRMonitor, traceroute, port_scan, udp_port_scan,
                  dns_lookup, doh_lookup, arp_scan, ping_sweep, get_local_interfaces,
                  BandwidthServer, BandwidthClient, IPerf3Client, find_iperf3,
                  PacketCapture, ExternalMonitor, COMMON_PORTS,
                  asn_lookup, asn_lookup_batch,
                  GeoIPResult, geoip_lookup, geoip_lookup_batch,
                  SSLInfo, ssl_inspect, HTTPResult, http_probe,
                  whois_lookup, wake_on_lan)


# ─────────────────────────────────────────────────────────────────
# Cross-tab navigation helper
# ─────────────────────────────────────────────────────────────────

def _get_app():
    """Return the running NetProbeApp instance (set in app.py __init__)."""
    try:
        from ui.app import _app_instance
        return _app_instance
    except Exception:
        return None


def _pulse_start():
    app = _get_app()
    if app and hasattr(app, 'status_bar'):
        app.status_bar.start_pulse()


def _pulse_stop(text='READY'):
    app = _get_app()
    if app and hasattr(app, 'status_bar'):
        app.status_bar.stop_pulse(text)


# ─────────────────────────────────────────────────────────────────
# Helper: target bar used by most panels
# ─────────────────────────────────────────────────────────────────

class TargetBar(tk.Frame):
    def __init__(self, parent, label='Target', default='', button_text='▶  START',
                 on_start=None, on_stop=None, extra_widgets=None):
        super().__init__(parent, bg=BG_PANEL)
        self._on_start = on_start
        self._on_stop = on_stop
        self._running = False

        tk.Label(self, text=label, **LABEL_OPTS).pack(side='left', padx=(6, 4))
        self.entry = tk.Entry(self, width=28, **ENTRY_OPTS)
        self.entry.insert(0, default)
        self.entry.pack(side='left', ipady=3, padx=2)
        self.entry.bind('<Return>', lambda e: self._toggle())

        if extra_widgets:
            for w in extra_widgets:
                w.pack(side='left', padx=4)

        self.btn = tk.Button(self, text=button_text, **BUTTON_GREEN_OPTS,
                             command=self._toggle)
        self.btn.pack(side='left', padx=8)

        self.status_lbl = tk.Label(self, text='', bg=BG_PANEL,
                                   fg=FG_DIM, font=FONT_LABEL)
        self.status_lbl.pack(side='left', padx=4)

    def _toggle(self):
        if not self._running:
            self._running = True
            self.btn.configure(text='■  STOP', **BUTTON_RED_OPTS)
            self.status_lbl.configure(text='RUNNING', fg=ACCENT_GREEN)
            if self._on_start:
                self._on_start(self.entry.get().strip())
        else:
            self._running = False
            self.btn.configure(text='▶  START', **BUTTON_GREEN_OPTS)
            self.status_lbl.configure(text='STOPPED', fg=FG_DIM)
            if self._on_stop:
                self._on_stop()

    def force_stop(self):
        if self._running:
            self._toggle()

    def get_target(self):
        return self.entry.get().strip()


# ─────────────────────────────────────────────────────────────────
# 1. PING PANEL
# ─────────────────────────────────────────────────────────────────

class PingPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._monitor = None
        self._results = []
        self._build()

    def _build(self):
        # Top controls
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        self._interval_var = tk.StringVar(value='1.0')
        ifrm = tk.Frame(ctrl, bg=BG_PANEL)
        tk.Label(ifrm, text='Interval(s)', **LABEL_OPTS).pack(side='left')
        tk.Entry(ifrm, textvariable=self._interval_var, width=5,
                 **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)

        # Loss alert threshold
        alert_frm = tk.Frame(ctrl, bg=BG_PANEL)
        tk.Label(alert_frm, text='Alert loss%>', **LABEL_OPTS).pack(side='left')
        self._alert_loss_var = tk.StringVar(value='')
        tk.Entry(alert_frm, textvariable=self._alert_loss_var, width=4,
                 **ENTRY_OPTS).pack(side='left', padx=2, ipady=3)

        self._tbar = TargetBar(ctrl, label='Host/IP', default='8.8.8.8',
                               extra_widgets=[ifrm, alert_frm],
                               on_start=self._start, on_stop=self._stop)
        self._tbar.pack(side='left')

        # Stats row
        stats_row = tk.Frame(self, bg=BG_PANEL)
        stats_row.pack(fill='x', padx=8, pady=2)
        self._stat_vars = {}
        for key, label in [('sent','SENT'),('recv','RECV'),('loss','LOSS%'),
                            ('min','MIN ms'),('avg','AVG ms'),('max','MAX ms'),
                            ('last','LAST ms'),('jitter','JITTER ms')]:
            frm = tk.Frame(stats_row, bg=BG_CARD,
                           highlightthickness=1, highlightbackground=BORDER_DIM,
                           padx=10, pady=6)
            frm.pack(side='left', padx=2)
            tk.Label(frm, text=label, bg=BG_CARD, fg=FG_DIM,
                     font=(_MONO, 7, 'bold')).pack()
            var = tk.StringVar(value='—')
            self._stat_vars[key] = var
            tk.Label(frm, textvariable=var, bg=BG_CARD, fg=ACCENT_CYAN,
                     font=FONT_MONO_MD).pack()

        # Graph
        graph_card = CardFrame(self, title='RTT GRAPH (last 120 pings)')
        graph_card.pack(fill='x', padx=8, pady=4)
        self._graph = RTTGraph(graph_card.body, height=72, max_points=120)
        self._graph.pack(fill='x', expand=True, padx=4, pady=4)

        # Log
        log_card = CardFrame(self, title='PING LOG')
        log_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._log = ScrolledText(log_card.body, height=14,
                                 timestamps=True, state='disabled')
        self._log.pack(fill='both', expand=True, padx=4, pady=4)
        self._log.configure_tags(
            ok=dict(foreground=ACCENT_GREEN),
            timeout=dict(foreground=ACCENT_RED),
            warn=dict(foreground=ACCENT_YELLOW),
            dim=dict(foreground=FG_DIM),
            hdr=dict(foreground=ACCENT_CYAN),
        )

        clr_btn = tk.Button(log_card.body, text='CLEAR', **BUTTON_OPTS,
                            command=self._log.clear)
        clr_btn.pack(anchor='e', padx=4, pady=2)

    def _start(self, host):
        if not host:
            messagebox.showwarning('NetProbe', 'Enter a host or IP')
            self._tbar.force_stop()
            return
        try:
            interval = float(self._interval_var.get())
        except ValueError:
            interval = 1.0

        self._results = []
        self._log.clear()
        self._log.append(f'PING {host} — interval={interval}s\n', 'hdr')
        self._monitor = PingMonitor(host, interval=interval, callback=self._on_result)
        self._monitor.start()
        _pulse_start()

    def _stop(self):
        if self._monitor:
            self._monitor.stop()
            self._log.append('— STOPPED —\n', 'dim')
        _pulse_stop()

    def _on_result(self, r):
        self._results.append(r)
        self._graph.push(r.rtt_ms)

        if r.rtt_ms < 0:
            line = f'  seq={r.seq:<5}  TIMEOUT\n'
            tag = 'timeout'
        else:
            color_tag = 'ok' if r.rtt_ms < 100 else 'warn'
            line = f'  seq={r.seq:<5}  {r.ip:<16}  ttl={r.ttl:<4}  {r.rtt_ms:>8.3f} ms\n'
            tag = color_tag

        self._log.append(line, tag)

        # Update stats
        valid = [x for x in self._results if x.rtt_ms >= 0]
        self._stat_vars['sent'].set(str(len(self._results)))
        self._stat_vars['recv'].set(str(len(valid)))
        loss = (len(self._results) - len(valid)) / len(self._results) * 100
        self._stat_vars['loss'].set(f'{loss:.1f}%')
        if valid:
            self._stat_vars['min'].set(f'{min(x.rtt_ms for x in valid):.1f}')
            avg_rtt = sum(x.rtt_ms for x in valid) / len(valid)
            self._stat_vars['avg'].set(f'{avg_rtt:.1f}')
            self._stat_vars['max'].set(f'{max(x.rtt_ms for x in valid):.1f}')
            self._stat_vars['last'].set(f'{r.rtt_ms:.1f}' if r.rtt_ms >= 0 else 'T/O')
            if len(valid) > 1:
                jitter = (sum((x.rtt_ms - avg_rtt)**2 for x in valid) / len(valid)) ** 0.5
                self._stat_vars['jitter'].set(f'{jitter:.1f}')

        # Loss alert
        try:
            alert_thresh = float(self._alert_loss_var.get())
            if loss >= alert_thresh:
                self._log.append(
                    f'  ⚠ ALERT: loss {loss:.1f}% exceeds threshold {alert_thresh:.0f}%\n',
                    'timeout')
        except (ValueError, AttributeError):
            pass


# ─────────────────────────────────────────────────────────────────
# 2. TRACEROUTE PANEL
# ─────────────────────────────────────────────────────────────────

class TraceroutePanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._thread = None
        self._stop_event = threading.Event()
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        self._max_hops = tk.StringVar(value='30')
        hops_frm = tk.Frame(ctrl, bg=BG_PANEL)
        tk.Label(hops_frm, text='Max Hops', **LABEL_OPTS).pack(side='left')
        tk.Entry(hops_frm, textvariable=self._max_hops, width=4,
                 **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)

        self._tbar = TargetBar(ctrl, label='Destination', default='8.8.8.8',
                               extra_widgets=[hops_frm],
                               on_start=self._start, on_stop=self._stop)
        self._tbar.pack(side='left')

        # Hops table
        card = CardFrame(self, title='HOP TABLE')
        card.pack(fill='both', expand=True, padx=8, pady=8)

        cols = ('hop', 'ip', 'hostname', 'rtt1', 'rtt2', 'rtt3', 'loss', 'asn', 'geo')
        hdrs = ('HOP', 'IP ADDRESS', 'HOSTNAME', 'RTT 1', 'RTT 2', 'RTT 3', 'LOSS%', 'ASN / CARRIER', 'GEO')
        widths = (45, 120, 180, 75, 75, 75, 55, 180, 130)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        self._tree.tree.tag_configure('ok',      foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('warn',     foreground=ACCENT_YELLOW)
        self._tree.tree.tag_configure('bad',      foreground=ACCENT_RED)
        self._tree.tree.tag_configure('timeout',  foreground=FG_DIM)
        self._tree.tree.tag_configure('dest',     foreground=ACCENT_CYAN)

        import platform as _plat
        _tr_cmd = 'tracert' if _plat.system() == 'Windows' else 'traceroute'
        self._tree.set_shell_cmd_fn(
            lambda v: f'ping {v[1]}' if v and len(v) > 1 and v[1] not in ('', '*') else '')

    def _start(self, host):
        if not host:
            self._tbar.force_stop()
            return
        self._tree.clear()
        self._stop_event.clear()
        self._hop_ips = {}  # hop_n -> item_id for ASN update
        try:
            max_hops = int(self._max_hops.get())
        except:
            max_hops = 30

        def run():
            traceroute(host, max_hops=max_hops, callback=self._on_hop)
            # After trace completes, do ASN lookups in background
            self._resolve_asns()
            self._tbar.force_stop()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def _resolve_asns(self):
        """Look up ASN + GeoIP for all hop IPs and update the tree."""
        ips = {ip: iid for ip, iid in self._hop_ips.items() if ip and ip != '*'}
        if not ips:
            return

        def on_asn(ip, asn):
            iid = ips.get(ip)
            if iid:
                try:
                    self._tree.tree.after(0, self._update_asn_cell, iid, asn)
                except Exception:
                    pass

        def on_geo(ip, geo):
            iid = ips.get(ip)
            if iid:
                try:
                    self._tree.tree.after(0, self._update_geo_cell, iid, geo.short())
                except Exception:
                    pass

        asn_lookup_batch(list(ips.keys()), callback=on_asn)
        geoip_lookup_batch(list(ips.keys()), callback=on_geo)

    def _update_asn_cell(self, iid, asn):
        try:
            vals = list(self._tree.tree.item(iid)['values'])
            if len(vals) >= 8:
                vals[7] = asn
                self._tree.tree.item(iid, values=vals)
        except Exception:
            pass

    def _update_geo_cell(self, iid, geo_str):
        try:
            vals = list(self._tree.tree.item(iid)['values'])
            if len(vals) >= 9:
                vals[8] = geo_str
                self._tree.tree.item(iid, values=vals)
        except Exception:
            pass

    def _stop(self):
        self._stop_event.set()

    def _on_hop(self, hop):
        if self._stop_event.is_set():
            return
        rtts = []
        for r in hop.rtts:
            rtts.append(f'{r:.1f}ms' if r >= 0 else '*')
        while len(rtts) < 3:
            rtts.append('*')

        valid = [r for r in hop.rtts if r >= 0]
        avg = sum(valid)/len(valid) if valid else -1

        tag = 'timeout'
        if avg >= 0:
            if avg < 50:    tag = 'ok'
            elif avg < 150: tag = 'warn'
            else:           tag = 'bad'
        if hop.loss_pct == 100:
            tag = 'timeout'

        values = (hop.hop, hop.ip, hop.hostname[:40],
                  rtts[0], rtts[1], rtts[2], f'{hop.loss_pct:.0f}%', '…', '…')
        iid = self._tree.tree.insert('', 'end', values=values, tags=(tag,))
        self._tree.tree.see(iid)

        # Store for ASN + GeoIP resolution
        if hop.ip and hop.ip != '*':
            self._hop_ips[hop.ip] = iid


# ─────────────────────────────────────────────────────────────────
# 3. MTR PANEL (continuous)
# ─────────────────────────────────────────────────────────────────

class MTRPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._mtr = None
        self._update_job = None
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        self._interval = tk.StringVar(value='1.0')
        ifrm = tk.Frame(ctrl, bg=BG_PANEL)
        tk.Label(ifrm, text='Interval(s)', **LABEL_OPTS).pack(side='left')
        tk.Entry(ifrm, textvariable=self._interval, width=5,
                 **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)

        self._tbar = TargetBar(ctrl, label='Target', default='8.8.8.8',
                               extra_widgets=[ifrm],
                               on_start=self._start, on_stop=self._stop)
        self._tbar.pack(side='left')

        info = tk.Label(self, text='MTR = continuous combined ping/traceroute — refreshes live',
                        bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL)
        info.pack(anchor='w', padx=12)

        card = CardFrame(self, title='MTR — LIVE HOP STATISTICS')
        card.pack(fill='both', expand=True, padx=8, pady=8)

        cols = ('hop','ip','hostname','loss','sent','last','avg','best','worst','stdev','asn','geo')
        hdrs = ('HOP','IP ADDRESS','HOSTNAME','LOSS%','SENT','LAST ms','AVG ms','BEST ms','WORST ms','STDEV','ASN / CARRIER','GEO')
        widths = (40, 115, 165, 55, 50, 65, 65, 65, 65, 60, 165, 120)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        self._tree.tree.tag_configure('ok',    foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('warn',  foreground=ACCENT_YELLOW)
        self._tree.tree.tag_configure('bad',   foreground=ACCENT_RED)
        self._tree.tree.tag_configure('dim',   foreground=FG_DIM)

    def _start(self, host):
        if not host:
            self._tbar.force_stop()
            return
        try:
            interval = float(self._interval.get())
        except:
            interval = 1.0
        self._mtr_asn_cache = {}
        self._mtr_geo_cache = {}
        self._mtr = MTRMonitor(host, interval=interval)
        self._mtr.start()
        self._schedule_update()
        _pulse_start()

    def _stop(self):
        if self._mtr:
            self._mtr.stop()
        if self._update_job:
            self.after_cancel(self._update_job)
            self._update_job = None
        _pulse_stop()

    def _schedule_update(self):
        self._refresh()
        self._update_job = self.after(500, self._schedule_update)

    def _refresh(self):
        if not self._mtr:
            return
        rows = self._mtr.get_rows()
        self._tree.clear()

        # Collect IPs needing ASN / GeoIP lookup
        needs_lookup = []
        for row in rows:
            if row.ip and row.ip != '*' and row.ip not in self._mtr_asn_cache:
                needs_lookup.append(row.ip)
                self._mtr_asn_cache[row.ip] = '…'
                self._mtr_geo_cache[row.ip] = '…'

        if needs_lookup:
            def do_lookup(ips):
                for ip in ips:
                    self._mtr_asn_cache[ip] = asn_lookup(ip)
                    self._mtr_geo_cache[ip] = geoip_lookup(ip).short()
            threading.Thread(target=do_lookup, args=(needs_lookup,), daemon=True).start()

        for row in rows:
            if row.loss_pct >= 50: tag = 'bad'
            elif row.loss_pct > 0 or row.avg_ms > 150: tag = 'warn'
            elif row.ip == '*': tag = 'dim'
            else: tag = 'ok'
            asn = self._mtr_asn_cache.get(row.ip, '') if row.ip != '*' else ''
            geo = self._mtr_geo_cache.get(row.ip, '') if row.ip != '*' else ''
            values = (
                row.hop, row.ip, row.hostname[:28],
                f'{row.loss_pct:.1f}%', row.sent,
                f'{row.last_ms:.1f}' if row.last_ms else '—',
                f'{row.avg_ms:.1f}'  if row.avg_ms else '—',
                f'{row.best_ms:.1f}' if row.best_ms < 999999 else '—',
                f'{row.worst_ms:.1f}' if row.worst_ms else '—',
                f'{row.stdev_ms:.1f}' if row.stdev_ms else '—',
                asn, geo,
            )
            self._tree.tree.insert('', 'end', values=values, tags=(tag,))


# ─────────────────────────────────────────────────────────────────
# 4. BANDWIDTH PANEL
# ─────────────────────────────────────────────────────────────────

class BandwidthPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._server = None
        self._client = None
        self._build()

    def _build(self):
        # Mode selector row
        top = tk.Frame(self, bg=BG_PANEL, pady=6)
        top.pack(fill='x', padx=8)
        self._mode = tk.StringVar(value='server')
        for val, txt in [('server', '▣  SERVER (listen)'), ('client', '▷  CLIENT (send)')]:
            rb = tk.Radiobutton(top, text=txt, variable=self._mode, value=val,
                                bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                                activebackground=BG_PANEL, activeforeground=ACCENT_CYAN,
                                font=FONT_UI, command=self._mode_changed)
            rb.pack(side='left', padx=10)

        # Client engine selector
        engine_frm = tk.Frame(top, bg=BG_PANEL)
        engine_frm.pack(side='left', padx=20)
        tk.Label(engine_frm, text='Engine:', **LABEL_OPTS).pack(side='left', padx=4)
        self._engine = tk.StringVar(value='iperf3')
        for val, txt in [('iperf3', 'iperf3'), ('builtin', 'Built-in TCP')]:
            rb = tk.Radiobutton(engine_frm, text=txt, variable=self._engine, value=val,
                                bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                                activebackground=BG_PANEL, font=FONT_UI_SM)
            rb.pack(side='left', padx=4)

        # iperf3 status indicator
        self._iperf3_status = tk.Label(top, text='', bg=BG_PANEL,
                                       fg=FG_DIM, font=FONT_LABEL)
        self._iperf3_status.pack(side='left', padx=8)
        self._check_iperf3()

        # Server frame
        self._server_frm = tk.Frame(self, bg=BG_PANEL)
        self._server_frm.pack(fill='x', padx=8)
        tk.Label(self._server_frm, text='Port', **LABEL_OPTS).pack(side='left')
        self._port_var = tk.StringVar(value='5201')
        tk.Entry(self._server_frm, textvariable=self._port_var,
                 width=7, **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)
        self._srv_btn = tk.Button(self._server_frm, text='▶  START SERVER',
                                  **BUTTON_GREEN_OPTS, command=self._toggle_server)
        self._srv_btn.pack(side='left', padx=8)
        tk.Label(self._server_frm,
                 text='Run this on the machine being tested TO',
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=8)

        # Client frame
        self._client_frm = tk.Frame(self, bg=BG_PANEL)
        tk.Label(self._client_frm, text='Server IP', **LABEL_OPTS).pack(side='left')
        self._host_var = tk.StringVar(value='')
        tk.Entry(self._client_frm, textvariable=self._host_var,
                 width=18, **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)
        tk.Label(self._client_frm, text='Port', **LABEL_OPTS).pack(side='left', padx=(8, 2))
        self._cli_port = tk.StringVar(value='5201')
        tk.Entry(self._client_frm, textvariable=self._cli_port,
                 width=6, **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)
        tk.Label(self._client_frm, text='Duration(s)', **LABEL_OPTS).pack(side='left', padx=(8, 2))
        self._dur_var = tk.StringVar(value='10')
        tk.Entry(self._client_frm, textvariable=self._dur_var,
                 width=5, **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)
        tk.Label(self._client_frm, text='Streams', **LABEL_OPTS).pack(side='left', padx=(8, 2))
        self._streams_var = tk.StringVar(value='1')
        tk.Entry(self._client_frm, textvariable=self._streams_var,
                 width=3, **ENTRY_OPTS).pack(side='left', padx=4, ipady=3)
        self._proto_var = tk.StringVar(value='tcp')
        for val, txt in [('tcp', 'TCP'), ('udp', 'UDP')]:
            tk.Radiobutton(self._client_frm, text=txt, variable=self._proto_var, value=val,
                           bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                           activebackground=BG_PANEL, font=FONT_UI_SM).pack(side='left', padx=3)
        self._cli_btn = tk.Button(self._client_frm, text='▶  RUN TEST',
                                  **BUTTON_GREEN_OPTS, command=self._toggle_client)
        self._cli_btn.pack(side='left', padx=8)

        # Big throughput display
        self._meter_card = CardFrame(self, title='THROUGHPUT')
        meter_card = self._meter_card
        meter_card.pack(fill='x', padx=8, pady=4)
        self._mbps_var = tk.StringVar(value='0.00')
        tk.Label(meter_card.body, textvariable=self._mbps_var,
                 bg=BG_CARD, fg=ACCENT_GREEN,
                 font=(_MONO, 32, 'bold')).pack(side='left', padx=20)
        tk.Label(meter_card.body, text='Mbps', bg=BG_CARD,
                 fg=FG_DIM, font=(_MONO, 14)).pack(side='left')

        # Graph
        graph_card = CardFrame(self, title='THROUGHPUT OVER TIME')
        graph_card.pack(fill='x', padx=8, pady=4)
        self._graph = MiniGraph(graph_card.body, height=60)
        self._graph.pack(fill='x', expand=True, padx=4, pady=4)

        # Log
        log_card = CardFrame(self, title='LOG')
        log_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._log = ScrolledText(log_card.body, height=10, state='disabled')
        self._log.pack(fill='both', expand=True, padx=4, pady=4)
        self._log.configure_tags(
            info=dict(foreground=ACCENT_CYAN),
            ok=dict(foreground=ACCENT_GREEN),
            err=dict(foreground=ACCENT_RED),
            warn=dict(foreground=ACCENT_YELLOW),
            dim=dict(foreground=FG_DIM),
        )

        self._server_running = False
        self._client_running = False
        self._mode_changed()

    def _check_iperf3(self):
        path = find_iperf3()
        if path:
            self._iperf3_status.configure(
                text=f'✓ iperf3 found', fg=ACCENT_GREEN)
        else:
            self._iperf3_status.configure(
                text='✗ iperf3 not found — place iperf3.exe next to NetProbe.exe',
                fg=ACCENT_YELLOW)
            self._engine.set('builtin')

    def _mode_changed(self):
        mode = self._mode.get()
        if mode == 'server':
            self._client_frm.pack_forget()
            self._server_frm.pack(fill='x', padx=8, before=self._meter_card)
        else:
            self._server_frm.pack_forget()
            self._client_frm.pack(fill='x', padx=8, before=self._meter_card)

    def _toggle_server(self):
        if not self._server_running:
            self._server_running = True
            self._srv_btn.configure(text='■  STOP SERVER', **BUTTON_RED_OPTS)
            port = int(self._port_var.get() or 5201)
            self._server = BandwidthServer(
                port=port,
                callback=lambda ev: self.after(0, self._on_server_event, ev))
            self._server.start()
        else:
            self._server_running = False
            self._srv_btn.configure(text='▶  START SERVER', **BUTTON_GREEN_OPTS)
            if self._server:
                self._server.stop()

    def _toggle_client(self):
        if not self._client_running:
            self._client_running = True
            self._cli_btn.configure(text='■  STOP', **BUTTON_RED_OPTS)
            host = self._host_var.get().strip()
            if not host:
                self._log.append('[ERROR] Enter a server IP address\n', 'err')
                self._client_running = False
                self._cli_btn.configure(text='▶  RUN TEST', **BUTTON_GREEN_OPTS)
                return
            port = int(self._cli_port.get() or 5201)
            dur = int(self._dur_var.get() or 10)
            streams = int(self._streams_var.get() or 1)
            proto = self._proto_var.get()

            if self._engine.get() == 'iperf3':
                self._log.append(f'[iperf3] Connecting to {host}:{port}  '
                                 f'{proto.upper()}  {dur}s  {streams} stream(s)\n', 'info')
                self._client = IPerf3Client(
                    host, port=port, duration=dur,
                    protocol=proto, streams=streams,
                    callback=lambda ev: self.after(0, self._on_client_event, ev))
                self._client.start()
            else:
                self._log.append(f'[Built-in] Connecting to {host}:{port}  TCP  {dur}s\n'
                                 f'[Built-in] Ensure NetProbe SERVER is running on {host}\n',
                                 'info')
                self._client = BandwidthClient(
                    host, port=port, duration=dur,
                    callback=lambda ev: self.after(0, self._on_client_event, ev))
                self._client.start()
        else:
            self._client_running = False
            self._cli_btn.configure(text='▶  RUN TEST', **BUTTON_GREEN_OPTS)
            if self._client:
                self._client.stop()

    def _on_server_event(self, ev):
        evt = ev.get('event')
        if evt == 'listening':
            self._log.append(f'[SERVER] Listening on port {ev["port"]}\n', 'info')
        elif evt == 'progress':
            mb = ev['bytes'] / 1_000_000
            self._log.append(
                f'[SERVER] RX {mb:.1f} MB @ {ev["mbps"]:.2f} Mbps  from {ev["client"]}\n', 'ok')
            self._mbps_var.set(f'{ev["mbps"]:.2f}')
            self._graph.push(ev['mbps'])
        elif evt == 'done':
            self._log.append(
                f'[SERVER] Done: {ev["bytes"]/1_000_000:.1f} MB '
                f'in {ev["duration"]}s = {ev["mbps"]:.2f} Mbps\n', 'ok')
        elif evt == 'error':
            self._log.append(f'[SERVER] Error: {ev["message"]}\n', 'err')

    def _on_client_event(self, ev):
        evt = ev.get('event')
        if evt == 'connected':
            self._log.append(
                f'[CLIENT] Connected to {ev["host"]}  '
                f'(iperf3: {ev.get("iperf3", "built-in")})\n', 'info')
        elif evt == 'progress':
            interval = ev.get('interval', '')
            self._log.append(
                f'[{interval}]  {ev["mbps"]:.2f} Mbps\n', 'ok')
            self._mbps_var.set(f'{ev["mbps"]:.2f}')
            self._graph.push(ev['mbps'])
        elif evt == 'done':
            role = ev.get('role', 'sender')
            self._mbps_var.set(f'{ev["mbps"]:.2f}')
            self._log.append(
                f'[DONE] {role}:  {ev["mbps"]:.2f} Mbps  '
                f'({ev.get("bytes",0)/1_000_000:.1f} MB in {ev.get("duration",0)}s)\n', 'ok')
            self._client_running = False
            self._cli_btn.configure(text='▶  RUN TEST', **BUTTON_GREEN_OPTS)
        elif evt == 'error':
            self._log.append(f'[ERROR] {ev["message"]}\n', 'err')
            self._client_running = False
            self._cli_btn.configure(text='▶  RUN TEST', **BUTTON_GREEN_OPTS)

    def _mode_changed(self):
        mode = self._mode.get()
        if mode == 'server':
            self._client_frm.pack_forget()
            self._server_frm.pack(fill='x', padx=8, before=self._meter_card)
        else:
            self._server_frm.pack_forget()
            self._client_frm.pack(fill='x', padx=8, before=self._meter_card)



# ─────────────────────────────────────────────────────────────────
# 5. PORT SCANNER PANEL
# ─────────────────────────────────────────────────────────────────

class PortScanPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._thread = None
        self._stop_event = threading.Event()
        self._open_count = 0
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        tk.Label(ctrl, text='Target', **LABEL_OPTS).pack(side='left', padx=(6, 4))
        self._host_entry = tk.Entry(ctrl, width=20, **ENTRY_OPTS)
        self._host_entry.insert(0, '127.0.0.1')
        self._host_entry.pack(side='left', padx=2, ipady=3)

        tk.Label(ctrl, text='Ports', **LABEL_OPTS).pack(side='left', padx=(10, 4))
        self._ports_entry = tk.Entry(ctrl, width=22, **ENTRY_OPTS)
        self._ports_entry.insert(0, '1-1024')
        self._ports_entry.pack(side='left', padx=2, ipady=3)

        tk.Label(ctrl, text='Timeout', **LABEL_OPTS).pack(side='left', padx=(6, 2))
        self._timeout_var = tk.StringVar(value='0.5')
        tk.Entry(ctrl, textvariable=self._timeout_var, width=5,
                 **ENTRY_OPTS).pack(side='left', padx=2, ipady=3)

        self._proto_var = tk.StringVar(value='TCP')
        proto_frm2 = tk.Frame(ctrl, bg=BG_PANEL)
        tk.Label(proto_frm2, text='Proto', **LABEL_OPTS).pack(side='left')
        for p in ['TCP', 'UDP']:
            tk.Radiobutton(proto_frm2, text=p, variable=self._proto_var, value=p,
                           bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                           activebackground=BG_PANEL, font=FONT_UI_SM).pack(side='left', padx=2)
        proto_frm2.pack(side='left', padx=(8, 4))

        self._scan_btn = tk.Button(ctrl, text='▶  SCAN', **BUTTON_GREEN_OPTS,
                                   command=self._toggle_scan)
        self._scan_btn.pack(side='left', padx=8)

        # Preset buttons
        preset_frm = tk.Frame(self, bg=BG_PANEL)
        preset_frm.pack(fill='x', padx=8, pady=2)
        tk.Label(preset_frm, text='Presets:', **LABEL_OPTS).pack(side='left', padx=4)
        presets = [
            ('Common', ','.join(str(p) for p in sorted(COMMON_PORTS.keys()))),
            ('1-1024', '1-1024'),
            ('Top 100', '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'),
            ('Full', '1-65535'),
        ]
        for name, ports in presets:
            btn = tk.Button(preset_frm, text=name, **BUTTON_OPTS,
                            command=lambda p=ports: self._ports_entry.delete(0, 'end') or self._ports_entry.insert(0, p))
            btn.pack(side='left', padx=2)

        # Stats
        stat_frm = tk.Frame(self, bg=BG_PANEL)
        stat_frm.pack(fill='x', padx=8, pady=2)
        self._progress_var = tk.StringVar(value='Ready')
        tk.Label(stat_frm, textvariable=self._progress_var,
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=6)

        # Results table
        card = CardFrame(self, title='SCAN RESULTS')
        card.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('host', 'port', 'service', 'state', 'rtt', 'banner')
        hdrs = ('HOST', 'PORT', 'SERVICE', 'STATE', 'RTT ms', 'BANNER')
        widths = (130, 60, 100, 70, 70, 300)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        self._tree.tree.tag_configure('open',         foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('closed',       foreground=FG_DIM)
        self._tree.tree.tag_configure('filtered',     foreground=ACCENT_YELLOW)
        self._tree.tree.tag_configure('open|filtered',foreground=ACCENT_CYAN)
        self._tree.set_shell_cmd_fn(
            lambda v: (f'nmap -sV -p {v[1]} {v[0]}' if v and len(v) >= 2 else ''))

        # Right-click context menu
        ctx_menu = tk.Menu(self._tree.tree, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                           activebackground=BG_SELECT, activeforeground=FG_BRIGHT)
        ctx_menu.add_command(label='Ping this host',
                             command=lambda: self._ctx_navigate('PING'))
        ctx_menu.add_command(label='DNS lookup',
                             command=lambda: self._ctx_navigate('DNS'))
        ctx_menu.add_command(label='SSL inspect (port 443)',
                             command=lambda: self._ctx_navigate('SSL/TLS'))
        ctx_menu.add_separator()
        self._tree._menu.add_separator()
        self._tree._menu.add_command(label='Ping this host',
                                     command=lambda: self._ctx_navigate('PING'))
        self._tree._menu.add_command(label='DNS lookup',
                                     command=lambda: self._ctx_navigate('DNS'))

        self._scanning = False

    def _expand_targets(self, target: str):
        """Return list of IP strings. Handles single host/IP and CIDR notation."""
        import ipaddress
        target = target.strip()
        if '/' in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                hosts = list(net.hosts())
                if len(hosts) > 1024:
                    if not messagebox.askyesno(
                            'Large subnet',
                            f'{target} contains {len(hosts)} hosts.\n'
                            f'Scanning all may take a long time. Continue?'):
                        return []
                return [str(h) for h in hosts]
            except ValueError:
                pass
        return [target]

    def _toggle_scan(self):
        if not self._scanning:
            self._scanning = True
            self._scan_btn.configure(text='■  STOP', **BUTTON_RED_OPTS)
            self._tree.clear()
            self._open_count = 0
            self._stop_event.clear()
            target = self._host_entry.get().strip()
            ports_str = self._ports_entry.get().strip()
            try:
                timeout = float(self._timeout_var.get())
            except Exception:
                timeout = 0.5
            ports = self._parse_ports(ports_str)
            if not ports:
                messagebox.showwarning('NetProbe', 'Invalid port range')
                self._scanning = False
                self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)
                return
            hosts = self._expand_targets(target)
            if not hosts:
                self._scanning = False
                self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)
                return

            self._total_hosts = len(hosts)
            self._hosts_done  = 0
            self._progress_var.set(
                f'Scanning {len(ports)} ports × {len(hosts)} host(s)…')

            proto = self._proto_var.get()

            def run():
                for host in hosts:
                    if self._stop_event.is_set():
                        break
                    if proto == 'UDP':
                        udp_port_scan(host, ports, timeout=timeout,
                                      callback=self._on_port)
                    else:
                        port_scan(host, ports, timeout=timeout,
                                  callback=self._on_port,
                                  threads=min(100, len(ports)))
                    self._hosts_done += 1
                    remaining = self._total_hosts - self._hosts_done
                    self.after(0, self._progress_var.set,
                               f'Host {self._hosts_done}/{self._total_hosts} done'
                               f'{f" — {remaining} remaining" if remaining else ""}  '
                               f'({self._open_count} open)')
                self.after(0, self._done_scan)

            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()
            _pulse_start()
        else:
            self._stop_event.set()
            self._scanning = False
            self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)
            _pulse_stop()

    def _done_scan(self):
        self._scanning = False
        self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)
        self._progress_var.set(
            f'Done — {self._open_count} open port(s) across '
            f'{self._hosts_done} host(s)')
        _pulse_stop('DONE')

    def _on_port(self, r):
        if self._stop_event.is_set():
            return
        if r.state == 'closed':
            return
        if r.state == 'open':
            self._open_count += 1
        values = (r.host, r.port, r.service, r.state.upper(),
                  f'{r.rtt_ms:.1f}', r.banner[:60] if r.banner else '')
        self.after(0, self._tree.tree.insert, '', 'end',
                   values=values, tags=(r.state,))

    def _ctx_navigate(self, tab):
        sel = self._tree.tree.selection()
        if not sel:
            return
        vals = self._tree.tree.item(sel[0])['values']
        host = str(vals[0]) if vals else self._host_entry.get().strip()
        app = _get_app()
        if app:
            app.navigate_to(tab, host)

    def _parse_ports(self, s: str):
        ports = set()
        for part in s.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    a, b = part.split('-')
                    ports.update(range(int(a), int(b)+1))
                except:
                    pass
            else:
                try:
                    ports.add(int(part))
                except:
                    pass
        return sorted(ports)


# ─────────────────────────────────────────────────────────────────
# 6. DNS PANEL
# ─────────────────────────────────────────────────────────────────

class DNSPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        tk.Label(ctrl, text='Domain', **LABEL_OPTS).pack(side='left', padx=(6, 4))
        self._host_entry = tk.Entry(ctrl, width=30, **ENTRY_OPTS)
        self._host_entry.insert(0, 'example.com')
        self._host_entry.pack(side='left', padx=2, ipady=3)
        self._host_entry.bind('<Return>', lambda e: self._lookup())

        # Record type checkboxes
        types_frm = tk.Frame(self, bg=BG_PANEL)
        types_frm.pack(fill='x', padx=8, pady=2)
        tk.Label(types_frm, text='Record Types:', **LABEL_OPTS).pack(side='left', padx=4)
        self._type_vars = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']:
            var = tk.BooleanVar(value=rtype in ('A', 'AAAA', 'MX', 'NS'))
            cb = tk.Checkbutton(types_frm, text=rtype, variable=var,
                                bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                                activebackground=BG_PANEL, font=FONT_UI_SM)
            cb.pack(side='left', padx=3)
            self._type_vars[rtype] = var

        btn = tk.Button(ctrl, text='⌖  LOOKUP', **BUTTON_GREEN_OPTS, command=self._lookup)
        btn.pack(side='left', padx=8)

        doh_btn = tk.Button(ctrl, text='⇅  COMPARE DoH', **BUTTON_OPTS,
                            command=self._doh_compare)
        doh_btn.pack(side='left', padx=4)

        # Results
        card = CardFrame(self, title='DNS RESULTS')
        card.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('type', 'query', 'answer', 'rtt', 'error')
        hdrs = ('TYPE', 'QUERY', 'ANSWER', 'RTT ms', 'ERROR')
        widths = (60, 160, 300, 70, 200)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        self._tree.tree.tag_configure('ok',  foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('err', foreground=ACCENT_RED)
        self._tree.tree.tag_configure('dim', foreground=FG_DIM)
        self._tree.set_shell_cmd_fn(
            lambda v: (f'nslookup -type={v[0]} {v[1]}' if v and len(v) >= 2 else ''))

        # Raw output
        raw_card = CardFrame(self, title='RAW OUTPUT')
        raw_card.pack(fill='x', padx=8, pady=(0, 8))
        self._raw = ScrolledText(raw_card.body, height=8, state='disabled')
        self._raw.pack(fill='both', expand=True, padx=4, pady=4)
        self._raw.configure_tags(
            ok=dict(foreground=ACCENT_GREEN),
            err=dict(foreground=ACCENT_RED),
            hdr=dict(foreground=ACCENT_CYAN),
        )

    def _lookup(self):
        host = self._host_entry.get().strip()
        if not host:
            return
        rtypes = [t for t, v in self._type_vars.items() if v.get()]
        self._tree.clear()
        self._raw.clear()
        self._raw.append(f'; DNS lookup for {host}  [{time.strftime("%H:%M:%S")}]\n', 'hdr')

        def run():
            dns_lookup(host, record_types=rtypes, callback=self._on_result)

        threading.Thread(target=run, daemon=True).start()

    def _on_result(self, r):
        for answer in (r.answers or ['(none)']):
            tag = 'ok' if r.answers and not r.error else ('err' if r.error else 'dim')
            values = (r.record_type, r.query, answer,
                      f'{r.rtt_ms:.1f}' if r.rtt_ms else '—',
                      r.error[:60] if r.error else '')
            self._tree.tree.insert('', 'end', values=values, tags=(tag,))

        if r.answers:
            for a in r.answers:
                self._raw.append(f'{r.query:<40} {r.record_type:<8} {a}\n', 'ok')
        elif r.error:
            self._raw.append(f'{r.query:<40} {r.record_type:<8} ERROR: {r.error}\n', 'err')

    def _doh_compare(self):
        host = self._host_entry.get().strip()
        if not host:
            return
        rtypes = [t for t, v in self._type_vars.items() if v.get()] or ['A']
        self._raw.clear()
        self._raw.append(f'; DoH comparison for {host}\n', 'hdr')

        def run():
            for rtype in rtypes:
                result = doh_lookup(host, rtype)
                self.after(0, self._show_doh, host, rtype, result)

        threading.Thread(target=run, daemon=True).start()

    def _show_doh(self, host, rtype, result):
        self._raw.append(f'\n; {rtype} records\n', 'hdr')
        g = result.get('google', [])
        cf = result.get('cloudflare', [])
        self._raw.append(f'  Google DoH      : {", ".join(g) or "(none)"}\n',
                         'ok' if g and not any("Error" in str(x) for x in g) else 'err')
        self._raw.append(f'  Cloudflare DoH  : {", ".join(cf) or "(none)"}\n',
                         'ok' if cf and not any("Error" in str(x) for x in cf) else 'err')
        if set(str(x) for x in g) == set(str(x) for x in cf):
            self._raw.append('  ✓ Results match\n', 'ok')
        else:
            self._raw.append('  ✗ Results differ!\n', 'err')


# ─────────────────────────────────────────────────────────────────
# 7. ARP / L2 PANEL
# ─────────────────────────────────────────────────────────────────

class ARPPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        # Interface info
        iface_card = CardFrame(self, title='LOCAL INTERFACES')
        iface_card.pack(fill='x', padx=8, pady=(4, 0))
        self._iface_tree = DarkTreeview(iface_card.body,
                                        ('name','ip','netmask'),
                                        ('INTERFACE','IP ADDRESS','NETMASK'),
                                        (120, 130, 130), height=4)
        self._iface_tree.pack(fill='x', padx=4, pady=4)
        self._iface_tree.tree.bind('<ButtonRelease-1>', self._select_iface)

        refresh_btn = tk.Button(iface_card.body, text='↻ REFRESH INTERFACES',
                                **BUTTON_OPTS, command=self._load_interfaces)
        refresh_btn.pack(anchor='e', padx=4, pady=2)

        # Scan controls
        scan_frm = tk.Frame(self, bg=BG_PANEL, pady=6)
        scan_frm.pack(fill='x', padx=8)
        tk.Label(scan_frm, text='Network (CIDR)', **LABEL_OPTS).pack(side='left', padx=4)
        self._net_entry = tk.Entry(scan_frm, width=20, **ENTRY_OPTS)
        self._net_entry.insert(0, '192.168.1.0/24')
        self._net_entry.pack(side='left', padx=4, ipady=3)

        arp_btn = tk.Button(scan_frm, text='⬡ ARP SCAN', **BUTTON_GREEN_OPTS,
                            command=self._arp_scan)
        arp_btn.pack(side='left', padx=4)
        ping_btn = tk.Button(scan_frm, text='● PING SWEEP', **BUTTON_OPTS,
                             command=self._ping_sweep)
        ping_btn.pack(side='left', padx=4)
        cache_btn = tk.Button(scan_frm, text='≡ ARP CACHE', **BUTTON_OPTS,
                              command=self._arp_cache)
        cache_btn.pack(side='left', padx=4)

        self._status_var = tk.StringVar(value='Ready')
        tk.Label(scan_frm, textvariable=self._status_var,
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=8)

        # Results
        card = CardFrame(self, title='DISCOVERED HOSTS')
        card.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('ip','mac','hostname','interface')
        hdrs = ('IP ADDRESS','MAC ADDRESS','HOSTNAME','INTERFACE')
        widths = (120, 140, 220, 100)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)
        self._tree.tree.tag_configure('found', foreground=ACCENT_GREEN)

        # Right-click context menu items (appended to DarkTreeview's existing menu)
        self._tree._menu.add_separator()
        self._tree._menu.add_command(label='Ping this host',
                                     command=lambda: self._arp_ctx('PING'))
        self._tree._menu.add_command(label='Port scan this host',
                                     command=lambda: self._arp_ctx('PORT SCAN'))
        self._tree._menu.add_command(label='DNS lookup',
                                     command=lambda: self._arp_ctx('DNS'))
        self._tree._menu.add_command(label='WHOIS lookup',
                                     command=lambda: self._arp_ctx('WHOIS'))
        self._tree._menu.add_command(label='Wake-on-LAN →',
                                     command=self._arp_ctx_wol)

        self._load_interfaces()

    def _load_interfaces(self):
        self._iface_tree.clear()
        ifaces = get_local_interfaces()
        for iface in ifaces:
            self._iface_tree.tree.insert('', 'end',
                                         values=(iface['name'], iface['ip'], iface['netmask']))

    def _select_iface(self, event):
        sel = self._iface_tree.tree.selection()
        if sel:
            vals = self._iface_tree.tree.item(sel[0])['values']
            if vals:
                ip = str(vals[1])
                mask = str(vals[2])
                # Auto-compute network
                try:
                    import ipaddress
                    net = ipaddress.IPv4Network(f'{ip}/{mask}', strict=False)
                    self._net_entry.delete(0, 'end')
                    self._net_entry.insert(0, str(net))
                except:
                    pass

    def _arp_scan(self):
        network = self._net_entry.get().strip()
        self._tree.clear()
        self._status_var.set(f'ARP scanning {network}...')

        def run():
            arp_scan(network, callback=self._on_host)
            self._status_var.set('ARP scan complete')

        threading.Thread(target=run, daemon=True).start()

    def _ping_sweep(self):
        network = self._net_entry.get().strip()
        self._tree.clear()
        self._status_var.set(f'Ping sweep {network}...')

        def run():
            ping_sweep(network, callback=lambda ip: self._on_host_ip(ip))
            self._status_var.set('Ping sweep complete')

        threading.Thread(target=run, daemon=True).start()

    def _arp_cache(self):
        from core.engine import _arp_cache_parse
        self._tree.clear()
        self._status_var.set('Reading ARP cache...')
        entries = _arp_cache_parse(callback=self._on_host)
        self._status_var.set(f'ARP cache: {len(entries)} entries')

    def _on_host(self, entry):
        values = (entry.ip, entry.mac, entry.hostname, entry.interface)
        self._tree.tree.insert('', 'end', values=values, tags=('found',))

    def _on_host_ip(self, ip):
        from core.engine import ARPEntry
        self._on_host(ARPEntry(ip=ip, mac='(ping sweep)', hostname=''))

    def _arp_selected_ip(self):
        sel = self._tree.tree.selection()
        if sel:
            vals = self._tree.tree.item(sel[0])['values']
            if vals:
                return str(vals[0])
        return None

    def _arp_ctx(self, tab):
        ip = self._arp_selected_ip()
        if ip:
            app = _get_app()
            if app:
                app.navigate_to(tab, ip)

    def _arp_ctx_wol(self):
        """Pre-fill Wake-on-LAN panel with selected row's MAC."""
        sel = self._tree.tree.selection()
        if not sel:
            return
        vals = self._tree.tree.item(sel[0])['values']
        if vals and len(vals) >= 2:
            mac = str(vals[1])
            app = _get_app()
            if app:
                app.navigate_to('WOL', mac)


# ─────────────────────────────────────────────────────────────────
# 8. PACKET CAPTURE PANEL
# ─────────────────────────────────────────────────────────────────

class PacketCapturePanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._capture = None
        self._packet_count = 0
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        tk.Label(ctrl, text='Filter IP', **LABEL_OPTS).pack(side='left', padx=(6,4))
        self._filter_host = tk.Entry(ctrl, width=18, **ENTRY_OPTS)
        self._filter_host.pack(side='left', padx=2, ipady=3)

        tk.Label(ctrl, text='Filter Port', **LABEL_OPTS).pack(side='left', padx=(8,4))
        self._filter_port = tk.Entry(ctrl, width=7, **ENTRY_OPTS)
        self._filter_port.pack(side='left', padx=2, ipady=3)

        self._cap_btn = tk.Button(ctrl, text='▶  START CAPTURE',
                                  **BUTTON_GREEN_OPTS, command=self._toggle)
        self._cap_btn.pack(side='left', padx=8)

        clr_btn = tk.Button(ctrl, text='CLEAR', **BUTTON_OPTS, command=self._clear)
        clr_btn.pack(side='left', padx=4)

        self._count_var = tk.StringVar(value='0 packets')
        tk.Label(ctrl, textvariable=self._count_var,
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=8)

        notice = tk.Label(self,
                          text='⚠  Packet capture requires root/admin privileges. '
                               'Uses scapy if installed, otherwise raw sockets.',
                          bg=BG_PANEL, fg=ACCENT_YELLOW, font=FONT_LABEL)
        notice.pack(anchor='w', padx=12, pady=2)

        # Protocol filter buttons
        proto_frm = tk.Frame(self, bg=BG_PANEL)
        proto_frm.pack(fill='x', padx=8, pady=2)
        tk.Label(proto_frm, text='Filter Proto:', **LABEL_OPTS).pack(side='left', padx=4)
        self._proto_filter = tk.StringVar(value='ALL')
        for p in ['ALL', 'TCP', 'UDP', 'ICMP']:
            rb = tk.Radiobutton(proto_frm, text=p, variable=self._proto_filter, value=p,
                                bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                                activebackground=BG_PANEL, font=FONT_UI_SM)
            rb.pack(side='left', padx=4)

        # Capture table
        card = CardFrame(self, title='CAPTURED PACKETS')
        card.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('time','proto','src','sport','dst','dport','flags','length','info')
        hdrs = ('TIME','PROTO','SRC IP','S.PORT','DST IP','D.PORT','FLAGS','LEN','INFO')
        widths = (80, 55, 115, 55, 115, 55, 80, 50, 200)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        self._tree.tree.tag_configure('TCP',  foreground=ACCENT_CYAN)
        self._tree.tree.tag_configure('UDP',  foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('ICMP', foreground=ACCENT_YELLOW)
        self._tree.tree.tag_configure('OTHER',foreground=FG_DIM)
        self._tree.tree.tag_configure('RST',  foreground=ACCENT_RED)
        self._tree.tree.tag_configure('SYN',  foreground=ACCENT_PURPLE)

        self._capturing = False

    def _toggle(self):
        if not self._capturing:
            self._capturing = True
            self._cap_btn.configure(text='■  STOP CAPTURE', **BUTTON_RED_OPTS)
            filter_host = self._filter_host.get().strip()
            try:
                filter_port = int(self._filter_port.get())
            except:
                filter_port = 0
            self._capture = PacketCapture(
                filter_host=filter_host,
                filter_port=filter_port,
                callback=self._on_packet
            )
            self._capture.start()
        else:
            self._capturing = False
            self._cap_btn.configure(text='▶  START CAPTURE', **BUTTON_GREEN_OPTS)
            if self._capture:
                self._capture.stop()

    def _clear(self):
        self._tree.clear()
        self._packet_count = 0
        self._count_var.set('0 packets')

    def _on_packet(self, pkt):
        proto_filter = self._proto_filter.get()
        if proto_filter != 'ALL' and pkt.protocol != proto_filter:
            return

        self._packet_count += 1
        self._count_var.set(f'{self._packet_count} packets')

        ts = time.strftime('%H:%M:%S', time.localtime(pkt.timestamp))
        ms = int((pkt.timestamp % 1) * 1000)

        # Determine tag
        tag = pkt.protocol
        if 'RST' in pkt.flags:
            tag = 'RST'
        elif 'SYN' in pkt.flags and 'ACK' not in pkt.flags:
            tag = 'SYN'
        if tag not in ('TCP','UDP','ICMP','RST','SYN'):
            tag = 'OTHER'

        values = (
            f'{ts}.{ms:03d}',
            pkt.protocol,
            pkt.src_ip,
            str(pkt.src_port) if pkt.src_port else '',
            pkt.dst_ip,
            str(pkt.dst_port) if pkt.dst_port else '',
            pkt.flags,
            str(pkt.length),
            pkt.info[:80] if pkt.info else ''
        )
        self._tree.tree.insert('', 'end', values=values, tags=(tag,))
        # Auto-scroll (keep last 500)
        children = self._tree.tree.get_children()
        if len(children) > 500:
            self._tree.tree.delete(children[0])
        if children:
            self._tree.tree.see(children[-1])


# ─────────────────────────────────────────────────────────────────
# 9. EXTERNAL MONITOR PANEL (multi-target live dashboard)
# ─────────────────────────────────────────────────────────────────

class ExternalMonitorPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._monitor = ExternalMonitor(callback=self._on_event)
        self._update_job = None
        self._target_rows: dict = {}
        self._ext_asn_cache: dict = {}  # host -> asn string  # host -> dict of widget refs
        self._build()
        self._schedule_update()

    def _build(self):
        # Add target bar
        add_frm = CardFrame(self, title='ADD MONITOR TARGET')
        add_frm.pack(fill='x', padx=8, pady=(8, 4))

        row = tk.Frame(add_frm.body, bg=BG_CARD)
        row.pack(fill='x', padx=8, pady=6)

        tk.Label(row, text='Host/IP', bg=BG_CARD, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=4)
        self._new_host = tk.Entry(row, width=22, **ENTRY_OPTS)
        self._new_host.pack(side='left', padx=4, ipady=3)
        self._new_host.bind('<Return>', lambda e: self._add_target())

        tk.Label(row, text='Interval(s)', bg=BG_CARD, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=4)
        self._new_interval = tk.Entry(row, width=5, **ENTRY_OPTS)
        self._new_interval.insert(0, '5')
        self._new_interval.pack(side='left', padx=4, ipady=3)

        self._mtr_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row, text='Run MTR', variable=self._mtr_var,
                       bg=BG_CARD, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                       activebackground=BG_CARD, font=FONT_UI_SM).pack(side='left', padx=8)

        tk.Label(row, text='Alert loss%>', bg=BG_CARD, fg=FG_DIM,
                 font=FONT_LABEL).pack(side='left', padx=(8, 2))
        self._alert_loss_ext = tk.Entry(row, width=4, **ENTRY_OPTS)
        self._alert_loss_ext.insert(0, '10')
        self._alert_loss_ext.pack(side='left', padx=2, ipady=2)

        tk.Label(row, text='ms>', bg=BG_CARD, fg=FG_DIM,
                 font=FONT_LABEL).pack(side='left', padx=(6, 2))
        self._alert_lat_ext = tk.Entry(row, width=5, **ENTRY_OPTS)
        self._alert_lat_ext.insert(0, '200')
        self._alert_lat_ext.pack(side='left', padx=2, ipady=2)

        add_btn = tk.Button(row, text='＋ ADD TARGET', **BUTTON_GREEN_OPTS,
                            command=self._add_target)
        add_btn.pack(side='left', padx=4)

        # Quick-add presets
        quick_frm = tk.Frame(add_frm.body, bg=BG_CARD)
        quick_frm.pack(fill='x', padx=8, pady=(0, 6))
        tk.Label(quick_frm, text='Quick add:', bg=BG_CARD, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=4)
        for host in ['8.8.8.8', '1.1.1.1', '8.8.4.4', 'google.com']:
            btn = tk.Button(quick_frm, text=host, **BUTTON_OPTS,
                            command=lambda h=host: self._quick_add(h))
            btn.pack(side='left', padx=2)

        # Summary table
        summary_card = CardFrame(self, title='MONITOR DASHBOARD')
        summary_card.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('status','host','sent','loss','min','avg','max','last','trend','asn')
        hdrs = ('●','HOST','SENT','LOSS%','MIN ms','AVG ms','MAX ms','LAST ms','TREND','ASN / CARRIER')
        widths = (25,160,55,60,70,70,70,70,100,180)
        self._tree = DarkTreeview(summary_card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=(4,0))

        self._tree.tree.tag_configure('up',   foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('warn', foreground=ACCENT_YELLOW)
        self._tree.tree.tag_configure('down', foreground=ACCENT_RED)

        # Remove button
        btn_row = tk.Frame(summary_card.body, bg=BG_CARD)
        btn_row.pack(fill='x', padx=4, pady=4)
        tk.Button(btn_row, text='✕ REMOVE SELECTED', **BUTTON_RED_OPTS,
                  command=self._remove_selected).pack(side='left', padx=4)
        tk.Button(btn_row, text='STOP ALL', **BUTTON_OPTS,
                  command=self._stop_all).pack(side='left', padx=4)

        # MTR detail panel
        mtr_card = CardFrame(self, title='MTR HOP DETAIL — SELECT TARGET ABOVE')
        mtr_card.pack(fill='x', padx=8, pady=(0,8))
        cols2 = ('hop','ip','hostname','loss','sent','avg','best','worst')
        hdrs2 = ('HOP','IP','HOSTNAME','LOSS%','SENT','AVG ms','BEST','WORST')
        widths2 = (40,120,200,60,50,70,70,70)
        self._mtr_tree = DarkTreeview(mtr_card.body, cols2, hdrs2, widths2, height=6)
        self._mtr_tree.pack(fill='x', padx=4, pady=4)
        self._mtr_tree.tree.tag_configure('ok',  foreground=ACCENT_GREEN)
        self._mtr_tree.tree.tag_configure('warn',foreground=ACCENT_YELLOW)
        self._mtr_tree.tree.tag_configure('bad', foreground=ACCENT_RED)

        self._tree.tree.bind('<ButtonRelease-1>', self._on_select)

    def _add_target(self):
        host = self._new_host.get().strip()
        if not host:
            return
        try:
            interval = float(self._new_interval.get())
        except:
            interval = 5.0
        run_mtr = self._mtr_var.get()
        if self._monitor.add_target(host, interval=interval, run_mtr=run_mtr):
            self._new_host.delete(0, 'end')
        else:
            messagebox.showinfo('NetProbe', f'{host} is already being monitored')

    def _quick_add(self, host):
        self._new_host.delete(0, 'end')
        self._new_host.insert(0, host)
        self._add_target()

    def _remove_selected(self):
        sel = self._tree.tree.selection()
        for item in sel:
            vals = self._tree.tree.item(item)['values']
            if vals:
                host = str(vals[1])
                self._monitor.remove_target(host)

    def _stop_all(self):
        self._monitor.stop_all()
        self._tree.clear()

    def _on_select(self, event):
        sel = self._tree.tree.selection()
        if not sel:
            return
        vals = self._tree.tree.item(sel[0])['values']
        if not vals:
            return
        host = str(vals[1])
        stats = self._monitor.get_stats(host)
        self._update_mtr_tree(stats.get('mtr_rows', []))

    def _update_mtr_tree(self, rows):
        self._mtr_tree.clear()
        for row in rows:
            loss = row.get('loss_pct', 0)
            if loss >= 50: tag = 'bad'
            elif loss > 0 or row.get('avg_ms', 0) > 150: tag = 'warn'
            else: tag = 'ok'
            values = (row['hop'], row['ip'], row['hostname'][:30],
                      f'{loss:.1f}%', row.get('sent',0),
                      f'{row.get("avg_ms",0):.1f}',
                      f'{row.get("best_ms",0):.1f}',
                      f'{row.get("worst_ms",0):.1f}')
            self._mtr_tree.tree.insert('', 'end', values=values, tags=(tag,))

    def _on_event(self, event_type, host, data):
        pass  # updates handled by polling

    def _schedule_update(self):
        self._refresh_dashboard()
        self._update_job = self.after(1000, self._schedule_update)

    def _refresh_dashboard(self):
        targets = self._monitor.get_targets()
        self._tree.clear()

        # Kick off ASN lookups for any new targets
        for host in targets:
            if host not in self._ext_asn_cache:
                self._ext_asn_cache[host] = '…'
                def do_lookup(h=host):
                    try:
                        ip = __import__('socket').gethostbyname(h)
                    except:
                        ip = h
                    asn = asn_lookup(ip)
                    self._ext_asn_cache[h] = asn
                threading.Thread(target=do_lookup, daemon=True).start()

        for host in targets:
            stats = self._monitor.get_stats(host)
            if not stats:
                continue
            loss = stats['loss_pct']
            last = stats['last_ms']

            try:
                alert_loss = float(self._alert_loss_ext.get())
            except (ValueError, AttributeError):
                alert_loss = 10.0
            try:
                alert_lat = float(self._alert_lat_ext.get())
            except (ValueError, AttributeError):
                alert_lat = 200.0

            if last < 0:
                status = '●'
                tag = 'down'
            elif loss >= alert_loss or (last >= 0 and last > alert_lat):
                status = '◑'
                tag = 'warn'
            else:
                status = '●'
                tag = 'up'

            trend = self._make_trend(stats.get('last_results', []))
            asn = self._ext_asn_cache.get(host, '')

            values = (
                status, host,
                stats['sent'],
                f'{loss:.1f}%',
                f'{stats["min_ms"]:.1f}' if stats["min_ms"] else '—',
                f'{stats["avg_ms"]:.1f}' if stats["avg_ms"] else '—',
                f'{stats["max_ms"]:.1f}' if stats["max_ms"] else '—',
                f'{last:.1f}' if last >= 0 else 'T/O',
                trend, asn
            )
            self._tree.tree.insert('', 'end', values=values, tags=(tag,))

    def _make_trend(self, results):
        """Generate ASCII sparkline from last results"""
        if not results:
            return ''
        bars = ' ▁▂▃▄▅▆▇█'
        last10 = results[-10:]
        valid = [r[0] for r in last10 if r[0] >= 0]
        if not valid:
            return '✕ ✕ ✕'
        max_v = max(valid) or 1
        parts = []
        for rtt, _ in last10:
            if rtt < 0:
                parts.append('✕')
            else:
                idx = min(int((rtt / max_v) * 8), 8)
                parts.append(bars[idx])
        return ''.join(parts)



# ─────────────────────────────────────────────────────────────────
# 10. SSL / TLS INSPECTOR PANEL
# ─────────────────────────────────────────────────────────────────

class SSLPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        tk.Label(ctrl, text='Host', **LABEL_OPTS).pack(side='left', padx=(6, 4))
        self._host = tk.Entry(ctrl, width=30, **ENTRY_OPTS)
        self._host.insert(0, 'example.com')
        self._host.pack(side='left', padx=2, ipady=3)
        self._host.bind('<Return>', lambda e: self._inspect())

        tk.Label(ctrl, text='Port', **LABEL_OPTS).pack(side='left', padx=(8, 4))
        self._port = tk.Entry(ctrl, width=6, **ENTRY_OPTS)
        self._port.insert(0, '443')
        self._port.pack(side='left', padx=2, ipady=3)

        tk.Button(ctrl, text='INSPECT TLS', **BUTTON_GREEN_OPTS,
                  command=self._inspect).pack(side='left', padx=8)

        self._status_var = tk.StringVar(value='')
        self._status_lbl = tk.Label(ctrl, textvariable=self._status_var,
                                    bg=BG_PANEL, fg=FG_DIM, font=FONT_MONO_SM)
        self._status_lbl.pack(side='left', padx=4)

        cert_card = CardFrame(self, title='CERTIFICATE INFO')
        cert_card.pack(fill='x', padx=8, pady=4)
        grid = cert_card.body
        grid.configure(bg=BG_CARD)

        self._fields = {}
        rows = [
            ('Status',         'status'),
            ('Subject CN',     'subject_cn'),
            ('Subject',        'subject'),
            ('Issuer',         'issuer'),
            ('TLS Version',    'version'),
            ('Cipher Suite',   'cipher'),
            ('Valid From',     'not_before'),
            ('Valid To',       'not_after'),
            ('Days Remaining', 'days_remaining'),
        ]
        for i, (label, key) in enumerate(rows):
            tk.Label(grid, text=label + ':', bg=BG_CARD, fg=FG_DIM,
                     font=FONT_LABEL, anchor='e', width=14).grid(
                row=i, column=0, sticky='e', padx=(10, 4), pady=2)
            var = tk.StringVar(value='\u2014')
            lbl = tk.Label(grid, textvariable=var, bg=BG_CARD,
                           fg=FG_PRIMARY, font=FONT_MONO_SM, anchor='w')
            lbl.grid(row=i, column=1, sticky='w', padx=4, pady=2)
            self._fields[key] = (var, lbl)

        san_card = CardFrame(self, title='SUBJECT ALTERNATIVE NAMES (SAN)')
        san_card.pack(fill='x', padx=8, pady=(0, 4))
        self._san_text = ScrolledText(san_card.body, height=4, state='disabled')
        self._san_text.pack(fill='both', expand=True, padx=4, pady=4)
        self._san_text.configure_tags(
            ok=dict(foreground=ACCENT_GREEN),
            wild=dict(foreground=ACCENT_YELLOW),
            dim=dict(foreground=FG_DIM),
        )

        log_card = CardFrame(self, title='RAW DETAIL')
        log_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._log = ScrolledText(log_card.body, height=8, state='disabled')
        self._log.pack(fill='both', expand=True, padx=4, pady=4)
        self._log.configure_tags(
            ok=dict(foreground=ACCENT_GREEN),
            warn=dict(foreground=ACCENT_YELLOW),
            err=dict(foreground=ACCENT_RED),
            hdr=dict(foreground=ACCENT_CYAN),
            dim=dict(foreground=FG_DIM),
        )

    def _inspect(self):
        host = self._host.get().strip()
        if not host:
            return
        try:
            port = int(self._port.get())
        except ValueError:
            port = 443
        self._status_var.set('Connecting...')
        self._status_lbl.configure(fg=ACCENT_YELLOW)
        self._log.clear()
        self._san_text.clear()
        for key, (var, lbl) in self._fields.items():
            var.set('\u2014')
            lbl.configure(fg=FG_PRIMARY)
        self._log.append(f'; TLS Inspection: {host}:{port}\n', 'hdr')

        def run():
            info = ssl_inspect(host, port)
            self.after(0, self._show_result, info)

        threading.Thread(target=run, daemon=True).start()

    def _show_result(self, info):
        self._status_var.set('')

        def sf(key, value, color=FG_PRIMARY):
            var, lbl = self._fields[key]
            var.set(str(value) if value else '\u2014')
            lbl.configure(fg=color)

        if info.error and not info.subject_cn:
            sf('status', f'ERROR: {info.error}', ACCENT_RED)
            self._status_var.set('ERROR')
            self._status_lbl.configure(fg=ACCENT_RED)
        elif info.expired:
            sf('status', 'EXPIRED', ACCENT_RED)
            self._status_var.set('EXPIRED')
            self._status_lbl.configure(fg=ACCENT_RED)
        elif info.days_remaining < 30 and info.not_after:
            sf('status', f'EXPIRING SOON \u2014 {info.days_remaining} days', ACCENT_YELLOW)
            self._status_var.set(f'EXPIRING SOON ({info.days_remaining}d)')
            self._status_lbl.configure(fg=ACCENT_YELLOW)
        elif info.verified:
            sf('status', f'VALID \u2713  ({info.days_remaining} days remaining)', ACCENT_GREEN)
            self._status_var.set(f'VALID \u2713  {info.days_remaining}d')
            self._status_lbl.configure(fg=ACCENT_GREEN)
        else:
            sf('status', f'UNVERIFIED  {info.error}', ACCENT_YELLOW)
            self._status_var.set('UNVERIFIED')
            self._status_lbl.configure(fg=ACCENT_YELLOW)

        sf('subject_cn', info.subject_cn)
        sf('subject',    info.subject)
        sf('issuer',     info.issuer)
        sf('version',    info.version,
           ACCENT_GREEN if info.version in ('TLSv1.3', 'TLSv1.2') else ACCENT_YELLOW)
        sf('cipher',     info.cipher)
        sf('not_before', info.not_before)
        sf('not_after',  info.not_after)
        days = info.days_remaining
        days_col = ACCENT_GREEN if days > 30 else (ACCENT_YELLOW if days > 0 else ACCENT_RED)
        sf('days_remaining', str(days) if info.not_after else '\u2014', days_col)

        if info.san:
            for name in info.san:
                tag = 'wild' if name.startswith('*') else 'ok'
                self._san_text.append(name + '\n', tag)
        else:
            self._san_text.append('(none)\n', 'dim')

        self._log.append(f'Host     : {info.host}:{info.port}\n', 'hdr')
        self._log.append(f'TLS      : {info.version}\n',
                         'ok' if info.version else 'dim')
        self._log.append(f'Cipher   : {info.cipher}\n', 'dim')
        self._log.append(f'CN       : {info.subject_cn}\n', 'ok')
        self._log.append(f'Subject  : {info.subject}\n', 'dim')
        self._log.append(f'Issuer   : {info.issuer}\n', 'dim')
        self._log.append(f'Valid    : {info.not_before}  \u2192  {info.not_after}\n', 'dim')
        if info.san:
            self._log.append(f'SANs     : {", ".join(info.san[:8])}\n', 'dim')
        if info.error:
            self._log.append(f'Error    : {info.error}\n', 'err')


# ─────────────────────────────────────────────────────────────────
# 11. HTTP PROBE PANEL
# ─────────────────────────────────────────────────────────────────

class HTTPProbePanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        tk.Label(ctrl, text='URL', **LABEL_OPTS).pack(side='left', padx=(6, 4))
        self._url = tk.Entry(ctrl, width=44, **ENTRY_OPTS)
        self._url.insert(0, 'https://example.com')
        self._url.pack(side='left', padx=2, ipady=3)
        self._url.bind('<Return>', lambda e: self._probe())

        self._method = tk.StringVar(value='GET')
        for m in ['GET', 'HEAD']:
            tk.Radiobutton(ctrl, text=m, variable=self._method, value=m,
                           bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                           activebackground=BG_PANEL, font=FONT_UI_SM).pack(side='left', padx=3)

        self._follow_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl, text='Follow redirects', variable=self._follow_var,
                       bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                       activebackground=BG_PANEL, font=FONT_UI_SM).pack(side='left', padx=6)

        tk.Button(ctrl, text='PROBE', **BUTTON_GREEN_OPTS,
                  command=self._probe).pack(side='left', padx=8)

        self._status_var = tk.StringVar(value='')
        self._status_lbl = tk.Label(ctrl, textvariable=self._status_var,
                                    bg=BG_PANEL, fg=FG_DIM, font=FONT_MONO_SM)
        self._status_lbl.pack(side='left', padx=4)

        stat_row = tk.Frame(self, bg=BG_PANEL, pady=4)
        stat_row.pack(fill='x', padx=8)
        self._stat_vars = {}
        for key, label in [('code', 'STATUS'), ('ttfb', 'TTFB ms'),
                            ('total', 'TOTAL ms'), ('server', 'SERVER'),
                            ('type', 'CONTENT TYPE'), ('size', 'SIZE')]:
            frm = tk.Frame(stat_row, bg=BG_CARD,
                           highlightthickness=1, highlightbackground=BORDER_DIM,
                           padx=10, pady=6)
            frm.pack(side='left', padx=2)
            tk.Label(frm, text=label, bg=BG_CARD, fg=FG_DIM,
                     font=(_MONO, 7, 'bold')).pack()
            var = tk.StringVar(value='\u2014')
            self._stat_vars[key] = var
            tk.Label(frm, textvariable=var, bg=BG_CARD,
                     fg=ACCENT_CYAN, font=FONT_MONO_SM).pack()

        redir_card = CardFrame(self, title='REDIRECT CHAIN')
        redir_card.pack(fill='x', padx=8, pady=4)
        self._redir_log = ScrolledText(redir_card.body, height=3, state='disabled')
        self._redir_log.pack(fill='both', expand=True, padx=4, pady=4)
        self._redir_log.configure_tags(
            hdr=dict(foreground=ACCENT_CYAN),
            ok=dict(foreground=ACCENT_GREEN),
            dim=dict(foreground=FG_DIM),
            err=dict(foreground=ACCENT_RED),
        )

        hdr_card = CardFrame(self, title='RESPONSE HEADERS')
        hdr_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._hdr_tree = DarkTreeview(hdr_card.body,
                                      ('name', 'value'),
                                      ('HEADER', 'VALUE'),
                                      (220, 520))
        self._hdr_tree.pack(fill='both', expand=True, padx=4, pady=4)

    def _probe(self):
        url = self._url.get().strip()
        if not url:
            return
        self._status_var.set('Probing...')
        self._status_lbl.configure(fg=ACCENT_YELLOW)
        self._redir_log.clear()
        self._hdr_tree.clear()
        for var in self._stat_vars.values():
            var.set('\u2014')

        def run():
            result = http_probe(url, method=self._method.get(),
                                follow_redirects=self._follow_var.get())
            self.after(0, self._show_result, result)

        threading.Thread(target=run, daemon=True).start()

    def _show_result(self, r):
        if r.error:
            self._status_var.set(f'Error: {r.error}')
            self._status_lbl.configure(fg=ACCENT_RED)
            return
        code = r.status_code
        code_color = (ACCENT_GREEN if 200 <= code < 300
                      else ACCENT_YELLOW if 300 <= code < 400
                      else ACCENT_RED)
        self._stat_vars['code'].set(f'{code} {r.status_text}')
        self._stat_vars['ttfb'].set(f'{r.ttfb_ms:.0f}')
        self._stat_vars['total'].set(f'{r.total_ms:.0f}')
        self._stat_vars['server'].set(r.server or '\u2014')
        self._stat_vars['type'].set(
            r.content_type.split(';')[0] if r.content_type else '\u2014')
        self._stat_vars['size'].set(
            f'{r.content_length/1024:.1f} KB' if r.content_length else '\u2014')
        self._status_var.set(f'{code} {r.status_text}  \u00b7  {r.total_ms:.0f} ms')
        self._status_lbl.configure(fg=code_color)

        if r.redirect_chain:
            self._redir_log.append(f'{r.url}\n', 'hdr')
            for step in r.redirect_chain:
                self._redir_log.append(f'  \u2192 {step}\n', 'ok')
            self._redir_log.append(f'  \u2192 {r.final_url}  [{code}]\n', 'ok')
        else:
            self._redir_log.append(
                f'{r.url}  \u2192  {r.final_url}  [{code}]\n', 'dim')

        for name, val in sorted(r.headers.items()):
            self._hdr_tree.tree.insert('', 'end', values=(name, str(val)[:200]))


# ─────────────────────────────────────────────────────────────────
# 12. WHOIS PANEL
# ─────────────────────────────────────────────────────────────────

class WHOISPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._build()

    def _build(self):
        ctrl = tk.Frame(self, bg=BG_PANEL, pady=6)
        ctrl.pack(fill='x', padx=8)

        tk.Label(ctrl, text='Domain / IP', **LABEL_OPTS).pack(side='left', padx=(6, 4))
        self._entry = tk.Entry(ctrl, width=30, **ENTRY_OPTS)
        self._entry.insert(0, 'example.com')
        self._entry.pack(side='left', padx=2, ipady=3)
        self._entry.bind('<Return>', lambda e: self._lookup())

        tk.Button(ctrl, text='WHOIS', **BUTTON_GREEN_OPTS,
                  command=self._lookup).pack(side='left', padx=8)

        self._status_var = tk.StringVar(value='')
        tk.Label(ctrl, textvariable=self._status_var,
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL).pack(side='left', padx=4)

        quick_frm = tk.Frame(self, bg=BG_PANEL)
        quick_frm.pack(fill='x', padx=8, pady=2)
        tk.Label(quick_frm, text='Quick:', **LABEL_OPTS).pack(side='left', padx=4)
        for target in ['8.8.8.8', '1.1.1.1', 'google.com', 'cloudflare.com', 'github.com']:
            tk.Button(quick_frm, text=target, **BUTTON_OPTS,
                      command=lambda t=target: (
                          self._entry.delete(0, 'end'),
                          self._entry.insert(0, t),
                          self._lookup()
                      )).pack(side='left', padx=2)

        out_card = CardFrame(self, title='WHOIS OUTPUT')
        out_card.pack(fill='both', expand=True, padx=8, pady=4)
        self._out = ScrolledText(out_card.body, height=30, state='disabled')
        self._out.pack(fill='both', expand=True, padx=4, pady=4)
        self._out.configure_tags(
            hdr=dict(foreground=ACCENT_CYAN, font=(_MONO, 9, 'bold')),
            key=dict(foreground=ACCENT_GREEN),
            val=dict(foreground=FG_PRIMARY),
            dim=dict(foreground=FG_DIM),
            err=dict(foreground=ACCENT_RED),
        )

    def _lookup(self):
        target = self._entry.get().strip()
        if not target:
            return
        self._status_var.set('Querying...')
        self._out.clear()
        self._out.append(
            f'; WHOIS: {target}  [{time.strftime("%H:%M:%S")}]\n', 'hdr')

        def run():
            text = whois_lookup(target)
            self.after(0, self._show, text)

        threading.Thread(target=run, daemon=True).start()

    def _show(self, text: str):
        self._status_var.set('')
        for line in text.split('\n'):
            stripped = line.strip()
            if (stripped.startswith(';') or stripped.startswith('%')
                    or stripped.startswith('>>>')):
                self._out.append(line + '\n', 'dim')
            elif (':' in line and not line.startswith(' ')
                  and not line.startswith('\t')):
                key, _, val = line.partition(':')
                self._out.append(key + ':', 'key')
                self._out.append(val + '\n', 'val')
            else:
                self._out.append(line + '\n', 'val')


# ─────────────────────────────────────────────────────────────────
# 13. WAKE-ON-LAN PANEL
# ─────────────────────────────────────────────────────────────────

class WakeOnLANPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._saved: list = []
        self._build()

    def _build(self):
        send_card = CardFrame(self, title='SEND MAGIC PACKET')
        send_card.pack(fill='x', padx=8, pady=8)
        grid = send_card.body
        grid.configure(bg=BG_CARD)

        fields = [
            ('MAC Address',  '_mac',       'AA:BB:CC:DD:EE:FF', 22),
            ('Broadcast IP', '_broadcast', '255.255.255.255',    18),
            ('UDP Port',     '_wol_port',  '9',                   8),
        ]
        for row_i, (label, attr, default, width) in enumerate(fields):
            tk.Label(grid, text=label + ':', bg=BG_CARD, fg=FG_DIM,
                     font=FONT_LABEL, anchor='e', width=14).grid(
                row=row_i, column=0, sticky='e', padx=(10, 4), pady=6)
            entry = tk.Entry(grid, width=width, **ENTRY_OPTS)
            entry.insert(0, default)
            entry.grid(row=row_i, column=1, sticky='w', padx=4, pady=6, ipady=3)
            setattr(self, attr, entry)

        btn_frm = tk.Frame(grid, bg=BG_CARD)
        btn_frm.grid(row=3, column=1, sticky='w', padx=4, pady=10)
        tk.Button(btn_frm, text='SEND MAGIC PACKET', **BUTTON_GREEN_OPTS,
                  command=self._send).pack(side='left', padx=4)
        tk.Button(btn_frm, text='SAVE TARGET', **BUTTON_OPTS,
                  command=self._save_target).pack(side='left', padx=4)

        tk.Label(self,
                 text=('WoL sends a UDP broadcast magic packet (6\u00d7FF + MAC\u00d716). '
                       'Target must have WoL enabled in BIOS/UEFI and NIC settings.'),
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL,
                 justify='left').pack(anchor='w', padx=12, pady=(0, 4))

        saved_card = CardFrame(self, title='SAVED TARGETS')
        saved_card.pack(fill='x', padx=8, pady=4)
        lbf = tk.Frame(saved_card.body, bg=BG_CARD)
        lbf.pack(fill='x', padx=4, pady=4)
        self._saved_lb = tk.Listbox(lbf, **LISTBOX_OPTS, height=5)
        self._saved_lb.pack(side='left', fill='both', expand=True)
        self._saved_lb.bind('<Double-Button-1>', self._load_saved)
        bc = tk.Frame(lbf, bg=BG_CARD)
        bc.pack(side='left', padx=4, fill='y')
        tk.Button(bc, text='LOAD',   **BUTTON_OPTS,
                  command=self._load_saved).pack(pady=2)
        tk.Button(bc, text='DELETE', **BUTTON_RED_OPTS,
                  command=self._delete_saved).pack(pady=2)

        log_card = CardFrame(self, title='LOG')
        log_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._log = ScrolledText(log_card.body, height=8, state='disabled')
        self._log.pack(fill='both', expand=True, padx=4, pady=4)
        self._log.configure_tags(
            ok=dict(foreground=ACCENT_GREEN),
            err=dict(foreground=ACCENT_RED),
            info=dict(foreground=ACCENT_CYAN),
            dim=dict(foreground=FG_DIM),
        )

    def _send(self):
        mac = self._mac.get().strip()
        broadcast = self._broadcast.get().strip() or '255.255.255.255'
        try:
            port = int(self._wol_port.get())
        except ValueError:
            port = 9
        ts = time.strftime('%H:%M:%S')
        try:
            wake_on_lan(mac, broadcast, port)
            self._log.append(
                f'[{ts}]  Magic packet sent  \u2192  {mac}  via {broadcast}:{port}\n', 'ok')
        except Exception as e:
            self._log.append(f'[{ts}]  Error: {e}\n', 'err')

    def _save_target(self):
        mac  = self._mac.get().strip()
        bc   = self._broadcast.get().strip()
        port = self._wol_port.get().strip()
        if mac:
            label = f'{mac}  |  {bc}:{port}'
            self._saved.append((label, mac, bc, port))
            self._saved_lb.insert('end', label)

    def _load_saved(self, event=None):
        sel = self._saved_lb.curselection()
        if sel:
            idx = sel[0]
            if idx < len(self._saved):
                _, mac, bc, port = self._saved[idx]
                for entry, val in [(self._mac, mac),
                                   (self._broadcast, bc),
                                   (self._wol_port, port)]:
                    entry.delete(0, 'end')
                    entry.insert(0, val)

    def _delete_saved(self):
        sel = self._saved_lb.curselection()
        if sel:
            idx = sel[0]
            self._saved_lb.delete(idx)
            if idx < len(self._saved):
                self._saved.pop(idx)

    def prefill_mac(self, mac: str):
        """Called via cross-tab navigation from ARP panel."""
        self._mac.delete(0, 'end')
        self._mac.insert(0, mac)



# ─────────────────────────────────────────────────────────────────
# 14. NETSTAT PANEL
# ─────────────────────────────────────────────────────────────────

class NetstatPanel(tk.Frame):
    _PROTOS = ['All', 'TCP', 'UDP', 'TCP6', 'UDP6']
    _STATES = ['All', 'LISTEN', 'ESTABLISHED', 'TIME_WAIT',
               'CLOSE_WAIT', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1',
               'FIN_WAIT2', 'CLOSING', 'CLOSED', 'NONE']
    _REFRESH_OPTS = {'Off': 0, '2 s': 2000, '5 s': 5000, '10 s': 10000}

    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._all_rows = []          # List[NetstatEntry]
        self._after_id = None
        self._refresh_ms = 0
        self._build()

    def _build(self):
        from core import netstat_snapshot as _ns

        # ── Filter bar ──────────────────────────────────────────────
        fbar = tk.Frame(self, bg=BG_PANEL)
        fbar.pack(fill='x', padx=10, pady=(8, 4))

        tk.Label(fbar, text='Proto:', **LABEL_OPTS).pack(side='left')
        self._proto_var = tk.StringVar(value='All')
        proto_cb = ttk.Combobox(fbar, textvariable=self._proto_var,
                                values=self._PROTOS, width=7, state='readonly')
        proto_cb.pack(side='left', padx=(2, 10))
        proto_cb.bind('<<ComboboxSelected>>', lambda e: self._apply_filter())

        tk.Label(fbar, text='State:', **LABEL_OPTS).pack(side='left')
        self._state_var = tk.StringVar(value='All')
        state_cb = ttk.Combobox(fbar, textvariable=self._state_var,
                                values=self._STATES, width=13, state='readonly')
        state_cb.pack(side='left', padx=(2, 10))
        state_cb.bind('<<ComboboxSelected>>', lambda e: self._apply_filter())

        tk.Label(fbar, text='Port:', **LABEL_OPTS).pack(side='left')
        self._port_var = tk.StringVar()
        port_e = tk.Entry(fbar, textvariable=self._port_var, width=7, **ENTRY_OPTS)
        port_e.pack(side='left', padx=(2, 10))
        self._port_var.trace_add('write', lambda *_: self._apply_filter())

        tk.Label(fbar, text='Process:', **LABEL_OPTS).pack(side='left')
        self._proc_var = tk.StringVar()
        proc_e = tk.Entry(fbar, textvariable=self._proc_var, width=12, **ENTRY_OPTS)
        proc_e.pack(side='left', padx=(2, 10))
        self._proc_var.trace_add('write', lambda *_: self._apply_filter())

        # Refresh controls
        tk.Frame(fbar, bg=BORDER_DIM, width=1).pack(
            side='left', fill='y', pady=2, padx=8)

        tk.Button(fbar, text='REFRESH', command=self._do_refresh,
                  **BUTTON_OPTS).pack(side='left', padx=4)

        tk.Label(fbar, text='Auto:', **LABEL_OPTS).pack(side='left', padx=(8, 2))
        self._auto_var = tk.StringVar(value='Off')
        auto_cb = ttk.Combobox(fbar, textvariable=self._auto_var,
                               values=list(self._REFRESH_OPTS.keys()),
                               width=6, state='readonly')
        auto_cb.pack(side='left')
        auto_cb.bind('<<ComboboxSelected>>', lambda e: self._set_auto())

        # ── Tree ────────────────────────────────────────────────────
        cols   = ('proto', 'local', 'remote', 'state', 'pid', 'process')
        hdrs   = ('PROTO', 'LOCAL', 'REMOTE', 'STATE', 'PID', 'PROCESS')
        widths = (60, 200, 200, 120, 60, 140)
        self._tree = DarkTreeview(self, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=10, pady=(0, 4))

        # State colour tags
        tv = self._tree.tree
        tv.tag_configure('LISTEN',      foreground=ACCENT_GREEN)
        tv.tag_configure('ESTABLISHED', foreground=ACCENT_CYAN)
        tv.tag_configure('TIME_WAIT',   foreground=ACCENT_YELLOW)
        tv.tag_configure('CLOSE_WAIT',  foreground=ACCENT_ORANGE)
        tv.tag_configure('closed',      foreground=FG_DIM)

        # Right-click context menu
        self._tree._menu.add_separator()
        self._tree._menu.add_command(label='Ping this host',
                                     command=self._ctx_ping)
        self._tree._menu.add_command(label='Port scan this host',
                                     command=self._ctx_portscan)
        self._tree._menu.add_command(label='WHOIS this host',
                                     command=self._ctx_whois)

        # ── Status line ─────────────────────────────────────────────
        self._status_var = tk.StringVar(value='Press REFRESH to load connections')
        tk.Label(self, textvariable=self._status_var,
                 bg=BG_PANEL, fg=FG_DIM,
                 font=FONT_LABEL, anchor='w').pack(
                     fill='x', padx=12, pady=(0, 6))

        # Initial load
        self.after(200, self._do_refresh)

    # ── Data ────────────────────────────────────────────────────────

    def _do_refresh(self):
        from core import netstat_snapshot
        from .widgets import run_in_thread
        self._status_var.set('Scanning…')

        def _fetch():
            return netstat_snapshot()

        def _done(rows):
            if rows is None:
                rows = []
            self._all_rows = rows
            self._apply_filter()

        run_in_thread(_fetch, callback=lambda r: self.after(0, _done, r))

    def _apply_filter(self):
        proto_f = self._proto_var.get()
        state_f = self._state_var.get()
        port_f  = self._port_var.get().strip()
        proc_f  = self._proc_var.get().strip().lower()

        self._tree.clear()
        counts = {}
        shown = 0

        for e in self._all_rows:
            if proto_f != 'All' and e.proto != proto_f:
                continue
            state_norm = (e.state or '').upper().replace('_WAIT', '_WAIT')
            if state_f != 'All' and state_norm != state_f:
                continue
            if port_f:
                if (str(e.local_port) != port_f and
                        str(e.remote_port) != port_f):
                    continue
            if proc_f and proc_f not in e.process.lower():
                continue

            local  = f'{e.local_addr}:{e.local_port}'  if e.local_addr  else '-'
            remote = f'{e.remote_addr}:{e.remote_port}' if e.remote_addr else '-'
            state_disp = state_norm or '-'

            tag = state_norm if state_norm in (
                'LISTEN', 'ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT') else ''

            self._tree.insert(
                (e.proto, local, remote, state_disp,
                 str(e.pid) if e.pid else '-', e.process),
                tags=(tag,) if tag else ())
            counts[state_norm] = counts.get(state_norm, 0) + 1
            shown += 1

        total = len(self._all_rows)
        summary = ', '.join(f'{s}: {n}' for s, n in
                            sorted(counts.items(), key=lambda x: -x[1])[:4])
        self._status_var.set(
            f'{shown} / {total} connections   [{summary}]')

    # ── Auto-refresh ─────────────────────────────────────────────

    def _set_auto(self):
        if self._after_id:
            self.after_cancel(self._after_id)
            self._after_id = None
        ms = self._REFRESH_OPTS.get(self._auto_var.get(), 0)
        self._refresh_ms = ms
        if ms:
            self._schedule_auto()

    def _schedule_auto(self):
        if self._refresh_ms:
            self._after_id = self.after(self._refresh_ms, self._auto_tick)

    def _auto_tick(self):
        self._do_refresh()
        self._schedule_auto()

    # ── Context menu ─────────────────────────────────────────────

    def _selected_remote_ip(self):
        sel = self._tree.tree.selection()
        if not sel:
            return None
        vals = self._tree.tree.item(sel[0])['values']
        remote = str(vals[2]) if len(vals) > 2 else ''
        if ':' in remote and remote != '-':
            return remote.rsplit(':', 1)[0]
        return None

    def _ctx_ping(self):
        ip = self._selected_remote_ip()
        if ip:
            app = _get_app()
            if app:
                app.navigate_to('PING', prefill=ip)

    def _ctx_portscan(self):
        ip = self._selected_remote_ip()
        if ip:
            app = _get_app()
            if app:
                app.navigate_to('PORT SCAN', prefill=ip)

    def _ctx_whois(self):
        ip = self._selected_remote_ip()
        if ip:
            app = _get_app()
            if app:
                app.navigate_to('WHOIS', prefill=ip)


# ─────────────────────────────────────────────────────────────────
# 15. GLOBAL PING / TRACE PANEL
# Fan-out ping/traceroute from local + optional remote NetProbe nodes.
# Nodes configured in nodes.json beside the .exe (or project root).
# ─────────────────────────────────────────────────────────────────

import sys as _sys
import os as _os
import queue as _queue
import json as _json
import urllib.request as _urllib_req
import urllib.parse   as _urllib_parse

# Locate nodes.json
if getattr(_sys, 'frozen', False):
    _GP_BASE = _os.path.dirname(_sys.executable)
else:
    _GP_BASE = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_NODES_FILE = _os.path.join(_GP_BASE, 'nodes.json')

_LOCAL_NODE = {
    'id': 'local', 'name': 'Local', 'city': '', 'country': '--',
    'flag': '⬡', 'url': 'self', 'key': '',
}

# Dot colour mapping (matches server's globalping.js)
_DOT_COLORS = {
    'ok':      '#00cc66',
    'warn':    '#f0c040',
    'orange':  '#ff8800',
    'bad':     '#ff4444',
    'timeout': '#1e2a35',
}

def _rtt_dot_color(ms: float) -> str:
    if ms < 0:    return _DOT_COLORS['timeout']
    if ms < 50:   return _DOT_COLORS['ok']
    if ms < 150:  return _DOT_COLORS['warn']
    if ms < 300:  return _DOT_COLORS['orange']
    return _DOT_COLORS['bad']


class _NodeRow(tk.Frame):
    """One row in the ping grid: flag | name/city | status | avg | loss | last | dots-canvas."""

    MAX_DOTS = 60

    def __init__(self, parent, node: dict):
        super().__init__(parent, bg=BG_CARD)
        self._node  = node
        self._dots  = []   # list of rtt_ms values
        self._sent  = 0
        self._recv  = 0
        self._rtts  = []   # rolling avg buffer

        # ── columns ──────────────────────────────────────────────
        # Flag
        tk.Label(self, text=node.get('flag', '◈'), bg=BG_CARD,
                 fg=ACCENT_CYAN, font=(_MONO, 11), width=2,
                 anchor='center').pack(side='left', padx=(6, 2))

        # Name / city
        name_col = tk.Frame(self, bg=BG_CARD, width=160)
        name_col.pack(side='left', padx=(0, 8))
        name_col.pack_propagate(False)
        tk.Label(name_col, text=node['name'], bg=BG_CARD,
                 fg=FG_PRIMARY, font=FONT_MONO_SM,
                 anchor='w').pack(fill='x')
        if node.get('city'):
            tk.Label(name_col, text=node['city'], bg=BG_CARD,
                     fg=FG_DIM, font=FONT_TINY,
                     anchor='w').pack(fill='x')

        # Status dot
        self._status_lbl = tk.Label(self, text='◌', bg=BG_CARD,
                                    fg=FG_DIM, font=(_MONO, 11), width=2)
        self._status_lbl.pack(side='left', padx=4)

        # Stats labels
        def _stat(width=70):
            lbl = tk.Label(self, text='—', bg=BG_CARD, fg=FG_DIM,
                           font=FONT_MONO_SM, width=width//7, anchor='e')
            lbl.pack(side='left', padx=2)
            return lbl

        self._avg_lbl  = _stat()
        self._loss_lbl = _stat(50)
        self._last_lbl = _stat()

        # Dots canvas (fills remaining)
        self._cv = tk.Canvas(self, bg=BG_CARD, height=22,
                             highlightthickness=0, bd=0)
        self._cv.pack(side='left', fill='x', expand=True, padx=(4, 6))
        self._cv.bind('<Configure>', lambda e: self._redraw_dots())

    def update_ping(self, rtt_ms: float):
        self._sent += 1
        if rtt_ms >= 0:
            self._recv += 1
            self._rtts.append(rtt_ms)
        self._dots.append(rtt_ms)
        if len(self._dots) > self.MAX_DOTS:
            self._dots = self._dots[-self.MAX_DOTS:]

        timeout = rtt_ms < 0
        if timeout:
            self._status_lbl.configure(text='○', fg=FG_DIM)
        else:
            self._status_lbl.configure(text='●', fg=_rtt_dot_color(rtt_ms))

        loss = (self._sent - self._recv) / self._sent * 100 if self._sent else 0
        avg  = sum(self._rtts) / len(self._rtts) if self._rtts else -1

        last_col = _rtt_dot_color(rtt_ms)
        avg_col  = _rtt_dot_color(avg)
        loss_col = (ACCENT_RED if loss >= 20 else
                    ACCENT_YELLOW if loss > 0 else ACCENT_GREEN)

        self._avg_lbl.configure(
            text=f'{avg:.1f}ms' if avg >= 0 else '—', fg=avg_col)
        self._loss_lbl.configure(
            text=f'{loss:.0f}%', fg=loss_col)
        self._last_lbl.configure(
            text=f'{rtt_ms:.1f}ms' if not timeout else 'T/O',
            fg=last_col if not timeout else FG_DIM)
        self._redraw_dots()

    def reset(self):
        self._dots = []
        self._sent = 0
        self._recv = 0
        self._rtts = []
        self._status_lbl.configure(text='◌', fg=FG_DIM)
        self._avg_lbl.configure(text='—', fg=FG_DIM)
        self._loss_lbl.configure(text='—', fg=FG_DIM)
        self._last_lbl.configure(text='—', fg=FG_DIM)
        self._cv.delete('all')

    def _redraw_dots(self):
        cv = self._cv
        cv.delete('all')
        W = cv.winfo_width()
        H = cv.winfo_height()
        if W < 4 or H < 4 or not self._dots:
            return
        dot_w  = 9
        gap    = 2
        stride = dot_w + gap
        n_show = min(len(self._dots), W // stride)
        dots   = self._dots[-n_show:]
        x      = W - n_show * stride
        for rtt in dots:
            col = _rtt_dot_color(rtt)
            cv.create_rectangle(x, 2, x + dot_w, H - 2, fill=col, outline='')
            x += stride


class GlobalPingPanel(tk.Frame):
    """Multi-node ping / traceroute fan-out — local always present, extras from nodes.json."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG_PANEL)
        self._nodes      = []
        self._node_rows  = {}   # node_id -> _NodeRow
        self._stop_event = threading.Event()
        self._q          = _queue.Queue()
        self._poll_job   = None
        self._mode       = 'ping'
        self._running    = False

        self._build()
        self._load_nodes()

    # ── Build ─────────────────────────────────────────────────────

    def _build(self):
        # Control bar
        ctrl = CardFrame(self, title='GLOBAL PING / TRACE')
        ctrl.pack(fill='x', padx=8, pady=(8, 4))

        row1 = tk.Frame(ctrl.body, bg=BG_CARD)
        row1.pack(fill='x', padx=8, pady=6)

        tk.Label(row1, text='Target', bg=BG_CARD, fg=FG_DIM,
                 font=FONT_LABEL).pack(side='left', padx=(0, 4))
        self._host_var = tk.StringVar()
        self._host_entry = tk.Entry(row1, textvariable=self._host_var,
                                    width=30, **ENTRY_OPTS)
        self._host_entry.pack(side='left', padx=2, ipady=3)
        self._host_entry.bind('<Return>', lambda e: self._toggle_ping())

        tk.Label(row1, text='Every', bg=BG_CARD, fg=FG_DIM,
                 font=FONT_LABEL).pack(side='left', padx=(10, 4))
        self._ivl_var = tk.StringVar(value='2')
        ivl_cb = ttk.Combobox(row1, textvariable=self._ivl_var,
                               values=['1', '2', '5', '10', '30'],
                               width=4, state='readonly',
                               style='Dark.TCombobox')
        ivl_cb.pack(side='left', padx=2)
        tk.Label(row1, text='s', bg=BG_CARD, fg=FG_DIM,
                 font=FONT_LABEL).pack(side='left', padx=(0, 8))

        self._ping_btn = tk.Button(row1, text='▶  Ping All',
                                   **BUTTON_GREEN_OPTS,
                                   command=self._toggle_ping)
        self._ping_btn.pack(side='left', padx=4)

        self._trace_btn = tk.Button(row1, text='⇢  Trace All',
                                    **BUTTON_OPTS,
                                    command=self._start_trace)
        self._trace_btn.pack(side='left', padx=4)

        # Node info row
        row2 = tk.Frame(ctrl.body, bg=BG_CARD)
        row2.pack(fill='x', padx=8, pady=(0, 6))
        self._node_info_lbl = tk.Label(row2, text='', bg=BG_CARD,
                                        fg=FG_DIM, font=FONT_LABEL)
        self._node_info_lbl.pack(side='left')
        tk.Button(row2, text='⟳ Reload nodes.json', **BUTTON_OPTS,
                  command=self._load_nodes).pack(side='left', padx=8)
        tk.Label(row2,
                 text='Add nodes.json beside the .exe for remote locations',
                 bg=BG_CARD, fg=FG_DIM, font=FONT_TINY).pack(side='left')

        # Ping grid card
        self._grid_card = CardFrame(self, title='PING GRID')
        self._grid_card.pack(fill='both', expand=True, padx=8, pady=4)

        # Column headers
        hdr = tk.Frame(self._grid_card.body, bg=BG_INPUT)
        hdr.pack(fill='x', padx=0, pady=0)

        def _hdr(text, width=None, anchor='e'):
            kw = dict(bg=BG_INPUT, fg=ACCENT_CYAN,
                      font=FONT_TINY_BOLD, anchor=anchor, pady=3)
            if width:
                kw['width'] = width
            lbl = tk.Label(hdr, text=text, **kw)
            lbl.pack(side='left', padx=2)

        _hdr('', width=2)           # flag
        _hdr('NODE', width=23, anchor='w')
        _hdr('', width=2)           # status
        _hdr('AVG', width=8)
        _hdr('LOSS', width=6)
        _hdr('LAST', width=8)
        _hdr('HISTORY', anchor='w')

        tk.Frame(self._grid_card.body, bg=BORDER_DIM, height=1).pack(fill='x')

        # Scrollable node rows
        self._rows_frame = tk.Frame(self._grid_card.body, bg=BG_CARD)
        self._rows_frame.pack(fill='both', expand=True)

        # Trace results (hidden until trace mode)
        self._trace_card = CardFrame(self, title='TRACE RESULTS')

    # ── Nodes ─────────────────────────────────────────────────────

    def _load_nodes(self):
        nodes = [_LOCAL_NODE.copy()]
        try:
            if _os.path.isfile(_NODES_FILE):
                with open(_NODES_FILE, encoding='utf-8') as f:
                    extra = _json.load(f)
                nodes += [n for n in extra if n.get('url') != 'self']
        except Exception:
            pass
        self._nodes = nodes
        self._node_info_lbl.configure(
            text=f'{len(nodes)} node(s) loaded'
                 + (f'  ·  {len(nodes)-1} remote' if len(nodes) > 1 else '  ·  local only'))
        self._build_rows()

    def _build_rows(self):
        for w in self._rows_frame.winfo_children():
            w.destroy()
        self._node_rows = {}
        for i, node in enumerate(self._nodes):
            row = _NodeRow(self._rows_frame, node)
            bg  = BG_CARD if i % 2 == 0 else '#111820'
            row.configure(bg=bg)
            row.pack(fill='x', pady=1)
            self._node_rows[node['id']] = row

    # ── Ping ──────────────────────────────────────────────────────

    def _toggle_ping(self):
        if self._running and self._mode == 'ping':
            self._stop()
        else:
            self._start_ping()

    def _start_ping(self):
        host = self._host_var.get().strip()
        if not host:
            self._host_entry.focus()
            return
        self._stop()
        self._mode = 'ping'
        self._running = True

        # Show ping grid, hide trace
        self._grid_card.pack(fill='both', expand=True, padx=8, pady=4)
        self._trace_card.pack_forget()

        for row in self._node_rows.values():
            row.reset()

        self._ping_btn.configure(text='■  Stop', **BUTTON_RED_OPTS)
        self._trace_btn.configure(state='disabled')
        self._stop_event.clear()

        try:
            interval = max(0.5, float(self._ivl_var.get()))
        except ValueError:
            interval = 2.0

        for node in self._nodes:
            t = threading.Thread(
                target=self._ping_node_loop,
                args=(node, host, interval),
                daemon=True)
            t.start()

        _pulse_start()
        self._poll_job = self.after(150, self._poll_queue)

    def _ping_node_loop(self, node: dict, host: str, interval: float):
        seq = 0
        while not self._stop_event.is_set():
            rtt = self._ping_once(node, host, seq)
            self._q.put(('ping', node['id'], rtt))
            seq += 1
            # interruptible sleep
            deadline = _time.monotonic() + interval
            while _time.monotonic() < deadline:
                if self._stop_event.is_set():
                    return
                _time.sleep(0.1)

    def _ping_once(self, node: dict, host: str, seq: int) -> float:
        if node.get('url') == 'self':
            try:
                from core.engine import _icmp_ping
                r = _icmp_ping(host, seq)
                return r.rtt_ms
            except Exception:
                return -1.0
        # Remote node via HTTP
        try:
            params = _urllib_parse.urlencode(
                {'host': host, 'count': 1, 'interval': 0.1})
            url = node['url'].rstrip('/') + f'/api/ping?{params}'
            req = _urllib_req.Request(url)
            if node.get('key'):
                req.add_header('X-API-Key', node['key'])
            with _urllib_req.urlopen(req, timeout=8) as resp:
                data = _json.loads(resp.read())
            results = data.get('results', [])
            last    = results[-1] if results else {}
            return float(last.get('rtt_ms', -1))
        except Exception:
            return -1.0

    # ── Trace ─────────────────────────────────────────────────────

    def _start_trace(self):
        host = self._host_var.get().strip()
        if not host:
            self._host_entry.focus()
            return
        self._stop()
        self._mode = 'trace'
        self._running = True

        # Show trace card, hide ping grid
        self._grid_card.pack_forget()
        self._trace_card.pack(fill='both', expand=True, padx=8, pady=4)

        # Clear and build trace card contents
        for w in self._trace_card.body.winfo_children():
            w.destroy()

        self._trace_trees = {}
        for node in self._nodes:
            ncard = CardFrame(self._trace_card.body,
                              title=f'{node.get("flag","◈")} {node["name"]}'
                                    + (f'  —  {node["city"]}' if node.get("city") else ''))
            ncard.pack(fill='x', padx=4, pady=4)
            cols  = ('hop', 'ip', 'hostname', 'rtt1', 'rtt2', 'rtt3', 'loss')
            hdrs  = ('HOP', 'IP ADDRESS', 'HOSTNAME', 'RTT 1', 'RTT 2', 'RTT 3', 'LOSS%')
            widths = (45, 130, 200, 75, 75, 75, 60)
            tree = DarkTreeview(ncard.body, cols, hdrs, widths, height=6)
            tree.pack(fill='x', padx=4, pady=4)
            self._trace_trees[node['id']] = tree

        self._ping_btn.configure(state='disabled')
        self._trace_btn.configure(text='⇢  Tracing…', state='disabled')
        self._stop_event.clear()

        for node in self._nodes:
            t = threading.Thread(
                target=self._trace_node,
                args=(node, host),
                daemon=True)
            t.start()

        _pulse_start()
        self._poll_job = self.after(150, self._poll_queue)

    def _trace_node(self, node: dict, host: str):
        if node.get('url') == 'self':
            try:
                hops = traceroute(host, max_hops=30,
                                  callback=lambda h: self._q.put(
                                      ('hop', node['id'], h)))
            except Exception:
                pass
        else:
            try:
                params = _urllib_parse.urlencode({'host': host, 'max_hops': 30})
                url = node['url'].rstrip('/') + f'/api/traceroute?{params}'
                req = _urllib_req.Request(url)
                if node.get('key'):
                    req.add_header('X-API-Key', node['key'])
                with _urllib_req.urlopen(req, timeout=120) as resp:
                    hops = _json.loads(resp.read())
                for hop in hops:
                    self._q.put(('hop_dict', node['id'], hop))
            except Exception:
                pass
        self._q.put(('trace_done', node['id'], None))

    # ── Queue poll ────────────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                kind, node_id, data = self._q.get_nowait()
                if kind == 'ping':
                    row = self._node_rows.get(node_id)
                    if row:
                        row.update_ping(data)
                elif kind == 'hop':
                    tree = self._trace_trees.get(node_id)
                    if tree:
                        rtts = getattr(data, 'rtts', [])
                        while len(rtts) < 3:
                            rtts.append(-1)
                        loss = getattr(data, 'loss_pct', 0)
                        tree.tree.insert('', 'end', values=(
                            getattr(data, 'hop', ''),
                            getattr(data, 'ip', '*'),
                            getattr(data, 'hostname', '')[:36],
                            f'{rtts[0]:.1f}ms' if rtts[0] >= 0 else '*',
                            f'{rtts[1]:.1f}ms' if rtts[1] >= 0 else '*',
                            f'{rtts[2]:.1f}ms' if rtts[2] >= 0 else '*',
                            f'{loss:.0f}%',
                        ))
                elif kind == 'hop_dict':
                    tree = self._trace_trees.get(node_id)
                    if tree:
                        rtts = data.get('rtts', [-1, -1, -1])
                        while len(rtts) < 3:
                            rtts.append(-1)
                        loss = data.get('loss_pct', 0)
                        tree.tree.insert('', 'end', values=(
                            data.get('hop', ''),
                            data.get('ip', '*'),
                            data.get('hostname', '')[:36],
                            f'{rtts[0]:.1f}ms' if rtts[0] >= 0 else '*',
                            f'{rtts[1]:.1f}ms' if rtts[1] >= 0 else '*',
                            f'{rtts[2]:.1f}ms' if rtts[2] >= 0 else '*',
                            f'{loss:.0f}%',
                        ))
                elif kind == 'trace_done':
                    pass  # could mark the node card as complete
        except _queue.Empty:
            pass

        if self._running:
            self._poll_job = self.after(150, self._poll_queue)

    # ── Stop ──────────────────────────────────────────────────────

    def _stop(self):
        self._stop_event.set()
        self._running = False
        if self._poll_job:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None
        self._ping_btn.configure(text='▶  Ping All', **BUTTON_GREEN_OPTS)
        self._trace_btn.configure(text='⇢  Trace All', **BUTTON_OPTS,
                                  state='normal')
        _pulse_stop()
