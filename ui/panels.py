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
                      DarkTreeview, MiniGraph, run_in_thread)
from core import (PingMonitor, MTRMonitor, traceroute, port_scan,
                  dns_lookup, arp_scan, ping_sweep, get_local_interfaces,
                  BandwidthServer, BandwidthClient, IPerf3Client, find_iperf3,
                  PacketCapture, ExternalMonitor, COMMON_PORTS,
                  asn_lookup, asn_lookup_batch)


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

        self._tbar = TargetBar(ctrl, label='Host/IP', default='8.8.8.8',
                               extra_widgets=[ifrm],
                               on_start=self._start, on_stop=self._stop)
        self._tbar.pack(side='left')

        # Stats row
        stats_row = tk.Frame(self, bg=BG_PANEL)
        stats_row.pack(fill='x', padx=8, pady=2)
        self._stat_vars = {}
        for key, label in [('sent','SENT'),('recv','RECV'),('loss','LOSS%'),
                            ('min','MIN ms'),('avg','AVG ms'),('max','MAX ms'),('last','LAST ms')]:
            frm = tk.Frame(stats_row, bg=BG_CARD,
                           highlightthickness=1, highlightbackground=BORDER_DIM,
                           padx=10, pady=6)
            frm.pack(side='left', padx=2)
            tk.Label(frm, text=label, bg=BG_CARD, fg=FG_DIM,
                     font=('Segoe UI', 7, 'bold')).pack()
            var = tk.StringVar(value='—')
            self._stat_vars[key] = var
            tk.Label(frm, textvariable=var, bg=BG_CARD, fg=ACCENT_CYAN,
                     font=FONT_MONO_MD).pack()

        # Graph
        graph_card = CardFrame(self, title='RTT GRAPH (last 60 pings)')
        graph_card.pack(fill='x', padx=8, pady=4)
        self._graph = MiniGraph(graph_card.body, height=60)
        self._graph.pack(fill='x', expand=True, padx=4, pady=4)

        # Log
        log_card = CardFrame(self, title='PING LOG')
        log_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self._log = ScrolledText(log_card.body, height=14, state='disabled')
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
        self._log.append(f'PING  {host}  —  started {time.strftime("%H:%M:%S")}\n', 'hdr')
        self._monitor = PingMonitor(host, interval=interval, callback=self._on_result)
        self._monitor.start()

    def _stop(self):
        if self._monitor:
            self._monitor.stop()
            self._log.append('— STOPPED —\n', 'dim')

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
            self._stat_vars['avg'].set(f'{sum(x.rtt_ms for x in valid)/len(valid):.1f}')
            self._stat_vars['max'].set(f'{max(x.rtt_ms for x in valid):.1f}')
            self._stat_vars['last'].set(f'{r.rtt_ms:.1f}' if r.rtt_ms >= 0 else 'T/O')


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

        cols = ('hop', 'ip', 'hostname', 'rtt1', 'rtt2', 'rtt3', 'loss', 'asn')
        hdrs = ('HOP', 'IP ADDRESS', 'HOSTNAME', 'RTT 1', 'RTT 2', 'RTT 3', 'LOSS%', 'ASN / CARRIER')
        widths = (45, 120, 200, 80, 80, 80, 60, 200)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        # Tag colors
        self._tree.tree.tag_configure('ok',      foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('warn',     foreground=ACCENT_YELLOW)
        self._tree.tree.tag_configure('bad',      foreground=ACCENT_RED)
        self._tree.tree.tag_configure('timeout',  foreground=FG_DIM)
        self._tree.tree.tag_configure('dest',     foreground=ACCENT_CYAN)

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
        """Look up ASN for all hop IPs and update the tree"""
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

        asn_lookup_batch(list(ips.keys()), callback=on_asn)

    def _update_asn_cell(self, iid, asn):
        try:
            vals = list(self._tree.tree.item(iid)['values'])
            if len(vals) >= 8:
                vals[7] = asn
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
                  rtts[0], rtts[1], rtts[2], f'{hop.loss_pct:.0f}%', '…')
        iid = self._tree.tree.insert('', 'end', values=values, tags=(tag,))
        self._tree.tree.see(iid)

        # Store for ASN resolution
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

        cols = ('hop','ip','hostname','loss','sent','last','avg','best','worst','stdev','asn')
        hdrs = ('HOP','IP ADDRESS','HOSTNAME','LOSS%','SENT','LAST ms','AVG ms','BEST ms','WORST ms','STDEV','ASN / CARRIER')
        widths = (40, 115, 180, 55, 50, 70, 70, 70, 70, 65, 180)
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
        self._mtr_asn_cache = {}  # ip -> asn string
        self._mtr = MTRMonitor(host, interval=interval)
        self._mtr.start()
        self._schedule_update()

    def _stop(self):
        if self._mtr:
            self._mtr.stop()
        if self._update_job:
            self.after_cancel(self._update_job)
            self._update_job = None

    def _schedule_update(self):
        self._refresh()
        self._update_job = self.after(500, self._schedule_update)

    def _refresh(self):
        if not self._mtr:
            return
        rows = self._mtr.get_rows()
        self._tree.clear()

        # Collect IPs needing ASN lookup
        needs_lookup = []
        for row in rows:
            if row.ip and row.ip != '*' and row.ip not in self._mtr_asn_cache:
                needs_lookup.append(row.ip)
                self._mtr_asn_cache[row.ip] = '…'  # placeholder

        # Fire background lookups for new IPs
        if needs_lookup:
            def do_lookup(ips):
                for ip in ips:
                    asn = asn_lookup(ip)
                    self._mtr_asn_cache[ip] = asn
            threading.Thread(target=do_lookup, args=(needs_lookup,), daemon=True).start()

        for row in rows:
            if row.loss_pct >= 50: tag = 'bad'
            elif row.loss_pct > 0 or row.avg_ms > 150: tag = 'warn'
            elif row.ip == '*': tag = 'dim'
            else: tag = 'ok'
            asn = self._mtr_asn_cache.get(row.ip, '') if row.ip != '*' else ''
            values = (
                row.hop, row.ip, row.hostname[:30],
                f'{row.loss_pct:.1f}%', row.sent,
                f'{row.last_ms:.1f}' if row.last_ms else '—',
                f'{row.avg_ms:.1f}'  if row.avg_ms else '—',
                f'{row.best_ms:.1f}' if row.best_ms < 999999 else '—',
                f'{row.worst_ms:.1f}' if row.worst_ms else '—',
                f'{row.stdev_ms:.1f}' if row.stdev_ms else '—',
                asn,
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
                 font=('Courier New', 32, 'bold')).pack(side='left', padx=20)
        tk.Label(meter_card.body, text='Mbps', bg=BG_CARD,
                 fg=FG_DIM, font=('Segoe UI', 14)).pack(side='left')

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

        cols = ('port', 'service', 'state', 'rtt', 'banner')
        hdrs = ('PORT', 'SERVICE', 'STATE', 'RTT ms', 'BANNER')
        widths = (60, 100, 70, 70, 350)
        self._tree = DarkTreeview(card.body, cols, hdrs, widths)
        self._tree.pack(fill='both', expand=True, padx=4, pady=4)

        self._tree.tree.tag_configure('open',     foreground=ACCENT_GREEN)
        self._tree.tree.tag_configure('closed',   foreground=FG_DIM)
        self._tree.tree.tag_configure('filtered', foreground=ACCENT_YELLOW)

        self._scanning = False

    def _toggle_scan(self):
        if not self._scanning:
            self._scanning = True
            self._scan_btn.configure(text='■  STOP', **BUTTON_RED_OPTS)
            self._tree.clear()
            self._open_count = 0
            self._stop_event.clear()
            host = self._host_entry.get().strip()
            ports_str = self._ports_entry.get().strip()
            try:
                timeout = float(self._timeout_var.get())
            except:
                timeout = 0.5
            ports = self._parse_ports(ports_str)
            if not ports:
                messagebox.showwarning('NetProbe', 'Invalid port range')
                self._scanning = False
                self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)
                return
            self._progress_var.set(f'Scanning {len(ports)} ports on {host}...')

            def run():
                port_scan(host, ports, timeout=timeout, callback=self._on_port,
                          threads=min(100, len(ports)))
                self._done_scan()

            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()
        else:
            self._stop_event.set()
            self._scanning = False
            self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)

    def _done_scan(self):
        self._scanning = False
        self._scan_btn.configure(text='▶  SCAN', **BUTTON_GREEN_OPTS)
        self._progress_var.set(f'Done — {self._open_count} open ports found')

    def _on_port(self, r):
        if self._stop_event.is_set():
            return
        if r.state == 'closed':
            return  # only show open/filtered
        if r.state == 'open':
            self._open_count += 1
        values = (r.port, r.service, r.state.upper(), f'{r.rtt_ms:.1f}', r.banner[:60])
        self._tree.tree.insert('', 'end', values=values, tags=(r.state,))

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

            if last < 0:
                status = '●'
                tag = 'down'
            elif loss > 10 or last > 200:
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
