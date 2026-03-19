"""
NetProbe Application — Main Window (Polished)
"""
import tkinter as tk
from tkinter import ttk
import platform
import socket

from .theme import *
from .widgets import StatusBar, apply_treeview_style, Tooltip
from .panels import (PingPanel, TraceroutePanel, MTRPanel, BandwidthPanel,
                     PortScanPanel, DNSPanel, ARPPanel,
                     PacketCapturePanel, ExternalMonitorPanel)

OS = platform.system()

VERSION = '1.0.0'


class NetProbeApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('NetProbe  —  Network Analysis Utility')
        self.root.geometry('1160x800')
        self.root.minsize(960, 640)
        self.root.configure(bg=BG_ROOT)
        self._set_icon()
        self._apply_global_style()
        self._build_ui()

    def _set_icon(self):
        try:
            icon = tk.PhotoImage(width=32, height=32)
            for i in range(32):
                for j in range(32):
                    dist = (i - 16) ** 2 + (j - 16) ** 2
                    if dist <= 196:
                        if dist <= 16:
                            icon.put(ACCENT_GREEN, (j, i))
                        elif (i == 16 or j == 16):
                            icon.put(ACCENT_CYAN, (j, i))
                        elif dist <= 100:
                            icon.put('#0a2818', (j, i))
                        else:
                            icon.put('#061410', (j, i))
            self.root.iconphoto(True, icon)
        except Exception:
            pass

    def _apply_global_style(self):
        style = ttk.Style(self.root)
        apply_treeview_style(style)

        style.configure('Dark.TNotebook',
                        background=BG_ROOT, borderwidth=0,
                        tabmargins=[0, 0, 0, 0])
        style.configure('Dark.TNotebook.Tab',
                        background=BG_INPUT, foreground=FG_DIM,
                        padding=[18, 8], font=('Segoe UI', 9, 'bold'),
                        borderwidth=0)
        style.map('Dark.TNotebook.Tab',
                  background=[('selected', BG_CARD), ('active', BG_HOVER)],
                  foreground=[('selected', ACCENT_CYAN), ('active', FG_PRIMARY)])

        self.root.option_add('*TCombobox*Listbox.background', BG_INPUT)
        self.root.option_add('*TCombobox*Listbox.foreground', FG_PRIMARY)
        self.root.option_add('*TCombobox*Listbox.selectBackground', BG_SELECT)
        self.root.option_add('*TCombobox*Listbox.font', FONT_MONO_SM)

        # Global widget defaults
        self.root.option_add('*Font', FONT_UI)

    def _build_ui(self):
        # ── Title bar ──────────────────────────────────────────────
        title_bar = tk.Frame(self.root, bg='#040608', height=50)
        title_bar.pack(fill='x')
        title_bar.pack_propagate(False)

        # Left: logo + name
        left = tk.Frame(title_bar, bg='#040608')
        left.pack(side='left', padx=8)

        tk.Label(left, text='⬡', bg='#040608', fg=ACCENT_GREEN,
                 font=('Courier New', 22)).pack(side='left', padx=(4, 6))

        name_col = tk.Frame(left, bg='#040608')
        name_col.pack(side='left')
        tk.Label(name_col, text='NetProbe', bg='#040608', fg=ACCENT_CYAN,
                 font=('Segoe UI', 15, 'bold')).pack(anchor='w')
        tk.Label(name_col, text='Network Analysis Utility',
                 bg='#040608', fg=FG_DIM,
                 font=('Segoe UI', 8)).pack(anchor='w')

        # Vertical divider
        tk.Frame(title_bar, bg=BORDER_DIM, width=1).pack(
            side='left', fill='y', pady=8, padx=10)

        # Center: quick-action info labels
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            hostname = 'unknown'
            local_ip = '?.?.?.?'

        info_row = tk.Frame(title_bar, bg='#040608')
        info_row.pack(side='left')

        for icon, val in [('⌂', hostname), ('◈', local_ip)]:
            chip = tk.Frame(info_row, bg='#0d1520',
                            highlightthickness=1,
                            highlightbackground=BORDER_DIM)
            chip.pack(side='left', padx=4, pady=10)
            tk.Label(chip, text=f' {icon} {val} ', bg='#0d1520',
                     fg=FG_DIM, font=('Segoe UI', 8)).pack()

        # Right: OS badge + version
        right = tk.Frame(title_bar, bg='#040608')
        right.pack(side='right', padx=12)

        os_str = f'{platform.system()} {platform.release()}'
        tk.Label(right, text=f'v{VERSION}', bg='#040608',
                 fg=FG_DIM, font=('Segoe UI', 8)).pack(anchor='e')
        tk.Label(right, text=os_str, bg='#040608',
                 fg=FG_DIM, font=('Segoe UI', 8)).pack(anchor='e')

        # Accent line under title bar
        tk.Frame(self.root, bg=BORDER_ACCENT, height=2).pack(fill='x')

        # ── Notebook ────────────────────────────────────────────────
        self.notebook = ttk.Notebook(self.root, style='Dark.TNotebook')
        self.notebook.pack(fill='both', expand=True)

        tabs = [
            ('  PING  ',           PingPanel),
            ('  TRACEROUTE  ',     TraceroutePanel),
            ('  MTR  ',            MTRPanel),
            ('  BANDWIDTH  ',      BandwidthPanel),
            ('  PORT SCAN  ',      PortScanPanel),
            ('  DNS  ',            DNSPanel),
            ('  L2 / ARP  ',       ARPPanel),
            ('  PKT CAPTURE  ',    PacketCapturePanel),
            ('  EXT MONITOR  ',    ExternalMonitorPanel),
        ]

        self._panels = {}
        for tab_name, PanelClass in tabs:
            panel = PanelClass(self.notebook)
            self.notebook.add(panel, text=tab_name)
            self._panels[tab_name.strip()] = panel

        # Update status bar when tab changes
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_change)

        # ── Status bar ──────────────────────────────────────────────
        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(fill='x', side='bottom')
        self.status_bar.set_ip(f'  {local_ip}')

        # ── Menu ────────────────────────────────────────────────────
        self._build_menu()

        # ── Keyboard shortcuts ───────────────────────────────────────
        for i in range(min(9, len(tabs))):
            self.root.bind(f'<Control-Key-{i+1}>',
                           lambda e, idx=i: self.notebook.select(idx))
        self.root.bind('<Control-e>', lambda e: self._export())
        self.root.bind('<Control-w>', lambda e: self.root.quit())

    def _on_tab_change(self, event):
        idx = self.notebook.index(self.notebook.select())
        tab_name = self.notebook.tab(idx, 'text').strip()
        self.status_bar.set_activity(f'  {tab_name}', ACCENT_CYAN)

    def _build_menu(self):
        menubar = tk.Menu(self.root, bg=BG_INPUT, fg=FG_PRIMARY,
                          activebackground=BG_SELECT,
                          activeforeground=FG_BRIGHT,
                          relief='flat', bd=0)

        # File
        file_menu = tk.Menu(menubar, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                            activebackground=BG_SELECT,
                            activeforeground=FG_BRIGHT)
        file_menu.add_command(label='Export Results...  Ctrl+E',
                              command=self._export)
        file_menu.add_separator()
        file_menu.add_command(label='Exit  Ctrl+W',
                              command=self.root.quit)
        menubar.add_cascade(label='File', menu=file_menu)

        # Tools
        tools_menu = tk.Menu(menubar, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                             activebackground=BG_SELECT,
                             activeforeground=FG_BRIGHT)
        tools_menu.add_command(label='Check Dependencies',
                               command=self._check_deps)
        tools_menu.add_command(label='Network Interfaces',
                               command=self._show_interfaces)
        tools_menu.add_command(label='Clear ASN Cache',
                               command=self._clear_asn_cache)
        menubar.add_cascade(label='Tools', menu=tools_menu)

        # Help
        help_menu = tk.Menu(menubar, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                            activebackground=BG_SELECT,
                            activeforeground=FG_BRIGHT)
        help_menu.add_command(label='OSI Layer Reference',
                              command=self._show_osi_ref)
        help_menu.add_command(label='Keyboard Shortcuts',
                              command=self._show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label='About NetProbe',
                              command=self._show_about)
        menubar.add_cascade(label='Help', menu=help_menu)

        self.root.configure(menu=menubar)

    # ── Export ──────────────────────────────────────────────────────

    def _export(self):
        from tkinter import filedialog
        import csv, json, datetime as dt

        fmt_win = tk.Toplevel(self.root)
        fmt_win.title('Export Format')
        fmt_win.configure(bg=BG_PANEL)
        fmt_win.geometry('340x170')
        fmt_win.resizable(False, False)
        fmt_win.grab_set()
        fmt_win.focus_set()

        tk.Label(fmt_win, text='Choose export format',
                 bg=BG_PANEL, fg=FG_PRIMARY,
                 font=FONT_UI_BOLD).pack(pady=(16, 8))

        fmt_var = tk.StringVar(value='txt')
        btn_row = tk.Frame(fmt_win, bg=BG_PANEL)
        btn_row.pack(pady=4)
        for val, txt, tip in [
            ('txt',  'Plain Text', 'Human-readable report'),
            ('csv',  'CSV',        'Import into Excel/Sheets'),
            ('json', 'JSON',       'Structured data / scripting'),
        ]:
            rb = tk.Radiobutton(btn_row, text=txt, variable=fmt_var, value=val,
                                bg=BG_PANEL, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                                activebackground=BG_PANEL, font=FONT_UI)
            rb.pack(side='left', padx=10)
            Tooltip(rb, tip)

        chosen = {'fmt': None}

        def do_export():
            chosen['fmt'] = fmt_var.get()
            fmt_win.destroy()

        tk.Button(fmt_win, text='  EXPORT  ', **BUTTON_GREEN_OPTS,
                  command=do_export).pack(pady=12)
        fmt_win.wait_window()

        if not chosen['fmt']:
            return

        fmt = chosen['fmt']
        path = filedialog.asksaveasfilename(
            defaultextension=f'.{fmt}',
            filetypes={
                'txt':  [('Text files', '*.txt')],
                'csv':  [('CSV files', '*.csv')],
                'json': [('JSON files', '*.json')],
            }[fmt],
            initialfile=f'netprobe_{dt.datetime.now().strftime("%Y%m%d_%H%M%S")}',
            title='Export Results'
        )
        if not path:
            return

        self.status_bar.set_status('EXPORTING...', ACCENT_YELLOW)
        data = self._collect_export_data()

        try:
            if fmt == 'txt':
                self._export_txt(path, data)
            elif fmt == 'csv':
                self._export_csv(path, data)
            elif fmt == 'json':
                self._export_json(path, data)
            self.status_bar.set_status('READY', ACCENT_GREEN)
            from tkinter import messagebox
            messagebox.showinfo('Export Complete',
                                f'Results saved to:\n{path}')
        except Exception as e:
            self.status_bar.set_status('EXPORT ERROR', ACCENT_RED)
            from tkinter import messagebox
            messagebox.showerror('Export Error', str(e))

    def _collect_export_data(self):
        import datetime as dt
        data = {
            'exported_at': dt.datetime.now().isoformat(),
            'host': '',
            'sections': {}
        }
        try:
            data['host'] = socket.gethostname()
        except Exception:
            pass

        def safe(fn):
            try:
                fn()
            except Exception:
                pass

        def collect_tree(panel, key, col_names):
            if panel and hasattr(panel, '_tree'):
                rows = []
                for item in panel._tree.tree.get_children():
                    vals = panel._tree.tree.item(item)['values']
                    if vals:
                        rows.append(dict(zip(col_names, vals)))
                if rows:
                    data['sections'][key] = rows

        # Ping
        def _ping():
            p = self._panels.get('PING')
            if p and hasattr(p, '_monitor') and p._monitor:
                results = p._monitor.results
                if results:
                    valid = [r for r in results if r.rtt_ms >= 0]
                    data['sections']['ping'] = {
                        'target': p._monitor.host,
                        'sent': len(results),
                        'received': len(valid),
                        'loss_pct': round((len(results)-len(valid))/len(results)*100, 1),
                        'min_ms': round(min(r.rtt_ms for r in valid), 3) if valid else 0,
                        'avg_ms': round(sum(r.rtt_ms for r in valid)/len(valid), 3) if valid else 0,
                        'max_ms': round(max(r.rtt_ms for r in valid), 3) if valid else 0,
                        'results': [{'seq': r.seq, 'ip': r.ip,
                                     'rtt_ms': r.rtt_ms, 'ttl': r.ttl}
                                    for r in results[-500:]]
                    }
        safe(_ping)

        safe(lambda: collect_tree(
            self._panels.get('TRACEROUTE'), 'traceroute',
            ['hop', 'ip', 'hostname', 'rtt1', 'rtt2', 'rtt3', 'loss_pct', 'asn']))

        def _mtr():
            p = self._panels.get('MTR')
            if p and hasattr(p, '_mtr') and p._mtr:
                rows = p._mtr.get_rows()
                if rows:
                    data['sections']['mtr'] = {
                        'target': p._mtr.host,
                        'hops': [{'hop': r.hop, 'ip': r.ip,
                                  'hostname': r.hostname,
                                  'loss_pct': r.loss_pct, 'sent': r.sent,
                                  'avg_ms': r.avg_ms, 'best_ms': r.best_ms,
                                  'worst_ms': r.worst_ms, 'stdev_ms': r.stdev_ms}
                                 for r in rows]
                    }
        safe(_mtr)

        safe(lambda: collect_tree(
            self._panels.get('PORT SCAN'), 'port_scan',
            ['port', 'service', 'state', 'rtt_ms', 'banner']))

        safe(lambda: collect_tree(
            self._panels.get('DNS'), 'dns',
            ['type', 'query', 'answer', 'rtt_ms', 'error']))

        safe(lambda: collect_tree(
            self._panels.get('L2 / ARP'), 'arp',
            ['ip', 'mac', 'hostname', 'interface']))

        def _ext():
            p = self._panels.get('EXT MONITOR')
            if p and hasattr(p, '_monitor'):
                targets = p._monitor.get_targets()
                if targets:
                    mon = {}
                    for host in targets:
                        stats = p._monitor.get_stats(host)
                        if stats:
                            mon[host] = stats
                    if mon:
                        data['sections']['ext_monitor'] = mon
        safe(_ext)

        def _pkt():
            p = self._panels.get('PKT CAPTURE')
            if p and hasattr(p, '_capture') and p._capture:
                pkts = p._capture.packets[-500:]
                if pkts:
                    data['sections']['packet_capture'] = {
                        'count': len(pkts),
                        'packets': [{'time': pk.timestamp,
                                     'proto': pk.protocol,
                                     'src': pk.src_ip, 'sport': pk.src_port,
                                     'dst': pk.dst_ip, 'dport': pk.dst_port,
                                     'flags': pk.flags, 'len': pk.length}
                                    for pk in pkts]
                    }
        safe(_pkt)

        return data

    def _export_txt(self, path, data):
        import datetime as dt
        lines = []
        div  = '─' * 70
        div2 = '═' * 70
        lines += [div2, '  NETPROBE EXPORT', f'  {data["exported_at"]}  /  {data["host"]}', div2]

        def section(title, rows, cols):
            lines.append(f'\n▸ {title}')
            lines.append(div)
            header = '  ' + '  '.join(f'{c.upper():<{w}}' for c, w in cols)
            lines.append(header)
            lines.append('  ' + '  '.join('─' * w for _, w in cols))
            for row in rows:
                lines.append('  ' + '  '.join(
                    f'{str(row.get(c,"")):<{w}}'[:w] for c, w in cols))

        if 'ping' in data['sections']:
            s = data['sections']['ping']
            lines.append(f'\n▸ PING — {s["target"]}')
            lines.append(div)
            lines.append(f'  Sent:{s["sent"]}  Recv:{s["received"]}  Loss:{s["loss_pct"]}%  '
                         f'Min:{s["min_ms"]}ms  Avg:{s["avg_ms"]}ms  Max:{s["max_ms"]}ms')
            lines.append('')
            for r in s['results']:
                rtt = f'{r["rtt_ms"]:.3f}ms' if r['rtt_ms'] >= 0 else 'TIMEOUT'
                lines.append(f'  seq={r["seq"]:<5} {r["ip"]:<18} ttl={r["ttl"]:<4} {rtt}')

        if 'traceroute' in data['sections']:
            section('TRACEROUTE', data['sections']['traceroute'],
                    [('hop',9),('ip',18),('hostname',30),('rtt1',10),
                     ('rtt2',10),('rtt3',10),('loss_pct',8),('asn',30)])

        if 'mtr' in data['sections']:
            s = data['sections']['mtr']
            lines.append(f'\n▸ MTR — {s["target"]}')
            lines.append(div)
            section('', s['hops'],
                    [('hop',5),('ip',18),('hostname',28),('loss_pct',8),
                     ('sent',6),('avg_ms',8),('best_ms',8),('worst_ms',8),('stdev_ms',6)])

        if 'port_scan' in data['sections']:
            section('PORT SCAN', data['sections']['port_scan'],
                    [('port',7),('service',12),('state',10),('rtt_ms',8),('banner',50)])

        if 'dns' in data['sections']:
            section('DNS', data['sections']['dns'],
                    [('type',8),('query',30),('answer',40),('rtt_ms',8)])

        if 'arp' in data['sections']:
            section('ARP / L2 SCAN', data['sections']['arp'],
                    [('ip',18),('mac',20),('hostname',30),('interface',14)])

        if 'ext_monitor' in data['sections']:
            lines.append(f'\n▸ EXTERNAL MONITOR')
            lines.append(div)
            fmt = '  {:<22} {:>6} {:>8} {:>8} {:>8} {:>8} {:>8}'
            lines.append(fmt.format('HOST','SENT','LOSS%','MIN','AVG','MAX','LAST'))
            lines.append('  ' + '─'*68)
            for host, s in data['sections']['ext_monitor'].items():
                lines.append(fmt.format(
                    host, s.get('sent',0),
                    f'{s.get("loss_pct",0):.1f}%',
                    f'{s.get("min_ms",0):.1f}ms',
                    f'{s.get("avg_ms",0):.1f}ms',
                    f'{s.get("max_ms",0):.1f}ms',
                    f'{s.get("last_ms",0):.1f}ms'))

        lines.append(f'\n{div2}')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def _export_csv(self, path, data):
        import csv, datetime as dt
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['NetProbe Export', data['exported_at'], data['host']])
            w.writerow([])

            def write_section(name, rows, keys):
                w.writerow([f'[{name}]'])
                w.writerow(keys)
                for row in rows:
                    w.writerow([row.get(k, '') for k in keys])
                w.writerow([])

            if 'ping' in data['sections']:
                s = data['sections']['ping']
                w.writerow(['[PING]', s['target']])
                w.writerow(['sent','received','loss_pct','min_ms','avg_ms','max_ms'])
                w.writerow([s['sent'],s['received'],s['loss_pct'],
                            s['min_ms'],s['avg_ms'],s['max_ms']])
                w.writerow([])
                write_section('PING RESULTS', s['results'],
                              ['seq','ip','ttl','rtt_ms'])

            if 'traceroute' in data['sections']:
                write_section('TRACEROUTE', data['sections']['traceroute'],
                              ['hop','ip','hostname','rtt1','rtt2','rtt3','loss_pct','asn'])

            if 'mtr' in data['sections']:
                s = data['sections']['mtr']
                w.writerow([f'[MTR]', s['target']])
                write_section('MTR HOPS', s['hops'],
                              ['hop','ip','hostname','loss_pct','sent',
                               'avg_ms','best_ms','worst_ms','stdev_ms'])

            if 'port_scan' in data['sections']:
                write_section('PORT SCAN', data['sections']['port_scan'],
                              ['port','service','state','rtt_ms','banner'])

            if 'dns' in data['sections']:
                write_section('DNS', data['sections']['dns'],
                              ['type','query','answer','rtt_ms','error'])

            if 'arp' in data['sections']:
                write_section('ARP', data['sections']['arp'],
                              ['ip','mac','hostname','interface'])

            if 'ext_monitor' in data['sections']:
                rows = [{'host': h, **s}
                        for h, s in data['sections']['ext_monitor'].items()]
                write_section('EXT MONITOR', rows,
                              ['host','sent','received','loss_pct',
                               'min_ms','avg_ms','max_ms','last_ms'])

            if 'packet_capture' in data['sections']:
                s = data['sections']['packet_capture']
                w.writerow([f'[PACKET CAPTURE]', s['count']])
                write_section('PACKETS', s['packets'],
                              ['time','proto','src','sport',
                               'dst','dport','flags','len'])

    def _export_json(self, path, data):
        import json
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

    # ── Tools ───────────────────────────────────────────────────────

    def _clear_asn_cache(self):
        try:
            from core.engine import _asn_cache
            _asn_cache.clear()
            from tkinter import messagebox
            messagebox.showinfo('ASN Cache', 'ASN cache cleared.')
        except Exception:
            pass

    def _check_deps(self):
        win = tk.Toplevel(self.root)
        win.title('Dependency Check')
        win.configure(bg=BG_PANEL)
        win.geometry('540x280')
        win.grab_set()

        from .widgets import CardFrame
        card = CardFrame(win, title='DEPENDENCY STATUS')
        card.pack(fill='both', expand=True, padx=12, pady=12)

        text = tk.Text(card.body, **TEXT_OPTS, height=10)
        text.pack(fill='both', expand=True, padx=6, pady=6)
        text.tag_configure('ok',   foreground=ACCENT_GREEN)
        text.tag_configure('warn', foreground=ACCENT_YELLOW)
        text.tag_configure('hdr',  foreground=ACCENT_CYAN,
                           font=('Courier New', 9, 'bold'))

        deps = [
            ('scapy',     'Packet capture L2/L3/L4, ARP scanning'),
            ('dns',       'Full DNS record types (dnspython)'),
            ('psutil',    'Network interface enumeration'),
        ]

        text.insert('end', f'  {"PACKAGE":<14} {"STATUS":<26} PROVIDES\n', 'hdr')
        text.insert('end', f'  {"─"*14}  {"─"*24}  {"─"*28}\n', 'hdr')

        for mod, desc in deps:
            try:
                __import__(mod)
                status = '✓  installed'
                tag = 'ok'
            except ImportError:
                status = '✗  not found (fallback)'
                tag = 'warn'
            text.insert('end', f'  {mod:<14}  {status:<26}  {desc}\n', tag)

        text.insert('end', '\n  pip install scapy dnspython psutil\n', 'hdr')
        text.configure(state='disabled')

    def _show_interfaces(self):
        from core import get_local_interfaces
        ifaces = get_local_interfaces()

        win = tk.Toplevel(self.root)
        win.title('Network Interfaces')
        win.configure(bg=BG_PANEL)
        win.geometry('500x320')
        win.grab_set()

        from .widgets import CardFrame, DarkTreeview
        card = CardFrame(win, title='LOCAL NETWORK INTERFACES')
        card.pack(fill='both', expand=True, padx=12, pady=12)

        tree = DarkTreeview(card.body,
                            ('name', 'ip', 'netmask'),
                            ('INTERFACE', 'IP ADDRESS', 'NETMASK'),
                            (140, 150, 150))
        tree.pack(fill='both', expand=True, padx=6, pady=6)
        for iface in ifaces:
            tree.insert((iface['name'], iface['ip'], iface['netmask']))

    def _show_osi_ref(self):
        layers = [
            ('L7', 'Application',  'HTTP FTP DNS SMTP SSH',  'DNS tab'),
            ('L6', 'Presentation', 'TLS/SSL encoding',       'Packet Capture'),
            ('L5', 'Session',      'NetBIOS RPC session mgmt','Packet Capture'),
            ('L4', 'Transport',    'TCP UDP — ports flow',    'Port Scan / Bandwidth'),
            ('L3', 'Network',      'IP ICMP routing',         'Ping / Traceroute / MTR'),
            ('L2', 'Data Link',    'Ethernet ARP MAC',        'L2 / ARP tab'),
            ('L1', 'Physical',     'Cables NICs signals',     '—'),
        ]

        win = tk.Toplevel(self.root)
        win.title('OSI Layer Reference')
        win.configure(bg=BG_PANEL)
        win.geometry('620x300')
        win.grab_set()

        from .widgets import CardFrame, DarkTreeview
        card = CardFrame(win, title='OSI MODEL — NETPROBE COVERAGE')
        card.pack(fill='both', expand=True, padx=12, pady=12)

        tree = DarkTreeview(card.body,
                            ('layer','name','protocols','tool'),
                            ('LAYER','NAME','PROTOCOLS','NETPROBE TAB'),
                            (55, 110, 200, 180))
        tree.pack(fill='both', expand=True, padx=6, pady=6)
        tree.tree.tag_configure('ok',   foreground=ACCENT_GREEN)
        tree.tree.tag_configure('dim',  foreground=FG_DIM)
        for row in layers:
            tag = 'dim' if row[3] == '—' else 'ok'
            tree.insert(row, tags=(tag,))

    def _show_shortcuts(self):
        win = tk.Toplevel(self.root)
        win.title('Keyboard Shortcuts')
        win.configure(bg=BG_PANEL)
        win.geometry('360x320')
        win.grab_set()

        from .widgets import CardFrame
        card = CardFrame(win, title='KEYBOARD SHORTCUTS')
        card.pack(fill='both', expand=True, padx=12, pady=12)

        text = tk.Text(card.body, **TEXT_OPTS, height=14)
        text.pack(fill='both', expand=True, padx=6, pady=6)
        text.tag_configure('key', foreground=ACCENT_CYAN,
                           font=('Courier New', 9, 'bold'))
        text.tag_configure('dim', foreground=FG_DIM)

        shortcuts = [
            ('Ctrl+1 … Ctrl+9', 'Switch to tab 1–9'),
            ('Ctrl+E',          'Export results'),
            ('Ctrl+W',          'Exit'),
            ('Right-click log', 'Copy / Clear log'),
            ('Right-click table','Copy row / Copy all'),
            ('Click column header','Sort by column'),
        ]
        for key, desc in shortcuts:
            text.insert('end', f'  {key:<22}', 'key')
            text.insert('end', f'  {desc}\n', 'dim')
        text.configure(state='disabled')

    def _show_about(self):
        win = tk.Toplevel(self.root)
        win.title('About NetProbe')
        win.configure(bg=BG_PANEL)
        win.geometry('420x280')
        win.resizable(False, False)
        win.grab_set()

        tk.Label(win, text='⬡', bg=BG_PANEL, fg=ACCENT_GREEN,
                 font=('Courier New', 36)).pack(pady=(20, 4))
        tk.Label(win, text='NetProbe', bg=BG_PANEL, fg=ACCENT_CYAN,
                 font=('Segoe UI', 18, 'bold')).pack()
        tk.Label(win, text=f'v{VERSION}  —  Network Analysis Utility',
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_UI).pack(pady=2)

        tk.Frame(win, bg=BORDER_DIM, height=1).pack(fill='x', padx=40, pady=8)

        tk.Label(win,
                 text='Ping · Traceroute · MTR · Bandwidth (iperf3)\n'
                      'Port Scan · DNS · ARP · Packet Capture\n'
                      'External Monitor · ASN / Carrier Lookup\n'
                      'Export: TXT · CSV · JSON',
                 bg=BG_PANEL, fg=FG_PRIMARY, font=FONT_LABEL,
                 justify='center').pack()

        tk.Frame(win, bg=BORDER_DIM, height=1).pack(fill='x', padx=40, pady=8)

        tk.Label(win,
                 text=f'Python {platform.python_version()}  /  '
                      f'{platform.system()} {platform.release()}',
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL).pack()
        tk.Label(win,
                 text='Run as Administrator for full ICMP + capture access',
                 bg=BG_PANEL, fg=ACCENT_YELLOW, font=FONT_LABEL).pack(pady=6)

    # ── Lifecycle ───────────────────────────────────────────────────

    def run(self):
        self.root.mainloop()
        for panel in self._panels.values():
            for attr in ('_monitor', '_mtr', '_capture'):
                obj = getattr(panel, attr, None)
                if obj:
                    try:
                        if hasattr(obj, 'stop_all'):
                            obj.stop_all()
                        elif hasattr(obj, 'stop'):
                            obj.stop()
                    except Exception:
                        pass
