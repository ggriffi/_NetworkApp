"""
NetProbe Application — Main Window
Sidebar navigation layout (collapsible) replacing tab notebook.
"""
import tkinter as tk
from tkinter import ttk
import platform
import socket
import json
import os

from .theme import *
from .widgets import StatusBar, apply_treeview_style, Tooltip
from .panels import (
    PingPanel, TraceroutePanel, MTRPanel, BandwidthPanel,
    PortScanPanel, DNSPanel, ARPPanel,
    PacketCapturePanel, ExternalMonitorPanel,
    SSLPanel, HTTPProbePanel, WHOISPanel, WakeOnLANPanel,
    NetstatPanel, GlobalPingPanel,
)

OS      = platform.system()
VERSION = '1.1.0'

_app_instance = None
SESSION_FILE  = os.path.join(os.path.dirname(__file__), '..', 'netprobe_session.json')

_SIDEBAR_OPEN   = 172
_SIDEBAR_CLOSED = 46

# (key, label, icon, group)
_NAV_TOOLS = [
    ('PING',        'Ping',        '◈', 'NETWORK'),
    ('TRACEROUTE',  'Traceroute',  '⇢', 'NETWORK'),
    ('MTR',         'MTR',         '⊞', 'NETWORK'),
    ('GLOBAL PING', 'Global Ping', '⊛', 'NETWORK'),
    ('BANDWIDTH',   'Bandwidth',   '⤢', 'NETWORK'),
    ('PORT SCAN',   'Port Scan',   '⬡', 'DISCOVERY'),
    ('DNS',         'DNS',         '◎', 'DISCOVERY'),
    ('L2 / ARP',    'L2 / ARP',    '⬟', 'DISCOVERY'),
    ('NETSTAT',     'Netstat',     '⊟', 'DISCOVERY'),
    ('SSL/TLS',     'SSL / TLS',   '⚿', 'SECURITY'),
    ('HTTP PROBE',  'HTTP Probe',  '↯', 'SECURITY'),
    ('WHOIS',       'WHOIS',       '?', 'SECURITY'),
    ('PKT CAPTURE', 'Pkt Capture', '⊡', 'TOOLS'),
    ('EXT MONITOR', 'Ext Monitor', '◉', 'TOOLS'),
    ('WAKE-ON-LAN', 'Wake-on-LAN', '⏻', 'TOOLS'),
]

_PANEL_MAP = {
    'PING':        PingPanel,
    'TRACEROUTE':  TraceroutePanel,
    'MTR':         MTRPanel,
    'GLOBAL PING': GlobalPingPanel,
    'BANDWIDTH':   BandwidthPanel,
    'PORT SCAN':   PortScanPanel,
    'DNS':         DNSPanel,
    'L2 / ARP':    ARPPanel,
    'NETSTAT':     NetstatPanel,
    'SSL/TLS':     SSLPanel,
    'HTTP PROBE':  HTTPProbePanel,
    'WHOIS':       WHOISPanel,
    'PKT CAPTURE': PacketCapturePanel,
    'EXT MONITOR': ExternalMonitorPanel,
    'WAKE-ON-LAN': WakeOnLANPanel,
}


# ─── Sidebar nav button ───────────────────────────────────────────────────────

class _NavButton(tk.Frame):
    """Single sidebar navigation item: accent-bar | icon | label."""

    _BG        = BG_PANEL
    _BG_ACTIVE = '#111820'
    _BG_HOVER  = BG_HOVER

    def __init__(self, parent, icon: str, label: str, command):
        super().__init__(parent, bg=self._BG, cursor='hand2')
        self._cmd    = command
        self._active = False

        # Left accent bar (3 px)
        self._bar = tk.Frame(self, bg=self._BG, width=3)
        self._bar.pack(side='left', fill='y')

        # Icon
        self._icon_lbl = tk.Label(
            self, text=icon, bg=self._BG, fg=FG_DIM,
            font=(MONO, 12), width=2, anchor='center')
        self._icon_lbl.pack(side='left', padx=(6, 3), pady=6)

        # Label (hidden when sidebar collapsed)
        self._text_lbl = tk.Label(
            self, text=label, bg=self._BG, fg=FG_DIM,
            font=FONT_UI, anchor='w')
        self._text_lbl.pack(side='left', fill='x', expand=True, padx=(0, 8))

        for w in (self, self._bar, self._icon_lbl, self._text_lbl):
            w.bind('<Button-1>', lambda e: self._cmd())
            w.bind('<Enter>',    self._on_enter)
            w.bind('<Leave>',    self._on_leave)

    def set_active(self, active: bool):
        self._active = active
        if active:
            self._bar.config(bg=ACCENT_CYAN)
            self._icon_lbl.config(fg=ACCENT_CYAN, bg=self._BG_ACTIVE)
            self._text_lbl.config(fg=FG_BRIGHT,   bg=self._BG_ACTIVE)
            self.config(bg=self._BG_ACTIVE)
        else:
            self._bar.config(bg=self._BG)
            self._icon_lbl.config(fg=FG_DIM, bg=self._BG)
            self._text_lbl.config(fg=FG_DIM, bg=self._BG)
            self.config(bg=self._BG)

    def set_collapsed(self, collapsed: bool):
        if collapsed:
            self._text_lbl.pack_forget()
        else:
            self._text_lbl.pack(side='left', fill='x', expand=True, padx=(0, 8))

    def _on_enter(self, _=None):
        if not self._active:
            bg = self._BG_HOVER
            self.config(bg=bg)
            self._icon_lbl.config(bg=bg, fg=FG_PRIMARY)
            self._text_lbl.config(bg=bg, fg=FG_PRIMARY)

    def _on_leave(self, _=None):
        if not self._active:
            self.config(bg=self._BG)
            self._icon_lbl.config(bg=self._BG, fg=FG_DIM)
            self._text_lbl.config(bg=self._BG, fg=FG_DIM)


# ─── Main application ─────────────────────────────────────────────────────────

class NetProbeApp:
    def __init__(self):
        global _app_instance
        _app_instance = self

        self.root = tk.Tk()
        self.root.title('NetProbe  —  Network Analysis Utility')
        self.root.geometry('1200x820')
        self.root.minsize(800, 580)
        self.root.configure(bg=BG_ROOT)

        self._sidebar_open  = True
        self._nav_buttons   = {}   # key -> _NavButton
        self._group_headers = []   # list of (label_widget, separator_widget)
        self._panels        = {}   # key -> tk.Frame panel
        self._active_key    = None

        self._set_icon()
        self._apply_global_style()
        self._build_ui()
        self._load_session()
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)

    # ── Icon ──────────────────────────────────────────────────────────────────

    def _set_icon(self):
        try:
            icon = tk.PhotoImage(width=32, height=32)
            for i in range(32):
                for j in range(32):
                    d = (i - 16) ** 2 + (j - 16) ** 2
                    if d <= 196:
                        if d <= 16:
                            icon.put(ACCENT_GREEN, (j, i))
                        elif i == 16 or j == 16:
                            icon.put(ACCENT_CYAN, (j, i))
                        elif d <= 100:
                            icon.put('#0a2818', (j, i))
                        else:
                            icon.put('#061410', (j, i))
            self.root.iconphoto(True, icon)
        except Exception:
            pass

    # ── Global style ──────────────────────────────────────────────────────────

    def _apply_global_style(self):
        style = ttk.Style(self.root)
        apply_treeview_style(style)
        self.root.option_add('*TCombobox*Listbox.background',       BG_INPUT)
        self.root.option_add('*TCombobox*Listbox.foreground',       FG_PRIMARY)
        self.root.option_add('*TCombobox*Listbox.selectBackground', BG_SELECT)
        self.root.option_add('*TCombobox*Listbox.font',             FONTMONO_SM)
        self.root.option_add('*Font', FONT_UI)

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Title bar
        self._build_title_bar()
        tk.Frame(self.root, bg=BORDER_ACCENT, height=2).pack(fill='x')

        # Quick target bar (global, persistent)
        self._build_quick_target_bar()
        tk.Frame(self.root, bg=BORDER_DIM, height=1).pack(fill='x')

        # Body: sidebar | divider | content
        body = tk.Frame(self.root, bg=BG_ROOT)
        body.pack(fill='both', expand=True)

        self._sidebar_frm = tk.Frame(body, bg=BG_PANEL, width=_SIDEBAR_OPEN)
        self._sidebar_frm.pack(side='left', fill='y')
        self._sidebar_frm.pack_propagate(False)

        tk.Frame(body, bg=BORDER_DIM, width=1).pack(side='left', fill='y')

        self._content_frm = tk.Frame(body, bg=BG_ROOT)
        self._content_frm.pack(side='left', fill='both', expand=True)

        self._build_sidebar()

        # Breadcrumb strip at top of content area
        self._breadcrumb_frm = tk.Frame(self._content_frm, bg='#060a0f', height=22)
        self._breadcrumb_frm.pack(fill='x', side='top')
        self._breadcrumb_frm.pack_propagate(False)
        self._breadcrumb_lbl = tk.Label(
            self._breadcrumb_frm,
            text='netprobe  ›',
            bg='#060a0f', fg=FG_DIM,
            font=(MONO, 8), anchor='w', padx=10)
        self._breadcrumb_lbl.pack(fill='x', pady=3)
        tk.Frame(self._content_frm, bg=BORDER_DIM, height=1).pack(fill='x')

        # Panel container (takes remaining space)
        self._panel_host = tk.Frame(self._content_frm, bg=BG_ROOT)
        self._panel_host.pack(fill='both', expand=True)

        # Create all panels stacked on top of each other
        for key, PanelClass in _PANEL_MAP.items():
            p = PanelClass(self._panel_host)
            p.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._panels[key] = p

        # Status bar
        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(fill='x', side='bottom')
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = '?.?.?.?'
        self.status_bar.set_ip(f'  {local_ip}')

        self._build_menu()

        # Keyboard shortcuts: Ctrl+1-9 navigate tools, Ctrl+B toggle sidebar
        for i, (key, *_) in enumerate(_NAV_TOOLS[:9]):
            self.root.bind(f'<Control-Key-{i+1}>',
                           lambda e, k=key: self.navigate_to(k))
        self.root.bind('<Control-e>', lambda e: self._export())
        self.root.bind('<Control-w>', lambda e: self._on_close())
        self.root.bind('<Control-b>', lambda e: self._toggle_sidebar())
        self.root.bind('<Control-p>', lambda e: self._open_command_palette())

        self.navigate_to('PING')

    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg='#040608', height=50)
        bar.pack(fill='x')
        bar.pack_propagate(False)

        # Logo
        left = tk.Frame(bar, bg='#040608')
        left.pack(side='left', padx=8)
        tk.Label(left, text='⬡', bg='#040608', fg=ACCENT_GREEN,
                 font=(MONO, 22)).pack(side='left', padx=(4, 6))
        name_col = tk.Frame(left, bg='#040608')
        name_col.pack(side='left')
        tk.Label(name_col, text='NetProbe', bg='#040608', fg=ACCENT_CYAN,
                 font=(MONO, 15, 'bold')).pack(anchor='w')
        tk.Label(name_col, text='Network Analysis Utility',
                 bg='#040608', fg=FG_DIM, font=(MONO, 8)).pack(anchor='w')

        tk.Frame(bar, bg=BORDER_DIM, width=1).pack(side='left', fill='y', pady=8, padx=10)

        # Host info chips
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            hostname, local_ip = 'unknown', '?.?.?.?'

        info_row = tk.Frame(bar, bg='#040608')
        info_row.pack(side='left')
        for icon, val in [('⌂', hostname), ('◈', local_ip)]:
            chip = tk.Frame(info_row, bg='#0d1520',
                            highlightthickness=1, highlightbackground=BORDER_DIM)
            chip.pack(side='left', padx=4, pady=10)
            tk.Label(chip, text=f' {icon} {val} ', bg='#0d1520',
                     fg=FG_DIM, font=(MONO, 8)).pack()

        # Right: version + toggle button
        right = tk.Frame(bar, bg='#040608')
        right.pack(side='right', padx=8)

        tk.Label(right, text=f'v{VERSION}', bg='#040608',
                 fg=FG_DIM, font=(MONO, 8)).pack(anchor='e')
        tk.Label(right, text=f'{platform.system()} {platform.release()}',
                 bg='#040608', fg=FG_DIM, font=(MONO, 8)).pack(anchor='e')

        tk.Frame(bar, bg=BORDER_DIM, width=1).pack(side='right', fill='y', pady=8, padx=6)

        self._sidebar_toggle_lbl = tk.Label(
            bar, text='◀', bg='#040608', fg=FG_DIM,
            font=(MONO, 14), cursor='hand2', padx=10)
        self._sidebar_toggle_lbl.pack(side='right', fill='y')
        self._sidebar_toggle_lbl.bind('<Button-1>', lambda e: self._toggle_sidebar())
        Tooltip(self._sidebar_toggle_lbl, 'Toggle sidebar  (Ctrl+B)')

    def _build_quick_target_bar(self):
        bar = tk.Frame(self.root, bg='#080c12', height=36)
        bar.pack(fill='x')
        bar.pack_propagate(False)

        tk.Label(bar, text='›', bg='#080c12', fg=ACCENT_CYAN,
                 font=(MONO, 14), padx=8).pack(side='left')

        self._qt_var = tk.StringVar()
        self._qt_entry = tk.Entry(bar, textvariable=self._qt_var,
                                  width=32,
                                  bg='#0d1520', fg=FG_PRIMARY,
                                  insertbackground=FG_PRIMARY,
                                  relief='flat', bd=0,
                                  font=(MONO, 10),
                                  highlightthickness=1,
                                  highlightcolor=BORDER_ACTIVE,
                                  highlightbackground='#080c12')
        self._qt_entry.pack(side='left', ipady=4, padx=(0, 6))
        self._qt_entry.bind('<Return>', lambda e: self._qt_dispatch('PING'))

        # Dispatch shortcut buttons
        dispatch_tools = [
            ('Ping',  'PING'),
            ('Trace', 'TRACEROUTE'),
            ('DNS',   'DNS'),
            ('SSL',   'SSL/TLS'),
            ('Scan',  'PORT SCAN'),
            ('WHOIS', 'WHOIS'),
        ]
        for label, key in dispatch_tools:
            btn = tk.Button(
                bar, text=label,
                bg='#0d1520', fg=FG_DIM,
                activebackground=BG_HOVER, activeforeground=ACCENT_CYAN,
                relief='flat', bd=0, font=(MONO, 9),
                highlightthickness=1,
                highlightcolor=BORDER_DIM,
                highlightbackground='#080c12',
                padx=8, pady=2, cursor='hand2',
                command=lambda k=key: self._qt_dispatch(k))
            btn.pack(side='left', padx=1)
            Tooltip(btn, f'Send target to {label}  (Ctrl+P for full palette)')

        # Ctrl+P hint on far right
        tk.Label(bar, text='Ctrl+P  palette', bg='#080c12',
                 fg=FG_DIM, font=(MONO, 8), padx=12).pack(side='right')

    def _qt_dispatch(self, key: str):
        host = self._qt_var.get().strip()
        self.navigate_to(key, prefill=host if host else None)

    def _build_sidebar(self):
        sb = self._sidebar_frm

        # Scrollable canvas so long nav lists work on small screens
        self._nav_canvas = tk.Canvas(sb, bg=BG_PANEL, highlightthickness=0, bd=0)
        self._nav_canvas.pack(fill='both', expand=True)

        self._nav_inner = tk.Frame(self._nav_canvas, bg=BG_PANEL)
        self._nav_win   = self._nav_canvas.create_window(
            (0, 0), window=self._nav_inner, anchor='nw')

        def _resize(e):
            self._nav_canvas.itemconfig(self._nav_win, width=e.width)
        self._nav_canvas.bind('<Configure>', _resize)
        self._nav_inner.bind('<Configure>',
            lambda e: self._nav_canvas.configure(
                scrollregion=self._nav_canvas.bbox('all')))
        self._nav_canvas.bind('<MouseWheel>',
            lambda e: self._nav_canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units'))

        # Build grouped nav entries
        last_group = None
        for key, label, icon, group in _NAV_TOOLS:
            if group != last_group:
                # Spacer + group header
                spacer = tk.Frame(self._nav_inner, bg=BG_PANEL, height=6)
                spacer.pack(fill='x')

                grp_lbl = tk.Label(
                    self._nav_inner, text=f'  {group}',
                    bg=BG_PANEL, fg=FG_DIM,
                    font=(MONO, 7, 'bold'), anchor='w')
                grp_lbl.pack(fill='x', padx=4, pady=(2, 0))

                sep = tk.Frame(self._nav_inner, bg=BORDER_DIM, height=1)
                sep.pack(fill='x', padx=8, pady=(2, 4))

                self._group_headers.append((grp_lbl, sep, spacer))
                last_group = group

            btn = _NavButton(
                self._nav_inner, icon=icon, label=label,
                command=lambda k=key: self.navigate_to(k))
            btn.pack(fill='x')
            self._nav_buttons[key] = btn

        # Bottom: keyboard hint
        hint_frm = tk.Frame(sb, bg=BG_PANEL)
        hint_frm.pack(fill='x', side='bottom', pady=4)
        tk.Frame(hint_frm, bg=BORDER_DIM, height=1).pack(fill='x')
        self._sidebar_hint = tk.Label(
            hint_frm, text='Ctrl+B  toggle sidebar',
            bg=BG_PANEL, fg=FG_DIM, font=(MONO, 7), pady=4)
        self._sidebar_hint.pack()

    # ── Navigation ────────────────────────────────────────────────────────────

    def navigate_to(self, key: str, prefill: str = None):
        """Raise a panel and mark its nav button active."""
        key = key.strip()
        if key not in self._panels:
            return

        if self._active_key and self._active_key in self._nav_buttons:
            self._nav_buttons[self._active_key].set_active(False)

        self._active_key = key
        self._panels[key].tkraise()
        self._nav_buttons[key].set_active(True)

        label = next((lbl for k, lbl, *_ in _NAV_TOOLS if k == key), key)

        if hasattr(self, 'status_bar'):
            self.status_bar.set_activity(f'  {label}', ACCENT_CYAN)

        # Update breadcrumb
        if hasattr(self, '_breadcrumb_lbl'):
            target = prefill or self._qt_var.get().strip() if hasattr(self, '_qt_var') else ''
            crumb = f'netprobe  ›  {label}'
            if target:
                crumb += f'  ›  {target}'
            self._breadcrumb_lbl.configure(text=crumb)

        if prefill:
            p = self._panels[key]
            for attr in ('_host_var', '_target_var', '_mac'):
                obj = getattr(p, attr, None)
                if obj is None:
                    continue
                if isinstance(obj, tk.StringVar):
                    obj.set(prefill)
                elif isinstance(obj, tk.Entry):
                    obj.delete(0, 'end')
                    obj.insert(0, prefill)
                break

    # ── Command palette (Ctrl+P) ──────────────────────────────────

    def _open_command_palette(self):
        pal = tk.Toplevel(self.root)
        pal.title('')
        pal.configure(bg=BG_PANEL)
        pal.geometry('480x320')
        pal.resizable(False, False)
        pal.transient(self.root)
        pal.grab_set()

        # Center on root
        self.root.update_idletasks()
        rx = self.root.winfo_x() + self.root.winfo_width()  // 2 - 240
        ry = self.root.winfo_y() + self.root.winfo_height() // 4
        pal.geometry(f'+{rx}+{ry}')

        # Input strip
        inp_frm = tk.Frame(pal, bg=BG_INPUT,
                           highlightthickness=1,
                           highlightbackground=ACCENT_CYAN)
        inp_frm.pack(fill='x', padx=0, pady=0)
        tk.Label(inp_frm, text='  ›', bg=BG_INPUT, fg=ACCENT_CYAN,
                 font=(MONO, 14)).pack(side='left')
        search_var = tk.StringVar()
        inp = tk.Entry(inp_frm, textvariable=search_var,
                       bg=BG_INPUT, fg=FG_PRIMARY,
                       insertbackground=FG_PRIMARY,
                       relief='flat', bd=0, font=(MONO, 12))
        inp.pack(side='left', fill='x', expand=True, ipady=8, padx=4)
        inp.focus_set()

        # Result list
        listbox = tk.Listbox(pal, bg=BG_CARD, fg=FG_PRIMARY,
                             font=(MONO, 10), relief='flat', bd=0,
                             selectbackground=BG_SELECT,
                             selectforeground=FG_BRIGHT,
                             activestyle='none',
                             highlightthickness=0)
        listbox.pack(fill='both', expand=True, padx=0, pady=0)

        hint = tk.Label(pal, text='Enter to navigate  ·  Esc to close',
                        bg='#060809', fg=FG_DIM, font=(MONO, 8))
        hint.pack(fill='x', pady=4)

        # Pre-fill search with quick target bar host
        qt_host = self._qt_var.get().strip() if hasattr(self, '_qt_var') else ''

        all_tools = [(k, lbl, icon) for k, lbl, icon, _ in _NAV_TOOLS]

        def refresh(*_):
            q = search_var.get().lower()
            listbox.delete(0, 'end')
            for k, lbl, icon in all_tools:
                if q in lbl.lower() or q in k.lower():
                    listbox.insert('end', f'  {icon}  {lbl}')
            if listbox.size():
                listbox.selection_set(0)

        def go(event=None):
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            key = all_tools[[i for i, (k, lbl, icon) in enumerate(all_tools)
                              if f'  {icon}  {lbl}' == listbox.get(idx)][0]][0]
            pal.destroy()
            self.navigate_to(key, prefill=qt_host or None)

        search_var.trace_add('write', refresh)
        listbox.bind('<Double-Button-1>', go)
        pal.bind('<Return>',  go)
        pal.bind('<Escape>',  lambda e: pal.destroy())
        pal.bind('<Down>',
                 lambda e: listbox.selection_set(
                     min(listbox.curselection()[0] + 1, listbox.size()-1)
                     if listbox.curselection() else 0))
        pal.bind('<Up>',
                 lambda e: listbox.selection_set(
                     max(listbox.curselection()[0] - 1, 0)
                     if listbox.curselection() else 0))

        refresh()

    # ── Sidebar toggle ────────────────────────────────────────────────────────

    def _toggle_sidebar(self):
        self._sidebar_open = not self._sidebar_open
        if self._sidebar_open:
            self._sidebar_frm.config(width=_SIDEBAR_OPEN)
            self._sidebar_toggle_lbl.config(text='◀')
            for btn in self._nav_buttons.values():
                btn.set_collapsed(False)
            for lbl, sep, spacer in self._group_headers:
                spacer.pack(fill='x')
                lbl.pack(fill='x', padx=4, pady=(2, 0))
                sep.pack(fill='x', padx=8, pady=(2, 4))
            self._sidebar_hint.pack()
        else:
            self._sidebar_frm.config(width=_SIDEBAR_CLOSED)
            self._sidebar_toggle_lbl.config(text='▶')
            for btn in self._nav_buttons.values():
                btn.set_collapsed(True)
            for lbl, sep, spacer in self._group_headers:
                spacer.pack_forget()
                lbl.pack_forget()
                sep.pack_forget()
            self._sidebar_hint.pack_forget()

    # ── Menu ──────────────────────────────────────────────────────────────────

    def _build_menu(self):
        menubar = tk.Menu(self.root, bg=BG_INPUT, fg=FG_PRIMARY,
                          activebackground=BG_SELECT, activeforeground=FG_BRIGHT,
                          relief='flat', bd=0)

        def _menu(label, **items_and_cmds):
            m = tk.Menu(menubar, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                        activebackground=BG_SELECT, activeforeground=FG_BRIGHT)
            menubar.add_cascade(label=label, menu=m)
            return m

        # File
        fm = _menu('File')
        fm.add_command(label='Export Results…  Ctrl+E', command=self._export)
        fm.add_separator()
        fm.add_command(label='Exit  Ctrl+W', command=self._on_close)

        # Tools
        tm = _menu('Tools')
        tm.add_command(label='Toggle Sidebar  Ctrl+B', command=self._toggle_sidebar)
        tm.add_separator()
        tm.add_command(label='Check Dependencies',  command=self._check_deps)
        tm.add_command(label='Network Interfaces',  command=self._show_interfaces)
        tm.add_command(label='Clear ASN Cache',     command=self._clear_asn_cache)
        tm.add_command(label='Clear GeoIP Cache',   command=self._clear_geoip_cache)

        # Help
        hm = _menu('Help')
        hm.add_command(label='OSI Layer Reference',  command=self._show_osi_ref)
        hm.add_command(label='Keyboard Shortcuts',   command=self._show_shortcuts)
        hm.add_separator()
        hm.add_command(label='About NetProbe',       command=self._show_about)

        self.root.configure(menu=menubar)

    # ── Export ────────────────────────────────────────────────────────────────

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
                 bg=BG_PANEL, fg=FG_PRIMARY, font=FONT_UI_BOLD).pack(pady=(16, 8))

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

        fmt  = chosen['fmt']
        path = filedialog.asksaveasfilename(
            defaultextension=f'.{fmt}',
            filetypes={
                'txt':  [('Text files',  '*.txt')],
                'csv':  [('CSV files',   '*.csv')],
                'json': [('JSON files',  '*.json')],
            }[fmt],
            initialfile=f'netprobe_{dt.datetime.now().strftime("%Y%m%d_%H%M%S")}',
            title='Export Results'
        )
        if not path:
            return

        self.status_bar.set_status('EXPORTING…', ACCENT_YELLOW)
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
            messagebox.showinfo('Export Complete', f'Results saved to:\n{path}')
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
                        'loss_pct': round((len(results) - len(valid)) / len(results) * 100, 1),
                        'min_ms': round(min(r.rtt_ms for r in valid), 3) if valid else 0,
                        'avg_ms': round(sum(r.rtt_ms for r in valid) / len(valid), 3) if valid else 0,
                        'max_ms': round(max(r.rtt_ms for r in valid), 3) if valid else 0,
                        'results': [{'seq': r.seq, 'ip': r.ip, 'rtt_ms': r.rtt_ms, 'ttl': r.ttl}
                                    for r in results[-500:]]
                    }
        safe(_ping)

        safe(lambda: collect_tree(
            self._panels.get('TRACEROUTE'), 'traceroute',
            ['hop', 'ip', 'hostname', 'rtt1', 'rtt2', 'rtt3', 'loss_pct', 'asn', 'geo']))

        def _mtr():
            p = self._panels.get('MTR')
            if p and hasattr(p, '_mtr') and p._mtr:
                rows = p._mtr.get_rows()
                if rows:
                    data['sections']['mtr'] = {
                        'target': p._mtr.host,
                        'hops': [{'hop': r.hop, 'ip': r.ip, 'hostname': r.hostname,
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
        safe(lambda: collect_tree(
            self._panels.get('NETSTAT'), 'netstat',
            ['proto', 'local', 'remote', 'state', 'pid', 'process']))

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
                        'packets': [{'time': pk.timestamp, 'proto': pk.protocol,
                                     'src': pk.src_ip, 'sport': pk.src_port,
                                     'dst': pk.dst_ip, 'dport': pk.dst_port,
                                     'flags': pk.flags, 'len': pk.length}
                                    for pk in pkts]
                    }
        safe(_pkt)

        return data

    def _export_txt(self, path, data):
        lines = []
        div  = '─' * 70
        div2 = '═' * 70
        lines += [div2, '  NETPROBE EXPORT',
                  f'  {data["exported_at"]}  /  {data["host"]}', div2]

        def section(title, rows, cols):
            lines.append(f'\n▸ {title}')
            lines.append(div)
            lines.append('  ' + '  '.join(f'{c.upper():<{w}}' for c, w in cols))
            lines.append('  ' + '  '.join('─' * w for _, w in cols))
            for row in rows:
                lines.append('  ' + '  '.join(
                    f'{str(row.get(c, "")):<{w}}'[:w] for c, w in cols))

        if 'ping' in data['sections']:
            s = data['sections']['ping']
            lines.append(f'\n▸ PING — {s["target"]}')
            lines.append(div)
            lines.append(
                f'  Sent:{s["sent"]}  Recv:{s["received"]}  Loss:{s["loss_pct"]}%  '
                f'Min:{s["min_ms"]}ms  Avg:{s["avg_ms"]}ms  Max:{s["max_ms"]}ms')
            for r in s['results']:
                rtt = f'{r["rtt_ms"]:.3f}ms' if r['rtt_ms'] >= 0 else 'TIMEOUT'
                lines.append(f'  seq={r["seq"]:<5} {r["ip"]:<18} ttl={r["ttl"]:<4} {rtt}')

        if 'traceroute' in data['sections']:
            section('TRACEROUTE', data['sections']['traceroute'],
                    [('hop', 5), ('ip', 18), ('hostname', 28),
                     ('rtt1', 10), ('rtt2', 10), ('rtt3', 10),
                     ('loss_pct', 8), ('asn', 24), ('geo', 20)])

        if 'mtr' in data['sections']:
            s = data['sections']['mtr']
            lines.append(f'\n▸ MTR — {s["target"]}')
            lines.append(div)
            section('', s['hops'],
                    [('hop', 5), ('ip', 18), ('hostname', 28),
                     ('loss_pct', 8), ('sent', 6), ('avg_ms', 8),
                     ('best_ms', 8), ('worst_ms', 8), ('stdev_ms', 6)])

        if 'port_scan' in data['sections']:
            section('PORT SCAN', data['sections']['port_scan'],
                    [('port', 7), ('service', 12), ('state', 14),
                     ('rtt_ms', 8), ('banner', 50)])

        if 'dns' in data['sections']:
            section('DNS', data['sections']['dns'],
                    [('type', 8), ('query', 30), ('answer', 40), ('rtt_ms', 8)])

        if 'arp' in data['sections']:
            section('ARP / L2 SCAN', data['sections']['arp'],
                    [('ip', 18), ('mac', 20), ('hostname', 30), ('interface', 14)])

        if 'netstat' in data['sections']:
            section('NETSTAT', data['sections']['netstat'],
                    [('proto', 6), ('local', 26), ('remote', 26),
                     ('state', 14), ('pid', 6), ('process', 20)])

        if 'ext_monitor' in data['sections']:
            lines.append(f'\n▸ EXTERNAL MONITOR')
            lines.append(div)
            fmt = '  {:<22} {:>6} {:>8} {:>8} {:>8} {:>8} {:>8}'
            lines.append(fmt.format('HOST', 'SENT', 'LOSS%', 'MIN', 'AVG', 'MAX', 'LAST'))
            lines.append('  ' + '─' * 68)
            for host, s in data['sections']['ext_monitor'].items():
                lines.append(fmt.format(
                    host, s.get('sent', 0),
                    f'{s.get("loss_pct", 0):.1f}%',
                    f'{s.get("min_ms", 0):.1f}ms',
                    f'{s.get("avg_ms", 0):.1f}ms',
                    f'{s.get("max_ms", 0):.1f}ms',
                    f'{s.get("last_ms", 0):.1f}ms'))

        lines.append(f'\n{div2}')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def _export_csv(self, path, data):
        import csv
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
                w.writerow(['sent', 'received', 'loss_pct', 'min_ms', 'avg_ms', 'max_ms'])
                w.writerow([s['sent'], s['received'], s['loss_pct'],
                            s['min_ms'], s['avg_ms'], s['max_ms']])
                w.writerow([])
                write_section('PING RESULTS', s['results'], ['seq', 'ip', 'ttl', 'rtt_ms'])

            for key, name, cols in [
                ('traceroute', 'TRACEROUTE',
                 ['hop', 'ip', 'hostname', 'rtt1', 'rtt2', 'rtt3', 'loss_pct', 'asn', 'geo']),
                ('port_scan',  'PORT SCAN',  ['port', 'service', 'state', 'rtt_ms', 'banner']),
                ('dns',        'DNS',        ['type', 'query', 'answer', 'rtt_ms', 'error']),
                ('arp',        'ARP',        ['ip', 'mac', 'hostname', 'interface']),
                ('netstat',    'NETSTAT',    ['proto', 'local', 'remote', 'state', 'pid', 'process']),
            ]:
                if key in data['sections']:
                    write_section(name, data['sections'][key], cols)

            if 'mtr' in data['sections']:
                s = data['sections']['mtr']
                w.writerow(['[MTR]', s['target']])
                write_section('MTR HOPS', s['hops'],
                              ['hop', 'ip', 'hostname', 'loss_pct', 'sent',
                               'avg_ms', 'best_ms', 'worst_ms', 'stdev_ms'])

            if 'ext_monitor' in data['sections']:
                rows = [{'host': h, **s}
                        for h, s in data['sections']['ext_monitor'].items()]
                write_section('EXT MONITOR', rows,
                              ['host', 'sent', 'received', 'loss_pct',
                               'min_ms', 'avg_ms', 'max_ms', 'last_ms'])

            if 'packet_capture' in data['sections']:
                s = data['sections']['packet_capture']
                w.writerow(['[PACKET CAPTURE]', s['count']])
                write_section('PACKETS', s['packets'],
                              ['time', 'proto', 'src', 'sport',
                               'dst', 'dport', 'flags', 'len'])

    def _export_json(self, path, data):
        import json
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

    # ── Session persistence ───────────────────────────────────────────────────

    def _save_session(self):
        try:
            session = {}
            for key, attr in [('PING', '_host_var'), ('DNS', '_host_var'),
                               ('SSL/TLS', '_host_var'), ('WHOIS', '_host_var')]:
                p = self._panels.get(key)
                if p:
                    v = getattr(p, attr, None)
                    if v and isinstance(v, tk.StringVar):
                        session[f'{key.lower()}_host'] = v.get()
            wol = self._panels.get('WAKE-ON-LAN')
            if wol and hasattr(wol, '_saved_lb'):
                session['wol_targets'] = list(wol._saved_lb.get(0, 'end'))
            with open(SESSION_FILE, 'w', encoding='utf-8') as f:
                json.dump(session, f, indent=2)
        except Exception:
            pass

    def _load_session(self):
        try:
            with open(SESSION_FILE, encoding='utf-8') as f:
                session = json.load(f)
        except Exception:
            return
        for key, attr, skey in [
            ('PING',    '_host_var', 'ping_host'),
            ('DNS',     '_host_var', 'dns_host'),
            ('SSL/TLS', '_host_var', 'ssl/tls_host'),
            ('WHOIS',   '_host_var', 'whois_host'),
        ]:
            val = session.get(skey, '')
            p   = self._panels.get(key)
            if p and val:
                v = getattr(p, attr, None)
                if v and isinstance(v, tk.StringVar):
                    v.set(val)
        try:
            wol = self._panels.get('WAKE-ON-LAN')
            if wol and hasattr(wol, '_saved_lb'):
                for entry in session.get('wol_targets', []):
                    if entry:
                        wol._saved_lb.insert('end', entry)
        except Exception:
            pass

    # ── Tool dialogs ──────────────────────────────────────────────────────────

    def _clear_asn_cache(self):
        try:
            from core.engine import _asn_cache
            _asn_cache.clear()
            from tkinter import messagebox
            messagebox.showinfo('ASN Cache', 'ASN cache cleared.')
        except Exception:
            pass

    def _clear_geoip_cache(self):
        try:
            from core.engine import _geoip_cache
            _geoip_cache.clear()
            from tkinter import messagebox
            messagebox.showinfo('GeoIP Cache', 'GeoIP cache cleared.')
        except Exception:
            pass

    def _check_deps(self):
        win = tk.Toplevel(self.root)
        win.title('Dependency Check')
        win.configure(bg=BG_PANEL)
        win.geometry('580x300')
        win.grab_set()

        from .widgets import CardFrame
        card = CardFrame(win, title='DEPENDENCY STATUS')
        card.pack(fill='both', expand=True, padx=12, pady=12)

        text = tk.Text(card.body, **TEXT_OPTS, height=11)
        text.pack(fill='both', expand=True, padx=6, pady=6)
        text.tag_configure('ok',   foreground=ACCENT_GREEN)
        text.tag_configure('warn', foreground=ACCENT_YELLOW)
        text.tag_configure('hdr',  foreground=ACCENT_CYAN,
                           font=(MONO, 9, 'bold'))

        deps = [
            ('scapy',       'Packet capture, ARP scanning (L2/L3/L4)'),
            ('dns',         'Full DNS record types (dnspython)'),
            ('psutil',      'Network interface enum, Netstat process info'),
            ('cryptography','Enhanced SSL certificate parsing'),
        ]
        text.insert('end', f'  {"PACKAGE":<16} {"STATUS":<26} PROVIDES\n', 'hdr')
        text.insert('end', f'  {"─"*16}  {"─"*24}  {"─"*28}\n', 'hdr')
        for mod, desc in deps:
            try:
                __import__(mod)
                status, tag = '✓  installed', 'ok'
            except ImportError:
                status, tag = '✗  not found (fallback)', 'warn'
            text.insert('end', f'  {mod:<16}  {status:<26}  {desc}\n', tag)
        text.insert('end', '\n  pip install scapy dnspython psutil cryptography\n', 'hdr')
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
        tree = DarkTreeview(card.body, ('name', 'ip', 'netmask'),
                            ('INTERFACE', 'IP ADDRESS', 'NETMASK'), (140, 150, 150))
        tree.pack(fill='both', expand=True, padx=6, pady=6)
        for iface in ifaces:
            tree.insert((iface['name'], iface['ip'], iface['netmask']))

    def _show_osi_ref(self):
        layers = [
            ('L7', 'Application',  'HTTP FTP DNS SMTP SSH',  'DNS / HTTP Probe / SSL'),
            ('L6', 'Presentation', 'TLS/SSL encoding',       'SSL/TLS Inspector'),
            ('L5', 'Session',      'NetBIOS RPC',            'Packet Capture'),
            ('L4', 'Transport',    'TCP UDP — ports / flow', 'Port Scan / Bandwidth'),
            ('L3', 'Network',      'IP ICMP routing',        'Ping / Traceroute / MTR'),
            ('L2', 'Data Link',    'Ethernet ARP MAC',       'L2 / ARP / Wake-on-LAN'),
            ('L1', 'Physical',     'Cables NICs signals',    '—'),
        ]
        win = tk.Toplevel(self.root)
        win.title('OSI Layer Reference')
        win.configure(bg=BG_PANEL)
        win.geometry('660x300')
        win.grab_set()
        from .widgets import CardFrame, DarkTreeview
        card = CardFrame(win, title='OSI MODEL — NETPROBE COVERAGE')
        card.pack(fill='both', expand=True, padx=12, pady=12)
        tree = DarkTreeview(card.body,
                            ('layer', 'name', 'protocols', 'tool'),
                            ('LAYER', 'NAME', 'PROTOCOLS', 'NETPROBE'),
                            (55, 110, 200, 220))
        tree.pack(fill='both', expand=True, padx=6, pady=6)
        tree.tree.tag_configure('ok',  foreground=ACCENT_GREEN)
        tree.tree.tag_configure('dim', foreground=FG_DIM)
        for row in layers:
            tree.insert(row, tags=('dim' if row[3] == '—' else 'ok',))

    def _show_shortcuts(self):
        win = tk.Toplevel(self.root)
        win.title('Keyboard Shortcuts')
        win.configure(bg=BG_PANEL)
        win.geometry('380x340')
        win.grab_set()
        from .widgets import CardFrame
        card = CardFrame(win, title='KEYBOARD SHORTCUTS')
        card.pack(fill='both', expand=True, padx=12, pady=12)
        text = tk.Text(card.body, **TEXT_OPTS, height=14)
        text.pack(fill='both', expand=True, padx=6, pady=6)
        text.tag_configure('key', foreground=ACCENT_CYAN,
                           font=(MONO, 9, 'bold'))
        text.tag_configure('dim', foreground=FG_DIM)
        shortcuts = [
            ('Ctrl+1 … Ctrl+9', 'Jump to tool 1–9'),
            ('Ctrl+B',          'Toggle sidebar'),
            ('Ctrl+E',          'Export results'),
            ('Ctrl+W',          'Exit'),
            ('Right-click log', 'Copy / Clear log'),
            ('Right-click table', 'Copy row / Copy all / Navigate'),
            ('Click column header', 'Sort by column'),
        ]
        for key, desc in shortcuts:
            text.insert('end', f'  {key:<24}', 'key')
            text.insert('end', f'  {desc}\n', 'dim')
        text.configure(state='disabled')

    def _show_about(self):
        win = tk.Toplevel(self.root)
        win.title('About NetProbe')
        win.configure(bg=BG_PANEL)
        win.geometry('440x300')
        win.resizable(False, False)
        win.grab_set()
        tk.Label(win, text='⬡', bg=BG_PANEL, fg=ACCENT_GREEN,
                 font=(MONO, 36)).pack(pady=(20, 4))
        tk.Label(win, text='NetProbe', bg=BG_PANEL, fg=ACCENT_CYAN,
                 font=(MONO, 18, 'bold')).pack()
        tk.Label(win, text=f'v{VERSION}  —  Network Analysis Utility',
                 bg=BG_PANEL, fg=FG_DIM, font=FONT_UI).pack(pady=2)
        tk.Frame(win, bg=BORDER_DIM, height=1).pack(fill='x', padx=40, pady=8)
        tk.Label(win,
                 text='Ping · Traceroute · MTR · Bandwidth (iperf3)\n'
                      'Port Scan (TCP/UDP) · DNS + DoH · ARP · Netstat\n'
                      'SSL/TLS · HTTP Probe · WHOIS · Wake-on-LAN\n'
                      'Ext Monitor · Pkt Capture · GeoIP · ASN Lookup\n'
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

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _on_close(self):
        self._save_session()
        for panel in self._panels.values():
            for attr in ('_monitor', '_mtr', '_capture', '_after_id'):
                obj = getattr(panel, attr, None)
                if obj is None:
                    continue
                if attr == '_after_id':
                    try:
                        panel.after_cancel(obj)
                    except Exception:
                        pass
                else:
                    try:
                        if hasattr(obj, 'stop_all'):
                            obj.stop_all()
                        elif hasattr(obj, 'stop'):
                            obj.stop()
                    except Exception:
                        pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()
