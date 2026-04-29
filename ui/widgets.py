"""
NetProbe Reusable Widgets
"""
import tkinter as tk
from tkinter import ttk
from .theme import *
import datetime
import time as _time


def apply_treeview_style(style: ttk.Style, compact: bool = False):
    rh = 20 if compact else 24
    style.theme_use('clam')
    style.configure('Dark.Treeview',
                    background=TREE_STYLE['background'],
                    foreground=TREE_STYLE['foreground'],
                    fieldbackground=TREE_STYLE['fieldbackground'],
                    rowheight=rh,
                    font=TREE_STYLE['font'])
    style.configure('Dark.Treeview.Heading',
                    background=BG_INPUT,
                    foreground=ACCENT_CYAN,
                    relief='flat',
                    font=(_MONO, 9, 'bold'))
    style.map('Dark.Treeview',
              background=[('selected', BG_SELECT)],
              foreground=[('selected', FG_BRIGHT)])
    style.map('Dark.Treeview.Heading',
              background=[('active', BG_HOVER)],
              foreground=[('active', FG_BRIGHT)])
    style.configure('Dark.Vertical.TScrollbar',
                    background=BG_INPUT, troughcolor=BG_CARD,
                    arrowcolor=FG_DIM, bordercolor=BG_CARD,
                    relief='flat', width=10)
    style.configure('Dark.Horizontal.TScrollbar',
                    background=BG_INPUT, troughcolor=BG_CARD,
                    arrowcolor=FG_DIM, bordercolor=BG_CARD,
                    relief='flat', width=10)
    style.configure('Dark.TCombobox',
                    fieldbackground=BG_INPUT, background=BG_INPUT,
                    foreground=FG_PRIMARY, arrowcolor=FG_DIM,
                    selectbackground=BG_SELECT, selectforeground=FG_BRIGHT)


# ─────────────────────────────────────────────
# Tooltip
# ─────────────────────────────────────────────

class Tooltip:
    def __init__(self, widget, text: str, delay: int = 600):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._tip_window = None
        self._job = None
        widget.bind('<Enter>', self._schedule)
        widget.bind('<Leave>', self._cancel)
        widget.bind('<ButtonPress>', self._cancel)

    def _schedule(self, event=None):
        self._cancel()
        self._job = self.widget.after(self.delay, self._show)

    def _cancel(self, event=None):
        if self._job:
            self.widget.after_cancel(self._job)
            self._job = None
        self._hide()

    def _show(self):
        if self._tip_window:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f'+{x}+{y}')
        tw.configure(bg=BORDER_ACTIVE)
        tk.Label(tw, text=self.text, bg=BG_INPUT, fg=FG_PRIMARY,
                 font=FONT_LABEL, padx=8, pady=4, relief='flat').pack()

    def _hide(self):
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None


# ─────────────────────────────────────────────
# Card Frame
# ─────────────────────────────────────────────

class CardFrame(tk.Frame):
    def __init__(self, parent, title='', right_text='', **kw):
        super().__init__(parent, **{**CARD_OPTS, **kw})
        if title:
            hdr = tk.Frame(self, bg=BG_INPUT, highlightthickness=0)
            hdr.pack(fill='x')
            tk.Label(hdr, text=f'  {title.upper()}', bg=BG_INPUT,
                     fg=ACCENT_CYAN, font=FONT_TINY_BOLD,
                     pady=5).pack(side='left')
            if right_text:
                self._right_lbl = tk.Label(hdr, text=right_text,
                                           bg=BG_INPUT, fg=FG_DIM,
                                           font=FONT_LABEL, padx=8)
                self._right_lbl.pack(side='right')
            tk.Frame(self, bg=BORDER_ACCENT, height=1).pack(fill='x')
        self.body = tk.Frame(self, bg=BG_CARD)
        self.body.pack(fill='both', expand=True)


# ─────────────────────────────────────────────
# Labeled Entry
# ─────────────────────────────────────────────

class LabeledEntry(tk.Frame):
    def __init__(self, parent, label: str, default: str = '',
                 width: int = 24, tooltip: str = '', **kw):
        super().__init__(parent, bg=BG_PANEL)
        tk.Label(self, text=label, **LABEL_OPTS,
                 width=14, anchor='e').pack(side='left', padx=(0, 4))
        self.var = tk.StringVar(value=default)
        self.entry = tk.Entry(self, textvariable=self.var,
                              width=width, **ENTRY_OPTS)
        self.entry.pack(side='left', ipady=3)
        if tooltip:
            Tooltip(self.entry, tooltip)

    def get(self): return self.var.get().strip()
    def set(self, v): self.var.set(v)


# ─────────────────────────────────────────────
# Scrolled Text  (optional auto-timestamps)
# ─────────────────────────────────────────────

class ScrolledText(tk.Frame):
    def __init__(self, parent, timestamps: bool = False, **kw):
        super().__init__(parent, bg=BG_CARD)
        self._timestamps = timestamps
        self.text = tk.Text(self, **{**TEXT_OPTS, **kw})
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.text.yview,
                            style='Dark.Vertical.TScrollbar')
        self.text.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.text.pack(side='left', fill='both', expand=True)
        self._menu = tk.Menu(self.text, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                             activebackground=BG_SELECT, activeforeground=FG_BRIGHT)
        self._menu.add_command(label='Copy Selection', command=self._copy)
        self._menu.add_command(label='Select All',     command=self._select_all)
        self._menu.add_separator()
        self._menu.add_command(label='Clear Log',      command=self.clear)
        self.text.bind('<Button-3>', self._show_menu)
        # pre-configure timestamp tag (dim cyan)
        self.text.tag_configure('_ts', foreground='#2a5a6a', font=(_MONO, 8))

    def _show_menu(self, event):
        self._menu.tk_popup(event.x_root, event.y_root)

    def _copy(self):
        try:
            sel = self.text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.text.clipboard_clear()
            self.text.clipboard_append(sel)
        except tk.TclError:
            pass

    def _select_all(self):
        self.text.tag_add(tk.SEL, '1.0', tk.END)

    def append(self, text: str, tag: str = ''):
        self.text.configure(state='normal')
        if self._timestamps and text and text != '\n':
            ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
            self.text.insert('end', f'[{ts}] ', '_ts')
        self.text.insert('end', text, tag)
        self.text.see('end')
        self.text.configure(state='disabled')

    def clear(self):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.configure(state='disabled')

    def configure_tags(self, **tags):
        for name, opts in tags.items():
            self.text.tag_configure(name, **opts)


# ─────────────────────────────────────────────
# Dark Treeview
# ─────────────────────────────────────────────

class DarkTreeview(tk.Frame):
    """Treeview: dark scrollbars, alternating rows, sortable columns, copy + shell-cmd menu."""

    def __init__(self, parent, columns, headings, widths=None, **kw):
        super().__init__(parent, bg=BG_CARD)
        self.tree = ttk.Treeview(self, columns=columns, show='headings',
                                 style='Dark.Treeview', **kw)
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview,
                            style='Dark.Vertical.TScrollbar')
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview,
                            style='Dark.Horizontal.TScrollbar')
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for i, col in enumerate(columns):
            heading = headings[i] if i < len(headings) else col
            width = widths[i] if widths and i < len(widths) else 100
            self.tree.heading(col, text=heading,
                              command=lambda c=col: self._sort_by(c, False))
            self.tree.column(col, width=width, minwidth=30)

        self.tree.tag_configure('evenrow', background='#111820')
        self.tree.tag_configure('oddrow',  background=BG_CARD)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._shell_cmd_fn = None
        self._menu = tk.Menu(self.tree, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                             activebackground=BG_SELECT, activeforeground=FG_BRIGHT)
        self._menu.add_command(label='Copy Row',  command=self._copy_row)
        self._menu.add_command(label='Copy All',  command=self._copy_all)
        self._menu.add_separator()
        self._menu.add_command(label='Copy as shell command',
                               command=self._copy_shell, state='disabled')
        self.tree.bind('<Button-3>', self._show_menu)

        self._row_count = 0

    def set_shell_cmd_fn(self, fn):
        """Register fn(values) -> str. Enables 'Copy as shell command' menu item."""
        self._shell_cmd_fn = fn
        self._menu.entryconfigure('Copy as shell command', state='normal')

    def _show_menu(self, event):
        self._menu.tk_popup(event.x_root, event.y_root)

    def _copy_row(self):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0])['values']
            self.tree.clipboard_clear()
            self.tree.clipboard_append('\t'.join(str(v) for v in vals))

    def _copy_all(self):
        lines = []
        for item in self.tree.get_children():
            vals = self.tree.item(item)['values']
            lines.append('\t'.join(str(v) for v in vals))
        self.tree.clipboard_clear()
        self.tree.clipboard_append('\n'.join(lines))

    def _copy_shell(self):
        if not self._shell_cmd_fn:
            return
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0])['values']
            cmd = self._shell_cmd_fn(vals)
            if cmd:
                self.tree.clipboard_clear()
                self.tree.clipboard_append(cmd)

    def _sort_by(self, col, reverse):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            items.sort(
                key=lambda t: float(
                    str(t[0]).replace('ms','').replace('%','').replace('*','').strip() or '0'),
                reverse=reverse)
        except (ValueError, AttributeError):
            items.sort(reverse=reverse)
        for index, (_, k) in enumerate(items):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self._sort_by(col, not reverse))

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._row_count = 0

    def insert(self, values, tags=()):
        row_tag = 'evenrow' if self._row_count % 2 == 0 else 'oddrow'
        all_tags = tuple(tags) + (row_tag,)
        iid = self.tree.insert('', 'end', values=values, tags=all_tags)
        self._row_count += 1
        return iid

    def set_row_color(self, iid, fg):
        self.tree.tag_configure(iid, foreground=fg)


# ─────────────────────────────────────────────
# Status Bar
# ─────────────────────────────────────────────

class StatusBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg='#060809',
                         highlightthickness=1,
                         highlightbackground=BORDER_DIM)
        self._labels = {}
        self._pulse_job = None
        self._pulse_state = False
        self._compact = False

        self._add_segment('status',   '● READY', ACCENT_GREEN)
        self._vsep()
        self._add_segment('activity', '',         FG_DIM)
        self._vsep()
        self._add_segment('ip',       '',         FG_DIM)

        # Right side
        self._add_segment('time',  '', FG_DIM,    side='right')
        self._vsep(side='right')

        # Compact density toggle
        self._density_btn = tk.Label(
            self, text='⊟', bg='#060809', fg=FG_DIM,
            font=(_MONO, 10), padx=6, cursor='hand2')
        self._density_btn.pack(side='right')
        self._density_btn.bind('<Button-1>', self._toggle_density)
        Tooltip(self._density_btn, 'Toggle compact row density')
        self._vsep(side='right')

        self._add_segment('admin', self._check_admin(), FG_DIM, side='right')
        self._vsep(side='right')

        self._tick()

    def _check_admin(self):
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return '⚡ ADMIN '
        except Exception:
            pass
        return '○ USER '

    def _vsep(self, side='left'):
        tk.Frame(self, bg=BORDER_DIM, width=1).pack(
            side=side, fill='y', pady=3, padx=1)

    def _add_segment(self, key, text, color, side='left'):
        lbl = tk.Label(self, text=text, bg='#060809', fg=color,
                       font=(_MONO, 8), padx=8, pady=3)
        lbl.pack(side=side)
        self._labels[key] = lbl

    def set_status(self, text, color=ACCENT_GREEN):
        self._labels['status'].configure(text=f'● {text}', fg=color)

    def set_activity(self, text, color=ACCENT_CYAN):
        self._labels['activity'].configure(text=text, fg=color)

    def set_ip(self, text):
        self._labels['ip'].configure(text=text)

    def start_pulse(self, text='RUNNING'):
        self._pulse_text = text
        self._pulse_state = False
        self._do_pulse()

    def stop_pulse(self, text='READY', color=ACCENT_GREEN):
        if self._pulse_job:
            self._labels['status'].after_cancel(self._pulse_job)
            self._pulse_job = None
        self.set_status(text, color)

    def _do_pulse(self):
        self._pulse_state = not self._pulse_state
        dot  = '●' if self._pulse_state else '○'
        col  = ACCENT_GREEN if self._pulse_state else ACCENT_YELLOW
        self._labels['status'].configure(
            text=f'{dot} {self._pulse_text}', fg=col)
        self._pulse_job = self._labels['status'].after(600, self._do_pulse)

    def _toggle_density(self, _=None):
        self._compact = not self._compact
        self._density_btn.configure(
            fg=ACCENT_CYAN if self._compact else FG_DIM)
        # Update the global treeview style
        try:
            style = ttk.Style()
            rh = 20 if self._compact else 24
            style.configure('Dark.Treeview', rowheight=rh)
        except Exception:
            pass

    def _tick(self):
        self._labels['time'].configure(
            text=f'  {datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")}  ')
        self._labels['time'].after(1000, self._tick)


# ─────────────────────────────────────────────
# Canvas RTT Graph  (replaces text sparkline)
# ─────────────────────────────────────────────

class RTTGraph(tk.Frame):
    """Canvas-based RTT line graph with threshold bands and filled area."""

    _BANDS = [
        (0,   50,  '#001a0d'),   # green zone bg
        (50,  150, '#1a1400'),   # yellow zone bg
        (150, 300, '#1a0900'),   # orange zone bg
    ]

    def __init__(self, parent, height=72, max_points=120,
                 label='RTT GRAPH', **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        self._data      = []
        self._max_pts   = max_points
        self._ceil      = 200.0

        hdr = tk.Frame(self, bg=BG_CARD)
        hdr.pack(fill='x', padx=6, pady=(4, 0))
        tk.Label(hdr, text=label, bg=BG_CARD, fg=FG_DIM,
                 font=FONT_TINY_BOLD).pack(side='left')
        self._stat_lbl = tk.Label(hdr, text='', bg=BG_CARD,
                                  fg=FG_DIM, font=FONT_MONO_SM)
        self._stat_lbl.pack(side='right')

        self._cv = tk.Canvas(self, bg=BG_CARD, height=height,
                             highlightthickness=0, bd=0)
        self._cv.pack(fill='x', padx=6, pady=(2, 4))
        self._cv.bind('<Configure>', lambda e: self._draw())

    def push(self, value: float):
        self._data.append(value)
        if len(self._data) > self._max_pts:
            self._data = self._data[-self._max_pts:]
        valid = [v for v in self._data if v >= 0]
        if valid:
            self._ceil = max(max(valid) * 1.15, 50.0)
            last = valid[-1]
            avg  = sum(valid) / len(valid)
            loss = (len(self._data) - len(valid)) / len(self._data) * 100
            self._stat_lbl.configure(
                text=(f'last {last:.1f}  avg {avg:.1f}  '
                      f'min {min(valid):.1f}  max {max(valid):.1f}  '
                      f'loss {loss:.0f}%  ms'),
                fg=latency_color(last))
        else:
            self._stat_lbl.configure(text='100% loss', fg=ACCENT_RED)
        self._draw()

    def _draw(self):
        cv = self._cv
        cv.delete('all')
        W = cv.winfo_width()
        H = cv.winfo_height()
        if W < 4 or H < 4:
            return
        data  = self._data
        n     = len(data)
        if n == 0:
            return
        scale = max(self._ceil, 1.0)

        def fy(ms):
            return H - max(2, int(ms / scale * (H - 4))) - 2

        # Threshold band backgrounds
        for lo, hi, col in self._BANDS:
            if hi <= scale * 1.05:
                y0 = fy(min(hi, scale))
                y1 = min(fy(lo) + 2, H)
                if y1 > y0:
                    cv.create_rectangle(0, y0, W, y1, fill=col, outline='')

        # Y-axis guides with labels
        for mark in [50, 100, 200, 300, 500, 1000]:
            if mark > scale * 1.1:
                break
            y = fy(mark)
            if 0 <= y <= H:
                cv.create_line(0, y, W, y, fill=BORDER_DIM, dash=(3, 8))
                cv.create_text(W - 2, y + 1, text=f'{mark}ms', anchor='se',
                               fill=FG_DIM, font=(_MONO, 7))

        # Build and draw data segments
        step = W / max(n, 1)
        seg  = []

        def flush(seg):
            if len(seg) < 2:
                if len(seg) == 1:
                    x, y, _ = seg[0]
                    cv.create_oval(x-2, y-2, x+2, y+2,
                                   fill=ACCENT_GREEN, outline='')
                return
            pts    = [(x, y) for x, y, _ in seg]
            last_v = seg[-1][2]
            color  = latency_color(last_v)
            poly   = pts + [(pts[-1][0], H), (pts[0][0], H)]
            flat_p = [c for pt in poly for c in pt]
            cv.create_polygon(flat_p, fill='#001a09', outline='')
            flat_l = [c for pt in pts for c in pt]
            if len(flat_l) >= 4:
                cv.create_line(flat_l, fill=color, width=1, smooth=True)

        for i, v in enumerate(data):
            x = (i + 0.5) * step
            if v < 0:
                flush(seg)
                seg = []
                cv.create_line(x, H - 6, x, H, fill=ACCENT_RED, width=1)
            else:
                seg.append((x, fy(v), v))
        flush(seg)


# ─────────────────────────────────────────────
# Mini Graph (legacy text sparkline — kept for
# non-RTT uses like bandwidth throughput)
# ─────────────────────────────────────────────

class MiniGraph(tk.Frame):
    BARS = ' ▁▂▃▄▅▆▇█'

    def __init__(self, parent, width=200, height=40, max_points=60, **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        self._graph_data = []
        self._max_points = max_points

        hdr = tk.Frame(self, bg=BG_CARD)
        hdr.pack(fill='x', padx=6, pady=(4, 0))
        tk.Label(hdr, text='SPARKLINE', bg=BG_CARD, fg=FG_DIM,
                 font=FONT_TINY_BOLD).pack(side='left')
        self._stat_lbl = tk.Label(hdr, text='', bg=BG_CARD,
                                  fg=FG_DIM, font=(_MONO, 8))
        self._stat_lbl.pack(side='right')

        self._spark_lbl = tk.Label(self, text='', bg=BG_CARD,
                                   fg=ACCENT_GREEN,
                                   font=(_MONO, 13),
                                   anchor='w', padx=6, pady=3)
        self._spark_lbl.pack(fill='x')

    def push(self, value: float):
        self._graph_data.append(value)
        if len(self._graph_data) > self._max_points:
            self._graph_data = self._graph_data[-self._max_points:]
        self._redraw()

    def _redraw(self):
        data = self._graph_data
        if not data:
            return
        valid = [v for v in data if v >= 0]
        if valid:
            max_v = max(valid) or 1
            parts = []
            for v in data:
                if v < 0:
                    parts.append('✕')
                else:
                    idx = min(int((v / max_v) * 8), 8)
                    parts.append(self.BARS[idx])
            last = valid[-1]
            color = latency_color(last)
            self._spark_lbl.configure(text=''.join(parts), fg=color)
            avg = sum(valid) / len(valid)
            loss = (len(data) - len(valid)) / len(data) * 100
            self._stat_lbl.configure(
                text=f'last {last:.1f}  avg {avg:.1f}  '
                     f'min {min(valid):.1f}  max {max(valid):.1f}  '
                     f'loss {loss:.0f}%  ms',
                fg=color)
        else:
            self._spark_lbl.configure(
                text='✕ ' * min(len(data), 40), fg=ACCENT_RED)
            self._stat_lbl.configure(text='100% loss', fg=ACCENT_RED)


# ─────────────────────────────────────────────
# Thread helper
# ─────────────────────────────────────────────

def run_in_thread(func, *args, callback=None, **kwargs):
    import threading
    def _run():
        result = func(*args, **kwargs)
        if callback:
            callback(result)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t
