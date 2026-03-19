"""
NetProbe Reusable Widgets — Polished
"""
import tkinter as tk
from tkinter import ttk
from .theme import *
import datetime


def apply_treeview_style(style: ttk.Style):
    style.theme_use('clam')
    style.configure('Dark.Treeview',
                    background=TREE_STYLE['background'],
                    foreground=TREE_STYLE['foreground'],
                    fieldbackground=TREE_STYLE['fieldbackground'],
                    rowheight=24,
                    font=TREE_STYLE['font'])
    style.configure('Dark.Treeview.Heading',
                    background=BG_INPUT,
                    foreground=ACCENT_CYAN,
                    relief='flat',
                    font=('Segoe UI', 9, 'bold'))
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
                     fg=ACCENT_CYAN, font=('Segoe UI', 8, 'bold'),
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
# Scrolled Text
# ─────────────────────────────────────────────

class ScrolledText(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_CARD)
        self.text = tk.Text(self, **{**TEXT_OPTS, **kw})
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.text.yview,
                            style='Dark.Vertical.TScrollbar')
        self.text.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.text.pack(side='left', fill='both', expand=True)
        # Right-click context menu
        self._menu = tk.Menu(self.text, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                             activebackground=BG_SELECT, activeforeground=FG_BRIGHT)
        self._menu.add_command(label='Copy Selection', command=self._copy)
        self._menu.add_command(label='Select All',     command=self._select_all)
        self._menu.add_separator()
        self._menu.add_command(label='Clear Log',      command=self.clear)
        self.text.bind('<Button-3>', self._show_menu)

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
    """Treeview with dark scrollbars, alternating rows, sortable columns, copy menu"""
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

        # Alternating row colors
        self.tree.tag_configure('evenrow', background='#111820')
        self.tree.tag_configure('oddrow',  background=BG_CARD)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Right-click copy menu
        self._menu = tk.Menu(self.tree, tearoff=0, bg=BG_INPUT, fg=FG_PRIMARY,
                             activebackground=BG_SELECT, activeforeground=FG_BRIGHT)
        self._menu.add_command(label='Copy Row',  command=self._copy_row)
        self._menu.add_command(label='Copy All',  command=self._copy_all)
        self.tree.bind('<Button-3>', self._show_menu)

        self._row_count = 0

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
        self._add_segment('status',   '● READY', ACCENT_GREEN)
        self._vsep()
        self._add_segment('activity', '',         FG_DIM)
        self._vsep()
        self._add_segment('ip',       '',         FG_DIM)

        # Right side
        self._add_segment('time',  '', FG_DIM,    side='right')
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
                       font=('Courier New', 8), padx=8, pady=3)
        lbl.pack(side=side)
        self._labels[key] = lbl

    def set_status(self, text, color=ACCENT_GREEN):
        self._labels['status'].configure(text=f'● {text}', fg=color)

    def set_activity(self, text, color=ACCENT_CYAN):
        self._labels['activity'].configure(text=text, fg=color)

    def set_ip(self, text):
        self._labels['ip'].configure(text=text)

    def _tick(self):
        self._labels['time'].configure(
            text=f'  {datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")}  ')
        self._labels['time'].after(1000, self._tick)


# ─────────────────────────────────────────────
# Mini Graph
# ─────────────────────────────────────────────

class MiniGraph(tk.Frame):
    """Sparkline RTT graph — Label-based, Python 3.14 safe"""
    BARS = ' ▁▂▃▄▅▆▇█'

    def __init__(self, parent, width=200, height=40, max_points=60, **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        self._graph_data = []
        self._max_points = max_points

        hdr = tk.Frame(self, bg=BG_CARD)
        hdr.pack(fill='x', padx=6, pady=(4, 0))
        tk.Label(hdr, text='SPARKLINE', bg=BG_CARD, fg=FG_DIM,
                 font=('Segoe UI', 7, 'bold')).pack(side='left')
        self._stat_lbl = tk.Label(hdr, text='', bg=BG_CARD,
                                  fg=FG_DIM, font=('Courier New', 8))
        self._stat_lbl.pack(side='right')

        self._spark_lbl = tk.Label(self, text='', bg=BG_CARD,
                                   fg=ACCENT_GREEN,
                                   font=('Courier New', 13),
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
