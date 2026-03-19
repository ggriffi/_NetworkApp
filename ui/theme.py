"""
NetProbe UI Theme - Dark terminal aesthetic
Monospace/industrial with green-on-black terminal feel
"""

# ─── Color Palette ───────────────────────────────────────────────
BG_ROOT     = '#0a0c0e'   # root window background
BG_PANEL    = '#0f1214'   # main panel
BG_CARD     = '#141820'   # card/frame backgrounds
BG_INPUT    = '#1a1f28'   # input fields
BG_HOVER    = '#1e2530'   # hover state
BG_SELECT   = '#0d2137'   # selected row

FG_PRIMARY  = '#c8d8e8'   # primary text
FG_DIM      = '#6a7a8a'   # dimmed/label text
FG_BRIGHT   = '#e8f0f8'   # bright/heading text

# Accent colors
ACCENT_GREEN  = '#00cc66'   # OK / live / good
ACCENT_CYAN   = '#00b4d8'   # info / headers
ACCENT_YELLOW = '#f0c040'   # warning / medium latency
ACCENT_RED    = '#ff4444'   # error / high loss / down
ACCENT_ORANGE = '#ff8800'   # high latency / caution
ACCENT_BLUE   = '#4488ff'   # interactive / links
ACCENT_PURPLE = '#9966ff'   # special / alternate

# Border colors
BORDER_DIM    = '#1e2a35'
BORDER_ACTIVE = '#2a3f55'
BORDER_ACCENT = '#004488'

# Latency color thresholds (ms)
def latency_color(ms: float) -> str:
    if ms < 0:    return ACCENT_RED
    if ms < 50:   return ACCENT_GREEN
    if ms < 150:  return ACCENT_YELLOW
    if ms < 300:  return ACCENT_ORANGE
    return ACCENT_RED

def loss_color(pct: float) -> str:
    if pct == 0:   return ACCENT_GREEN
    if pct < 5:    return ACCENT_YELLOW
    if pct < 20:   return ACCENT_ORANGE
    return ACCENT_RED

# ─── Fonts ───────────────────────────────────────────────────────
FONT_MONO_SM  = ('Courier New', 9)
FONT_MONO     = ('Courier New', 10)
FONT_MONO_MD  = ('Courier New', 11)
FONT_MONO_LG  = ('Courier New', 13, 'bold')
FONT_UI       = ('Segoe UI', 10)         # Windows preferred
FONT_UI_SM    = ('Segoe UI', 9)
FONT_UI_BOLD  = ('Segoe UI', 10, 'bold')
FONT_HEADING  = ('Segoe UI', 12, 'bold')
FONT_TITLE    = ('Segoe UI', 16, 'bold')
FONT_LABEL    = ('Segoe UI', 9)

# ─── Widget defaults ─────────────────────────────────────────────
ENTRY_OPTS = dict(
    bg=BG_INPUT, fg=FG_PRIMARY, insertbackground=FG_PRIMARY,
    relief='flat', bd=0, font=FONT_MONO,
    highlightthickness=1, highlightcolor=BORDER_ACTIVE,
    highlightbackground=BORDER_DIM
)

TEXT_OPTS = dict(
    bg=BG_CARD, fg=FG_PRIMARY, insertbackground=FG_PRIMARY,
    relief='flat', bd=0, font=FONT_MONO,
    highlightthickness=1, highlightcolor=BORDER_ACTIVE,
    highlightbackground=BORDER_DIM,
    selectbackground=BG_SELECT, selectforeground=FG_BRIGHT
)

BUTTON_OPTS = dict(
    bg=BG_INPUT, fg=ACCENT_CYAN, activebackground=BG_HOVER,
    activeforeground=ACCENT_CYAN, relief='flat', bd=0,
    font=FONT_UI_BOLD, cursor='hand2',
    highlightthickness=1, highlightcolor=BORDER_ACCENT,
    highlightbackground=BORDER_DIM, padx=12, pady=5
)

BUTTON_RED_OPTS = dict(
    bg='#2a0808', fg=ACCENT_RED, activebackground='#3a1010',
    activeforeground=ACCENT_RED, relief='flat', bd=0,
    font=FONT_UI_BOLD, cursor='hand2',
    highlightthickness=1, highlightcolor=ACCENT_RED,
    highlightbackground='#2a0808', padx=12, pady=5
)

BUTTON_GREEN_OPTS = dict(
    bg='#082a14', fg=ACCENT_GREEN, activebackground='#0d3a1c',
    activeforeground=ACCENT_GREEN, relief='flat', bd=0,
    font=FONT_UI_BOLD, cursor='hand2',
    highlightthickness=1, highlightcolor=ACCENT_GREEN,
    highlightbackground='#082a14', padx=12, pady=5
)

LABEL_OPTS = dict(bg=BG_PANEL, fg=FG_DIM, font=FONT_LABEL)
LABEL_CARD_OPTS = dict(bg=BG_CARD, fg=FG_DIM, font=FONT_LABEL)
FRAME_OPTS = dict(bg=BG_PANEL, relief='flat')
CARD_OPTS  = dict(bg=BG_CARD, relief='flat',
                  highlightthickness=1, highlightbackground=BORDER_DIM)

LISTBOX_OPTS = dict(
    bg=BG_CARD, fg=FG_PRIMARY, font=FONT_MONO,
    relief='flat', bd=0, selectbackground=BG_SELECT,
    selectforeground=FG_BRIGHT, activestyle='none',
    highlightthickness=1, highlightcolor=BORDER_ACTIVE,
    highlightbackground=BORDER_DIM
)

# Treeview style config
TREE_STYLE = {
    'background': BG_CARD,
    'foreground': FG_PRIMARY,
    'fieldbackground': BG_CARD,
    'rowheight': 22,
    'font': FONT_MONO_SM,
}
TREE_HEADING_STYLE = {
    'background': BG_INPUT,
    'foreground': ACCENT_CYAN,
    'relief': 'flat',
    'font': ('Segoe UI', 9, 'bold'),
}
