#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Password Generator GUI (PySide6)
- Cryptographically secure (uses secrets)
- Character-based mode with per-class "must contain" counts
- Passphrase (wordlist) mode with loadable wordlist
- Single or multiple outputs
- Exclude ambiguous characters option
- Live entropy estimate
- Copy-first / Copy-all / Save buttons
- Remembers ALL settings & geometry between sessions
"""

import csv
import math
import secrets
import string
import sys
from pathlib import Path
from typing import List, Dict

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QGuiApplication, QClipboard
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    QSizePolicy,
    QSpacerItem,
)

# ---------------- Constants & defaults ----------------

AMBIGUOUS = set("Il1O0B8S5Z2QG6")
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,./?~"

APP_DIR = Path(__file__).resolve().parent
SETTINGS_ORG = "BryanTools"
SETTINGS_APP = "PasswordGenerator"
SETTINGS_WORDLIST = "wordlist_path"
DEFAULT_OUTPUT_DIR = APP_DIR / "generated_passwords"


# Small fallback list (use "Load wordlist…" for real security)
FALLBACK_WORDS = [
    "able","about","above","acid","acorn","actor","adapt","agent","agree","ahead","album","alert","alien","alpha",
    "amber","angle","ankle","apple","april","arena","argue","arise","armor","arrow","asset","audio","autumn","award",
    "avoid","awake","bacon","badge","basic","batch","beach","beard","beast","begin","bench","berry","bingo","birch",
    "black","blade","blank","blend","bless","blind","block","blond","blood","board","boost","bound","brave","bread",
    "brick","bride","bring","broad","broom","brown","brush","buddy","build","cabin","cable","candy","canoe","cargo",
    "carry","carve","cause","cease","chain","chair","chalk","champ","chart","cheek","chess","chief","child","cider",
    "civic","claim","clerk","clock","cloud","coach","coast","cobra","cocoa","color","comic","coral","couch","cover",
    "craft","crane","crash","cream","creek","crisp","crown","cycle","daily","dairy","dance","debut","delay","delta",
    "dense","depth","digit","diner","dodge","dough","draft","drama","dream","drift","drink","drive","eager","eagle",
    "early","earth","ebony","eight","elbow","elder","elite","ember","empty","enter","equal","equip","event","every",
    "exact","exile","exist","extra","fable","fairy","faith","false","fancy","feast","fiber","field","fiery","fight",
    "final","flame","flash","flute","focus","force","forge","frame","fresh","frost","fuzzy","giant","ginger","girth",
    "glade","glare","glide","globe","glory","glove","grace","grade","grain","grand","grape","grass","grave","green",
    "grind","groom","group","guide","habit","happy","harsh","harbor","hazel","heart","heavy","hedge","hello","hobby",
    "honey","honor","horse","house","human","humor","ivory","jelly","jolly","judge","juice","jumpy","knack","kneel",
    "knife","koala","label","labor","lacey","ladle","lager","laser","later","laugh","layer","learn","lemon","level",
    "light","lilac","liver","lodge","logic","loyal","lucky","lunar","lunch","magic","mango","maple","march","marsh",
    "match","meadow","merit","metal","micro","mimic","mines","minor","model","money","month","moral","motor","mount",
    "movie","music","naive","navy","nearly","neon","nerve","never","noble","noisy","north","novel","nurse","nymph",
    "oasis","ocean","offer","often","olive","onion","opera","orbit","order","organ","outer","owner","oxide","ozone",
    "panda","panel","panic","paper","parka","patch","patio","peach","pearl","penny","perch","phase","phone","photo",
    "piano","piece","pilot","pizza","plain","plane","plant","plate","plaza","polar","porch","pound","power","pride",
    "prime","print","prize","proud","pulse","punch","puppy","purse","pylon","queen","quick","quiet","quilt","quota",
    "quote","ranch","raven","reach","ready","relax","reply","rhino","rider","ridge","right","river","robot","rocky",
    "roger","roman","rough","round","royal","rugby","ruler","rural","salad","salsa","sandy","scarf","scene","scoop",
    "score","scout","scrub","seize","sense","seven","shark","sheep","shelf","shine","shore","short","shrub","sight",
    "siren","skate","skill","skirt","skull","slate","slice","slope","small","smart","smile","smoke","snake","sneak",
    "sniff","solar","solid","sonic","sound","south","space","spare","spark","speak","speed","spice","spike","spoon",
    "sport","spray","squad","stack","stage","stain","stair","stake","stamp","stand","start","steam","steel","steep",
    "stool","storm","story","straw","strip","stuck","style","sugar","sunny","super","swamp","swing","table","tango",
    "tasty","teach","tease","tenth","tiger","toast","token","topic","torch","total","touch","tower","toxic","trace",
    "trail","train","treat","trend","trial","tribe","trout","truly","trust","truth","tweet","twice","uncle","under",
    "union","urban","usage","vapor","vivid","vocal","voter","wagon","waist","waltz","waste","watch","water","weary",
    "wheat","wheel","whisk","white","whole","windy","wiser","woman","world","worry","worth","woven","wrist","xenon",
    "young","youth","zebra","zesty","zonal"
]

# ---------------- Core helpers ----------------

def build_charset(include_lower: bool, include_upper: bool, include_digits: bool,
                  include_symbols: bool, custom_symbols: str, exclude_ambiguous: bool) -> str:
    charset = ""
    if include_lower: charset += string.ascii_lowercase
    if include_upper: charset += string.ascii_uppercase
    if include_digits: charset += string.digits
    if include_symbols:
        sym = custom_symbols.strip() if custom_symbols.strip() else DEFAULT_SYMBOLS
        charset += sym
    if exclude_ambiguous:
        charset = "".join(ch for ch in charset if ch not in AMBIGUOUS)
    # de-dup preserving order
    seen, out = set(), []
    for ch in charset:
        if ch not in seen:
            seen.add(ch); out.append(ch)
    return "".join(out)

def estimate_entropy_bits(length: int, charset_size: int) -> float:
    if length <= 0 or charset_size <= 1: return 0.0
    return length * math.log2(charset_size)

def generate_with_requirements(length: int,
                               pools: Dict[str, str],
                               required: Dict[str, int],
                               full_charset: str) -> str:
    """Generate one password meeting per-class minimum counts."""
    if not full_charset:
        raise ValueError("Character set is empty.")

    # total required must fit
    total_req = sum(max(0, n) for n in required.values())
    if total_req > length:
        raise ValueError(f"Required characters ({total_req}) exceed length {length}.")

    pw_chars: List[str] = []

    # Pre-place required characters from each pool
    for key, n in required.items():
        pool = pools.get(key, "")
        if n and not pool:
            raise ValueError(f"Requirement for '{key}' but its character set is empty.")
        for _ in range(n):
            pw_chars.append(secrets.choice(pool))

    # Fill the remainder from the full pool
    for _ in range(length - len(pw_chars)):
        pw_chars.append(secrets.choice(full_charset))

    # secrets-based Fisher–Yates shuffle
    for i in range(len(pw_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]

    return "".join(pw_chars)

def generate_passphrase(n_words: int, words: List[str], sep: str = "-", cap: bool = False) -> str:
    picks = [secrets.choice(words) for _ in range(n_words)]
    if cap:
        picks = [w.capitalize() for w in picks]
    return sep.join(picks)

# ---------------- Main window ----------------

class PasswordGeneratorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Generator")
        self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)

        # Passphrase state
        self.wordlist: List[str] = list(FALLBACK_WORDS)
        self.wordlist_path: str | None = self.settings.value(SETTINGS_WORDLIST, None)
        if self.wordlist_path and Path(self.wordlist_path).exists():
            self._load_wordlist_from_path(self.wordlist_path)

        # ---------- Window size: clamp, center, and restore ----------
        restored = False
        geom = self.settings.value("geometry", None)
        if geom is not None:
            if self.restoreGeometry(geom):
                restored = True
        if not restored:
            screen = QGuiApplication.primaryScreen()
            if screen:
                avail = screen.availableGeometry()
                init_w = min(max(900, int(avail.width() * 0.30)), 1200)
                init_h = min(max(600, int(avail.height() * 0.50)), 900)
                self.resize(init_w, init_h)
                frame = self.frameGeometry(); frame.moveCenter(avail.center()); self.move(frame.topLeft())
            else:
                self.resize(1000, 700)

        # ---------- Root layout ----------
        central = QWidget(self); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(12, 12, 12, 12); root.setSpacing(12)

        # Presets
        presets_row = QHBoxLayout()
        self.preset_combo = QComboBox()
        self.preset_combo.addItems([
            "Custom",
            "Memorable (lower+upper, no digits/symbols)",
            "Strong (lower+upper+digits+symbols)",
            "PIN (digits only)",
            "Passphrase (words)",
        ])
        self.preset_combo.currentIndexChanged.connect(self.apply_preset)
        presets_row.addWidget(QLabel("Preset:")); presets_row.addWidget(self.preset_combo, 1)
        root.addLayout(presets_row)

        # -------- Character classes (with per-class 'min' counters) --------
        self.classes_box = QGroupBox("Character Classes")
        classes_layout = QGridLayout(self.classes_box)
        classes_layout.setHorizontalSpacing(8)
        classes_layout.setVerticalSpacing(6)
        classes_layout.setContentsMargins(10, 8, 10, 10)

        # Checkboxes
        self.chk_lower  = QCheckBox("Lowercase (a–z)")
        self.chk_upper  = QCheckBox("Uppercase (A–Z)")
        self.chk_digits = QCheckBox("Digits (0–9)")
        self.chk_symbols= QCheckBox("Symbols")
        for chk in (self.chk_lower, self.chk_upper, self.chk_digits, self.chk_symbols):
            chk.setChecked(True)

        # Custom symbols (own row; we’ll indent it a bit)
        self.txt_custom_symbols = QLineEdit()
        self.txt_custom_symbols.setPlaceholderText(f"Custom symbols (optional). Default: {DEFAULT_SYMBOLS}")
        self.txt_custom_symbols.setToolTip("Override the default symbol set. Leave blank to use the default.")
        self.txt_custom_symbols.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Exclude ambiguous
        self.chk_exclude_ambiguous = QCheckBox("Exclude ambiguous characters (e.g., Il1O0)")

        def make_min_spin():
            s = QSpinBox()
            s.setRange(0, 200)  # kept in sync with Length
            s.setValue(1)
            s.setButtonSymbols(QAbstractSpinBox.NoButtons)  # external [-][+]
            s.setMaximumWidth(56)
            return s

        def make_dec_button(spin: QSpinBox):
            b = QPushButton("–")
            b.setAutoRepeat(True); b.setAutoRepeatDelay(250); b.setAutoRepeatInterval(60)
            b.setFixedWidth(24)
            b.clicked.connect(lambda _=False, s=spin: s.setValue(s.value() - 1))
            return b

        def make_inc_button(spin: QSpinBox):
            b = QPushButton("+")
            b.setAutoRepeat(True); b.setAutoRepeatDelay(250); b.setAutoRepeatInterval(60)
            b.setFixedWidth(24)
            b.clicked.connect(lambda _=False, s=spin: s.setValue(s.value() + 1))
            return b

        # Create min widgets
        self.min_lower   = make_min_spin()
        self.min_upper   = make_min_spin()
        self.min_digits  = make_min_spin()
        self.min_symbols = make_min_spin()

        def add_class_row(r: int, chk: QCheckBox, spin: QSpinBox):
            # Col0: checkbox (no stretch)
            classes_layout.addWidget(chk, r, 0)

            # Col1: "min:" label (left aligned)
            lbl = QLabel("min:")
            lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            classes_layout.addWidget(lbl, r, 1)

            # Col2–4: [-] [spin] [+]
            dec = make_dec_button(spin)
            inc = make_inc_button(spin)
            classes_layout.addWidget(dec,  r, 2)
            classes_layout.addWidget(spin, r, 3)
            classes_layout.addWidget(inc,  r, 4)

            # Col5: stretch filler so rows can grow without moving columns
            filler = QWidget()
            filler.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            classes_layout.addWidget(filler, r, 5)

        # Add rows (0–3)
        add_class_row(0, self.chk_lower,  self.min_lower)
        add_class_row(1, self.chk_upper,  self.min_upper)
        add_class_row(2, self.chk_digits, self.min_digits)
        add_class_row(3, self.chk_symbols,self.min_symbols)

        # Custom symbols row under the Symbols checkbox (col0..5 span)
        sym_row = QHBoxLayout()
        sym_row.setContentsMargins(24, 0, 0, 0)  # small left indent (24px), adjust as you like
        sym_row.addWidget(self.txt_custom_symbols, 1)
        classes_layout.addLayout(sym_row, 4, 0, 1, 6)

        # Ambiguous checkbox on its own row spanning all columns
        classes_layout.addWidget(self.chk_exclude_ambiguous, 5, 0, 1, 6)

        # Column stretch policy:
        # - 0..4 sized to contents (checkbox + min controls)
        # - 5 is the only stretch column, so the controls stay clustered left
        classes_layout.setColumnStretch(0, 0)
        classes_layout.setColumnStretch(1, 0)
        classes_layout.setColumnStretch(2, 0)
        classes_layout.setColumnStretch(3, 0)
        classes_layout.setColumnStretch(4, 0)
        classes_layout.setColumnStretch(5, 1)

        root.addWidget(self.classes_box)

        # -------- Parameters --------
        params_box = QGroupBox("Parameters")
        grid = QGridLayout(params_box)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)
        grid.setContentsMargins(10, 8, 10, 10)

        # Length controls  [-] [spin] [+]
        self.spin_length = QSpinBox()
        self.spin_length.setRange(4, 200)
        self.spin_length.setValue(16)
        self.spin_length.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.spin_length.setMaximumWidth(72)

        self.btn_len_dec = QPushButton("–")
        self.btn_len_inc = QPushButton("+")
        for b, d in ((self.btn_len_dec, -1), (self.btn_len_inc, +1)):
            b.setAutoRepeat(True); b.setAutoRepeatDelay(250); b.setAutoRepeatInterval(60)
            b.setFixedWidth(24)
            b.clicked.connect(lambda _=False, delta=d: self.spin_length.setValue(self.spin_length.value() + delta))

        len_row = QHBoxLayout()
        len_row.setSpacing(6)
        len_row.addWidget(self.btn_len_dec)
        len_row.addWidget(self.spin_length)
        len_row.addWidget(self.btn_len_inc)
        self.length_controls_w = QWidget()
        self.length_controls_w.setLayout(len_row)
        self.lbl_length = QLabel("Length:")

        # Mode & Count row (two columns on the same row)
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItems(["Single", "Multiple"])
        self.cmb_mode.currentIndexChanged.connect(self.on_mode_changed)

        self.spin_count = QSpinBox()
        self.spin_count.setRange(1, 10_000)
        self.spin_count.setValue(10)
        self.spin_count.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.spin_count.setMaximumWidth(72)

        self.btn_cnt_dec = QPushButton("–")
        self.btn_cnt_inc = QPushButton("+")
        for b, d in ((self.btn_cnt_dec, -1), (self.btn_cnt_inc, +1)):
            b.setAutoRepeat(True); b.setAutoRepeatDelay(250); b.setAutoRepeatInterval(60)
            b.setFixedWidth(24)
            b.clicked.connect(lambda _=False, delta=d: self.spin_count.setValue(self.spin_count.value() + delta))

        cnt_row = QHBoxLayout()
        cnt_row.setSpacing(6)
        cnt_row.addWidget(self.btn_cnt_dec)
        cnt_row.addWidget(self.spin_count)
        cnt_row.addWidget(self.btn_cnt_inc)
        self.count_controls_w = QWidget()
        self.count_controls_w.setLayout(cnt_row)

        # Entropy/charset labels
        self.lbl_entropy = QLabel("Entropy: —")
        self.lbl_charset = QLabel("Charset size: —")
        self.lbl_entropy.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_charset.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # ---- Place items in a fixed 4-column grid ----
        # Row 0: Length
        grid.addWidget(self.lbl_length,           0, 0, alignment=Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.length_controls_w,    0, 1, 1, 3)

        # Row 1: Mode | Count (same row)
        grid.addWidget(QLabel("Mode:"),           1, 0, alignment=Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.cmb_mode,             1, 1)
        grid.addWidget(QLabel("Count:"),          1, 2, alignment=Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.count_controls_w,     1, 3)

        # Row 2: Charset size | Estimated entropy (same row)
        grid.addWidget(QLabel("Charset size:"),   2, 0, alignment=Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.lbl_charset,          2, 1)
        grid.addWidget(QLabel("Estimated entropy:"), 2, 2, alignment=Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.lbl_entropy,          2, 3)

        # Let columns 1 and 3 grow; labels stay compact
        grid.setColumnStretch(0, 0)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 0)
        grid.setColumnStretch(3, 1)

        root.addWidget(params_box)

        # -------- Passphrase options (own group; 2-column grid) --------
        self.pass_box = QGroupBox("Passphrase options")
        pass_grid = QGridLayout(self.pass_box)
        pass_grid.setHorizontalSpacing(10)
        pass_grid.setVerticalSpacing(6)

        # Words (spinner with [-][+] like before)
        self.spin_words = QSpinBox()
        self.spin_words.setRange(2, 12)
        self.spin_words.setValue(6)
        self.spin_words.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.spin_words.setMaximumWidth(72)
        self.spin_words.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        words_row = QHBoxLayout()
        self.btn_words_dec = QPushButton("–")
        self.btn_words_inc = QPushButton("+")
        for b, d in ((self.btn_words_dec, -1), (self.btn_words_inc, +1)):
            b.setAutoRepeat(True)
            b.setAutoRepeatDelay(250)
            b.setAutoRepeatInterval(60)
            b.setFixedWidth(24)
            b.clicked.connect(lambda _=False, delta=d: self.spin_words.setValue(self.spin_words.value() + delta))
        words_row.addWidget(self.btn_words_dec)
        words_row.addWidget(self.spin_words)
        words_row.addWidget(self.btn_words_inc)
        self.words_row_w = self._row_to_widget(words_row)

        # Separator
        self.txt_separator = QLineEdit("-")
        self.txt_separator.setMaxLength(4)
        self.txt_separator.setPlaceholderText("separator")
        self.txt_separator.setMaximumWidth(64)
        self.txt_separator.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        # Capitalize, Load, Wordlist label
        self.chk_capitalize = QCheckBox("Capitalize words")
        self.btn_load_wordlist = QPushButton("Load wordlist…")
        self.btn_load_wordlist.clicked.connect(self.on_load_wordlist)
        self.lbl_wordlist = QLabel(self._wordlist_label_text())

        # Place in a 2-column grid
        # Left column
        pass_grid.addWidget(QLabel("Words:"),       0, 0, Qt.AlignRight)
        pass_grid.addWidget(self.words_row_w,       0, 1)
        pass_grid.addWidget(QLabel("Separator:"),   1, 0, Qt.AlignRight)
        pass_grid.addWidget(self.txt_separator,     1, 1)
        pass_grid.addWidget(self.chk_capitalize,    2, 1)
        # Right column
        pass_grid.addWidget(self.btn_load_wordlist, 0, 2)
        pass_grid.addWidget(QLabel("Wordlist:"),    1, 2, Qt.AlignRight)
        pass_grid.addWidget(self.lbl_wordlist,      1, 3)

        # Let the wordlist label stretch naturally
        pass_grid.setColumnStretch(1, 0)
        pass_grid.setColumnStretch(3, 1)

        root.addWidget(self.pass_box)


        # Buttons
        btns = QHBoxLayout(); btns.setSpacing(8)
        self.btn_generate = QPushButton("Generate")
        self.btn_copy_first = QPushButton("Copy First")
        self.btn_copy_all = QPushButton("Copy All")
        self.btn_save = QPushButton("Save…")
        self.btn_clear = QPushButton("Clear")
        self.btn_generate.clicked.connect(self.on_generate)
        self.btn_copy_first.clicked.connect(self.copy_first)
        self.btn_copy_all.clicked.connect(self.copy_all)
        self.btn_save.clicked.connect(self.on_save)
        self.btn_clear.clicked.connect(self.clear_output)
        btns.addStretch(1)
        for b in (self.btn_generate, self.btn_copy_first, self.btn_copy_all, self.btn_save, self.btn_clear):
            btns.addWidget(b)
        root.addLayout(btns)

        # Output
        self.out = QPlainTextEdit(); self.out.setReadOnly(True)
        self.out.setPlaceholderText("Generated passwords will appear here...")
        root.addWidget(self.out, 1)

        # ---------------- Signal wiring (live updates) ----------------
        # Enable/disable the per-class "min" spinboxes when their checkbox toggles,
        # and update entropy.
        self.chk_lower.stateChanged.connect(lambda _=0: self.min_lower.setEnabled(self.chk_lower.isChecked()))
        self.chk_upper.stateChanged.connect(lambda _=0: self.min_upper.setEnabled(self.chk_upper.isChecked()))
        self.chk_digits.stateChanged.connect(lambda _=0: self.min_digits.setEnabled(self.chk_digits.isChecked()))
        self.chk_symbols.stateChanged.connect(lambda _=0: self.min_symbols.setEnabled(self.chk_symbols.isChecked()))
        # Enable/disable the custom symbols field with the Symbols checkbox
        self.chk_symbols.stateChanged.connect(lambda _=0: self.txt_custom_symbols.setEnabled(self.chk_symbols.isChecked()))

        for chk in (
            self.chk_lower,
            self.chk_upper,
            self.chk_digits,
            self.chk_symbols,
            self.chk_exclude_ambiguous,
        ):
            chk.stateChanged.connect(self.update_entropy_labels)

        # Spinners / numeric inputs -> valueChanged
        for spin in (
            self.spin_length,
            self.spin_words,
            self.min_lower,
            self.min_upper,
            self.min_digits,
            self.min_symbols,
        ):
            spin.valueChanged.connect(self.update_entropy_labels)

        # Keep min-spin maximums synced with length
        self.spin_length.valueChanged.connect(self._sync_min_max_with_length)

        # Line edits -> textChanged
        self.txt_custom_symbols.textChanged.connect(self.update_entropy_labels)
        self.txt_separator.textChanged.connect(self.update_entropy_labels)
        # --------------------------------------------------------------

        # Restore settings for controls
        self._restore_settings()
        # Ensure custom symbols field enabled state matches current checkbox at startup
        self.txt_custom_symbols.setEnabled(self.chk_symbols.isChecked())

        # Set initial mode to "Single"
        self.cmb_mode.setCurrentText("Single")

        self.on_mode_changed()
        self.apply_preset(apply_defaults_if_needed=False)  # reflect current preset state
        self._sync_min_max_with_length()
        self.update_entropy_labels()

    # ---------- helpers & events ----------

    def _row_to_widget(self, row_layout: QHBoxLayout) -> QWidget:
        w = QWidget(); w.setLayout(row_layout); return w

    def _sync_min_max_with_length(self):
        L = self.spin_length.value()
        for s in (self.min_lower, self.min_upper, self.min_digits, self.min_symbols):
            s.setMaximum(L)

    def closeEvent(self, event) -> None:  # noqa: N802
        try:
            self.settings.setValue("geometry", self.saveGeometry())
            if self.wordlist_path:
                self.settings.setValue(SETTINGS_WORDLIST, self.wordlist_path)
            self._save_settings()
        finally:
            super().closeEvent(event)

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Error", message)

    def on_mode_changed(self) -> None:
        is_multiple = (self.cmb_mode.currentText().lower() == "multiple")
        self.spin_count.setEnabled(is_multiple)
        self.btn_cnt_dec.setEnabled(is_multiple)
        self.btn_cnt_inc.setEnabled(is_multiple)

    def _set_passphrase_mode_enabled(self, enabled: bool) -> None:
        # Disable char-class box when passphrase preset is active
        self.classes_box.setDisabled(enabled)
        # Enable/disable passphrase controls
        for w in (self.spin_words, self.btn_words_dec, self.btn_words_inc,
                  self.txt_separator, self.chk_capitalize, self.btn_load_wordlist):
            w.setEnabled(enabled)

    def apply_preset(self, apply_defaults_if_needed: bool = True) -> None:
        idx = self.preset_combo.currentIndex()
        passphrase = (idx == 4)

        # Show/hide major sections
        self.classes_box.setVisible(not passphrase)
        self.lbl_length.setVisible(not passphrase)
        self.length_controls_w.setVisible(not passphrase)
        self.pass_box.setVisible(passphrase)

        if passphrase:
            # Do not clobber saved values; just ensure visibility and update entropy
            self.update_entropy_labels()
            return

        if not apply_defaults_if_needed:
            # Restoring from settings; leave current values alone
            self.update_entropy_labels()
            return

        # Character-mode presets (set both classes and min counts)
        if idx == 0:  # Custom: leave as-is
            pass
        elif idx == 1:  # Memorable
            self.chk_lower.setChecked(True);  self.min_lower.setValue(1)
            self.chk_upper.setChecked(True);  self.min_upper.setValue(1)
            self.chk_digits.setChecked(False); self.min_digits.setValue(0)
            self.chk_symbols.setChecked(False); self.min_symbols.setValue(0)
            self.spin_length.setValue(16)
            self.chk_exclude_ambiguous.setChecked(True)
        elif idx == 2:  # Strong
            self.chk_lower.setChecked(True);  self.min_lower.setValue(1)
            self.chk_upper.setChecked(True);  self.min_upper.setValue(1)
            self.chk_digits.setChecked(True); self.min_digits.setValue(1)
            self.chk_symbols.setChecked(True); self.min_symbols.setValue(1)
            self.spin_length.setValue(20)
            self.chk_exclude_ambiguous.setChecked(True)
        elif idx == 3:  # PIN
            self.chk_lower.setChecked(False); self.min_lower.setValue(0)
            self.chk_upper.setChecked(False); self.min_upper.setValue(0)
            self.chk_digits.setChecked(True);  self.min_digits.setValue(4)
            self.chk_symbols.setChecked(False); self.min_symbols.setValue(0)
            self.spin_length.setValue(8)
            self.chk_exclude_ambiguous.setChecked(False)

        self.update_entropy_labels()

    def _wordlist_label_text(self) -> str:
        if self.wordlist_path:
            return f"{len(self.wordlist)} words from: {Path(self.wordlist_path).name}"
        return f"{len(self.wordlist)} words (fallback list)"

    def on_load_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load wordlist (one word per line)", "", "Text Files (*.txt);;All Files (*)"
        )
        if not path:
            return
        ok = self._load_wordlist_from_path(path)
        if ok:
            self.wordlist_path = path
            self.lbl_wordlist.setText(self._wordlist_label_text())
            self.update_entropy_labels()

    def _load_wordlist_from_path(self, path: str) -> bool:
        try:
            words: List[str] = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if not w:
                        continue
                    if all(("a" <= ch.lower() <= "z") or ch in ("'", "-") for ch in w):
                        words.append(w.lower())
            # Dedup preserve order
            seen, filtered = set(), []
            for w in words:
                if w not in seen:
                    seen.add(w); filtered.append(w)
            if len(filtered) < 256:
                QMessageBox.warning(self, "Wordlist too small",
                    "The selected wordlist has fewer than 256 words.\nConsider using a larger list (e.g., EFF long).")
            if filtered:
                self.wordlist = filtered
                return True
            self.show_error("No usable words found in the selected file.")
            return False
        except Exception as exc:
            self.show_error(f"Failed to load wordlist:\n{exc}")
            return False

    def update_entropy_labels(self) -> None:
        passphrase_mode = (self.preset_combo.currentIndex() == 4)
        if passphrase_mode:
            n = self.spin_words.value()
            vocab = max(1, len(self.wordlist))
            bits = n * math.log2(vocab) if vocab > 1 else 0.0
            self.lbl_charset.setText(f"{vocab} (wordlist)")
            self.lbl_entropy.setText(f"{bits:.1f} bits" if bits else "—")
            return

        include_lower = self.chk_lower.isChecked()
        include_upper = self.chk_upper.isChecked()
        include_digits = self.chk_digits.isChecked()
        include_symbols = self.chk_symbols.isChecked()
        exclude_ambig = self.chk_exclude_ambiguous.isChecked()
        custom_symbols = self.txt_custom_symbols.text()

        charset = build_charset(include_lower, include_upper, include_digits,
                                include_symbols, custom_symbols, exclude_ambig)
        charset_size = len(charset)
        length = self.spin_length.value()
        bits = estimate_entropy_bits(length, charset_size)
        self.lbl_charset.setText(str(charset_size) if charset_size else "—")
        self.lbl_entropy.setText(f"{bits:.1f} bits" if bits else "—")

    # ---------- generation & actions ----------

    def on_generate(self) -> None:
        try:
            count = self.spin_count.value() if self.cmb_mode.currentText().lower() == "multiple" else 1
            passphrase_mode = (self.preset_combo.currentIndex() == 4)

            if passphrase_mode:
                n = self.spin_words.value()
                sep = self.txt_separator.text() or "-"
                cap = self.chk_capitalize.isChecked()
                if not self.wordlist:
                    self.show_error("No wordlist available. Load a wordlist first.")
                    return
                passwords = [generate_passphrase(n, self.wordlist, sep, cap) for _ in range(count)]
                self.out.setPlainText("\n".join(passwords))
                return

            include_lower = self.chk_lower.isChecked()
            include_upper = self.chk_upper.isChecked()
            include_digits = self.chk_digits.isChecked()
            include_symbols = self.chk_symbols.isChecked()
            exclude_ambig = self.chk_exclude_ambiguous.isChecked()
            custom_symbols = self.txt_custom_symbols.text()
            length = self.spin_length.value()

            if not any([include_lower, include_upper, include_digits, include_symbols]):
                self.show_error("Please select at least one character class.")
                return

            charset = build_charset(include_lower, include_upper, include_digits,
                                    include_symbols, custom_symbols, exclude_ambig)
            if not charset:
                self.show_error("The character set is empty after applying exclusions.")
                return

            # Build pools & requirements (disabled classes contribute 0)
            pools: Dict[str, str] = {}
            req: Dict[str, int] = {}
            if include_lower:
                pools["lower"] = "".join(ch for ch in string.ascii_lowercase if ch in charset)
                req["lower"] = self.min_lower.value()
            else:
                req["lower"] = 0

            if include_upper:
                pools["upper"] = "".join(ch for ch in string.ascii_uppercase if ch in charset)
                req["upper"] = self.min_upper.value()
            else:
                req["upper"] = 0

            if include_digits:
                pools["digits"] = "".join(ch for ch in string.digits if ch in charset)
                req["digits"] = self.min_digits.value()
            else:
                req["digits"] = 0

            if include_symbols:
                raw = self.txt_custom_symbols.text().strip() or DEFAULT_SYMBOLS
                pools["symbols"] = "".join(ch for ch in raw if ch in charset)
                req["symbols"] = self.min_symbols.value()
            else:
                req["symbols"] = 0

            # Sanity: sum requirements must be <= length
            total_req = sum(req.values())
            if total_req > length:
                self.show_error(
                    f"Total required characters ({total_req}) exceed length {length}. "
                    f"Reduce the per-class minimums or increase Length."
                )
                return

            passwords = [generate_with_requirements(length, pools, req, charset) for _ in range(count)]
            self.out.setPlainText("\n".join(passwords))

        except Exception as exc:
            self.show_error(f"Generation failed:\n{exc}")

    # ----- clipboard, save, clear -----

    def copy_first(self) -> None:
        lines = self.out.toPlainText().splitlines()
        if not lines: return
        first = lines[0].strip()
        if not first: return
        QApplication.clipboard().setText(first, mode=QClipboard.Clipboard)

    def copy_all(self) -> None:
        text = self.out.toPlainText().strip()
        if not text: return
        QApplication.clipboard().setText(text, mode=QClipboard.Clipboard)

    def on_save(self) -> None:
        text = self.out.toPlainText().strip()
        if not text:
            self.show_error("Nothing to save. Generate some passwords first.")
            return

        passwords = [line for line in text.splitlines() if line.strip()]

        # Ensure our default folder exists
        try:
            DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            # Not fatal; we can still show the dialog (will fall back if needed)
            pass

        initial_path = str(DEFAULT_OUTPUT_DIR / "passwords.txt")

        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save Passwords",
            initial_path,  # default in generated_passwords/
            "Text Files (*.txt);;CSV Files (*.csv)",
        )
        if not path:
            return

        save_csv = path.lower().endswith(".csv") or "csv" in selected_filter.lower()

        try:
            if save_csv:
                if not path.lower().endswith(".csv"):
                    path += ".csv"
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["password"])
                    for pw in passwords:
                        writer.writerow([pw])
            else:
                if not path.lower().endswith(".txt"):
                    path += ".txt"
                with open(path, "w", encoding="utf-8") as f:
                    for pw in passwords:
                        f.write(pw + "\n")
        except Exception as exc:
            self.show_error(f"Failed to save file:\n{exc}")
            return

        QMessageBox.information(self, "Saved", f"Saved {len(passwords)} password(s) to:\n{path}")

    def clear_output(self) -> None:
        self.out.clear()

    # ----- settings persistence -----

    def _save_settings(self) -> None:
        s = self.settings
        # Preset / mode
        s.setValue("preset_index", self.preset_combo.currentIndex())
        s.setValue("mode", self.cmb_mode.currentText())

        # Character mode
        s.setValue("lower_checked", self.chk_lower.isChecked())
        s.setValue("upper_checked", self.chk_upper.isChecked())
        s.setValue("digits_checked", self.chk_digits.isChecked())
        s.setValue("symbols_checked", self.chk_symbols.isChecked())
        s.setValue("exclude_ambig", self.chk_exclude_ambiguous.isChecked())
        s.setValue("custom_symbols", self.txt_custom_symbols.text())
        s.setValue("length", self.spin_length.value())
        s.setValue("count", self.spin_count.value())
        s.setValue("min_lower", self.min_lower.value())
        s.setValue("min_upper", self.min_upper.value())
        s.setValue("min_digits", self.min_digits.value())
        s.setValue("min_symbols", self.min_symbols.value())

        # Passphrase
        s.setValue("words", self.spin_words.value())
        s.setValue("separator", self.txt_separator.text())
        s.setValue("capitalize", self.chk_capitalize.isChecked())

    def _restore_settings(self) -> None:
        s = self.settings

        # Character mode basics
        self.chk_lower.setChecked(s.value("lower_checked", True, bool))
        self.chk_upper.setChecked(s.value("upper_checked", True, bool))
        self.chk_digits.setChecked(s.value("digits_checked", True, bool))
        self.chk_symbols.setChecked(s.value("symbols_checked", True, bool))
        self.chk_exclude_ambiguous.setChecked(s.value("exclude_ambig", False, bool))
        self.txt_custom_symbols.setText(s.value("custom_symbols", "", str))
        self.spin_length.setValue(int(s.value("length", 16)))
        self.spin_count.setValue(int(s.value("count", 10)))

        # Per-class mins (default to 1 each per your preference)
        self.min_lower.setValue(int(s.value("min_lower", 1)))
        self.min_upper.setValue(int(s.value("min_upper", 1)))
        self.min_digits.setValue(int(s.value("min_digits", 1)))
        self.min_symbols.setValue(int(s.value("min_symbols", 1)))

        # Passphrase
        self.spin_words.setValue(int(s.value("words", 6)))
        self.txt_separator.setText(s.value("separator", "-", str))
        self.chk_capitalize.setChecked(s.value("capitalize", False, bool))

        # Preset & mode last (to avoid overriding restored controls)
        preset_idx = int(s.value("preset_index", 0))
        self.preset_combo.setCurrentIndex(preset_idx)
        mode_text = s.value("mode", "Single", str)
        idx = self.cmb_mode.findText(mode_text)
        if idx >= 0:
            self.cmb_mode.setCurrentIndex(idx)

        # Enable/disable min spins based on checkboxes
        for chk, spin in (
            (self.chk_lower, self.min_lower),
            (self.chk_upper, self.min_upper),
            (self.chk_digits, self.min_digits),
            (self.chk_symbols, self.min_symbols),
        ):
            spin.setEnabled(chk.isChecked())

# ---------------- Entrypoint ----------------

def main() -> None:
    app = QApplication(sys.argv)
    w = PasswordGeneratorWindow(); w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
