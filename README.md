# Password Generator (PySide6)

A small, local, cryptographically-secure password & passphrase generator with a friendly Qt GUI.

- Character passwords with customizable **character classes** (lower/upper/digits/symbols)
- **Per-class “must contain” counts** (e.g., ≥2 digits, ≥1 symbol, …)
- **Passphrase mode** (load your own wordlist; choose words/separator/capitalization)
- Generate **single** or **multiple** results
- **Entropy estimate** and **charset size** shown live
- **Exclude ambiguous characters** (e.g., `Il1O0…`)
- **Copy First / Copy All / Save… (TXT or CSV)** — saves by default to `generated_passwords/` next to the script
- **Remembers all settings** (including window size and last wordlist) between sessions

> ⚠️ This app generates passwords locally and never phones home. Still, treat any saved files as sensitive.

---

## Requirements

- Python **3.10+**
- OS: Windows, macOS, or Linux
- Dependency: **PySide6**

`requirements.txt`:
```txt
PySide6>=6.5
```

---

## Quick Start

### 1) Clone and enter the project

```bash
git clone https://github.com/InsolentFlunkey/password-generator.git password-generator
cd password-generator
```

### 2) Create & activate a virtual environment

**Windows (PowerShell)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### 3) Install dependencies

```bash
pip install -r requirements.txt
```

### 4) Run it

```bash
python password_generator.py
```

---

## Usage Notes

### Presets
- **Custom** – use the character classes you want; set per-class minimums (defaults to 1 each).
- **Memorable** – lower+upper, no digits/symbols, ambiguous excluded.
- **Strong** – all classes, ambiguous excluded.
- **PIN** – digits only.
- **Passphrase (words)** – switches to passphrase options (words/separator/caps/wordlist). Character classes and Length are hidden in this preset.

### Character passwords
- Toggle the classes you want (Lowercase / Uppercase / Digits / Symbols).
- Set **min** per class (spinboxes). Total required must be ≤ **Length**.
- Optional **Custom symbols** field overrides the default symbol set. (The field disables if “Symbols” is unchecked.)
- **Exclude ambiguous characters** removes look-alikes (e.g., `I l 1 O 0 …`).

### Passphrases
- Choose number of **words**, **separator**, and whether to **Capitalize words**.
- **Load wordlist…** to use your own list (one word per line). A small fallback list ships for convenience; prefer a large list (e.g., EFF long) for real use.
- Entropy ≈ `words × log2(vocabulary_size)`.

### Modes & Counts
- **Mode: Single** → one output line.
- **Mode: Multiple** → set **Count** to generate many lines.

### Entropy & Charset
- The **Statistics** box shows **Charset size** and **Estimated entropy**.
- In passphrase mode, “charset size” reflects wordlist size.

### Saving
- **Save…** writes TXT (one per line) or CSV (`password` column).
- Default save directory is created on first use:
  ```
  generated_passwords/
  ```
  next to `password_generator.py`.

### Persistence
- The app uses Qt **QSettings** to remember everything (window geometry, preset, toggles, per-class mins, length/count, passphrase options, wordlist path, etc.) between runs.

---

## Wordlists

Any UTF-8 text file with one word per line works. The loader filters for simple alphabetic words plus `'` and `-`. For security, use a **large** list (thousands of words). Example: “EFF Diceware (long)” style lists.

---

## Project Structure

```
.
├── password_generator.py      # main app
├── requirements.txt
└── generated_passwords/       # created on first save
```

---

## Development Tips

- Lint/type-check against Python **3.10+** (the code uses `X | None` type hints).
- If you package it (optional), `pyinstaller` works well:
  ```bash
  pip install pyinstaller
  pyinstaller --noconsole --name "Password Generator" password_generator.py
  ```
- On Windows, if PowerShell blocks venv activation, run:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
  ```

---

## Troubleshooting

- **“Required characters exceed length”** — Lower the per-class mins or increase **Length**.
- **Wordlist shows very small vocabulary** — Ensure the file is one word per line and mostly alphabetic; the loader drops lines that don’t look like words.

---

## Security Notes

- Entropy numbers are theoretical upper bounds; real-world strength also depends on how/where you store and use passwords.
- Avoid reusing passwords; prefer a password manager.
- Treat saved TXT/CSV as sensitive material.

---

## License

Choose a license (e.g., MIT) and add it to the repo.
