## Smart Password Intelligence

Human-centric password analysis and generation for the Empathy Encryption Hackathon (Theme: “Smarter Security: Human-Centric Password Intelligence”). This project balances security, usability, and intent. It avoids rigid rules, favors thoughtful patterns, and gives empathetic guidance via both CLI and GUI.

### Why this matters
Conventional validators nag users into adding symbols and numbers, producing hard-to-remember, still-weak passwords. This tool recognizes human-friendly structure and intention, penalizes predictable or confusing patterns, and helps users craft strong, memorable passwords with clear feedback.

---

## Key Features
- **Human-centric scoring (0–100)**: Blends length, variety, uniqueness, pronounceability, and intent-based bonuses; subtracts penalties for predictability and confusion.
- **Predictable-pattern detection**: Keyboard sequences, repeated tokens/chars, year/number sequences, palindromes, low-vowel “key-smash”, alternating patterns, excessive symbols.
- **Empathetic feedback**: Actionable tips in English and Hindi with a friendly tone.
- **Memorable suggestions**: Improves user inputs, generates hint-based and pattern-based options with mnemonics.
- **History & reuse awareness**: Locally tracks hashed history to discourage reuse.
- **CLI and Tkinter GUI**: Works in the terminal or a polished desktop UI.
- **Internationalization**: `en` and `hi` built-in.


---

## Quickstart

### Prerequisites
- Python 3.8+
- Windows/macOS/Linux
- Tkinter for GUI (bundled with most Python builds on Windows/macOS). On minimal Linux images, install your distro’s Tk packages if needed.

### Install (optional extra)
```bash
pip install zxcvbn  # optional; improves scoring when available
```

### Run (CLI)
```bash
python Aditya.py            # interactive CLI
python Aditya.py --language hi
python Aditya.py --strictness strict
```

### Run (GUI)
```bash
python Aditya.py --gui
python Aditya.py --gui --language hi --strictness balanced
```

Command-line flags:
- `--gui`: launch graphical UI
- `--language {en,hi}`: UI/feedback language
- `--strictness {lenient,balanced,strict}`: thresholds for Weak/Fair/Good/Excellent

---

## How the Scoring Works
Base score (0–100) = positives − penalties, then optionally blended with zxcvbn if installed.

### Positives
- **Length (max ~50)**: Logarithmic growth beyond 8 chars to reward practical length.
- **Variety (max 25)**: Lowercase, uppercase, digits, symbols; balance rewarded.
- **Uniqueness (max 15)**: Shannon-like diversity across characters.
- **Pronounceability (max 10)**: Encourages human-readability and memory.
- **Bonus (5)**: For balanced composition and sufficient length.

### Penalties
- **Blacklist/common similarity**: Known common passwords and close variants.
- **Predictable patterns**: Keyboard runs, repeated tokens/chars, palindromes, year/number sequences, low-vowel key-smash, alternating ABAB…, excessive symbols.
- **Confusing characters**: Consecutive or multiple of `1 l I 0 O`.
- **Reuse**: Seen before in local session history (hashed).

If `zxcvbn` is available, final score = 70% project score + 30% zxcvbn-derived score.

---

## Using the CLI
```bash
python Aditya.py
```
What you get:
- Strength bar and validity (✓/✗)
- Clear “what to improve” list
- Optional suggestions
- Optional hint-driven password generation (simple/balanced/complex)

Exit with `quit`, `exit`, or `Ctrl+C`.

---

## Using the GUI (Tkinter)
```bash
python Aditya.py --gui
```
Highlights:
- Real-time strength bar and score
- Show/hide password, set hint, switch language
- One-click: Analyze, Suggest, Generate, Clear, Save Health Report
- **History panel**: Shows previous scores with timestamps (no raw passwords stored)
- **Challenge Mode**: Try to craft a password scoring 80+

If the GUI does not launch on Linux, install Tk packages (e.g., `sudo apt-get install python3-tk`).

---

## Public API (import and reuse)

### Class: `PasswordIntelligence`
- `is_valid_password(password) -> bool`
- `score_password(password, hint="") -> (score:int, analysis:dict)`
- `give_feedback(score, analysis) -> str`
- `suggest_alternatives(password, hint="", count=3) -> list`
- `generate_memorable_password(hint, length=16, complexity="balanced") -> str`
- `format_strength_bar(score, width=20) -> str`
- `generate_health_report(password, hint="") -> str`

### Class: `PasswordIntelligenceGUI`
- `run()` to start the Tkinter app

### Script entry
- `python Aditya.py [--gui] [--language en|hi] [--strictness lenient|balanced|strict]`

---

## Examples

### Strong inputs
```text
River-Code#2024!, OceanRun@2025!, CodeMaster#42!, TigerRun#2024
```

### Weak inputs (will be flagged)
```text
password, 123456, qwerty, aaaaaa, zxcvbnm, pass123, 1q2w3e, I1lusion
```

### Sample CLI session
```text
🔐 Welcome to Smart Password Intelligence!
=======================================================
🔑 Enter your password: OceanRun@2025!
💭 Hint (press Enter to skip): ocean

📊 ANALYSIS
[███████████████████░░] 86/100
Status: ✓ Valid
Password Strength: Excellent (86/100)
Strengths: good length, nice character variety, well-balanced composition

Areas to improve:
   1. Avoid year sequences if you can

Tip: Aim for 60+ for most accounts, 80+ for critical ones.
```

---

## Hackathon Fit
- **Relevance**: Directly targets “Smarter Security: Human-Centric Password Intelligence”.
- **Functionality**: End-to-end CLI and GUI with analysis, suggestions, generation, reports.
- **Creativity**: Pronounceability, empathy-first messaging, reuse awareness, challenge mode, i18n.
- **Clarity**: Clean feedback, strength bars, detailed breakdowns, and a health report export.
- **Technical execution**: Modular Python, optional `zxcvbn` blending, pattern analysis, hashed history.

---

## Submission Guide (Unstop)
- Submit the single Python file: `Aditya.py`.
- Include this `README.md` (recommended for evaluators).
- If you used `zxcvbn`, document it as an optional dependency (see below).
- Build window compliance: All core code authored within the hackathon time; no unmodified templates.

### External Libraries
- `zxcvbn` (optional): Improves scoring realism. Install with `pip install zxcvbn`.

---

## Troubleshooting
- GUI won’t open (Linux): Install Tk: `sudo apt-get install python3-tk`.
- Font/emoji rendering: Use a modern terminal or run the GUI.
- zxcvbn import error: It’s optional. Either install it or proceed without.

---

## Credits
- Built by Aditya Raulji for The Empathy Encryption Hackathon, mentored by Dr. Kushal Shah.
- Theme reference and event logistics: UnsaidTalks Education (Unstop listing).

For event updates: [Join the WhatsApp Group](https://chat.whatsapp.com/BhPqbjE4oDK5RmhOkEUp6j?mode=ac_t)
