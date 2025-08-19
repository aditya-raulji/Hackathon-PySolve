#!/usr/bin/env python3
"""
Empathy Encryption Hackathon: Smart But Friendly Passwords
Philosophy: Balances security, usability, and intentionality by rewarding memorable, thoughtful patterns
while penalizing trivial, confusing, or random passwords. Includes CLI and GUI interfaces with
internationalization, accessibility, and unique features like password history and custom mnemonics.


Author: Aditya Raulji 
ChatGpt Link : https://chatgpt.com/share/68a03aca-6e00-8006-b671-0ca795fdb51c


Setup Instructions:
1. Install dependencies: `pip install zxcvbn` (optional for enhanced scoring).
2. Run CLI: `python password_validator.py` or GUI: `python password_validator.py --gui`.
3. Use `--strictness [lenient|balanced|strict]` to adjust scoring.

Hackathon Alignment:
- Security: Rejects common passwords, keyboard patterns, and low-entropy strings.
- Intentionality: Rewards word-based patterns and user hints, penalizes random key smashing.
- Usability: Provides empathetic feedback, mnemonic suggestions, and a user-friendly GUI.
- Uniqueness: Features internationalization, password history, and a challenge mode.
"""

import re
import random
import string
import math
import argparse
import hashlib
import time
from collections import Counter
from typing import List, Dict, Tuple, Optional
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# Common passwords (top 20 for efficiency)
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "111111", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123"
]

# Keyboard patterns for detection
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "asdfghjkl", "zxcv", "zxcvbnm",
    "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm", "ik", "ol", "p"
]

# Leet speak substitutions
LEET_SUBSTITUTIONS = {
    'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['5', '$'],
    't': ['7'], 'l': ['1'], 'g': ['9'], 'b': ['6'], 'z': ['2']
}

# Visually confusing characters
CONFUSING_CHARS = {'1', 'l', 'I', '0', 'O'}

# Internationalization: Translation dictionary
TRANSLATIONS = {
    "en": {
        "welcome": "Welcome to Smart Password Intelligence!",
        "enter_password": "Enter your password:",
        "hint_label": "Hint (optional):",
        "show_password": "Show password",
        "analyze": "Analyze",
        "suggest": "Suggest",
        "generate": "Generate",
        "clear": "Clear",
        "strength": "Password Strength: {strength} ({score}/100)",
        "valid": "✓ Valid",
        "invalid": "✗ Invalid",
        "empty_error": "Please enter a password.",
        "hint_error": "Provide a hint for personalized passwords.",
        "strengths": "Strengths: {points}",
        "improve": "Areas to improve:",
        "tip": "Tip: Aim for 60+ for most accounts, 80+ for critical ones."
    },
    "hi": {
        "welcome": "स्मार्ट पासवर्ड इंटेलिजेंस में आपका स्वागत है!",
        "enter_password": "अपना पासवर्ड दर्ज करें:",
        "hint_label": "संकेत (वैकल्पिक):",
        "show_password": "पासवर्ड दिखाएं",
        "analyze": "विश्लेषण",
        "suggest": "सुझाव",
        "generate": "उत्पन्न करें",
        "clear": "साफ़ करें",
        "strength": "पासवर्ड की ताकत: {strength} ({score}/100)",
        "valid": "✓ वैध",
        "invalid": "✗ अमान्य",
        "empty_error": "कृपया एक पासवर्ड दर्ज करें।",
        "hint_error": "वैयक्तिकृत पासवर्ड के लिए एक संकेत प्रदान करें।",
        "strengths": "ताकत: {points}",
        "improve": "सुधार के लिए क्षेत्र:",
        "tip": "सुझाव: सामान्य खातों के लिए 60+ और महत्वपूर्ण खातों के लिए 80+ का लक्ष्य रखें।"
    }
}

class PasswordIntelligence:
    """Validates passwords with human-centric principles: security, intentionality, clarity."""
    
    def __init__(self, strictness_mode: str = "balanced", language: str = "en"):
        """Initialize with strictness mode, language, and password history."""
        self.strictness_mode = strictness_mode
        self.language = language
        self.common_passwords_set = set(pwd.lower() for pwd in COMMON_PASSWORDS)
        self.score_thresholds = {
            "lenient": {"weak": 30, "fair": 50, "good": 70, "excellent": 85},
            "balanced": {"weak": 40, "fair": 60, "good": 80, "excellent": 90},
            "strict": {"weak": 50, "fair": 70, "good": 85, "excellent": 95}
        }
        self.password_history = []  # Store (hash, score, timestamp)

    def is_valid_password(self, password: str) -> bool:
        """Valid if score >= 60 and length >= 8. Ensures security and usability."""
        if len(password) < 8:
            return False
        score, _ = self.score_password(password)
        return score >= 60

    def check_common_passwords(self, password: str) -> Tuple[bool, float]:
        """Check for common passwords or similar variations."""
        password_lower = password.lower()
        if password_lower in self.common_passwords_set:
            return True, 0.9
        for common_pwd in COMMON_PASSWORDS:
            if self._is_similar_password(password_lower, common_pwd.lower()):
                return True, 0.7
        return False, 0.0

    def _is_similar_password(self, password: str, common_pwd: str) -> bool:
        """Detect variations of common passwords using leet speak and edit distance."""
        cleaned_password = re.sub(r'^[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]*', '', password)
        cleaned_password = re.sub(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?0-9]*$', '', cleaned_password)
        deleet_password = self._reverse_leet_speak(cleaned_password)
        return (deleet_password == common_pwd or 
                cleaned_password == common_pwd or
                self._simple_edit_distance(deleet_password, common_pwd) <= 2)

    def _reverse_leet_speak(self, password: str) -> str:
        """Convert leet speak back to normal characters."""
        result = password
        for char, substitutions in LEET_SUBSTITUTIONS.items():
            for sub in substitutions:
                result = result.replace(sub, char)
        return result

    def _simple_edit_distance(self, s1: str, s2: str) -> int:
        """Optimized edit distance with early exit for efficiency."""
        if len(s1) < len(s2):
            return self._simple_edit_distance(s2, s1)
        if not s2:
            return len(s1)
        if len(s1) - len(s2) > 2:
            return 3
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def detect_patterns(self, password: str) -> List[Dict[str, any]]:
        """Detect problematic patterns: keyboard sequences, repetitions, palindromes, low vowels."""
        patterns = []
        password_lower = password.lower()

        # Keyboard sequences
        for pattern in KEYBOARD_PATTERNS:
            if pattern in password_lower:
                patterns.append({
                    "type": "keyboard_sequence",
                    "description": f"Contains keyboard sequence '{pattern}'",
                    "penalty": 0.3
                })

        # Repeated characters
        for char in set(password):
            if password.count(char) >= 3:
                patterns.append({
                    "type": "repeated_character",
                    "description": f"Character '{char}' repeats {password.count(char)} times",
                    "penalty": 0.2 * (password.count(char) - 2)
                })

        # Repeated tokens
        if len(password) >= 6:
            for i in range(2, len(password) // 2 + 1):
                token = password[:i]
                if token * (len(password) // i) == password[:len(token) * (len(password) // i)]:
                    patterns.append({
                        "type": "repeated_token",
                        "description": f"Repeating pattern '{token}'",
                        "penalty": 0.4
                    })
                    break

        # Year patterns
        current_year = 2025
        for year in range(1950, current_year + 10):
            if str(year) in password:
                patterns.append({
                    "type": "year_pattern",
                    "description": f"Contains year '{year}'",
                    "penalty": 0.15
                })

        # Number sequences
        sequences = ["123", "234", "345", "456", "567", "678", "789", "890"]
        for seq in sequences:
            if seq in password or seq[::-1] in password:
                patterns.append({
                    "type": "number_sequence",
                    "description": f"Contains number sequence '{seq}'",
                    "penalty": 0.25
                })

        # Palindromes
        if len(password) >= 5 and password_lower == password_lower[::-1]:
            patterns.append({
                "type": "palindrome",
                "description": "Password is a palindrome (e.g., 'deked')",
                "penalty": 0.2
            })

        # Low vowel frequency (indicates key smashing)
        vowels = set('aeiou')
        vowel_count = sum(1 for c in password_lower if c in vowels)
        if len(password) >= 8 and vowel_count / len(password) < 0.1:
            patterns.append({
                "type": "low_vowels",
                "description": "Low vowel frequency (possibly random)",
                "penalty": 0.3
            })

        # Alternating patterns (e.g., "ababab")
        for i in range(2, len(password) // 2 + 1):
            if all(password[j] == password[j % 2] for j in range(len(password))):
                patterns.append({
                    "type": "alternating_pattern",
                    "description": "Alternating pattern detected",
                    "penalty": 0.3
                })
                break

        # Excessive symbols
        symbol_count = sum(1 for c in password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?")
        if symbol_count / len(password) > 0.5:
            patterns.append({
                "type": "excessive_symbols",
                "description": "Too many symbols reduce readability",
                "penalty": 0.2
            })

        return patterns

    def check_confusing_chars(self, password: str) -> Tuple[bool, float]:
        """Penalize consecutive confusing characters (e.g., 'I1l')."""
        confusing_count = sum(1 for c in password if c in CONFUSING_CHARS)
        consecutive_confusing = False
        for i in range(len(password) - 1):
            if password[i] in CONFUSING_CHARS and password[i+1] in CONFUSING_CHARS:
                consecutive_confusing = True
                break
        penalty = 0.3 if consecutive_confusing else 0.2 if confusing_count >= 2 else 0.0
        return confusing_count >= 2 or consecutive_confusing, penalty

    def estimate_pronounceability(self, password: str) -> float:
        """Estimate pronounceability based on syllable count and vowel presence."""
        vowels = set('aeiou')
        syllable_count = 0
        prev_vowel = False
        for c in password.lower():
            is_vowel = c in vowels
            if is_vowel and not prev_vowel:
                syllable_count += 1
            prev_vowel = is_vowel
        return min(1.0, syllable_count / (len(password) / 4))  # Normalize to 0-1

    def check_password_reuse(self, password: str) -> Tuple[bool, float]:
        """Check if password was used before (hashed for privacy)."""
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        for stored_hash, _, _ in self.password_history:
            if stored_hash == pwd_hash:
                return True, 0.5
        return False, 0.0

    def add_to_history(self, password: str, score: int):
        """Add password to history with hash, score, and timestamp."""
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        self.password_history.append((pwd_hash, score, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        if len(self.password_history) > 50:  # Limit history size
            self.password_history.pop(0)

    def score_password(self, password: str, hint: str = "") -> Tuple[int, Dict[str, any]]:
        """Score password (0-100) with context-aware analysis."""
        if not password:
            return 0, {"error": "Empty password"}

        analysis = {
            "length_score": 0,
            "variety_score": 0,
            "uniqueness_score": 0,
            "pronounceability_score": 0,
            "pattern_penalties": [],
            "blacklist_penalty": 0,
            "confusing_penalty": 0,
            "reuse_penalty": 0,
            "hint_relevance_score": 0,
            "bonus_points": 0
        }

        # Length scoring
        length = len(password)
        if length < 8:
            analysis["length_score"] = max(0, length * 5)
        else:
            analysis["length_score"] = min(50, 20 + 10 * math.log(length - 5))

        # Variety scoring
        char_types = {
            "lowercase": any(c.islower() for c in password),
            "uppercase": any(c.isupper() for c in password),
            "digits": any(c.isdigit() for c in password),
            "symbols": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        }
        variety_count = sum(char_types.values())
        analysis["variety_score"] = min(25, variety_count * 6.25)

        # Bonus for balanced passwords
        if variety_count >= 3 and length >= 8:
            analysis["bonus_points"] += 5

        # Uniqueness scoring
        char_freq = Counter(password.lower())
        if len(char_freq) > 1:
            entropy_estimate = -sum(freq/len(password) * math.log2(freq/len(password)) 
                                  for freq in char_freq.values())
            analysis["uniqueness_score"] = min(15, entropy_estimate * 3)

        # Pronounceability scoring
        analysis["pronounceability_score"] = self.estimate_pronounceability(password) * 10

        # Pattern penalties
        patterns = self.detect_patterns(password)
        analysis["pattern_penalties"] = patterns
        analysis["total_penalty"] = sum(pattern["penalty"] * 10 for pattern in patterns)

        # Common password penalty
        is_common, blacklist_penalty = self.check_common_passwords(password)
        analysis["blacklist_penalty"] = blacklist_penalty * 30

        # Confusing characters penalty
        is_confusing, confusing_penalty = self.check_confusing_chars(password)
        analysis["confusing_penalty"] = confusing_penalty * 10

        # Password reuse penalty
        is_reused, reuse_penalty = self.check_password_reuse(password)
        analysis["reuse_penalty"] = reuse_penalty * 10

        # Hint relevance bonus
        if hint and hint.lower() in password.lower():
            analysis["hint_relevance_score"] = 5

        # Final score
        base_score = (analysis["length_score"] + analysis["variety_score"] + 
                     analysis["uniqueness_score"] + analysis["pronounceability_score"] +
                     analysis["hint_relevance_score"] + analysis["bonus_points"])
        final_score = max(0, min(100, base_score - analysis["total_penalty"] - 
                                 analysis["blacklist_penalty"] - analysis["confusing_penalty"] -
                                 analysis["reuse_penalty"]))

        if ZXCVBN_AVAILABLE:
            try:
                zxcvbn_result = zxcvbn.zxcvbn(password)
                zxcvbn_score = (zxcvbn_result["score"] / 4.0) * 100
                final_score = int(final_score * 0.7 + zxcvbn_score * 0.3)
                analysis["zxcvbn_feedback"] = zxcvbn_result.get("feedback", {})
            except:
                pass

        self.add_to_history(password, final_score)
        return int(final_score), analysis

    def give_feedback(self, score: int, analysis: Dict[str, any]) -> str:
        """Generate empathetic feedback in the selected language."""
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        threshold = self.score_thresholds[self.strictness_mode]
        strength = "Weak" if score < threshold["weak"] else "Fair" if score < threshold["fair"] else \
                   "Good" if score < threshold["good"] else "Excellent"
        emoji = "🔴" if score < threshold["weak"] else "🟡" if score < threshold["fair"] else "🟢"

        feedback = [t["strength"].format(strength=strength, score=score)]

        positive_points = []
        if analysis["length_score"] >= 35:
            positive_points.append("good length")
        if analysis["variety_score"] >= 15:
            positive_points.append("nice character variety")
        if analysis["uniqueness_score"] >= 10:
            positive_points.append("good character distribution")
        if analysis["pronounceability_score"] >= 8:
            positive_points.append("easy to pronounce")
        if analysis["bonus_points"] > 0:
            positive_points.append("well-balanced composition")

        if positive_points:
            feedback.append(t["strengths"].format(points=", ".join(positive_points)))

        issues = []
        if len(analysis.get("error", "")) > 0:
            issues.append("Password cannot be empty")
        if analysis["length_score"] < 25:
            issues.append("Password is too short - aim for 8+ characters")
        if analysis["variety_score"] < 15:
            issues.append("Add more character types (uppercase, numbers, symbols)")
        if analysis["blacklist_penalty"] > 20:
            issues.append("Password is too common or similar to common passwords")
        if analysis["confusing_penalty"] > 0:
            issues.append("Avoid confusing characters like '1', 'l', 'I', '0', 'O' together")
        if analysis["reuse_penalty"] > 0:
            issues.append("Password was used before - choose a new one")
        if analysis["pattern_penalties"]:
            pattern_issues = [p["description"] for p in analysis["pattern_penalties"]]
            issues.append("Predictable patterns: " + "; ".join(pattern_issues))

        if issues:
            feedback.append(f"\n{t['improve']}")
            for i, issue in enumerate(issues, 1):
                feedback.append(f"   {i}. {issue}")

        feedback.append(f"\n{t['tip']}")
        return "\n".join(feedback)

    def suggest_alternatives(self, password: str, hint: str = "", count: int = 3) -> List[Dict[str, str]]:
        """Generate improved password suggestions with mnemonics."""
        suggestions = []
        score, analysis = self.score_password(password, hint)

        if len(password) >= 4:
            enhanced = self._enhance_existing_password(password)
            suggestions.append({
                "password": enhanced,
                "explanation": "Enhanced your password with better security",
                "mnemonic": "Based on your original with added strength"
            })

        if hint:
            memorable = self.generate_memorable_password(hint, length=14, complexity="balanced")
            mnemonic = f"Think of your favorite {hint.lower()} and a recent year!"
            suggestions.append({
                "password": memorable,
                "explanation": f"Based on hint '{hint}' with strong security",
                "mnemonic": mnemonic
            })

        pattern_based = self._generate_pattern_based_password()
        suggestions.append({
            "password": pattern_based,
            "explanation": "Human-friendly pattern, easy to remember",
            "mnemonic": "Word-Word#Year! structure"
        })

        return suggestions[:count]

    def _enhance_existing_password(self, password: str) -> str:
        """Enhance user’s password while keeping it recognizable."""
        enhanced = password
        if not any(c.isupper() for c in enhanced):
            if enhanced[0].islower():
                enhanced = enhanced[0].upper() + enhanced[1:]
        if not any(c in "!@#$%^&*()" for c in enhanced):
            enhanced += random.choice(["!", "#", "$"])
        if not any(c.isdigit() for c in enhanced):
            enhanced += str(random.randint(10, 99))
        if len(enhanced) < 10:
            additions = ["Secure", "Strong", "Safe"]
            enhanced = random.choice(additions) + enhanced
        return enhanced

    def _generate_pattern_based_password(self) -> str:
        """Generate a memorable, pattern-based password."""
        words = ["Sunset", "Ocean", "Mountain", "River", "Forest", "Garden", "Bridge"]
        actions = ["Run", "Jump", "Fly", "Code", "Build"]
        word1 = random.choice(words)
        word2 = random.choice(actions)
        symbol = random.choice(["#", "&", "@"])
        year = random.randint(2020, 2025)
        return f"{word1}-{word2}{symbol}{year}!"

    def _generate_passphrase_style(self) -> str:
        """Generate a passphrase-style password."""
        adjectives = ["Quick", "Bright", "Silent", "Smooth"]
        nouns = ["Fox", "Wolf", "Bear", "Hawk"]
        verbs = ["Jumps", "Runs", "Flies", "Codes"]
        adj = random.choice(adjectives)
        noun = random.choice(nouns)
        verb = random.choice(verbs)
        num = random.randint(42, 99)
        return f"{adj}{noun}{verb}{num}!"

    def generate_memorable_password(self, hint: str, length: int = 16, complexity: str = "balanced") -> str:
        """Generate a memorable password from user’s hint."""
        if not hint:
            hint = "Secure"
        hint_clean = re.sub(r'[^a-zA-Z0-9]', '', hint).title()
        if len(hint_clean) < 3:
            hint_clean = "Secure" + hint_clean

        complexity_configs = {
            "simple": {"symbols": ["!", "#"], "numbers": True, "transformations": False},
            "balanced": {"symbols": ["!", "@", "#", "$"], "numbers": True, "transformations": True},
            "complex": {"symbols": ["!", "@", "#", "$", "%"], "numbers": True, "transformations": True}
        }
        config = complexity_configs.get(complexity, complexity_configs["balanced"])

        components = []
        if config["transformations"]:
            transformed_hint = hint_clean
            if 'a' in transformed_hint.lower():
                transformed_hint = transformed_hint.replace('a', '@').replace('A', '@')
            if 'e' in transformed_hint.lower():
                transformed_hint = transformed_hint.replace('e', '3').replace('E', '3')
            components.append(transformed_hint)
        else:
            components.append(hint_clean)

        components.append(random.choice(["Secure", "Strong", "Safe"]))
        if config["numbers"]:
            components.append(str(random.randint(2020, 2025)))
        components.append(random.choice(config["symbols"]))

        password = "".join(components)
        if len(password) < length:
            password += random.choice(["Pro", "Max", "Plus"])
        elif len(password) > length:
            password = password[:length]
        return password

    def format_strength_bar(self, score: int, width: int = 20) -> str:
        """Create ASCII progress bar for CLI display."""
        filled_chars = int((score / 100) * width)
        empty_chars = width - filled_chars
        fill_char = "█" if score >= 80 else "▓" if score >= 60 else "▒" if score >= 40 else "░"
        return f"[{fill_char * filled_chars}{'░' * empty_chars}] {score}/100"

    def generate_health_report(self, password: str, hint: str = "") -> str:
        """Generate a detailed password health report."""
        score, analysis = self.score_password(password, hint)
        feedback = self.give_feedback(score, analysis)
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])

        report = [
            f"🔒 Password Health Report",
            f"{'='*50}",
            f"Password: {'*' * len(password)}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n📊 Analysis",
            f"{self.format_strength_bar(score)}",
            f"Status: {t['valid'] if self.is_valid_password(password) else t['invalid']}",
            feedback,
            f"\n🔬 Detailed Breakdown",
            f"Length Score: {analysis['length_score']:.1f}/50",
            f"Variety Score: {analysis['variety_score']:.1f}/25",
            f"Uniqueness Score: {analysis['uniqueness_score']:.1f}/15",
            f"Pronounceability Score: {analysis['pronounceability_score']:.1f}/10",
            f"Hint Relevance Bonus: {analysis['hint_relevance_score']:.1f}/5",
            f"Pattern Penalty: -{analysis['total_penalty']:.1f}",
            f"Blacklist Penalty: -{analysis['blacklist_penalty']:.1f}",
            f"Confusing Chars Penalty: -{analysis['confusing_penalty']:.1f}",
            f"Reuse Penalty: -{analysis['reuse_penalty']:.1f}"
        ]
        return "\n".join(report)

class PasswordIntelligenceGUI:
    """Tkinter GUI with accessibility and history features."""
    
    def __init__(self, language: str = "en"):
        if not TKINTER_AVAILABLE:
            raise ImportError("Tkinter is not available")
        self.intelligence = PasswordIntelligence(language=language)
        self.language = language
        self.setup_gui()

    def setup_gui(self):
        """Configure GUI with accessibility and history panel."""
        self.root = tk.Tk()
        self.root.title("Smart Password Intelligence - Hackathon")
        self.root.geometry("1000x800")
        self.root.configure(bg="#f5f5f5")
        self.root.attributes('-alpha', 0.95)  # Slight transparency for effect

        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        ttk.Label(main_frame, text="🔐 " + t["welcome"], 
                 font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Password input
        ttk.Label(main_frame, text=t["enter_password"]).grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.password_var = tk.StringVar()
        self.password_var.trace("w", self.on_password_change)
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, width=50, show="*")
        self.password_entry.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        self.password_entry.configure(justify="center")  # Accessibility: centered text

        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(main_frame, text=t["show_password"], variable=self.show_password_var,
                       command=self.toggle_password_visibility).grid(row=3, column=0, sticky=tk.W, pady=(0, 20))

        # Hint input
        ttk.Label(main_frame, text=t["hint_label"]).grid(row=4, column=0, sticky=tk.W, pady=(0, 5))
        self.hint_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.hint_var, width=50).grid(row=5, column=0, columnspan=2, 
                                                                       sticky=(tk.W, tk.E), pady=(0, 20))

        # Language selector
        ttk.Label(main_frame, text="Language:").grid(row=3, column=1, sticky=tk.W, pady=(0, 20))
        self.language_var = tk.StringVar(value=self.language)
        ttk.Combobox(main_frame, textvariable=self.language_var, 
                     values=["en", "hi"], state="readonly").grid(row=3, column=1, sticky=tk.E)
        self.language_var.trace("w", self.update_language)

        # Strength bar
        self.strength_bar = ttk.Progressbar(main_frame, length=300, mode='determinate')
        self.strength_bar.grid(row=6, column=0, columnspan=2, pady=(0, 10))
        self.strength_label = ttk.Label(main_frame, text="Strength: 0/100")
        self.strength_label.grid(row=6, column=2, sticky=tk.W)

        # Results text
        self.results_text = scrolledtext.ScrolledText(main_frame, width=80, height=15, 
                                                    wrap=tk.WORD, font=("Consolas", 10))
        self.results_text.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))

        # History panel
        ttk.Label(main_frame, text="Password History").grid(row=8, column=0, columnspan=3, pady=(0, 5))
        self.history_text = scrolledtext.ScrolledText(main_frame, width=80, height=5, 
                                                    wrap=tk.WORD, font=("Consolas", 10))
        self.history_text.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
        self.history_text.configure(state='disabled')

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=10, column=0, columnspan=3, pady=(10, 0))
        ttk.Button(button_frame, text="🔍 " + t["analyze"], command=self.analyze_password).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="💡 " + t["suggest"], command=self.get_suggestions).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🎲 " + t["generate"], command=self.generate_memorable).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🗑️ " + t["clear"], command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="📊 Health Report", command=self.save_health_report).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🎮 Challenge Mode", command=self.start_challenge_mode).pack(side=tk.LEFT)

        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(7, weight=1)
        self.show_welcome_message()

    def show_welcome_message(self):
        """Display welcome message in selected language."""
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        welcome_msg = f"""🌟 {t["welcome"]}

This tool embodies the hackathon’s theme of human-centric security:
• Validates passwords for security and intentionality
• Avoids rigid rules, encourages thoughtful patterns
• Penalizes confusing characters (e.g., '1' vs 'l')
• Provides empathetic feedback and suggestions
• Supports multiple languages and accessibility

Try it:
1. Enter a password and optional hint
2. Analyze, get suggestions, or generate new passwords
3. Check history or try challenge mode!
All analysis is local for privacy!
"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, welcome_msg)

    def on_password_change(self, *args):
        """Real-time feedback for password strength."""
        password = self.password_var.get()
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        if not password:
            self.strength_bar['value'] = 0
            self.strength_label.configure(text="Strength: 0/100")
            return
        score, _ = self.intelligence.score_password(password, self.hint_var.get())
        self.strength_bar['value'] = score
        self.strength_bar['style'] = ('green.Horizontal.TProgressbar' if score >= 60 else
                                     'yellow.Horizontal.TProgressbar' if score >= 40 else
                                     'red.Horizontal.TProgressbar')
        self.strength_label.configure(text=f"Strength: {score}/100")

    def toggle_password_visibility(self):
        """Toggle password visibility."""
        self.password_entry.configure(show="" if self.show_password_var.get() else "*")

    def update_language(self, *args):
        """Update GUI text based on selected language."""
        self.intelligence.language = self.language_var.get()
        self.show_welcome_message()
        self.setup_gui()  # Rebuild GUI with new language

    def update_history_display(self):
        """Update history panel with hashed passwords and scores."""
        self.history_text.configure(state='normal')
        self.history_text.delete(1.0, tk.END)
        for _, score, timestamp in self.intelligence.password_history:
            self.history_text.insert(tk.END, f"[{timestamp}] Score: {score}/100\n")
        self.history_text.configure(state='disabled')

    def analyze_password(self):
        """Analyze password and display results."""
        password = self.password_var.get()
        hint = self.hint_var.get()
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        if not password:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, f"⚠️ {t['empty_error']}")
            return

        score, analysis = self.intelligence.score_password(password, hint)
        feedback = self.intelligence.give_feedback(score, analysis)
        strength_bar = self.intelligence.format_strength_bar(score)
        is_valid = t["valid"] if self.intelligence.is_valid_password(password) else t["invalid"]

        results = f"""📊 PASSWORD ANALYSIS
{'='*50}

{strength_bar}
Status: {is_valid}
{feedback}

🔬 Details:
Length: {analysis['length_score']:.1f}/50
Variety: {analysis['variety_score']:.1f}/25
Uniqueness: {analysis['uniqueness_score']:.1f}/15
Pronounceability: {analysis['pronounceability_score']:.1f}/10
Hint Relevance: {analysis['hint_relevance_score']:.1f}/5
Bonus: {analysis['bonus_points']}
Pattern Penalty: -{analysis['total_penalty']:.1f}
Blacklist Penalty: -{analysis['blacklist_penalty']:.1f}
Confusing Chars Penalty: -{analysis['confusing_penalty']:.1f}
Reuse Penalty: -{analysis['reuse_penalty']:.1f}
"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results)
        self.update_history_display()

    def get_suggestions(self):
        """Generate and display password suggestions."""
        password = self.password_var.get()
        hint = self.hint_var.get()
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        if not password:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, f"⚠️ {t['empty_error']}")
            return

        suggestions = self.intelligence.suggest_alternatives(password, hint, count=3)
        results = f"""💡 SUGGESTIONS
{'='*50}

Based on your input:
"""
        for i, suggestion in enumerate(suggestions, 1):
            score, _ = self.intelligence.score_password(suggestion["password"], hint)
            strength_bar = self.intelligence.format_strength_bar(score)
            results += f"""
Suggestion #{i}: {suggestion['password']}
{strength_bar}
💭 {suggestion['explanation']}
🧠 {suggestion['mnemonic']}
{'-'*60}"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results)

    def generate_memorable(self):
        """Generate memorable passwords from hint."""
        hint = self.hint_var.get()
        t = TRANSLATIONS.get(self.language, TRANSLATIONS["en"])
        if not hint:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, f"💭 {t['hint_error']}")
            return

        passwords = [
            ("Simple", self.intelligence.generate_memorable_password(hint, 12, "simple")),
            ("Balanced", self.intelligence.generate_memorable_password(hint, 16, "balanced")),
            ("Complex", self.intelligence.generate_memorable_password(hint, 20, "complex"))
        ]

        results = f"""🎲 MEMORABLE PASSWORDS
{'='*50}

Based on hint: "{hint}"
"""
        for complexity, password in passwords:
            score, _ = self.intelligence.score_password(password, hint)
            strength_bar = self.intelligence.format_strength_bar(score)
            results += f"""{complexity}: {password}
{strength_bar}
{'-'*60}
"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results)

    def save_health_report(self):
        """Save password health report to a text file."""
        password = self.password_var.get()
        hint = self.hint_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to generate a report.")
            return
        report = self.intelligence.generate_health_report(password, hint)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"password_report_{timestamp}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report)
        messagebox.showinfo("Success", f"Health report saved as {filename}")

    def start_challenge_mode(self):
        """Start challenge mode to test password creation skills."""
        challenge_window = tk.Toplevel(self.root)
        challenge_window.title("Password Challenge Mode")
        challenge_window.geometry("600x400")

        ttk.Label(challenge_window, text="🎮 Password Challenge Mode", 
                 font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(challenge_window, text="Create a password that scores 80+!").pack(pady=5)

        password_var = tk.StringVar()
        ttk.Entry(challenge_window, textvariable=password_var, width=40, show="*").pack(pady=10)
        result_label = ttk.Label(challenge_window, text="Enter a password to start")
        result_label.pack(pady=10)

        def check_challenge():
            password = password_var.get()
            score, _ = self.intelligence.score_password(password)
            if score >= 80:
                result_label.configure(text=f"🎉 Success! Score: {score}/100")
            else:
                result_label.configure(text=f"Try again! Score: {score}/100. Aim for 80+.")

        ttk.Button(challenge_window, text="Check Password", command=check_challenge).pack(pady=10)

    def clear_results(self):
        """Clear results and show welcome message."""
        self.show_welcome_message()
        self.strength_bar['value'] = 0
        self.strength_label.configure(text="Strength: 0/100")

    def run(self):
        """Start GUI with accessibility styles."""
        style = ttk.Style()
        style.configure('green.Horizontal.TProgressbar', background='green')
        style.configure('yellow.Horizontal.TProgressbar', background='yellow')
        style.configure('red.Horizontal.TProgressbar', background='red')
        style.configure('TLabel', font=("Arial", 12))  # Accessibility: larger font
        self.root.mainloop()

def run_cli():
    """Run CLI version with internationalization support."""
    intelligence = PasswordIntelligence()
    t = TRANSLATIONS["en"]

    print("🔐 " + t["welcome"])
    print("=" * 55)
    print("Validates passwords with human-centric principles.")

    while True:
        try:
            password = input(f"\n🔑 {t['enter_password']} (or 'quit'): ").strip()
            if password.lower() in ['quit', 'exit', 'q']:
                print("👋 Exiting...")
                break
            if not password:
                print(f"⚠️ {t['empty_error']}")
                continue

            hint = input(f"💭 {t['hint_label']} (press Enter to skip): ").strip()
            score, analysis = intelligence.score_password(password, hint)
            strength_bar = intelligence.format_strength_bar(score)
            is_valid = t["valid"] if intelligence.is_valid_password(password) else t["invalid"]

            print(f"\n📊 ANALYSIS\n{strength_bar}\nStatus: {is_valid}")
            print(intelligence.give_feedback(score, analysis))

            if input("\n🤔 Want suggestions? (y/n): ").strip().lower() in ['y', 'yes']:
                print(f"\n💡 SUGGESTIONS")
                suggestions = intelligence.suggest_alternatives(password, hint, count=2)
                for i, suggestion in enumerate(suggestions, 1):
                    sugg_score, _ = intelligence.score_password(suggestion["password"], hint)
                    sugg_bar = intelligence.format_strength_bar(sugg_score)
                    print(f"\nSuggestion #{i}: {suggestion['password']}\n{sugg_bar}\n💭 {suggestion['explanation']}")

            if hint and input("\n🎲 Generate from hint? (y/n): ").strip().lower() in ['y', 'yes']:
                print(f"\n🎲 MEMORABLE PASSWORDS")
                for complexity in ["simple", "balanced", "complex"]:
                    pwd = intelligence.generate_memorable_password(hint, 16, complexity)
                    score, _ = intelligence.score_password(pwd, hint)
                    bar = intelligence.format_strength_bar(score)
                    print(f"{complexity.title()}: {pwd}\n{bar}")

        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            break

def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Smart Password Intelligence - Hackathon Submission",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with --gui for graphical interface or without for CLI."
    )
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    parser.add_argument("--strictness", choices=["lenient", "balanced", "strict"], 
                       default="balanced", help="Scoring strictness")
    parser.add_argument("--language", choices=["en", "hi"], default="en", help="Language")
    args = parser.parse_args()

    if args.gui and TKINTER_AVAILABLE:
        gui = PasswordIntelligenceGUI(language=args.language)
        gui.intelligence.strictness_mode = args.strictness
        gui.run()
    else:
        intelligence = PasswordIntelligence(args.strictness, args.language)
        run_cli()

    # Hackathon submission: Accepted and rejected passwords
    accepted = [
        "RiverCode#2024!", "SunnyHill92$", "BlueSky@2023", "DragonFly!88",
        "CodeMaster#42", "StarJump2025$", "OceanWave&99", "TigerRun#2024",
        "BrightMoon!23", "ForestPath$88"
    ]
    rejected = [
        "password", "123456", "qwerty", "aaaaaa", "zxcvbnm", "pass123",
        "111111", "1q2w3e", "I1lusion", "xzvqwp"
    ]

    print("\nAccepted Passwords:")
    intelligence = PasswordIntelligence()
    for pwd in accepted:
        score, _ = intelligence.score_password(pwd)
        print(f"{pwd}: Score {score} {'✓' if intelligence.is_valid_password(pwd) else '✗'}")

    print("\nRejected Passwords:")
    for pwd in rejected:
        score, _ = intelligence.score_password(pwd)
        print(f"{pwd}: Score {score} {'✓' if intelligence.is_valid_password(pwd) else '✗'}")

if __name__ == "__main__":
    exit(main())