"""Password strength analysis and secure password generation.

Passwords are only ever processed in-memory for the duration of a request.
Nothing in this module writes a raw password to disk, a database, or a log.
"""
from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass, field

from zxcvbn import zxcvbn

# ---------------------------------------------------------------------------
# Wordlists / character sets
# ---------------------------------------------------------------------------

AMBIGUOUS_CHARS = "Il1O0"

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# A compact passphrase wordlist (short, common, easy-to-type English words).
# Kept intentionally offline/embedded so the app never needs network access.
WORDLIST = [
    "amber", "anchor", "angle", "apple", "arrow", "ash", "aspen", "atlas",
    "autumn", "banjo", "barley", "basil", "beacon", "bear", "birch", "bison",
    "blaze", "bloom", "blue", "bolt", "bramble", "brave", "breeze", "bright",
    "brook", "cabin", "canyon", "cedar", "chalk", "charm", "cinder", "circuit",
    "clover", "cobalt", "comet", "coral", "cove", "crane", "crater", "crimson",
    "crystal", "dawn", "delta", "denim", "desert", "dove", "dune", "eagle",
    "echo", "ember", "falcon", "feather", "fern", "field", "finch", "flame",
    "flint", "forest", "forge", "fox", "garnet", "glacier", "glow", "gold",
    "granite", "grove", "harbor", "hawk", "hazel", "hearth", "hickory",
    "horizon", "hollow", "honey", "indigo", "ivory", "ivy", "jasper",
    "jungle", "juniper", "kestrel", "lagoon", "lantern", "laurel", "lark",
    "linen", "lotus", "lumen", "lunar", "lynx", "maple", "marble", "marsh",
    "meadow", "mesa", "meteor", "mint", "mist", "moss", "nebula", "nectar",
    "north", "oak", "oasis", "obsidian", "ocean", "olive", "onyx", "opal",
    "orbit", "orchid", "osprey", "otter", "pearl", "pebble", "petal",
    "phoenix", "pine", "plateau", "plum", "polar", "poppy", "prairie",
    "quartz", "quill", "raven", "reef", "ridge", "river", "robin", "rowan",
    "ruby", "sage", "sail", "sapling", "sequoia", "shadow", "shale",
    "shore", "silver", "slate", "sol", "solstice", "sparrow", "spruce",
    "star", "storm", "summit", "sunset", "swan", "tandem", "thicket",
    "thistle", "thunder", "timber", "topaz", "trail", "tundra", "twilight",
    "umber", "valley", "velvet", "verdant", "violet", "vista", "walnut",
    "warbler", "wave", "willow", "wisp", "wolf", "woodland", "wren", "zephyr",
    "zenith",
]

# A short, well-known list of catastrophically weak passwords / substrings.
# This is intentionally small (zxcvbn already carries a much larger
# frequency-ranked dictionary); it exists mainly as a seed for the
# user-contributed pattern system below.
SEED_WEAK_PATTERNS = [
    "password", "letmein", "qwerty", "111111", "123456", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "football", "baseball",
    "trustno1", "superman", "master",
]

# Common "leetspeak" character substitutions, richest-looking option first.
LEET_MAP = {
    "a": ["@", "4"],
    "b": ["8"],
    "e": ["3"],
    "g": ["9"],
    "i": ["1", "!"],
    "l": ["1"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "z": ["2"],
}


# ---------------------------------------------------------------------------
# Strength analysis
# ---------------------------------------------------------------------------

STRENGTH_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}


@dataclass
class StrengthResult:
    score: int  # 0-4, matches zxcvbn scale
    label: str
    crack_time_display: str
    entropy_bits: float
    warning: str
    suggestions: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    checks: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "crack_time_display": self.crack_time_display,
            "entropy_bits": round(self.entropy_bits, 1),
            "warning": self.warning,
            "suggestions": self.suggestions,
            "matched_patterns": self.matched_patterns,
            "checks": self.checks,
        }


def _basic_checks(pw: str) -> dict:
    return {
        "length_ok": len(pw) >= 12,
        "has_lower": bool(re.search(r"[a-z]", pw)),
        "has_upper": bool(re.search(r"[A-Z]", pw)),
        "has_digit": bool(re.search(r"\d", pw)),
        "has_symbol": bool(re.search(r"[^A-Za-z0-9]", pw)),
        "no_repeats": not bool(re.search(r"(.)\1\1", pw)),
        "no_sequence": not _has_sequential_run(pw),
    }


_SEQUENCES = [
    string.ascii_lowercase,
    string.ascii_lowercase[::-1],
    "0123456789",
    "9876543210",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def _has_sequential_run(pw: str, run_len: int = 4) -> bool:
    lower = pw.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - run_len + 1):
            if seq[i : i + run_len] in lower:
                return True
    return False


def _matched_custom_patterns(pw: str, patterns: list[str]) -> list[str]:
    """Return the subset of user-contributed patterns found in the password.

    Patterns may be plain substrings (case-insensitive) or, if wrapped in
    slashes e.g. /foo\\d+/, a regular expression.
    """
    lower_pw = pw.lower()
    hits: list[str] = []
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        try:
            if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 1:
                if re.search(pattern[1:-1], pw, re.IGNORECASE):
                    hits.append(pattern)
            elif pattern.lower() in lower_pw:
                hits.append(pattern)
        except re.error:
            # Malformed regex contributed by a user shouldn't break checking.
            if pattern.lower() in lower_pw:
                hits.append(pattern)
    return hits


def analyze_password(password: str, custom_patterns: list[str] | None = None,
                      user_inputs: list[str] | None = None) -> StrengthResult:
    """Score a password using zxcvbn plus a denylist of contributed patterns.

    `user_inputs` lets the caller pass contextual strings (e.g. a name or
    company already typed elsewhere in the form) that zxcvbn should also
    penalize if reused inside the password.
    """
    custom_patterns = custom_patterns or []
    all_seed = SEED_WEAK_PATTERNS + custom_patterns

    result = zxcvbn(password, user_inputs=user_inputs or [])
    score = result["score"]

    matched = _matched_custom_patterns(password, all_seed)
    if matched and score > 0:
        # A contributed weak pattern found inside the password is a strong
        # negative signal even if zxcvbn's model didn't flag it -- knock the
        # score down (never below 0).
        score = max(0, score - 2)

    checks = _basic_checks(password)
    entropy_bits = math.log2(result["guesses"]) if result["guesses"] > 0 else 0.0

    feedback = result.get("feedback", {})
    suggestions = list(feedback.get("suggestions", []))
    warning = feedback.get("warning") or ""

    if matched:
        warning = warning or "Contains a pattern flagged by the community denylist."
        suggestions.append(
            "Avoid using: " + ", ".join(m.strip("/") for m in matched)
        )
    if not checks["length_ok"]:
        suggestions.append("Use at least 12 characters.")
    if not checks["has_symbol"]:
        suggestions.append("Add a symbol (e.g. !, #, %, or @).")
    if not checks["no_sequence"]:
        suggestions.append("Avoid keyboard or alphabetic sequences (e.g. abcd, qwerty).")
    if not checks["no_repeats"]:
        suggestions.append("Avoid repeating the same character three or more times.")

    crack_times = result.get("crack_times_display", {})
    crack_time_display = crack_times.get(
        "offline_slow_hashing_1e4_per_second", "unknown"
    )

    return StrengthResult(
        score=score,
        label=STRENGTH_LABELS[score],
        crack_time_display=crack_time_display,
        entropy_bits=entropy_bits,
        warning=warning,
        suggestions=list(dict.fromkeys(suggestions)),  # de-dupe, keep order
        matched_patterns=matched,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    length = max(8, min(length, 128))

    pools = []
    if use_lower:
        pools.append(LOWER)
    if use_upper:
        pools.append(UPPER)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)
    if not pools:
        pools = [LOWER, UPPER, DIGITS]

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS_CHARS) for pool in pools]

    alphabet = "".join(pools)

    # Guarantee at least one character from every selected pool.
    guaranteed = [secrets.choice(pool) for pool in pools]
    remaining = [secrets.choice(alphabet) for _ in range(length - len(guaranteed))]

    chars = guaranteed + remaining
    # Fisher-Yates shuffle using a CSPRNG so pool order doesn't leak position.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True,
    add_symbol: bool = True,
) -> str:
    num_words = max(3, min(num_words, 10))
    words = [secrets.choice(WORDLIST) for _ in range(num_words)]
    if capitalize:
        words = [w.capitalize() for w in words]

    parts = list(words)
    if add_number:
        parts.append(str(secrets.randbelow(9000) + 1000))
    if add_symbol:
        parts.append(secrets.choice(SYMBOLS))

    return separator.join(parts)


def generate_from_word(
    word: str,
    substitution_rate: float = 0.85,
    randomize_case: bool = True,
    add_digits: bool = True,
    add_symbol: bool = True,
) -> str:
    """Turn a memorable word/phrase into a leetspeak-style password.

    e.g. "innovation" -> "1nN0v@710n". Substitutable letters (a, e, i, o, s,
    t, ...) are swapped for look-alike digits/symbols; other letters get
    randomized casing. On its own this is still a disguised dictionary word
    -- modern crackers explicitly unmunge l33t substitutions -- so by
    default a short random digit/symbol tail is appended for real strength.
    """
    word = word.strip()
    if not word:
        raise ValueError("Word must not be empty.")
    if len(word) > 64:
        raise ValueError("Word must be 64 characters or fewer.")

    rate = max(0.0, min(substitution_rate, 1.0))
    out = []
    for ch in word:
        lower = ch.lower()
        if lower in LEET_MAP and secrets.randbelow(100) < int(rate * 100):
            out.append(secrets.choice(LEET_MAP[lower]))
        elif ch.isalpha() and randomize_case:
            out.append(ch.upper() if secrets.randbelow(2) else ch.lower())
        else:
            out.append(ch)

    if add_digits:
        out.append(str(secrets.randbelow(90) + 10))
    if add_symbol:
        out.append(secrets.choice(SYMBOLS))

    return "".join(out)


def generate_from_pattern(pattern: str) -> str:
    """Fill a user-supplied template mask into a concrete random password.

    Mask characters:
        L = random uppercase letter    l = random lowercase letter
        d = random digit                s = random symbol
        w = random word from the wordlist (capitalized)
    Any other character in the pattern is copied through literally, so a
    pattern like "Ll-dddd-s" yields e.g. "Ab-4821-#".
    """
    if not pattern or len(pattern) > 200:
        raise ValueError("Pattern must be 1-200 characters long.")

    out = []
    for ch in pattern:
        if ch == "L":
            out.append(secrets.choice(UPPER))
        elif ch == "l":
            out.append(secrets.choice(LOWER))
        elif ch == "d":
            out.append(secrets.choice(DIGITS))
        elif ch == "s":
            out.append(secrets.choice(SYMBOLS))
        elif ch == "w":
            out.append(secrets.choice(WORDLIST).capitalize())
        else:
            out.append(ch)
    return "".join(out)
