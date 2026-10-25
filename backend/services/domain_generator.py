"""
Domain Generation Service
Generates typosquatting and lookalike variants using 12 techniques.
"""
from typing import List, Set
import tldextract

COMMON_TLDS = [
    ".com", ".net", ".org", ".info", ".biz",
    ".co", ".io", ".online", ".site", ".xyz"
]

KEYBOARD_ADJACENT: dict = {
    'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'ersfxc',
    'e': 'wsdr', 'f': 'rtgdvc', 'g': 'tyhfvb', 'h': 'yugjbn',
    'i': 'ujko', 'j': 'uihknm', 'k': 'iojlm', 'l': 'opk',
    'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
    'q': 'wa', 'r': 'etdf', 's': 'wedxza', 't': 'ryfg',
    'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
    'y': 'tghu', 'z': 'asx'
}

HOMOGLYPHS: dict = {
    'a': ['4', '@'], 'e': ['3'], 'i': ['1', 'l'],
    'l': ['1', 'i'], 'o': ['0'], 's': ['5'],
    't': ['7'], 'g': ['9'], 'b': ['6'],
}

PHISHING_PREFIXES = [
    "secure-", "login-", "signin-", "my-",
    "account-", "verify-", "update-", "support-"
]
PHISHING_SUFFIXES = [
    "-secure", "-login", "-signin", "-account",
    "-verify", "-support", "-online", "-official"
]


def extract_domain_parts(domain: str):
    ext = tldextract.extract(domain.lower().strip())
    return ext.domain, ext.suffix or "com"


def generate_all_variants(domain: str, max_variants: int = 1000) -> List[dict]:
    name, tld = extract_domain_parts(domain)
    variants = []
    seen = set()

    def add(d: str, technique: str):
        clean = d.lower().strip(".")
        if clean and clean != f"{name}.{tld}" and clean not in seen:
            seen.add(clean)
            variants.append({"domain": clean, "technique": technique})

    # 1. Omission
    for i in range(len(name)):
        add(f"{name[:i]}{name[i+1:]}.{tld}", "omission")

    # 2. Repetition
    for i in range(len(name)):
        add(f"{name[:i]}{name[i]*2}{name[i+1:]}.{tld}", "repetition")

    # 3. Transposition
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i+1] = s[i+1], s[i]
        add(f"{''.join(s)}.{tld}", "transposition")

    # 4. Keyboard adjacency
    for i, ch in enumerate(name):
        for adj in KEYBOARD_ADJACENT.get(ch, ""):
            add(f"{name[:i]}{adj}{name[i+1:]}.{tld}", "keyboard-typo")

    # 5. Homoglyphs
    for i, ch in enumerate(name):
        for hg in HOMOGLYPHS.get(ch, []):
            add(f"{name[:i]}{hg}{name[i+1:]}.{tld}", "homoglyph")

    # 6. TLD variation
    for alt_tld in COMMON_TLDS:
        add(f"{name}{alt_tld}", "tld-variation")

    # 7. Hyphen insertion
    for i in range(1, len(name)):
        add(f"{name[:i]}-{name[i:]}.{tld}", "hyphen-insertion")

    # 8. Phishing prefix
    for prefix in PHISHING_PREFIXES:
        add(f"{prefix}{name}.{tld}", "phishing-prefix")

    # 9. Phishing suffix
    for suffix in PHISHING_SUFFIXES:
        add(f"{name}{suffix}.{tld}", "phishing-suffix")

    # 10. Character insertion
    for i in range(len(name) + 1):
        for ch in "aeiou":
            if i > 0 and name[i-1] == ch:
                continue
            add(f"{name[:i]}{ch}{name[i:]}.{tld}", "char-insertion")

    # 11. Combosquatting
    for word in ["shop", "store", "pay", "help", "service", "web"]:
        add(f"{name}{word}.{tld}", "combosquatting")
        add(f"{word}{name}.{tld}", "combosquatting")

    # 12. WWW typo
    add(f"www-{name}.{tld}", "www-prefix-typo")

    # filter
    variants = [v for v in variants if len(v["domain"]) < 30]

    return variants[:max(0, max_variants)]


def calculate_similarity(domain1: str, domain2: str) -> float:
    try:
        import Levenshtein
        n1 = tldextract.extract(domain1).domain
        n2 = tldextract.extract(domain2).domain
        if not n1 or not n2:
            return 0.0
        dist = Levenshtein.distance(n1, n2)
        return round(1.0 - (dist / max(len(n1), len(n2))), 3)
    except ImportError:
        n1 = tldextract.extract(domain1).domain
        n2 = tldextract.extract(domain2).domain
        if not n1 or not n2:
            return 0.0
        common = set(n1) & set(n2)
        return round(len(common) / max(len(n1), len(n2)), 3)
