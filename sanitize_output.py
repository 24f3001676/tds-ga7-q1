import re
from urllib.parse import unquote, urlparse

# ============================================================
# Sanitizer Configuration
# ============================================================

SANITIZE_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}

ALLOWED_EXTERNAL_HOSTS = {
    "cdn-0nl2whi.example",
    "app-a2ytvc7.example",
}

NAMED_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}

HTML_ENTITY_PATTERN = re.compile(
    r"&(?:(lt|gt|quot|apos|amp)|#(?:([0-9]+)|[xX]([0-9a-fA-F]+)));"
)

UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})")

# HTML opening dangerous tags: <script, <iframe, <object, <embed
HTML_SCRIPT_TAG_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

# HTML event handlers in attribute position: <tag ... onxxx=
HTML_EVENT_HANDLER_RE = re.compile(
    r"<[a-zA-Z][a-zA-Z0-9:-]*\b[^>]*\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
    re.IGNORECASE,
)

# Dangerous schemes anywhere in text: javascript:, data:, vbscript:
DANGEROUS_SCHEME_TEXT_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

# Quoted src and href in HTML
HTML_QUOTED_URL_RE = re.compile(
    r"""\b(?:src|href)\s*=\s*(?P<q>["'])(?P<url>.*?)(?P=q)""",
    re.IGNORECASE,
)

# Markdown link/image target inside ](...)
MARKDOWN_URL_RE = re.compile(
    r"""\]\(\s*(?:<(?P<angle>[^>]+)>|(?P<plain>[^\s\)\"']+))(?:\s+["'][^)]*["'])?\s*\)""",
    re.IGNORECASE,
)

# SQL metacharacters
SQL_METACHAR_RE = re.compile(
    r"""['";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
    re.IGNORECASE,
)

# Shell metacharacters: ; & | ` < > $( ${
SHELL_METACHAR_RE = re.compile(
    r"[;&|`<>]|\$\(|\$\{"
)


# ============================================================
# Decoder (Rule 2)
# ============================================================

def decode_entities_single_pass(text: str) -> str:
    def _replace_entity(match):
        named, dec, hex_val = match.groups()
        if named:
            return NAMED_ENTITIES[f"&{named};"]
        try:
            cp = int(dec, 10) if dec is not None else int(hex_val, 16)
            if 0 <= cp <= 0x10FFFF:
                return chr(cp)
        except (ValueError, OverflowError):
            pass
        return match.group(0)

    return HTML_ENTITY_PATTERN.sub(_replace_entity, text)


def decode_once(value: str) -> str:
    # 1. Percent escapes
    decoded = unquote(value)

    # 2. Specific HTML entities (named & numeric)
    decoded = decode_entities_single_pass(decoded)

    # 3. Literal \uXXXX escapes
    decoded = UNICODE_ESCAPE_PATTERN.sub(
        lambda m: chr(int(m.group(1), 16)),
        decoded,
    )

    return decoded


# ============================================================
# URL Extraction & Safety Checks
# ============================================================

def extract_channel_urls(channel: str, output: str) -> list:
    if channel == "html":
        return [
            match.group("url").strip()
            for match in HTML_QUOTED_URL_RE.finditer(output)
        ]

    if channel == "markdown":
        urls = []
        for match in MARKDOWN_URL_RE.finditer(output):
            angle = match.group("angle")
            plain = match.group("plain")
            if angle is not None:
                urls.append(angle.strip())
            elif plain is not None:
                urls.append(plain.strip())
        return urls

    if channel == "url":
        trimmed = output.strip()
        return [trimmed] if trimmed else []

    return []


def is_dangerous_url_scheme(url: str) -> bool:
    if not url:
        return False

    if DANGEROUS_SCHEME_TEXT_RE.search(url):
        return True

    # Protocol-relative resolves as https (safe scheme)
    if url.startswith("//"):
        return False

    parsed = urlparse(url)
    if parsed.scheme:
        return parsed.scheme.lower() not in {"http", "https"}

    return False


def is_external_exfil(url: str) -> bool:
    if not url:
        return False

    if url.startswith("//"):
        parsed = urlparse("https:" + url)
    else:
        parsed = urlparse(url)

    # Relative references are safe
    if not parsed.scheme and not url.startswith("//"):
        return False

    hostname = parsed.hostname
    if hostname is None:
        return True

    return hostname.lower() not in ALLOWED_EXTERNAL_HOSTS


# ============================================================
# Channel Rules (Applied in exact order)
# ============================================================

def apply_channel_rules(output: str, channel: str) -> str:
    # --------------------------------------------------------
    # HTML: SCRIPT_TAG -> EVENT_HANDLER -> DANGEROUS_SCHEME -> EXTERNAL_EXFIL
    # --------------------------------------------------------
    if channel == "html":
        if HTML_SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"

        if HTML_EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"

        if DANGEROUS_SCHEME_TEXT_RE.search(output):
            return "DANGEROUS_SCHEME"

        urls = extract_channel_urls("html", output)
        for u in urls:
            if is_dangerous_url_scheme(u):
                return "DANGEROUS_SCHEME"

        for u in urls:
            if is_external_exfil(u):
                return "EXTERNAL_EXFIL"

        return "SAFE"

    # --------------------------------------------------------
    # Markdown: DANGEROUS_SCHEME -> EXTERNAL_EXFIL
    # --------------------------------------------------------
    if channel == "markdown":
        if DANGEROUS_SCHEME_TEXT_RE.search(output):
            return "DANGEROUS_SCHEME"

        urls = extract_channel_urls("markdown", output)
        for u in urls:
            if is_dangerous_url_scheme(u):
                return "DANGEROUS_SCHEME"

        for u in urls:
            if is_external_exfil(u):
                return "EXTERNAL_EXFIL"

        return "SAFE"

    # --------------------------------------------------------
    # URL: DANGEROUS_SCHEME -> EXTERNAL_EXFIL
    # --------------------------------------------------------
    if channel == "url":
        if DANGEROUS_SCHEME_TEXT_RE.search(output):
            return "DANGEROUS_SCHEME"

        urls = extract_channel_urls("url", output)
        for u in urls:
            if is_dangerous_url_scheme(u):
                return "DANGEROUS_SCHEME"

        for u in urls:
            if is_external_exfil(u):
                return "EXTERNAL_EXFIL"

        return "SAFE"

    # --------------------------------------------------------
    # SQL: SQL_METACHAR
    # --------------------------------------------------------
    if channel == "sql":
        if SQL_METACHAR_RE.search(output):
            return "SQL_METACHAR"
        return "SAFE"

    # --------------------------------------------------------
    # Shell: SHELL_METACHAR
    # --------------------------------------------------------
    if channel == "shell":
        if SHELL_METACHAR_RE.search(output):
            return "SHELL_METACHAR"
        return "SAFE"

    return "INVALID_SCHEMA"


# ============================================================
# Main Sanitizer Decision Function
# ============================================================

def evaluate_sanitize_output(data) -> dict:
    # --------------------------------------------------------
    # Rule 1: INVALID_SCHEMA
    # --------------------------------------------------------
    if not isinstance(data, dict):
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    if set(data.keys()) != {"channel", "output"}:
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    channel = data.get("channel")
    output = data.get("output")

    if channel not in SANITIZE_CHANNELS:
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    if not isinstance(output, str):
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    if len(output) > 20000:
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    # --------------------------------------------------------
    # Rule 2: ENCODED_PAYLOAD
    # --------------------------------------------------------
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = apply_channel_rules(decoded, channel)
        if decoded_reason != "SAFE":
            return {"safe": False, "reason": "ENCODED_PAYLOAD"}

    # --------------------------------------------------------
    # Rule 3: Channel rules on ORIGINAL output
    # --------------------------------------------------------
    reason = apply_channel_rules(output, channel)
    if reason != "SAFE":
        return {"safe": False, "reason": reason}

    return {"safe": True, "reason": "SAFE"}
