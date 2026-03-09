import re
from urllib.parse import unquote

SQLI_PATTERN = re.compile(r"(union|select|sleep|or\s+1=1|and\s+1=1)", re.I)
TOOL_UA = re.compile(r"(sqlmap|curl|python-requests)", re.I)

def make_features(url: str, method: str, status: int, ua: str):
    u = unquote(url or "")
    m = (method or "").upper()
    ua = ua or ""

    f_len = len(u)
    f_specials = sum(not c.isalnum() for c in u)
    f_sqli_kw = 1 if SQLI_PATTERN.search(u) else 0
    f_is_post = 1 if m == "POST" else 0
    f_tool_ua = 1 if TOOL_UA.search(ua) else 0

    return [f_len, f_specials, f_sqli_kw, f_is_post, f_tool_ua]
