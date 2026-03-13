import re
from urllib.parse import unquote

pattern_sql = re.compile(r"(union|select|sleep|or\s+1=1|and\s+1=1)",re.I)
pattern_tool = re.compile(r"(sqlmap|curl|python-requests)",re.I)

def make_features(url,method,status,ua):

    url = unquote(url or "")
    method = method.upper()

    length = len(url)

    specials = 0
    for c in url:
        if not c.isalnum():
            specials += 1

    has_sql = 1 if pattern_sql.search(url) else 0
    is_post = 1 if method == "POST" else 0
    tool = 1 if pattern_tool.search(ua) else 0

    return [length,specials,has_sql,is_post,tool]
