from __future__ import annotations

import json
import re
import sys
from pathlib import Path

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
LOCAL_PATH_RE = re.compile(r"(?i)(?:/home/[^/\s]+|/Users/[^/\s]+|[A-Z]:\\Users\\[^\\\s]+)")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")
SECRET_LITERAL_RE = re.compile(
    r"(?i)(?:api[_ -]?key|client[_ -]?secret|access[_ -]?token|password|private[_ -]?token)"
    r"\s*[=:]\s*[\"'][^\"']{8,}[\"']"
)
MAILTO_RE = re.compile(r"(?i)mailto:")
AUTHOR_META_RE = re.compile(r"(?i)<meta\s+[^>]*name=[\"']author[\"']")
DENIED_PROPERTY_TERMS = {
    "owner", "taxpayer", "mailing", "email", "phone", "contact",
    "person", "ssn", "birth", "account",
}
ALLOWED_SUFFIXES = {".html", ".css", ".js", ".json", ".geojson", ".txt", ".md", ".xml", ".svg"}
SAFE_EXTENSIONLESS_FILES = {"LICENSE", "CNAME"}


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    issues: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == ".nojekyll":
            continue
        rel = str(path.relative_to(root))
        if path.suffix.casefold() not in ALLOWED_SUFFIXES and path.name not in SAFE_EXTENSIONLESS_FILES:
            issues.add(("unexpected_file_type", rel))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            issues.add(("non_utf8_file", rel))
            continue
        checks = {
            "email_address": EMAIL_RE.search(text),
            "local_user_path": LOCAL_PATH_RE.search(text),
            "private_key": PRIVATE_KEY_RE.search(text),
            "secret_literal": SECRET_LITERAL_RE.search(text),
            "mailto_link": MAILTO_RE.search(text),
            "author_metadata": AUTHOR_META_RE.search(text),
        }
        for category, match in checks.items():
            if match:
                issues.add((category, rel))
        if path.suffix.casefold() in {".json", ".geojson"}:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                issues.add(("invalid_json", rel))
                continue
            stack = [payload]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    for key, child in value.items():
                        if any(term in str(key).casefold() for term in DENIED_PROPERTY_TERMS):
                            issues.add(("disallowed_property_name", rel))
                        stack.append(child)
                elif isinstance(value, list):
                    stack.extend(value)
    if issues:
        print(json.dumps({"ok": False, "issues": [{"category": c, "path": p} for c, p in sorted(issues)]}, indent=2))
        raise SystemExit(1)
    print(json.dumps({"ok": True, "issue_count": 0}))


if __name__ == "__main__":
    main()
