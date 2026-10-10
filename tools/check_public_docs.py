"""Check local documentation links and fictional screenshot metadata."""
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.release_guard import manifest


def check(root=ROOT):
    approved = set(manifest(root)); findings = []
    for name in approved:
        if not name.endswith('.md'): continue
        text = (root / name).read_text(encoding='utf-8')
        for match in re.finditer(r'!?\[[^\]]*\]\(([^\s)]+)\)', text):
            target = match.group(1).strip('<>')
            if target.startswith('#') or urlsplit(target).scheme: continue
            relative = unquote(target.split('#', 1)[0])
            resolved = ((root / name).parent / relative).resolve()
            if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
                findings.append({'file': name, 'reason': 'missing-or-unsafe-local-link'})
            elif resolved.relative_to(root.resolve()).as_posix() not in approved:
                findings.append({'file': name, 'reason': 'link-outside-public-manifest'})
    for name in approved:
        if not name.startswith('docs/screenshots/'): continue
        data = (root / name).read_bytes()
        if not name.endswith('.jpg') or not data.startswith(b'\xff\xd8') or len(data) > 1_000_000:
            findings.append({'file': name, 'reason': 'unsupported-screenshot-format-or-size'}); continue
        # Browser captures require no EXIF/XMP/comment metadata. Look only at
        # header segments, not compressed pixels where marker bytes may occur.
        offset = 2
        while offset < len(data):
            if data[offset] != 0xff:
                findings.append({'file': name, 'reason': 'invalid-jpeg-header'}); break
            while offset < len(data) and data[offset] == 0xff: offset += 1
            if offset >= len(data): break
            marker = data[offset]; offset += 1
            if marker in (0xda, 0xd9): break
            if marker in (0xe1, 0xed, 0xfe): findings.append({'file': name, 'reason': 'unreviewed-image-metadata'})
            if offset + 2 > len(data):
                findings.append({'file': name, 'reason': 'truncated-jpeg-header'}); break
            length = int.from_bytes(data[offset:offset+2], 'big')
            if length < 2 or offset + length > len(data):
                findings.append({'file': name, 'reason': 'invalid-jpeg-segment'}); break
            offset += length
    return findings


def main():
    findings = check()
    print(json.dumps({'passed': not findings, 'findings': findings, 'scope': 'Public local links and JPEG headers; screenshots still require fictional provenance and visual review.'}, indent=2))
    raise SystemExit(1 if findings else 0)


if __name__ == '__main__': main()
