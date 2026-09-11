#!/usr/bin/env python3
"""Scrape a directory subtree of source files out of the NetBurner Doxygen docs.

The doc site renders its file tree client-side, but Doxygen also ships the tree
as plain JS data files (files_dup.js, then one dir_<md5>.js per directory), so
no browser or HTML link-crawling is needed: we walk the JS, then fetch one
"<file>_source.html" per file and turn it back into source text.

  python3 nbdocs_scrape.py --root /arch/coldfire/cpu/MCF5441X --out out/
  python3 nbdocs_scrape.py --list                 # just print the directory tree
"""

import argparse, concurrent.futures as cf, hashlib, html, os, re, sys, time, urllib.error, urllib.request

BASE = "https://www.netburner.com/NBDocsTest/Developer/html/"
UA = "Mozilla/5.0 (compatible; nbdocs-scrape/1.0)"

CACHE = None          # set from --cache
ENTRY = re.compile(r'\[\s*"((?:[^"\\]|\\.)*)"\s*,\s*"([^"]*)"\s*,\s*("[^"]*"|null)\s*\]')
FRAGMENT = re.compile(r'<div class="fragment">', re.S)
LINE = re.compile(r'<div class="line">(.*?)</div>', re.S)
LNUM = re.compile(r'<a id="l0*(\d+)"')
LINENO = re.compile(r'<span class="lineno">.*?</span>', re.S)
TAG = re.compile(r'<[^>]+>')


def fetch(name, tries=3):
    """GET one doc-site file, with an on-disk cache and retries."""
    if CACHE:
        path = os.path.join(CACHE, hashlib.sha1(name.encode()).hexdigest())
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return f.read()
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(BASE + name, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read().decode("utf-8", "replace")
            break
        except Exception as e:                      # noqa: BLE001 - retry anything
            last = e
            time.sleep(1.5 * (attempt + 1))
    else:
        raise last
    if CACHE:
        os.makedirs(CACHE, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
    return body


def walk(js, path, files, dirs):
    """Recurse the dir_*.js tree, collecting (path, doc-page) for every file."""
    dirs.append(path or "/")
    for name, page, _child in ENTRY.findall(fetch(js)):
        if page.startswith("dir_"):
            walk(page[:-5] + ".js", path + "/" + name, files, dirs)
        else:
            # Doxygen disambiguates duplicate basenames by prefixing a path;
            # we already know the directory, so keep only the basename.
            files.append((path + "/" + name.rsplit("/", 1)[-1], page))


def source_page(page):
    """Doc page -> the matching *_source.html holding the full listing."""
    return page if page.endswith("_source.html") else page[:-5] + "_source.html"


def extract(page_html):
    """Turn a Doxygen source listing back into plain source text."""
    m = FRAGMENT.search(page_html)
    if not m:
        return None
    # Foldable regions (struct/enum bodies) wrap lines in extra nested divs, so
    # the fragment cannot be delimited by its closing tag; instead match the
    # line divs directly, which never nest. Trailing hover-tooltip blocks are
    # not source, so stop at the first one.
    body = page_html[m.end():].split('<div class="ttc"')[0]
    # The site is generated with STRIP_CODE_COMMENTS=YES, so documentation
    # comment blocks are missing from the listing and line numbers jump. Place
    # each line at its published number and leave the gaps blank, so line
    # numbers still match the real header (and the doc page's anchors).
    lines, last = {}, 0
    for chunk in LINE.findall(body):
        n = LNUM.search(chunk)
        text = TAG.sub("", LINENO.sub("", chunk))
        text = html.unescape(text).replace(" ", " ").rstrip()
        last = int(n.group(1)) if n else last + 1
        lines[last] = text
    if not lines:
        return None
    return "\n".join(lines.get(i, "") for i in range(1, last + 1)) + "\n"


def grab(item, outdir):
    relpath, page = item
    try:
        text = extract(fetch(source_page(page)))
    except urllib.error.HTTPError as e:
        return relpath, "HTTP %s" % e.code, 0
    except Exception as e:                          # noqa: BLE001
        return relpath, str(e), 0
    if not text:
        return relpath, "no source fragment on page", 0
    dest = os.path.join(outdir, relpath.lstrip("/"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text)
    return relpath, None, len(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", action="append", default=None, metavar="PATH",
                    help="doc-tree path prefix to pull; repeatable "
                         "(default: /arch/coldfire/cpu/MCF5441X)")
    ap.add_argument("--out", default="nbdocs")
    ap.add_argument("--cache", default=".nbcache")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--list", action="store_true", help="list the tree, download nothing")
    args = ap.parse_args()

    global CACHE
    CACHE = args.cache

    files, dirs = [], []
    walk("files_dup.js", "", files, dirs)
    roots = args.root or ["/arch/coldfire/cpu/MCF5441X"]
    roots = [r.rstrip("/") + "/" for r in roots]
    sel = [f for f in files if any(f[0].startswith(r) for r in roots)]
    if not sel:
        print("no files under %s; known dirs:" % ", ".join(roots), file=sys.stderr)
        for d in dirs:
            print("  " + d, file=sys.stderr)
        return 1

    if args.list:
        for relpath, page in sel:
            print("%-60s %s" % (relpath, page))
        print("\n%d files under %s" % (len(sel), ", ".join(roots)))
        return 0

    ok = bad = 0
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        for relpath, err, size in ex.map(lambda i: grab(i, args.out), sel):
            if err:
                bad += 1
                print("FAIL %-55s %s" % (relpath, err))
            else:
                ok += 1
                print("ok   %-55s %6d B" % (relpath, size))
    print("\n%d written, %d failed -> %s/" % (ok, bad, args.out))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
