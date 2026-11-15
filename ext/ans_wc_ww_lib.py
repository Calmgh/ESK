# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
# -*- coding: utf-8 -*-
"""WC-01 / WW-01 共用工具（只读检材）。"""
import sys, os, io, json, re, sqlite3, datetime

BASE = r'E:\ALL\AAAI\Works\RE\meiya'
if BASE not in sys.path:
    sys.path.insert(0, BASE)

SRC = {
    'WC-01': r'D:\meiya\src\WC-01\WC-01\WC-01.bin',
    'WW-01': r'D:\meiya\src\WW-01\WW-01\WW-01.bin',
}

_cache = {}


def get_fs(key):
    if key in _cache:
        return _cache[key]
    from mkit.image import Image
    from mkit.ntfs import NTFS
    fs = NTFS(Image(SRC[key]))
    _cache[key] = fs
    return fs


def mft_index(key):
    ck = 'mft:' + key
    if ck in _cache:
        return _cache[ck]
    fs = get_fs(key)
    idx = {}
    for e in fs.iter_mft():
        try:
            if not e.valid:
                continue
        except Exception:
            pass
        idx[e.num] = e
    _cache[ck] = idx
    return idx


def path_of(key, num, idx=None):
    if idx is None:
        idx = mft_index(key)
    parts, seen, cur = [], set(), num
    while cur and cur in idx and cur not in seen:
        seen.add(cur)
        e = idx[cur]
        nm = str(e.name)
        if nm in ('.', ''):
            break
        parts.append(nm)
        pn = getattr(e, 'parent_num', None)
        if pn is None or pn == cur:
            break
        cur = pn
    return '/' + '/'.join(reversed(parts))


def all_paths(key):
    """num -> (path, entry) 全量路径表"""
    ck = 'paths:' + key
    if ck in _cache:
        return _cache[ck]
    idx = mft_index(key)
    out = {}
    for n, e in idx.items():
        out[n] = (path_of(key, n, idx), e)
    _cache[ck] = out
    return out


def find(key, pat, is_dir=None):
    rx = re.compile(pat, re.I)
    res = []
    for n, (p, e) in all_paths(key).items():
        if rx.search(p):
            if is_dir is None or bool(e.is_dir) == is_dir:
                res.append((p, e))
    res.sort(key=lambda t: t[0])
    return res


def read(key, path):
    return get_fs(key).read_file(path)


def save(key, path, dest):
    data = read(key, path)
    d = os.path.dirname(dest)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(dest, 'wb') as f:
        f.write(data)
    return len(data)


def apple_dt(v):
    if v is None:
        return None
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=float(v) + 978307200)


def hkt(v):
    try:
        d = apple_dt(v)
        if d is None:
            return None
        return (d + datetime.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return 'BAD(%r)' % (v,)


def unix_hkt(v):
    return (datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=float(v), hours=8)).strftime('%Y-%m-%d %H:%M:%S')


def hkt_to_apple(s):
    """'YYYY-MM-DD HH:MM:SS' HKT -> apple epoch"""
    d = datetime.datetime.strptime(s, '%Y-%m-%d %H:%M:%S') - datetime.timedelta(hours=8)
    return (d - datetime.datetime(1970, 1, 1)).total_seconds() - 978307200


def open_db(path):
    c = sqlite3.connect('file:%s?mode=ro' % path.replace('\\', '/'), uri=True)
    c.text_factory = bytes
    return c


def q(c, sql, args=()):
    cur = c.execute(sql, args)
    cols = [d[0] for d in cur.description]
    rows = []
    for r in cur.fetchall():
        rows.append(dict(zip(cols, [x.decode('utf8', 'replace') if isinstance(x, bytes) else x for x in r])))
    return rows


def dump(obj, name):
    p = os.path.join(BASE, 'out', name)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, default=str)
    return p
