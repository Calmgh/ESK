"""verify_goal.py —— 目标完成度核验"""
import io
import os
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
os.chdir(r"E:\ALL\AAAI\Works\RE\ESK")
PY = r"C:\Users\LUCCa\AppData\Local\Programs\Python\Python311\python.exe"

ITEMS = [
    ("(1) bitlocker", "mkit/bitlocker.py", "BitLocker 恢复密码解锁 + XTS/CBC/diffuser"),
    ("(2) btrfs", "mkit/btrfs.py", "超级块 / chunk 树合并 / 目录遍历 / 读文件"),
    ("(3) timeline", "mkit/timeline.py", "6 种时间戳换算 + CSV/JSONL/SQLite 导出"),
    ("(4) udf", "mkit/udf.py", "UDF 1.02-2.01"),
    ("(5a) ad1", "mkit/ad1.py", "AD1 逻辑镜像"),
    ("(5b) dmg", "mkit/dmg.py", "Apple DMG (UDIF)"),
    ("(6) parttable", "mkit/parttable.py", "APM / BSD label / Amiga RDB"),
    ("(7) cli", "esk_cli.py", "CLI + JSONL 会话"),
]

print("=" * 78)
print("目标完成度核验")
print("=" * 78)
ok = 0
for label, path, desc in ITEMS:
    if not os.path.exists(path):
        print("  %-16s 缺文件  %s" % (label, path))
        continue
    size = os.path.getsize(path)
    lines = sum(1 for _ in open(path, encoding="utf-8", errors="replace"))
    # 跑自检
    if path.endswith(".py") and not path.startswith("esk_cli"):
        r = subprocess.run([PY, path], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=600)
        status = "自检通过" if r.returncode == 0 else "自检失败"
        tail = ((r.stdout or "").strip().splitlines() or [""])[-1][:40]
    else:
        r = subprocess.run([PY, path, "schema"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        status = "可执行" if r.returncode == 0 else "执行失败"
        tail = "schema 输出正常" if r.returncode == 0 else ""
    if "通过" in status or status == "可执行":
        ok += 1
    print("  %-16s %6.1f KB %5d 行  %-8s  %s" % (label, size / 1024, lines, status, tail))

print()
print("=" * 78)
print("集成与文档")
print("=" * 78)

r = subprocess.run([PY, "-c",
                    "import sys;sys.path.insert(0,r'%s');import mkit;"
                    "print(mkit.__version__, len(mkit.__all__))" % os.getcwd()],
                   capture_output=True, text=True, encoding="utf-8")
print("  包版本 / 模块数 : %s" % (r.stdout.strip() or r.stderr.strip()))

r = subprocess.run([PY, "selftest_new.py"], capture_output=True, text=True,
                   encoding="utf-8", errors="replace", timeout=600)
tail = [l for l in (r.stdout or "").splitlines() if "结果" in l]
print("  selftest_new.py : %s" % (tail[-1].strip() if tail else "?"))

for f in ("CHANGELOG.md", "README.md", "docs/FEATURES.md"):
    s = open(f, encoding="utf-8").read()
    marks = []
    for kw in ("1.5.0", "bitlocker", "btrfs", "timeline", "udf", "ad1", "dmg", "parttable"):
        if kw.lower() in s.lower():
            marks.append(kw)
    print("  %-20s 提到 %d/8 个关键词" % (f, len(marks)))

print()
print("=" * 78)
print("Git 状态")
print("=" * 78)
for cmd in (["git", "rev-parse", "--short", "HEAD"],
            ["git", "rev-parse", "--short", "origin/main"]):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    print("  %-26s %s" % (" ".join(cmd[1:]), r.stdout.strip()))
r = subprocess.run(["git", "status", "--short"], capture_output=True, text=True,
                   encoding="utf-8")
print("  未提交改动: %d 个" % len([l for l in r.stdout.splitlines() if l.strip()]))

print()
print("  完成项：%d / %d" % (ok, len(ITEMS)))
