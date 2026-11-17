#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  全模块自检入口
# ============================================================

"""跑遍 ``mkit/`` 下每个模块自带的 ``__main__`` 自检，给出统一账单。

为什么要这个文件
----------------
``selftest_new.py`` 是**项目级功能自检**（内联断言 + 只对 vdisk/luks 起子进程），
它并不覆盖全部模块。而 ESK 的约定是「每个模块自带合成镜像自检」，所以需要
一个入口把 78 个模块逐一跑一遍——本文件就是它。

三种运行结果（分类是**按证据判的**，不是猜的）
---------------------------------------------
* ``PASS``      —— 直接 ``python mkit/x.py`` 就能 exit 0
* ``PASS(-m)``  —— 直接跑报 ``attempted relative import``（模块用了包内相对导入），
                   改以 ``python -m mkit.x`` 跑就 exit 0。**这不是缺陷**，
                   只说明该模块需要包上下文
* ``SKIP(CLI)`` —— 退出码 2 且输出里有 usage / 用法 / required / argument，
                   说明它是带 argparse 的命令行工具、缺参数属正常
* ``FAIL``      —— 以上都不成立的失败，**有 FAIL 时本脚本 exit 1**

用法
----
    python selftest_all.py            # 全部跑一遍
    python selftest_all.py -q         # 只打汇总
    python selftest_all.py xfs ocfs2  # 只跑指定模块
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MKIT = os.path.join(HERE, "mkit")

# 相对导入失败的判据
_REL_IMPORT = ("attempted relative import",)
# CLI 工具缺参数的判据
_CLI_HINTS = ("usage", "用法", "required", "argument", "参数")


def list_modules():
    out = []
    for name in sorted(os.listdir(MKIT)):
        if not name.endswith(".py"):
            continue
        if name in ("__init__.py",):
            continue
        out.append(name[:-3])
    return out


def _classify_output(rc, text):
    low = text.lower()
    if rc == 2 and any(h in low for h in _CLI_HINTS):
        return "skip"
    return None


def run_one(mod, timeout=600):
    """返回 (status, detail)。status ∈ pass/pass_m/skip/fail"""
    script = os.path.join(MKIT, mod + ".py")
    try:
        r = subprocess.run([sys.executable, script],
                           cwd=HERE, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "fail", "超时（%ds）" % timeout
    blobs = (r.stdout or b"") + (r.stderr or b"")
    text = blobs.decode("utf-8", "replace")

    if r.returncode == 0:
        return "pass", _tail_line(text)

    if any(k in text for k in _REL_IMPORT):
        # 换成包内模块方式再跑一次
        try:
            r2 = subprocess.run([sys.executable, "-m", "mkit." + mod],
                                cwd=HERE, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "fail", "超时（-m，%ds）" % timeout
        text2 = ((r2.stdout or b"") + (r2.stderr or b"")).decode("utf-8", "replace")
        if r2.returncode == 0:
            return "pass_m", _tail_line(text2)
        kind = _classify_output(r2.returncode, text2)
        if kind == "skip":
            return "skip", "命令行工具（需参数）"
        return "fail", "exit=%d  %s" % (r2.returncode, _tail_line(text2) or "（无输出）")

    kind = _classify_output(r.returncode, text)
    if kind == "skip":
        return "skip", "命令行工具（需参数）"
    return "fail", "exit=%d  %s" % (r.returncode, _tail_line(text) or "（无输出）")


def _tail_line(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line:
            return line[:96]
    return ""


def main(argv):
    quiet = "-q" in argv or "--quiet" in argv
    only = [a for a in argv if not a.startswith("-")]

    mods = list_modules()
    if only:
        missing = [m for m in only if m not in mods]
        if missing:
            print("找不到这些模块：%s" % ", ".join(missing))
            return 2
        mods = [m for m in mods if m in only]

    print("=" * 72)
    print(" ESK 全模块自检 ——  共 %d 个模块" % len(mods))
    print("=" * 72)

    started = time.time()
    counts = {"pass": 0, "pass_m": 0, "skip": 0, "fail": 0}
    failures = []
    skipped = []
    needed_m = []

    for i, mod in enumerate(mods, 1):
        status, detail = run_one(mod)
        counts[status] += 1
        if status == "pass_m":
            needed_m.append(mod)
        elif status == "skip":
            skipped.append((mod, detail))
        elif status == "fail":
            failures.append((mod, detail))
        if not quiet:
            mark = {"pass": "PASS", "pass_m": "PASS(-m)",
                    "skip": "SKIP", "fail": "FAIL"}[status]
            print("[%3d/%3d] %-16s %-10s %s" % (i, len(mods), mod, mark, detail))

    elapsed = time.time() - started
    print("-" * 72)
    print(" 直接通过      : %d" % counts["pass"])
    print(" 需 -m 才能跑  : %d%s" % (counts["pass_m"],
                                ("  " + ", ".join(needed_m)) if needed_m else ""))
    print(" 跳过的命令行工具: %d%s" % (counts["skip"],
                                  ("  " + ", ".join(m for m, _ in skipped))
                                  if skipped else ""))
    print(" 失败          : %d" % counts["fail"])
    for mod, detail in failures:
        print("     %-16s %s" % (mod, detail))
    print(" 用时 %.1fs" % elapsed)
    print("-" * 72)

    if counts["fail"]:
        print("结论：有 %d 个模块自检失败，需要修。" % counts["fail"])
        return 1

    passed = counts["pass"] + counts["pass_m"]
    print("结论：%d 个模块自检通过（直接 %d + 需 -m %d），另有 %d 个是命令行工具"
          "（不跑自检），失败 0 个；共 %d 个模块"
          % (passed, counts["pass"], counts["pass_m"], counts["skip"], len(mods)))
    if needed_m:
        print("提示：%s 用了包内相对导入，直接 python mkit/x.py 会报 "
              "attempted relative import，"
              "改 python -m mkit.x 即可——不是缺陷。" % ", ".join(needed_m))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))