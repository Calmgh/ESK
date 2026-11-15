#!/usr/bin/env python3
# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""anslog.py —— 按官方模板记录每题取证过程，确保「照命令复现」得到同一答案。

模板（每题）：
    第一步 通过 <命令> 从 <检材> <动作>，找到 <中间结果>
    第二步 然后，……
    第三步 最后，……（得出答案）

用法：
  # 1) 新建/追加一题（取证题，N 步）
  python anslog.py add --q 3 --score 2 --answer "dq4kr7dg" \
      --s "导出 WiFi 配置|python mk.py pull F:\\A.dd /misc/wifi/wpa_supplicant.conf out\\wpa.conf|network={ssid=\"ChinaNet-iuVW\" psk=\"dq4kr7dg\"}" \
      --s "定位该 SSID 的 psk|Select-String -Path out\\wpa.conf -Pattern 'ChinaNet-iuVW' -Context 0,3|psk=\"dq4kr7dg\""

  # 2) 理论题：只写答案
  python anslog.py add --q 12 --score 1 --answer "B" --type 理论

  # 3) 校验（检查每题是否都有答案、取证题是否都有命令与结果）
  python anslog.py check

  # 4) 导出提交用 Markdown
  python anslog.py show
"""
import argparse
import datetime
import json
import os
import re
import sys

DEFAULT_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "out", "answers.json")
DEFAULT_DB = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "answers.json"))


def load(db):
    if os.path.exists(db):
        with open(db, encoding="utf8") as f:
            return json.load(f)
    return dict(case="", created=datetime.datetime.now().isoformat(timespec="seconds"), items=[])


def save(db, data):
    os.makedirs(os.path.dirname(os.path.abspath(db)), exist_ok=True)
    with open(db, "w", encoding="utf8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def parse_step(s):
    """'概括|命令|结果' -> dict；允许命令里含 | 时用 || 分隔三段"""
    parts = [p.strip() for p in re.split(r"\|(?!\|)", s)]
    if len(parts) < 3:
        parts = [p.strip() for p in s.split("||", 2)]
    while len(parts) < 3:
        parts.append("")
    return dict(caption=parts[0], cmd=parts[1], result=parts[2])


def cmd_add(a):
    db = a.db
    data = load(db)
    item = dict(q=a.q, score=a.score, type=a.type, answer=a.answer,
                evidence=a.evidence or "", note=a.note or "",
                steps=[parse_step(s) for s in (a.s or [])],
                ts=datetime.datetime.now().isoformat(timespec="seconds"))
    # 同题号覆盖
    data["items"] = [i for i in data["items"] if str(i["q"]) != str(a.q)]
    data["items"].append(item)
    data["items"].sort(key=lambda i: _qkey(i["q"]))
    save(db, data)
    print(f"已记录 题 {a.q}  答案={a.answer}  步骤={len(item['steps'])}  -> {db}")
    return 0


def _qkey(q):
    m = re.match(r"(\d+)", str(q))
    return (0, int(m.group(1))) if m else (1, str(q))


CN = "一二三四五六七八九十"


def render_item(i, idx=None):
    out = []
    head = f"### 题目 {i['q']}"
    if i.get("score"):
        head += f"（{i['score']} 分）"
    if i.get("type"):
        head += f"［{i['type']}］"
    out.append(head)
    if i.get("evidence"):
        out.append(f"**检材：**{i['evidence']}")
    out.append(f"**答案：**{i['answer']}")
    steps = i.get("steps") or []
    if i.get("type") != "理论" and steps:
        out.append("")
        out.append("**取证过程：**")
        for n, s in enumerate(steps, 1):
            cn = CN[n - 1] if n <= len(CN) else str(n)
            cap = s.get("caption") or "执行命令"
            out.append("")
            out.append(f"{n}. **第{cn}步** {cap}：")
            if s.get("cmd"):
                out.append("")
                out.append("```powershell")
                out.append(s["cmd"])
                out.append("```")
            if s.get("result"):
                out.append("")
                out.append(f"→ 输出：`{s['result']}`")
    if i.get("note"):
        out.append("")
        out.append(f"注：{i['note']}")
    return "\n".join(out)


def cmd_show(a):
    data = load(a.db)
    print(f"# {data.get('case') or '美亚杯 答题记录'}\n")
    for i in data["items"]:
        print(render_item(i))
        print()
    return 0


def cmd_check(a):
    data = load(a.db)
    bad = []
    for i in data["items"]:
        if not i.get("answer"):
            bad.append((i["q"], "缺答案"))
        if i.get("type") == "理论":
            continue
        steps = i.get("steps") or []
        if not steps:
            bad.append((i["q"], "取证题但没有步骤"))
        for n, s in enumerate(steps, 1):
            if not s.get("cmd"):
                bad.append((i["q"], f"第{n}步缺命令"))
            if not s.get("result"):
                bad.append((i["q"], f"第{n}步缺输出（无法证明可复现）"))
    print(f"题数 {len(data['items'])}")
    if bad:
        for q, why in bad:
            print(f"  ✗ 题 {q}: {why}")
        return 1
    print("  ✓ 全部通过：每题有答案；取证题每步都有命令与输出")
    return 0


def main():
    ap = argparse.ArgumentParser(description="按模板记录取证过程")
    ap.add_argument("--db", default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add")
    p.add_argument("--q", required=True, help="题号")
    p.add_argument("--answer", required=True)
    p.add_argument("--score", default="")
    p.add_argument("--type", default="取证", choices=["取证", "理论"])
    p.add_argument("--evidence", default="", help="检材，如 LL-01")
    p.add_argument("--s", action="append", help="步骤：'概括|命令|输出'，可重复")
    p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("show"); p.set_defaults(fn=cmd_show)
    p = sub.add_parser("check"); p.set_defaults(fn=cmd_check)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
