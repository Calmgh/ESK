#!/usr/bin/env python3
# ============================================================
#  ESK  ·  Calmgh06
#  Electronic Software Kit  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
"""shot.py —— 纯截图渲染器（Windows 原生外观，无标题栏文字、无背景装饰）。

版式：
  terminal()  命令执行结果（cmd 窗口，黑底宋体）
  table()     检材数据表（白底表格，自动换行不截断）
  hexdump()   原始字节
  panel()     属性面板
  phone()     手机 App 界面

共同点：画布宽度固定 1280，高度按内容自动裁剪，不留大片空白。
"""
import os
import textwrap

from PIL import Image, ImageDraw, ImageFont

FONT_DIR = r"C:\Windows\Fonts"
MONO = os.path.join(FONT_DIR, "simsun.ttc")
CJK = os.path.join(FONT_DIR, "msyh.ttc")
CJK_B = os.path.join(FONT_DIR, "msyhbd.ttc")
UI = os.path.join(FONT_DIR, "segoeui.ttf")

W = 1280
TITLE_H = 28
MAX_H = 720


def _f(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.truetype(os.path.join(FONT_DIR, "simsun.ttc"), size)


def win_frame(img, title, title_bg="#F0F0F0", title_fg="#000000"):
    """Windows 窗口标题栏：图标方框 + 标题 + 用线条画的 ─ □ ✕。"""
    d = ImageDraw.Draw(img)
    w = img.width
    d.rectangle([0, 0, w, TITLE_H], fill=title_bg)
    d.line([0, TITLE_H, w, TITLE_H], fill="#D0D0D0")
    d.rectangle([0, 0, w - 1, img.height - 1], outline="#9A9A9A")

    # 应用图标（空心小方框）
    d.rectangle([9, 8, 19, 18], outline="#5A5A5A")
    d.text((26, 4), title, font=_f(CJK, 15), fill=title_fg)

    # 右上三个按钮：用线条绘制，避免字体缺字
    bx = w - 104
    cy = TITLE_H // 2
    # 最小化
    d.line([bx, cy + 4, bx + 12, cy + 4], fill="#333333", width=2)
    # 最大化
    d.rectangle([bx + 32, cy - 5, bx + 44, cy + 5], outline="#333333", width=2)
    # 关闭
    d.line([bx + 64, cy - 5, bx + 76, cy + 5], fill="#333333", width=2)
    d.line([bx + 76, cy - 5, bx + 64, cy + 5], fill="#333333", width=2)
    return d


def _crop(img, pad=10, bg=None):
    """按内容裁掉底部空白，保留 pad 边距。"""
    w, h = img.size
    if bg is None:
        bg = img.getpixel((w - 3, h - 3))
    bottom = h
    for y in range(h - 1, TITLE_H, -1):
        row_bg = True
        for x in range(2, w - 2, 3):
            if img.getpixel((x, y)) != bg:
                row_bg = False
                break
        if not row_bg:
            bottom = min(h, y + pad + 1)
            break
    if bottom < h:
        img = img.crop((0, 0, w, max(bottom, TITLE_H + 60)))
    return img


def scrollbar(img, top=TITLE_H + 1):
    d = ImageDraw.Draw(img)
    w, h = img.size
    d.rectangle([w - 17, top, w - 2, h - 2], fill="#F0F0F0")
    d.rectangle([w - 16, top + 1, w - 3, min(h - 3, top + 64)], fill="#CDCDCD")


# ------------------------------------------------------------------ 命令执行结果
def terminal(steps, path, title="命令提示符", cols=104,
             prompt=r"E:\ALL\AAAI\Works\RE\meiya>"):
    lh = 26
    fm = _f(MONO, 18)
    # 先估算高度
    need = TITLE_H + 12
    for cmd, out in steps:
        if cmd:
            need += lh
        need += max(1, len(str(out).splitlines())) * lh
        need += 8
    H = max(240, min(MAX_H, need + 14))

    img = Image.new("RGB", (W, H), "#000000")
    win_frame(img, title)
    fm_b = _f(MONO, 18)
    y = TITLE_H + 10
    d = ImageDraw.Draw(img)
    for cmd, out in steps:
        if cmd:
            d.text((12, y), prompt, font=fm, fill="#CCCCCC")
            pw = d.textlength(prompt, font=fm)
            d.text((12 + pw, y), cmd, font=fm_b, fill="#FFFFFF")
            y += lh
        for line in str(out).splitlines():
            for piece in textwrap.wrap(line, cols) or [""]:
                if y > H - lh - 18:
                    break
                d.text((12, y), piece, font=fm, fill="#D0D0D0")
                y += lh
        y += 8
    scrollbar(img)
    _crop(img, bg=(0, 0, 0)).save(path)
    return path


# ------------------------------------------------------------------ 检材数据表
def table(headers, rows, path, title, caption=None, col_w=None, wrap=True):
    fh = _f(CJK_B, 17)
    fc = _f(CJK, 16)
    pad_x, pad_y = 14, 10
    x0, top = 14, TITLE_H + 10
    avail = W - 46

    if col_w is None:
        col_w = [1] * len(headers)
    s = sum(col_w)
    col_w = [int(c / s * avail) for c in col_w]

    def wrap_cell(text, width, font):
        text = str(text)
        lines, cur = [], ""
        for ch in text:
            if font.getlength(cur + ch) > width - pad_x * 2:
                lines.append(cur)
                cur = ch
            else:
                cur += ch
        if cur:
            lines.append(cur)
        return lines or [""]

    # 预计算每行高度
    body = []
    for row in rows:
        cells = [wrap_cell(v, w, fc) for v, w in zip(row, col_w)]
        h = max(len(c) for c in cells) * 24 + pad_y * 2
        body.append((cells, max(h, 42)))
    header_h = 44
    total = top + header_h + sum(h for _, h in body) + 16
    H = max(220, min(MAX_H, total))

    img = Image.new("RGB", (W, H), "#FFFFFF")
    win_frame(img, title)
    d = ImageDraw.Draw(img)

    x = x0
    d.rectangle([x0, top, x0 + avail, top + header_h], fill="#E8EEF7")
    d.line([x0, top, x0 + avail, top], fill="#B8C6DA")
    d.line([x0, top + header_h, x0 + avail, top + header_h], fill="#B8C6DA")
    for h, w in zip(headers, col_w):
        d.text((x + pad_x, top + (header_h - 24) // 2), str(h), font=fh, fill="#1A1A1A")
        x += w

    y = top + header_h
    for i, (cells, h) in enumerate(body):
        if y + h > H - 12:
            break
        if i % 2 == 1:
            d.rectangle([x0, y, x0 + avail, y + h], fill="#F7F9FC")
        x = x0
        for lines, w in zip(cells, col_w):
            yy = y + pad_y
            for ln in lines:
                d.text((x + pad_x, yy), ln, font=fc, fill="#1A1A1A")
                yy += 24
            x += w
        y += h
        d.line([x0, y, x0 + avail, y], fill="#E6E6E6")

    if caption:
        d.text((x0, min(H - 26, y + 6)), str(caption)[:100], font=_f(CJK, 14), fill="#606060")
    _crop(img, bg=(255, 255, 255)).save(path)
    return path


# ------------------------------------------------------------------ 十六进制
def hexdump(lines, path, title, caption=None):
    fm = _f(MONO, 16)
    lh = 23
    H = max(240, min(MAX_H, TITLE_H + 20 + len(lines) * lh))
    img = Image.new("RGB", (W, H), "#000000")
    win_frame(img, title)
    d = ImageDraw.Draw(img)
    y = TITLE_H + 10
    for ln in lines:
        if y > H - lh - 10:
            break
        d.text((12, y), str(ln), font=fm, fill="#CCCCCC")
        y += lh
    scrollbar(img)
    _crop(img, bg=(0, 0, 0)).save(path)
    return path


# ------------------------------------------------------------------ 属性面板
def panel(title, groups, path, caption=None):
    fk = _f(CJK, 16)
    fv = _f(MONO, 16)
    fg = _f(CJK_B, 17)
    need = TITLE_H + 16
    for _, items in groups:
        need += 34 + len(items) * 32 + 10
    H = max(220, min(MAX_H, need))

    img = Image.new("RGB", (W, H), "#FFFFFF")
    win_frame(img, title)
    d = ImageDraw.Draw(img)
    y = TITLE_H + 12
    for gname, items in groups:
        if y > H - 60:
            break
        d.rectangle([14, y, W - 26, y + 32], fill="#E8EEF7")
        d.line([14, y + 32, W - 26, y + 32], fill="#B8C6DA")
        d.text((24, y + 5), gname, font=fg, fill="#1A3E6E")
        y += 32
        for k, v in items:
            if y > H - 40:
                break
            d.text((32, y + 5), str(k), font=fk, fill="#404040")
            d.text((330, y + 5), str(v)[:80], font=fv, fill="#101010")
            y += 32
        y += 10
    _crop(img, bg=(255, 255, 255)).save(path)
    return path


# ------------------------------------------------------------------ 手机界面
def phone(path, header, bubbles, title=None, footer=None, w=720, h=1280):
    img = Image.new("RGB", (w, h), "#ECE5DD")
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 54], fill="#075E54")
    d.text((22, 14), "11:48", font=_f(CJK_B, 20), fill="#FFFFFF")
    d.text((w - 130, 14), "4G  86%", font=_f(CJK, 20), fill="#FFFFFF")
    d.rectangle([0, 54, w, 150], fill="#075E54")
    d.text((28, 78), header, font=_f(CJK_B, 30), fill="#FFFFFF")
    if title:
        d.text((28, 116), title, font=_f(CJK, 18), fill="#CFE9E3")

    y = 176
    for side, who, ts, text in bubbles:
        lines = []
        for para in str(text).split("\n"):
            lines.extend(textwrap.wrap(para, 24) or [""])
        bw = 470
        bh = 26 + 24 + len(lines) * 30
        x = 24 if side == "in" else w - 24 - bw
        d.rounded_rectangle([x, y, x + bw, y + bh], 14,
                            fill="#FFFFFF" if side == "in" else "#DCF8C6")
        if who:
            d.text((x + 18, y + 10), who, font=_f(CJK_B, 18), fill="#B4623C")
        yy = y + 38
        for ln in lines:
            d.text((x + 18, yy), ln, font=_f(CJK, 21), fill="#111111")
            yy += 30
        d.text((x + bw - 92, y + bh - 26), ts, font=_f(CJK, 16), fill="#8A8A8A")
        y += bh + 16
        if y > h - 120:
            break
    if footer:
        d.rectangle([0, h - 70, w, h], fill="#F0F0F0")
        d.text((28, h - 50), footer, font=_f(CJK, 20), fill="#666666")
    img.save(path)
    return path


if __name__ == "__main__":
    os.makedirs("out/pics", exist_ok=True)
    terminal([("python ans_fc01_chat.py",
               "ChatStorage.sqlite → ZWAMESSAGE\nZ_PK=10: 'I previously worked as IT staff at a school.'\n结果：B 学校（school）")],
             "out/pics/_demo_term.png")
    table(["项", "内容"], [["检材", "FC-01"], ["位置", "ChatStorage.sqlite → ZWAMESSAGE"],
                          ["记录内容", "ZISFROMME=1 为冯程发出，Z_PK=10: I previously worked as IT staff at a school."]],
          "out/pics/_demo_table.png", "FC-01 检材数据")
    print("demo ok")
