<!-- ESK · Calmgh06 -->
### 缘起

打了几年美亚杯。每年赛前最烦的是装美亚的工具——主办方的工具箱动辄几十个G，还一直报毒，要权限，申请授权，环境还经常对不上。

等装完、跑通，时间过去了几个小时。

今年就灵机一动 把往年的题目弄了个数据集 搓了一套框架出来

### 成绩

- 个人赛 **二等奖**（前 100，全部ak，不过有个别错题）
- 团队赛 **三等奖**（285 / 291）

因为主办方限制在线模型，只能本地lora的qwen 跑，几个需要跨镜像长链推理的题顶不住

### 里面有什么

| 部分 | 规模 |
|---|---|
| `mkit/` 核心库 | 28 模块 / 25,982 行 |
| `ext/` 自建扩展 | 34 模块 |
| `examples/` 可运行示例 | 6 个 |
| `docs/` 技术笔记 | 3 份 |

**亮点**（相对于一般公开工具的补位）：

- **APFS 文件级读取** —— `mkit.macart` 只到 `info()`/`volumes()`，这里实现了容器 omap B-tree 翻译 + 卷文件系统树
- **VMDK / LVM2 / VHDX** —— GPT → LVM2 → ext4 三层剖开，含 `pe_start` 精确解析
- **RAID5 缺块重建** —— mdadm left-symmetric，三重验证
- **PNG 像素级同源判定** —— 识别 LSB 隐写关系的量化判据
- **Q/A 排错** —— 每一条都是真实踩过并导致过错误结论的

### 快速开始

```bash
pip install libewf-python        # 唯一必需依赖
python examples/00_selftest.py   # 自检
python examples/01_mount_ewf.py  disk.E01
```

裸镜像（`.dd` / `.raw` / `.bin`）连 libewf 都不需要。

### 已知限制（重要）

- **APFS 完整 B-tree 遍历未完成** —— TOC `voff` 约定没收敛，现用按记录类型模式匹配绕过。能读文件，不能完整遍历
- APFS 快照 / FileVault 不支持
- LVM2 元数据区常读为全零，靠 `pe_start` + ext4 魔数验证兜底
- RAID5 只实现 left-symmetric
- VHDX 未实现日志回放
- **不含内存镜像分析**，请配 Volatility 3

### 关于 AI

框架是 AI 按需求写的，扩展是比赛期间 AI 出初版、人工调试

但所有答案判断、检材解释都由人工完成。

---

欢迎师傅们批判指正（取证小白瑟瑟发抖）

**License**: MIT　｜　**Calmgh06**

---

<sub>ESK · **Calmgh06**</sub>
