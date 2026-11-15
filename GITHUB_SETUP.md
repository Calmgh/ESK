<!-- mkit_toolkit · dev by Calmgh06 -->
# 建议的 GitHub 仓库设置

## 仓库名

`mkit_toolkit`　或　`mkit-forensics`

## Description（一句话，160 字符内）

```
自己搓的电子数据取证工具包：NTFS/ext4/APFS 文件级读取、VMDK/LVM2/VHDX/RAID5 解析、隐写与钱包提取。纯 Python，只读，零依赖起步。
```

## Topics（标签，按这个顺序加）

```
digital-forensics
forensics
dfir
apfs
ntfs
ext4
vmdk
lvm2
raid5
steganography
python
incident-response
evidence-analysis
ctf-tools
```

## 其他设置

- **License**: MIT
- **Include in the home page**: ✅ Releases / ✅ Packages 关掉 / ✅ Topics
- **Discussions**: 建议开启（技术讨论比 Issue 更合适）
- **Wiki**: 关掉（文档都在 `docs/`）
- **Projects**: 关掉

## 首次 push 步骤

```bash
cd mkit_toolkit
git init
git add .
git commit -m "init: mkit_toolkit v1.0.0 - 自搓电子数据取证工具包"

# 在 GitHub 建空仓库（不要勾 README/LICENSE/gitignore），然后：
git remote add origin https://github.com/<你的用户名>/mkit_toolkit.git
git branch -M main
git push -u origin main

# 打 tag 并发布 Release
git tag -a v1.0.0 -m "v1.0.0 首个公开版本"
git push origin v1.0.0
```

然后在 GitHub 网页 → Releases → Draft a new release：
- Tag: `v1.0.0`
- Title: `mkit_toolkit v1.0.0 — 自己搓的取证工具包`
- Description: 贴 `RELEASE.md` 的内容（去掉第一行标题）
- 附件：上传 `mkit_toolkit.zip`

## 注意

`.gitignore` 里已经把 `*.E01` / `*.dd` / `*.raw` / `*.vmdk` / `*.hive` 全部排除——
**绝对不要把检材推进仓库**。推之前跑一次：

```bash
git status --short | findstr /I "E01 e01 dd raw img bin vmdk vhdx hive"
```

有输出就说明有东西混进来了，检查 `.gitignore`。

---

<sub>mkit_toolkit · **dev by Calmgh06**</sub>
