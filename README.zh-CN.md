# malmathic

面向已感染 Windows 机器的离线恶意软件分诊工具：自行读取裸 NTFS 与注册表配置单元，按证据为候选文件排序，并恢复样本的字节。不挂载、不执行、不传输任何东西。

[![CI](https://github.com/milk-analyzer/malmathic/actions/workflows/ci.yml/badge.svg)](https://github.com/milk-analyzer/malmathic/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/milk-analyzer/malmathic)](https://github.com/milk-analyzer/malmathic/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.94+](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](Cargo.toml)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](#安装)

[English](README.md) · [Русский](README.ru.md) · **简体中文**

## 功能

- 可在已提权的运行中系统上运行，可在无法启动的机器上从 WinRE 控制台运行，也可针对磁盘映像运行（`dd`、VDI、带快照链的 VMDK）。
- 在进程内解析 `$MFT`、USN 日志、Amcache、ShimCache、prefetch、PCA、UserAssist、计划任务、Run 键与启动文件夹快捷方式、Defender 日志与隔离区、回收站、mark-of-the-web 以及 PE 结构（imphash、Rich header）——分析路径上不使用任何 Windows API，因此被锁定的文件和未挂载的配置单元照样能读。
- 以每台机器各自的先验为基础，用对数似然比对候选评分；每条证据都连同权重一起打印，`malmathic explain` 给出每个权重背后的理由。
- 从现存文件、Defender 隔离区、回收站、卷影副本、已删除 `$MFT` 记录的簇、索引残留区、孤立记录、被重用 `$MFT` 记录的未用尾部，以及仍留在 `$LogFile` 中的记录映像里恢复样本，并把每次恢复标为 `VERIFIED`、`UNVERIFIED` 或 `PARTIAL`。
- 使用 `--deep` 时按记录的摘要在空闲空间中雕取；若没有任何工件记录过该文件的摘要，则按映像自身携带的名字（调试目录或导出表）匹配。
- 依据内置的根证书离线验证 Authenticode 与目录签名。
- 为公开分享对报告做化名处理（`--redact`、`malmathic redact`）。
- Python 绑定（`pymalmathic`）：解析器、PE 分析、映像读取。

## 安装

从 [Releases](https://github.com/milk-analyzer/malmathic/releases) 下载 x86-64 或 ARM64 版 `malmathic.exe`：单个静态文件，约 4 MB，无需运行时。

从源码构建：Rust 1.94+ 与 MSVC 工具链，`cargo build --release`。

读取已挂接的卷需要管理员权限（WinRE 本身已具备）。读取映像不需要任何权限。

## 用法

```
malmathic                                   分诊自动找到的 Windows 卷；案件写入工具所在盘的 cases\
malmathic --out D:\case                     自选案件目录
malmathic --image disk.vmdk --out D:\case   磁盘映像；必须给出 --out
malmathic --redact                          额外写出 report.redacted.*
malmathic explain <feature>                 某个特征 id 背后的权重
malmathic redact D:\case\report.json        对已有报告做化名处理
```

双击启动（“以管理员身份运行”）时，先显示案件目录，等待回车确认或输入其他路径。

退出码：`0`——分析完成且案件已写出（阴性结果也是结果）；`1`——提前停止（未提权、没有 Windows 卷、位置被拒绝）或报告无法写出；`diag` 与 `redact` 在用法错误或输出路径被拒绝时返回 `2`。

### 选项

| 选项 | |
| --- | --- |
| `-o, --out <目录>` | 案件目录。默认是 exe 所在盘上的 `cases\<卷>-<时间>`；配合 `--image` 时必须给出。以下情况会被拒绝：目录已存有结果、位于源码树内或 exe 自己的文件夹中（exe 位于盘根时指盘根本身），以及使用 `--deep` 时位于正被读取的卷上。 |
| `--overwrite-case` | 替换已存在的案件目录。 |
| `--volume <V>` | 要分析的卷：盘符或卷 GUID 的一部分。 |
| `--image <文件>` | 用磁盘映像代替设备；按文件头识别，无需权限。不要自行挂载。 |
| `--list-volumes` | 列出各卷及其上的发现（stderr），然后退出。 |
| `--list-snapshots` | 配合 `--image`：打印 VMDK 快照链，然后退出。 |
| `--no-samples` | 照常恢复并计算哈希，但不把恶意文件写进案件目录。 |
| `--deep` | 额外雕取未分配簇，针对有记录哈希、或其名字可能写在映像内部、但没有字节的候选。慢。 |
| `--acquire-top <N>` | 最多恢复排名前 N 的候选（默认 10），且只处理超过上报阈值的。 |
| `--verify-top <N>` | 沿排名列表往下验证代码签名到第几位（默认 200）。 |
| `--redact` | 额外写出 `report.redacted.txt` 和 `report.redacted.json`。 |
| `--json` | 向 stdout 打印 JSON 报告而非文本报告。 |
| `--quiet` | 不在 stderr 输出逐阶段进度。 |
| `--pause`、`--no-pause` | 强制或禁止在结束时等待回车（`--no-pause` 同时跳过案件目录的询问）；默认只在窗口即将关闭时等待。 |

### 子命令

| 命令 | |
| --- | --- |
| `explain [FEATURE...]` | 权重表，或某一行：特征含义、权重理由、在干净机器上的出现率。 |
| `redact <REPORT.JSON> [--out 文件] [--overwrite] [--keep-urls]` | 写出 `<名称>.redacted.json` 与 `.txt`：用户名变为 `user1`…，机器名变为 `host1`…，SID 域、卷标识与序列号重新编号，电子邮件与 IP 被掩盖，URL 截断到主机，案件路径被删除。同一名字全文使用同一化名。 |
| `diag mft [PATH] [--record N] [--children]` | 一条 `$MFT` 记录及其全部祖先；找出过期的父引用。 |
| `diag attribute-lists [--follow]` | 统计带 `$ATTRIBUTE_LIST` 的记录。 |
| `diag lzx-capture --out <文件> [--overwrite] [--mount ROOT] [--all-algorithms] [--limit N]` | 抓取 Compact-OS 压缩流及其明文（WinRE）。 |
| `diag lzx-describe <文件>` | 描述这样的抓取文件。 |

### 案件目录

| 路径 | |
| --- | --- |
| `report.txt`、`report.json` | 带证据与权重的候选排名、卷级发现、以及无法读取内容的覆盖情况。 |
| `report.redacted.txt`、`report.redacted.json` | 化名处理后的副本。提交 issue 时请附这两个文件。 |
| `sample/C<id>.bin` | 某个已排名候选恢复出的字节——真实的恶意软件；杀毒软件会隔离它，这是预期行为。使用 `--no-samples` 时不存在。 |
| `sample/unranked/` | 排名触及不到的恢复：仍保有 runlist 的已删除记录、从临时目录消失的可执行文件、索引残留区里的名字、低于阈值的雕取结果。上限 64 个文件或 256 MB。 |

## 由测试保证的性质

- 发布的源码中没有进程创建、库加载、挂载或网络 API；唯一的 `DeviceIoControl` 只查询长度；`Cargo.lock` 与经审计的依赖清单一致。
- 映像读取器不持有可写句柄；使用 `--deep` 时，位于正被读取的卷上的案件目录会被拒绝。
- `imphash` 与 Rich header 哈希逐条规则与 `pefile` 一致，包括冻结的序数表和针对加壳样本的启发式规则；Python 测试会对照 `pefile` 检查。
- 每个解析器都能承受截断、自引用、谎报大小和全零的输入。

## 局限

- 权重是专家估计，不是在带标注语料上拟合的值；每份报告都会说明这一点。
- 先验是机器候选总数分之一：在小机器上足以定罪的证据，在大机器上未必够。
- 有效签名的恶意软件会被减分；被盗的证书能抵消表中最强的负权重。
- 没有记录哈希的已删除文件仍可能凭其 PE 头中自带的名字找到，但此时没有任何东西能证明这些字节属于该文件，而不是同一程序的另一份副本。
- 从记录残留区或 `$LogFile` 中恢复的属性，仅凭一个遗留的名字与路径相绑定；只有匹配的摘要才能把它变成证据，而通常并没有摘要。
- 只看磁盘与注册表：不看进程、内存或网络，也不做清除。
- 在运行中的系统上，用户态 rootkit 仍可过滤读取内容；WinRE 与映像不受此影响。
- 仅支持 Windows。

## Python 绑定

```
cd bindings\python
pip install maturin pefile
maturin build --release
pip install target\wheels\pymalmathic-0.1.0-cp39-abi3-win_amd64.whl
```

```python
import pymalmathic as mm
mm.parse_amcache(hive)          # parse_shimcache, parse_prefetch, parse_tasks, parse_defender_log, parse_persistence, parse_recycle_bin, analyze_pe
mm.imphash(pe); mm.imports(pe); mm.rich_header(pe)
img = mm.Image("disk.vmdk"); img.list_dir("\\Users"); img.read_file(path, max_bytes=64 << 20)
```

它是独立的 cargo workspace，因此 PyO3 不会进入经审计的依赖树。一个 `abi3` wheel 覆盖 CPython 3.9+，附带类型存根。解析器返回与 `report.json` 同结构的观察字典。

## 开发

| Crate | |
| --- | --- |
| `mm-core` | 候选、观察、路径、哈希、LZX 与 Xpress 解码器 |
| `mm-raw` | NTFS：`$MFT`、索引与残留区、USN 日志、卷影副本、WOF |
| `mm-env` | 卷、`dd`/VDI/VMDK 映像、快照链、只读文件类型、Win32 层 |
| `mm-harvest` | 取证工件解析器、PE、imphash、Rich header、批量加密检测 |
| `mm-sign` | Authenticode 与目录签名验证、内置根证书 |
| `mm-score` | 候选图、区域、特征、权重表、事件窗口、基线 |
| `mm-report` | 报告模型、文本渲染、化名处理 |
| `malmathic` | 流水线、恢复链、CLI、诊断 |
| `bindings/python` | `pymalmathic` |

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

每个权重背后的理由都在 [`crates/mm-score/rules/weights.toml`](crates/mm-score/rules/weights.toml)。另见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md)。

## 许可证

MIT——见 [LICENSE](LICENSE)。派生代码与依赖许可（含取自 [pefile](https://github.com/erocarrera/pefile) 的 imphash 序数表，MIT，Ero Carrera）列于 [NOTICE](NOTICE)。
