# Reader DecompressZLib：卡死与假成功修复

状态：实现稿，供独立 review。分支 `t3/fix-zlib-reader-stall` 基于个人 fork `personal/master` 的 `d0e46ae`，只改 `DecompressZLib` 与独立测试，不涉及生产 FUSE、真实源盘或既有 reader 语义。本文区分已复现的合成行为、未验证的现场结论和发布前置条件。

## 1. 背景

真实 111 键 M1 在 H-R3 通过后启动，约 7 分钟无首条可见输出：reader 单核持续 CPU，scanner 阻塞在 `open`，source cgroup 只读约 8.8 MB，ioerr 3738、SCSI trace 0 未变。owner 主动终止，SIGTERM 30 秒未退出后由 systemd KILL，无 `finished`/`summary`，无源重试。证据见 `runs/manifest-hr3-pass-m1-zlib-stall-20261108.md`。

现场 `perf -F49 2s`（117 samples，无丢样）主要栈为 `inflate → DecompressZLib → DecompressFile → apfs_open`，约 59% 样本在 `inflate`。**没有取得受影响 path，也没有取得该文件的压缩字节**；本 PR 不声称复现了现场文件，只复现了代码层面的两种失败模式：

1. `DecompressZLib` 的循环只在 `Z_STREAM_END` 退出。截断输入耗尽 `avail_in`、输出缓冲写满或流无进展时，`inflate()` 反复返回 `Z_BUF_ERROR`，循环永不退出，reader 线程 100% CPU。
2. 遇到 `Z_NEED_DICT`/`Z_DATA_ERROR`/`Z_MEM_ERROR` 时旧代码把 `avail_out` 置 0 后 `break`，返回值变成 `dst_size`。调用方只比较“返回值 == 期望长度”，于是损坏数据可能被当成完整块接受。

第 2 点比第 1 点更危险：它不会卡住，只会静默返回错误数据。两者都必须 fail-closed。

## 2. 需求

来自 design r4 §2 的 reader 可靠性契约和本任务约束：

- **R1 有界返回**：任何输入（截断、空、损坏、输出不足、字典流、超大尺寸）都必须在有限时间内返回，不得在 `inflate` 中空转。
- **R2 失败不伪装成功**：任何未到达 `Z_STREAM_END` 的调用返回 0，绝不返回 `dst_size` 或任何看似完整的长度。调用方据此拒绝该压缩块。
- **R3 正常语义不变**：有效 zlib 数据必须逐字节一致并保持 SHA-256 一致；支持单个 64 KiB 块、多个块、非整块尾块；`Z_STREAM_END` 之后允许存在 trailing bytes（APFS 分块协议允许，不得因此判失败）。
- **R4 错误传播**：`DecompressFile` 在长度不匹配时返回 `false`；`apfs_open` 在默认（非 `-l`）模式下返回 `EIO`，不返回未解压数据。
- **R5 最小改动**：不改 ADC/LZVN/LZFSE/LZBITMAP，不改正常 APFS 解压语义，不引入新依赖；不访问真实源或生产挂载。

## 3. 设计

### 3.1 循环终止

`ApfsLib/Util.cpp` 中的新循环每次迭代先记录 `avail_in`/`avail_out`，再调用 `inflate(Z_NO_FLUSH)`：

- `Z_STREAM_END`：标记 `complete = true` 并退出，返回实际产出长度。
- 其他任何非 `Z_OK`（`Z_BUF_ERROR`、`Z_NEED_DICT`、`Z_DATA_ERROR`、`Z_MEM_ERROR`、`Z_STREAM_ERROR`）：退出，返回 0。
- `Z_OK` 但 `avail_in` 与 `avail_out` 都没有变化：防御性退出，返回 0。zlib 正常情况下不会这样，但不能让“无进展”重新变成死循环。

因此“输入耗尽但流未结束”和“输出写满但流未结束”都在一次额外的 `inflate` 后以 `Z_BUF_ERROR` 结束，而不是无限循环。

### 3.2 失败返回值

`complete` 为 false 时统一返回 0。选择 0 而不是部分产出长度，是因为现有两个调用点都以“返回值 == expected_len”作为接受条件：

- `Decmpfs.cpp` attr 路径（algo 3）：`decoded_bytes != hdr->size` → `DecompressFile` 返回 false。
- `Decmpfs.cpp` resource-fork 路径（algo 4）：每个 64 KiB entry 的 `decoded_bytes != expected_len` → false。

部分产出长度或 `dst_size` 都可能与期望长度相等，只有 0 对真实压缩内容（期望长度 > 0）稳定失败。空文件/零长度期望不属于 APFS 压缩文件的实际路径，见 §6 剩余风险。

### 3.3 size_t → uInt

zlib 的 `avail_in`/`avail_out` 是 `uInt`。旧代码直接把 `size_t` 赋给它们；在 64 位平台上传入超过 `UINT_MAX` 的长度会被静默截断，解压范围与调用方请求不一致。新代码在 `inflateInit2` 之前检查 `src_size`/`dst_size`，超出 `UINT_MAX` 直接返回 0。

### 3.4 合法的“精确输出 + trailing bytes”

循环只以 `Z_STREAM_END` 判定成功，不要求 `avail_in == 0`。因此“解压结果恰好填满输出缓冲，后面还有 trailing bytes”的合法块仍返回精确长度。64 KiB 精确填满的流也由测试覆盖，确认最终调用返回 `Z_STREAM_END` 而不是 `Z_BUF_ERROR`。

### 3.5 调用方传播

`apfs_open` 在 `DecompressFile` 返回 false 且 `g_lax == false`（默认）时 `fuse_reply_err(req, EIO)`；`g_lax` 仅由 `-l` 打开。本 PR 不改该逻辑，只让 `DecompressZLib` 不再把失败伪装成完整块。

`DeviceDMG.cpp` 也调用 `DecompressZLib`，但忽略返回值；本 PR 不修改该路径。其行为变化仅是坏流不再空转、返回 0（调用方仍忽略），见 §6。

## 4. 测试

新增 `tests/ZlibDecompressTest.cpp`，不依赖 FUSE、真实镜像或新依赖，使用系统 zlib 生成确定性数据，并用极小 SHA-256 校验正常输出。CMake 新增 `zlib-decompress` 测试目标。

每个可能空转的调用都放在 2 秒 `SIGALRM` 保护下：旧实现会触发超时并使测试失败，而不是让 CI 挂死。

| # | 用例 | 断言 |
|---|---|---|
| 1 | 有效 64 KiB 块，输出缓冲恰好 64 KiB | 返回 65536，逐字节 + SHA-256 一致 |
| 2 | 有效多块（3×64 KiB + 12345 字节尾块） | 每块返回各自长度，拼接后逐字节 + SHA-256 一致 |
| 3 | 有效流后附加 6 个 trailing bytes | 返回原始长度，数据一致（协议不被收紧） |
| 4 | 截断到一半的流 | 2 秒内返回 0 |
| 5 | 输出已完整产生但 Adler-32 损坏 | 返回 0，不返回 `dst_size` |
| 6 | deflate 载荷中间字节损坏 | 返回 0 |
| 7 | 输出缓冲比真实长度少 1 字节 | 返回 0 |
| 8 | 带 FDICT 的 zlib header（`Z_NEED_DICT`） | 返回 0 |
| 9 | 空输入 | 返回 0 |
| 10 | `size_t` 超过 `UINT_MAX` 的输入/输出长度 | 返回 0，不截断 |

### 4.1 反向验证（修复前）

用 `d0e46ae` 原实现构建独立探针（不进入仓库）：

- 截断流：`timeout 3` 下进程未返回，exit 124，确认在 `inflate` 空转。
- 输出缓冲少 1 字节：`timeout 5` 下 exit 124，确认同样空转。
- 输出 4096 字节、Adler-32 损坏、`dst_size = 65536`：返回 **65536**，而真实解压内容只有 4096 字节，确认“假成功返回 `dst_size`”。

同一份测试在旧实现上第 4 例触发 2 秒超时并失败，证明测试确实能捕获旧行为。

### 4.2 修复后结果

- Debug：`zlib-decompress` 10 例全部通过；完整套件（排除需 sudo/FUSE 的 `reader-fuse`）5 pass，`lookup-generation` skip。
- Release：同上，5 pass，`lookup-generation` skip。
- ASan + UBSan（`-fsanitize=address,undefined`，`detect_leaks=1`，`halt_on_error=1`）：10 例全部通过，无 sanitizer 报告。
- `reader-integration` 在 `TMPDIR` 指向数据盘的条件下通过；本机 `/tmp` 曾满导致一次“cannot write image”，换 `TMPDIR` 后复跑通过，与代码无关。
- `reader-fuse` 未运行：本任务禁止 FUSE/sudo，且该脚本需要挂载；因此**没有**端到端 FUSE 验证。
- `lookup-generation` 在本环境 skip。

## 5. 验收

本 PR 的验收以合成证据为限：

1. 旧实现能稳定复现两类缺陷：截断/输出不足空转，坏校验返回 `dst_size`。
2. 新实现在 Debug、Release、ASan+UBSan 下 10 个用例全部通过，正常数据逐字节与 SHA-256 一致。
3. 失败路径返回 0，`DecompressFile` 因长度不匹配返回 false，`apfs_open` 默认路径返回 `EIO`（代码路径核对，非 FUSE 实测）。
4. 不修改 ADC/LZVN/LZFSE/LZBITMAP，不修改 manifest/设计文档，不访问真实源。

## 6. 剩余风险（供 review）

- **未覆盖真实压缩字节**：现场 path、压缩块和损坏原因均未知。本修复保证“坏流不再卡住、不再假成功”，但不能证明现场 7 分钟卡顿就由该缺陷单独造成；需在隔离、只读、非 root、限速条件下用同一 reader 版本重放真实 111 键并观察 `ioerr`/trace。
- **`dst_size == 0` 的 0 返回值有歧义**：成功空流与失败都返回 0。APFS 压缩文件的实际期望长度 > 0，现有调用点不会接受 0 作为完整块；若未来新增零长度压缩语义，应改成显式 bool/out 参数。
- **`DeviceDMG.cpp` 忽略返回值**：坏 DMG 流现在会快速返回 0，但调用方仍不看返回值。是否应改为失败传播超出本 PR 范围，未测试。
- **大 `hdr->size` 的分配仍发生在 `DecompressZLib` 之前**：`DecompressFile` 先 `resize(hdr->size)`；`size_t > UINT_MAX` 的守卫只能阻止错误解压，不能阻止这次分配。`apfs_open` 的 `g_max_decomp_size` 默认 0（不限），异常头仍可能触发大分配；`bad_alloc`/`length_error` 已被捕获为 EIO。
- **未跑 FUSE 挂载、未跑真实 APFS 镜像**：`apfs_open` 的 EIO 只做了代码核对；没有挂载级回归。
- **没有性能基准**：修复消除了空转，但正常大文件的解压成本不变。

## 7. 部署与发布条件

- 构建：Debug/Release 使用 `-DBUILD_TESTING=ON`，本机 CMake 4.x 需 `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`；目标 `zlib-decompress-test`。
- 发布前必须由独立 Opus review 通过，并把本 PR 合入个人 fork；不得直接替换生产 binary。
- 下一次真实读取前，必须重新绑定 reader commit 与 manifest/M0 规则，不得静默沿用 `d0e46ae` 或旧 111 键规则绕过错误集合。
- 真实重放只能在隔离、只读、非 root、限速的 reader 进程中进行，并保留 H-R 健康窗口/`ioerr` 证据；本 PR 不授权自动重跑真实源。
- 回滚：保留旧 binary；若新 reader 在真实数据上把原本“能读出”的文件变成 EIO，应先取证再决定是否回滚。fail-closed 意味着损坏数据现在会明确失败，这是预期行为，不是回归。
- 不声称 production ready：未覆盖真实压缩字节、未做 FUSE 端到端、未覆盖 DMG 路径。
