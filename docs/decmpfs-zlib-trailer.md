# APFS decmpfs zlib：缺失 Adler-32 的兼容修复

状态：实现稿，供独立 review。分支 `fix/zlib-format-evidence` 基于个人 fork `personal/master` 的 `dc8dc94`。修改 `DecompressZLib`、decmpfs调用点、单元测试和本文，不访问真实源盘或生产挂载。

## 1. 背景与现场证据

H-R4 的 111 键样本结果为 89 成功、1 个预期 class6 错误、21 个 unexpected 错误。21 个错误全部是 `stage=open`、`errno=5`（EIO）、`bytes=0`，对象均为 Spotlight 缓存，解压后大小 16650..1185949 字节。

`reader.log` 恰好有 21 条 `APFS_ZLIB_ERROR`，形态完全一致：

- `ret=-5`（`Z_BUF_ERROR`），`msg=none`；
- 每条都 `total_in == src_size`（输入被完整消费）；
- 每条都 `dst_size=65536`（resource-fork zlib 路径固定按 64 KiB 块解码）；
- 20 条 `total_out` 等于目标文件大小（单块文件），1 条 `total_out=65536`（多块文件的第一个块）。

这组签名说明：zlib 已经产出全部期望字节并读完了全部输入，但没有返回 `Z_STREAM_END`。多块文件在第一个块就返回失败，所以每个文件只留下一条日志，`65536` 那条正是首块。21 条日志尚未与 21 个对象逐一绑定，因此不能据此判定源数据损坏。

不能因为“输出长度刚好正确、输入刚好耗尽”就允许任意 `Z_BUF_ERROR`：那会把真正的截断和校验损坏一并放过。必须先确定 Apple 的 zlib 块在磁盘上到底是什么终止形态。

## 2. 上游一手证据

APFS 写端未开源，但 AppleFSCompression 的行为有可核验的原生抓包：

- 仓库 `deploymenttheory/go-apfs-v2`（MIT）的 `testdata/appledouble/native/compression-writer.json.gz` 记录了 macOS 27.0.1（build 26A434）、SDK 27.0 上由 `AppleFSCompression.framework`（UUID `3B5065D1-5D8A-3443-B4B8-293DA9FE47C3`）实际写出的 33 组 type selection，包含原生 `Attribute` 与 `Fork` 字节。
- 该仓库的测试要求自家 encoder 对同一选择产生的字节与原生 `Fork` **完全一致**（`bytes.Equal`），因此这些字节可以作为独立黄金样本。

取 `requested type 4`（zlib + resource fork）的一条 64 KiB 文件：

- resource fork 共 408 字节；`data_offset=0x100`，`data_length=0x66`，尾部 50 字节 map/trailer（含 `cmpf`）；
- data 区：`data_offset+4` 处 LE block count = 1，随后 8 字节 `{offset=12, size=86}`；
- 压缩块 86 字节：`78 5e ... ef 1f`，没有结尾的 4 字节 Adler-32。

用独立参考解码器（Python 标准库 zlib，RFC 1950/1951）验证该块：

- 完整解压得到 65536 字节，SHA-256 `ba1e423063874c1bc997e1fe7aa9971477f851b118cc9ad92921b953dd27c309`；
- 解压器 `eof=False`，输入全部耗尽，即停在 checksum 状态；
- 在该块后追加按解压结果计算的正确 Adler-32，标准 `zlib.decompress()` 随即成功，内容与明文一致。这证明 DEFLATE 流在 final block 处正常结束，缺的只是 4 字节 trailer，不是流中间被截断；
- 块尾为 `ef 1f`，不含 `00 00 ff ff`，排除 `Z_SYNC_FLUSH` 形态。

旁证：

- `keramics`（libfsapfs 作者 Joachim Metz 的格式库）的 zlib 解码器显式允许 checksum 缺失（`test_decompress_without_checksum`，且只在剩余字节大于 4 时校验）；
- `go-apfs-v2` 的编码器注释明确写着原生 producer 使用 level 5 / 32 KiB window，并且 “decmpfs omits the Adler-32 trailer”。

布局核对：本仓库 `Decmpfs.cpp`（`data_offset + 4` 为基址、LE count、8 字节 `{offset, size}`）与 keramics 的 `offset 260/264`、`block offset + 260` 完全一致，也与上述原生 fork 吻合。因此块边界定位正确，问题只在流的终止判定。

结论：**缺失 Adler-32 是 APFS decmpfs zlib 的合法磁盘格式，不是损坏。** 独立审查复核的第三方抓包中170个type-4块均为该形态；这能解释现场日志模式，但不能证明21个现场文件无损，也不能反推其他89个键的压缩类型。

## 3. 需求

- **R1 合法格式可读**：接受“zlib header + 完整 DEFLATE + 无 Adler-32”的 decmpfs 块，返回准确字节数与内容。
- **R2 失败仍 fail-closed**：截断（包括只缺尾部若干字节）、错误 trailer、输出缓冲不足、字典流、空输入仍返回 0，且时间有界。
- **R3 语义不回退**：带正确 trailer 的普通 zlib 流、`Z_STREAM_END` 之后的 trailing bytes、精确 64 KiB 输出保持原行为。
- **R4 最小改动**：只修改 zlib 边界和 decmpfs 显式调用，不改其他压缩算法、不新增依赖。

## 4. 设计

`DecompressZLib` 新增 `allow_missing_adler=false` 参数，只有 decmpfs type 3/4 显式传 true。type 4 有第三方原生抓包；type 3 共用协议是推断，没有原生样本。DMG 等其他调用仍要求完整校验。

显式启用时使用 zlib `Z_BLOCK`，只有 `ret==Z_OK`、`(data_type & 0xC0)==0xC0`、`avail_in==0`、`total_out>0` 才接受缺尾：zlib 确认当前位置是最后一个 DEFLATE block 的结束边界。存在剩余输入时继续正常解码，要求完整正确的 Adler-32；部分 trailer 1–3 字节一律失败，不合成校验值。普通完整流仍以 Z_STREAM_END 成功，错误和无进展有界退出。

语义与版本说明：本轮已在 zlib 1.3.1（本机 `ZLIB_VERSION`）上验证上述 `Z_BLOCK`/`data_type` 边界；这是已验证版本，不声明最低版本。若生产构建使用其他 zlib 版本，需按同一组边界用例单独复验，不能仅凭版本号推断行为一致。

缺少生产者 checksum 的内容只有结构及调用方长度检查。合法编码内部的位翻转可能解出同长度错误内容；不能将解码成功或内容SHA称为独立完整性验证。真实21文件没有逐对象字节证据，不能宣称无损。

## 5. 修改范围

Util.cpp/Util.h 实现显式opt-in和确定性边界；Decmpfs.cpp两处调用开启；独立单测覆盖默认严格模式、stored/fixed/dynamic所有截断点及部分trailer碰撞。原生抓包固定 upstream commit `2bd8a20b`，文件SHA256 `2dbeb1ced7175692d0de004c96a9328acded752744687e973a744db6bd1133cc`（MIT）。

## 6. 验收

### 6.1 反向验证

把 `personal/master`（`dc8dc94`）的旧 `DecompressZLib` 原样抽出，对同一原生 86 字节块运行：

```
APFS_ZLIB_ERROR ret=-5 msg=none total_in=86 total_out=65536 src_size=86 dst_size=65536
old implementation returned 0 for the native 86-byte block
```

与现场 21 条日志同型（`ret=-5`、`total_in==src_size`、`total_out` 等于期望长度），确认旧实现必然拒绝该合法格式。

### 6.2 正向结果

- 原生黄金块解出 65536 字节，SHA-256 与抓包明文一致。
- Debug 与 Release 全量 `ctest`（排除需要 FUSE/sudo 的 `reader-fuse`）：5 passed，`lookup-generation` skip；`zlib-decompress` 22 个用例全部通过，包含原有 10 个 fail-closed 用例。
- 负例全部返回 0 且在 2 秒保护内返回：原生块去掉 1..4 字节、原生块后追加 `00 00 00 00`、普通流截断、坏 Adler-32、输出缓冲少 1 字节、字典流、空输入。
- 普通带 trailer 的流、trailing bytes、精确 64 KiB 输出仍逐字节与 SHA-256 一致。

## 7. 部署与发布条件

- 构建（本机）：`cmake -S . -B <build> -DCMAKE_BUILD_TYPE=Debug|Release -DBUILD_TESTING=ON -DCMAKE_POLICY_VERSION_MINIMUM=3.5`，目标 `zlib-decompress-test`；测试时 `TMPDIR` 指向数据盘。
- 先合入个人 fork，经独立 review 后才允许替换生产 binary；不得静默沿用旧 reader commit 或旧 manifest 规则。
- 真实重放前必须：重新绑定 reader commit 与 manifest/M0 规则；在隔离、只读、非 root、限速的 reader 进程中重放同一 111 键；确认 21 个 unexpected 变为成功，或给出新的可归因证据。不得扩大 class6 预期集合。
- 回滚：保留旧 binary。若新 reader 在真实数据上产生新的 EIO，先取证再决定，不得直接回滚掩盖。
- 本 PR 不声称 production ready：未做 FUSE 端到端，未重放真实源盘。

## 8. 未覆盖边界与剩余风险

- **type 3 inline zlib 未直接观测**：修复在函数级生效，但原生抓包只覆盖 type 4；同一 producer/encoder 的推断成立性未验证。现场 21 条 `dst_size=65536` 均为 type 4，不受影响。
- **无 trailer 时无内容校验**：只能依赖调用方长度检查；这是磁盘格式的固有限制。
- **resource fork 表越界校验**：本 PR 合入时 `Decmpfs.cpp` 尚未检查块数以及 `src_offset + src_len` 是否落在 rsrc 内，属既有缺口。已由后续独立 reader PR 补齐：类型 4 精确匹配 `ceil(size/64K)` 个块，表、offset、size 均在声明 data section 内校验，其余 rsrc 算法共享同一 fail-closed 解析边界。
- **DMG 路径**：`DeviceDMG.cpp` 共用 `DecompressZLib`，默认严格校验不启用缺尾兼容，既有忽略返回值问题仍未处理。
- **未对 21 个现场对象逐条取证**：按约束不访问生产挂载；结论基于“原生格式系统性 + 现场日志签名完全一致”，不是对每个对象的独立证明。

## 9. 审查修正与自验

P2-1以Z_BLOCK确定性边界替代合成Adler；P2-2默认严格模式，仅decmpfs type3/4 opt-in；P2-3许可与固定来源修正。新增stored/fixed/dynamic每个截断点及adler首尾碰撞的部分trailer负例、默认拒绝无尾正例。Debug/Release各5 PASS、1既有lookup-generation skip；本轮未跑FUSE。真实重放前还必须补resource fork块数与范围校验、逐对象缺尾诊断、重新绑定reader与M0，并独立复核阶段条件。

构建证据纠正：71d422e的测试源码含vector构造误参数，构建失败；当时未启用shell fail-fast，ctest实际运行旧二进制，不能作为新测试证据。后续删除误参数，使用set -e依次构建并测试Debug/Release，两者均5 PASS、1既有skip。新证据日志为owner-build-fixed.log / owner-debug-fixed.log / owner-release-build-fixed.log / owner-release-fixed.log，位于/data/tmp/apfs-zlib-format-20261109。
