# APFS decmpfs resource fork：块表边界校验与逐对象缺 checksum 诊断

状态：实现稿，供独立 review。分支 `fix/reader-rf-bounds` 基于个人 fork `personal/master`（PR6 合入后 `4d6b944`，PR6 head `7d678ad`）。本 PR 只改 reader（`ApfsLib/Decmpfs.*`、`ApfsLib/Util.*`）、合成 fixture 与测试、相关文档；不改 manifest，不访问真实源盘或生产挂载。

## 1. 背景

PR6 让 decmpfs type 3/4 的 zlib 块可以按“DEFLATE 完整、缺 Adler-32 trailer”形态成功解码。审查同时指出 `Decmpfs.cpp` 的 resource fork 解析存在既有缺口，PR6 合入后这些路径会真正执行：

- type 4 的 `entries` 没有和 `ceil(logical_size / 64K)` 对齐。偏少时尾部保留 `resize` 后的零填充却返回成功；偏多时 `expected_len` 下溢，`dst` 越过输出缓冲区。
- 表项 `off`/`size` 没有对 rsrc 或声明 data section 做边界检查，`src[0]` 与 `src_len - 1` 在零长度块上越界。
- `(size + 0xFFFF) & 0xFFFF0000` 是 32 位掩码，逻辑大小达到或超过 4 GiB 时会截断高位，可能分配过小。
- 8/10/12/14 的共享 `off_list` 存在同一类未验证读和 `src[0]`/`src_len - 1` 问题。
- 缺 trailer 被接受时，没有逐对象、可解析的诊断把“结构/长度验证”与“完整 checksum”区分开。

## 2. 需求

- **R1 完整表校验**：类型 4 只有在显式块记录数精确等于 `ceil(logical_size / 65536)`、且每条记录都落在声明 data section 内时才解码；少块、多块、短表、空块、非单调/重叠 offset、表内指针、越界 offset/size 一律失败。
- **R2 溢出安全**：逻辑大小、块数、表大小、分配大小使用 `size_t`/`uint64_t` 检查和减法边界，不使用 32 位掩码；分配失败按失败处理。
- **R3 共享 off_list fail-closed**：算法 8/10/12/14 在同一解析边界内校验表长度、首 offset、单调性、终点 offset 和块长度；raw marker 必须恰好是 `expected + 1` 字节。解码算法本体不改。
- **R4 语义不变**：合法的 type 4 zlib/LZVN、单/多块、短尾、inline type 3 正常流仍逐字节成功；真实用户 resource fork 仍是普通属性，不参与压缩解码。
- **R5 逐对象诊断**：成功时每个 zlib 块输出一行可解析 `stderr`，包含 `ino`、`algo`、`block`、`compressed`、`expected`、`decoded`、`validation`、`missing_adler`；只有真正按缺 Adler 边界接受时才是 `validation=structure_length_only`，完整 `Z_STREAM_END` 为 `validation=length_with_checksum`。失败只输出错误行，带 `ino`/`algo`/`block`/`stage`/`reason`，不含文件名、路径或内容。`DecompressFile` 通过可选 `DecompressResult` 把本次是否接受缺 Adler 返回调用方，默认调用保持兼容。

## 3. 设计取舍

- **先完整验证再解码**：解析阶段只构造已验证的 `{offset, size}` 记录，任何指针都在验证后形成；解码阶段不再做边界推断。
- **以声明 data section 为边界**：类型 4 使用 `RsrcForkHeader.data_offset/data_size`，要求 `data_offset + data_size` 不越过实际 rsrc。这样 resource map 和尾部 padding 不会被当作压缩内容。未额外要求 `mgmt_offset` 的固定关系，避免收紧没有证据的格式。
- **块记录完整覆盖**：`entries == ceil(size / 64K)`。即使多出的记录本身合法也拒绝，因为无法证明它们不是重复或替换内容；少块则明确不返回零填充假成功。
- **允许表后 padding**：首条记录的 offset 必须不早于表尾，但允许大于表尾；这是对合法 padding 的最小让步。
- **共享解析边界**：8/10/12/14 的 offset 表要求 `blocks + 1` 项可读、首 offset 不早于表尾、offset 严格递增且终点不越过 rsrc、每块长度不超过 64 KiB + 1。解码函数保持原样。
- **诊断延后输出**：类型 4/8/10/12/14 先完成整个对象解码，再输出本次的 validation 行；后续块失败时不会留下前面块的“成功”行。错误行立即输出。
- **结果元数据最小化**：`DecompressResult` 只含 `accepted_missing_adler`、`zlib_block_count`、`missing_adler_block_count`，不引入全局状态。DMG 等其他调用仍使用默认严格模式。

诊断示例：

```
APFS_DECMPFS_VALIDATION ino=67 algo=4 block=0 compressed=404 expected=65536 decoded=65536 validation=structure_length_only missing_adler=1
APFS_DECMPFS_VALIDATION ino=60 algo=4 block=0 compressed=408 expected=65536 decoded=65536 validation=length_with_checksum missing_adler=0
APFS_DECMPFS_ERROR ino=70 algo=4 block=0 stage=rsrc_table reason=block_count
```

## 4. 验收

必须通过真实 `DecompressFile` 和合成 APFS 入口，不使用镜像解析器的纯 helper：

- 正常：RF zlib/LZVN 单块、多块短尾、inline type 3 正常流保持逐字节和 SHA-256 不变；新增无 trailer 的 type 4 正例成功，`DecompressResult` 与诊断行正确。
- 反例（全部断言 `false`、无成功诊断、无越界/零填充假成功）：少块、多块、短表、零长度块、offset/size 越界、倒序/重叠、表内指针、raw marker 长度错误、data_offset 越界、4 GiB 逻辑大小、零逻辑大小、短 header、空载体，以及 8/10/14 的短表/表内指针/零长度/越界/raw 长度错误。
- 诊断：缺 Adler 正例与完整 checksum 对照；多块每个 `block` 索引可解析；错误行 `ino`/`algo`/`block`/`stage`/`reason` 准确，不含镜像路径或文件名。
- Debug 与 Release 分别构建并运行 `ctest`（排除 FUSE 的 `reader-fuse` 与既有 `lookup-generation` skip）；另外用 ASan/UBSan 库层构建运行 `zlib-decompress` 与 `reader-integration`，已知基线对齐问题单独记录。
- 不运行 FUSE，不访问真实源盘、块设备、生产挂载或服务。

## 5. 部署与发布条件

- 仅在个人 fork 合入并经独立 review 后才允许替换生产 reader；不得静默沿用旧 reader commit 或旧 manifest 规则。
- 真实重放前仍需：重新绑定 reader commit 与 manifest/M0 规则；在 owner 掌控的隔离、只读、非 root、限速窗口中重放同一 111 键；逐条收集新的 `APFS_DECMPFS_VALIDATION` 并与对象绑定。
- 缺 Adler 的对象在 manifest 中只能标 `integrity=structural+length`，不能计入“经 producer 校验”的统计；本 PR 不声称 21 个现场文件无损。
- 回滚保留旧 binary；新 reader 在真实数据上出现新的 EIO 时先取证，不以直接回滚掩盖。

## 6. 未覆盖边界

- 本 PR 未做 FUSE 端到端，未重放真实 111 键，未修改 manifest。
- raw marker（0xFF/0x06/0xCC）块没有生产者 checksum，本 PR 只做 marker + 长度校验，不输出缺 checksum 诊断；其完整性语义仍弱于带 checksum 的 zlib。
- zlib 缺 Adler 接受只覆盖已验证的 zlib 1.3.1 行为；不声明最低版本。
- LZVN/LZFSE/LZBITMAP 解码器内部仍依赖上游实现的防御；本 PR 只保证调用前输入指针和长度已落在已验证的 rsrc 区间内。
