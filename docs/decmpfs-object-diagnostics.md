# APFS decmpfs：对象级诊断、seq 与前台采集

状态：实现稿，供独立 review。分支 `fix/reader-object-diagnostics` 基于个人 fork
`personal/master`（PR7 合入后 `165da21`，PR7 head `c7a817d`）。本 PR 只改 reader
（`ApfsLib/Decmpfs.*`、`apfsfuse/ApfsFuse.cpp`）、合成 fixture 与测试、相关文档；
不改 manifest 仓库，不访问真实源盘、块设备或生产挂载，不运行 FUSE。

## 1. 背景

PR7 的逐块 `APFS_DECMPFS_VALIDATION` 行能说明“某个 zlib 块怎样被接受”，但不能
回答“这个对象的全部块是否都被记录过”。stderr 丢失、写失败、日志轮转、同一 ino
的多次 open 都会让消费方无法判断证据是否完整。manifest 侧因此只能把缺少对象汇总
的对象记为 unknown，不能把“没有出现缺 Adler 行”推定为 checksum 完整。

本 PR 是完整 manifest 主线下的最小 reader 前置，对应 PR7 独立审查的 P2-3 与
P2-4。它不实现 manifest 对接，也不授权真实重放。

## 2. 需求

- **R1 进程内唯一 seq**：每次 `DecompressFile` 调用分配一个进程内单调递增的
  `seq`（atomic，线程安全）。进程/attempt 由外部 runner 绑定，本 PR 不引入
  attempt 全局状态。
- **R2 固定诊断**：所有 `APFS_DECMPFS_VALIDATION`、`APFS_DECMPFS_ERROR` 与
  `APFS_DECMPFS_OBJECT` 行都带同一个 `seq`；ERROR 与 VALIDATION 仍带
  `ino`/`algo`/`block`。固定诊断与 `-d` 无关，始终写 stderr。
- **R3 对象汇总**：成功时在全部 validation 行之后只输出一条
  `APFS_DECMPFS_OBJECT`，至少包含
  `seq,ino,algo,logical_size,blocks,zlib,raw,native,missing_adler,
  validation,checksum_verified,result=ok`。
- **R4 失败语义**：失败时没有 OBJECT、没有 VALIDATION；输出清空、`DecompressResult`
  归零；ERROR 带 seq。任何日志构造失败都按失败处理，不得留下“成功但无完整证据”。
- **R5 发布原子性**：一个对象的全部成功行先收集成一个 blob，再用同一把互斥锁
  一次写入 stderr，使多线程调用时对象日志不交错。错误行同样单次写入。
- **R6 不夸大完整性**：只有 `blocks > 0`、`zlib == blocks` 且
  `missing_adler == 0` 时 `validation=checksum`、`checksum_verified=1`。raw
  marker、LZVN/LZFSE/LZBITMAP、缺 Adler 一律
  `validation=structure_length_only`、`checksum_verified=0`。零长度对象为
  `validation=empty`、`checksum_verified=0`。
- **R7 前台选项**：新增 `-F`（`-f` 已是 fusion 副设备，不能复用），只关闭
  `fuse_daemonize`，不打开任何 `-d` 位；默认与 `-d` 语义不变。帮助与 README
  必须写明。`-F` 下 stderr 可由 wrapper 重定向到 attempt 专属 0600 文件。
- **R8 P3 回归**：零长度未知算法必须返回 false，错误 stage 与非零长度未知算法一致；
  `data_size` 超出真实载体的 type-4 负例不得靠 fixture 自动扩容掩盖。

## 3. 诊断 schema

成功对象（示例为两块、第一块 zlib 带 Adler、第二块 raw）：

```
APFS_DECMPFS_VALIDATION seq=7 ino=93 algo=4 block=0 compressed=... expected=65536 decoded=65536 validation=length_with_checksum missing_adler=0
APFS_DECMPFS_OBJECT seq=7 ino=93 algo=4 logical_size=65659 blocks=2 zlib=1 raw=1 native=0 missing_adler=0 validation=structure_length_only checksum_verified=0 result=ok
```

失败对象只有一行错误，没有 VALIDATION/OBJECT：

```
APFS_DECMPFS_ERROR seq=8 ino=90 algo=4 block=1 stage=block reason=block_marker
```

字段定义：

| 字段 | 含义 |
|---|---|
| `seq` | 本进程内 `DecompressFile` 调用序号，从 1 开始，atomic 递增 |
| `blocks` | 解码单元数：resource fork 为 `ceil(logical_size / 65536)`；非空 inline 为 1；空对象为 0 |
| `zlib` | 通过 zlib 解码的块数（仅 algo 3/4 的 0x78 块） |
| `raw` | 通过 raw marker 直接拷贝的块数（0xFF/0x06/0xCC 形态） |
| `native` | 通过 LZVN/LZFSE/LZBITMAP 解码器解出的块数（不含 raw marker） |
| `missing_adler` | 缺少 Adler-32 trailer、但仍按完整 DEFLATE 边界接受的 zlib 块数 |
| `validation` | `checksum` / `structure_length_only` / `empty` |
| `checksum_verified` | 仅当 `blocks>0 && zlib==blocks && missing_adler==0` 为 1 |
| `result` | 成功固定为 `ok`；失败不输出 OBJECT |

恒等式：成功对象 `blocks == zlib + raw + native`；
`VALIDATION` 行数等于 `zlib`。这些恒等式由测试逐对象校验。

消费规则（manifest 另 PR 实现）：按 attempt + reader SHA + volume + ino + seq
关联；缺 OBJECT、缺字段或块序列不完整一律 unknown。同一 ino 多次 open 会产生
多个不同的 seq，不得手工去重后当作一次成功。

## 4. 设计取舍

- **只扩展现有 `DecompressResult`**：新增 `seq`、`logical_size`、`block_count`、
  `raw_block_count`、`native_block_count`、`checksum_verified`，不引入全局对象表、
  队列或日志框架。默认调用保持源码兼容。
- **先收集后发布**：validation 行与 OBJECT 行在本地拼成一个 `std::string`，在
  `std::mutex` 保护下用一次 `std::cerr.write` 写出。错误行用栈上 `snprintf` 缓冲
  单次写出。这样多线程调用不会把两个对象的对象级日志交错；内存不足时按失败处理，
  不输出“成功但缺证据”的对象。
- **seq 归属本次调用**：失败时 `DecompressResult` 归零（与现有“失败清空”契约一致），
  seq 只出现在 ERROR 行。成功时 result 与 OBJECT 行的 seq 相同。
- **计数按块来源**：zlib/raw/native 三分，避免把 LZVN 或 raw 块误算成 checksum
  验证。零长度对象不读载体，仍输出空汇总。
- **前台不做成 debug**：`-F` 只控制 daemonize，不触碰 `g_debug`。这样不会因为
  打开 `Dbg_Errors` 把压缩字节 DumpHex 到 stdout，也不会打开 `Dbg_Info`/`Dbg_Cmpfs`
  的名字或内容输出。
- **不接管 `APFS_ZLIB_ERROR`**：它由 `DecompressZLib` 直接写 stderr，缺少 seq/ino；
  失败时紧随其后的带 seq 的 `APFS_DECMPFS_ERROR` 负责对象绑定。manifest 只以
  `APFS_DECMPFS_*` 行为准；该既有行的改造不在本 PR 范围。

## 5. 验收

全部走真实 `DecompressFile` 与现有合成 APFS fixture，不写镜像实现的假测试：

- 正例：zlib、LZVN、inline zlib、canonical 混合 Adler、新增 zlib+raw 混合对象，
  逐字节与 SHA-256 不变；每个成功对象恰好一条 OBJECT，计数恒等式成立。
- checksum 语义：完整 zlib 为 `validation=checksum`；缺 Adler、raw、LZVN、
  zlib+raw 混合一律 `structure_length_only`；空对象为 `empty` 且
  `checksum_verified=0`。
- 失败：第二块损坏（ino90）、malformed carrier 全部无 OBJECT/VALIDATION，
  output 与 result 清空，ERROR 行带非零 seq。
- seq：连续调用严格递增；同一 ino 两次调用得到两个不同 seq；每次成功 result.seq
  与 OBJECT 行一致。
- 并发：多个线程各自打开独立 image、解码独立对象，stderr 中的对象日志按 seq
  连续成块，不交错。
- P3：零长度未知算法返回 false 且 `stage=algorithm reason=unsupported`；
  `data_size` 超出真实载体（不自动扩容）返回 `rsrc_table/data_size`。
- mutation：至少验证删除零长度算法检查、删除 `data_size` 上界检查、删除 OBJECT
  输出、把 raw/native 误标为 checksum 都会被测试捕获。
- Debug/Release 新构建各跑 `ctest -E reader-fuse`；ASan/UBSan 库层跑
  `zlib-decompress` 与 `reader-integration`。`TMPDIR` 指向私有目录。
- `-F`：真实二进制接受该选项、帮助列出该选项，且不会把它误当 `-f` 的参数。

## 6. 部署与发布条件

- 仅在个人 fork 合入并经独立 review 后才允许替换生产 reader；不得静默沿用旧
  reader commit 或旧 manifest 规则。
- 真实重放前必须由 owner 在隔离、只读、非 root 窗口中用 `-F` 启动独立 reader，
  把 stderr 写入 attempt 专属 0600 文件，并在非 root 合成 FUSE 上确认
  `APFS_DECMPFS_OBJECT` 实际落盘。本 PR 不运行 FUSE，不完成这项验收。
- manifest 对接（attempt + reader SHA + volume + ino + seq、unknown 规则）必须
  另开 PR 实现并 review；在本 PR 合入后仍不能声称完整 manifest 完成。
- 缺 Adler、raw 与 LZVN 对象只能标 `integrity=structural+length`；checksum 只是
  decmpfs 格式内部校验，不等价原文件无损。
- 回滚保留旧 binary；真实数据出现新的 EIO 时先取证，不以直接回滚掩盖。

## 7. 未覆盖边界

- 未运行 FUSE，未做真实 111 键重放，未访问 `/dev/sdb` 或任何块设备。
- 未改 manifest 仓库，未实现 attempt/volume 绑定与 unknown 分类。
- `APFS_ZLIB_ERROR` 仍不带 seq/ino；多线程下它可能与本对象的对象级日志分开，
  但不改变成功/失败结论。
- LZVN/LZFSE/LZBITMAP 解码器内部仍依赖上游实现；本 PR 只保证输入范围已经过
  表校验，并按块来源计数。
- zlib 缺 Adler 接受依赖已验证的 zlib 1.3.1 行为；本 PR 不声明最低版本。

## stderr发布失败合同

EmitBlob在互斥区内清除此前流错误、write及flush、检查good并清除流状态。写失败（含短写）返回false，finish转diagnostic/write错误并清空output/result，不把这次内容发布为成功。错误行自身可能因同一故障丢失，因此manifest仍必须将缺summary/截断/冲突记unknown，不能以无ERROR作为成功。恢复sink后后续对象允许正常写出。测试注入拒写及短写streambuf，保留badbit换回正常sink后验证恢复和OBJECT末行。

Owner set-e新构建：Debug/Release各6PASS1既有lookup-generation skip；ASan/UBSan库层zlib-decompress与reader-integration 2PASS（既有对齐问题范围沿用前审，非全无UB声明）。未运行FUSE或真实源。
