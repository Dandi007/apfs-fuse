# APFS reader：压缩硬链接双路径与 `-F` 前台回归

状态：tests-only 实现稿，供独立 review。分支 `t3/reader-hardlink-manifest-tests`
基于个人 fork `personal/master`（`a04c619`，PR8 已合入）。本 PR 只改 `tests/` 与
本文档：不修改 reader 生产代码、`ApfsLib/Decmpfs.*`、manifest 或 allowlist，不访问
真实源盘、块设备、生产挂载，不运行 FUSE/sudo。

## 1. 背景

PR8 已让 reader 在每次 `DecompressFile` 调用时分配进程内递增 `seq`，并为成功对象
输出一条完整 `APFS_DECMPFS_OBJECT`。raid-image-backup PR9 已合入 manifest 侧的解
析与 attempt 绑定。实际 `ContentManifest` 对每个硬链接目录项仍各自 `open`，只跳过
重复 `read`，因此同一个压缩 inode 的第二条硬链接路径必须再次进入
`DecompressFile`，得到新的 `seq` 和新的 OBJECT 记录；不能复用第一次 open 的解压
结果去冒充第二次成功。

现有合成 fixture 的压缩文件每个 inode 只有一个目录项，无法表达“同一 ino、两条
路径”。现有 `reader-fuse` 前台测试仍使用 `-d 1`，且把 stdout/stderr 合并到同一个
文件，无法证明生产默认模式下 stdout 为空，也无法区分对象诊断与 debug 输出。

本 PR 是完整 manifest 主线的最小测试前置，只补齐 fixture 与回归，不改变 reader
行为。

## 2. 需求

- **R1 双路径 fixture**：为已有压缩单块 inode 60（`rf-zlib-1blk`）增加第二个
  directory record，名称 `rf-zlib-1blk-hardlink`，指向同一 inode；把该 inode 的
  `nlink` 设为 2。只在 good 镜像启用，避免改变 bad-tree 刻意损坏的 leaf 分组。
  不修改生产 nlink 语义或 reader 链接处理。
- **R2 库层同 ino 断言**：`reader-integration` 必须通过真实 `LookupName` 证明两个
  名称都解析到 `file_id == 60`，且 `GetInode(60).nchildren_nlink == 2`。
- **R3 前台默认模式**：`reader_fuse_test.py` 的前台挂载改用 `-F`，不传 `-d`、不传
  `-l`；stdout 与 stderr 分别重定向到独立文件。
- **R4 双路径对象记录**：先对 `rf-zlib-1blk` open+read 并校验 golden SHA-256；再对
  `rf-zlib-1blk-hardlink` open 后立即 close、不 read。两次 open 各自产生恰好一条
  完整 OBJECT 和一条 VALIDATION：同一 `ino=60`，`seq` 不同且后一次严格更大，
  `blocks=1 zlib=1 raw=0 native=0 missing_adler=0 validation=checksum
  checksum_verified=1 result=ok`。
- **R5 MissingCarrier 边界**：`rf-missing`（有 decmpfs、无 ResourceFork）open 必须
  EIO，且该操作窗口内不得出现 `APFS_DECMPFS_ERROR` 或 OBJECT；坏载体是另一个
  fixture 名 `rf`，不在本断言内混用。
- **R6 保持既有断言**：默认 daemon 挂载、backup view、bad image、Unicode fallback、
  damaged inline zlib 的 `APFS_ZLIB_ERROR` 与 EIO 断言全部保留；前台 stdout 必须为
  0 字节。
- **R7 非 root 可实测**：`reader-fuse.sh` 支持 `APFS_FUSE_USE_SUDO=0`，允许 owner
  在普通用户、无 sudo、fusermount3 可用的主机上直接运行。未设置该变量时保持原有
  自动 sudo 回退逻辑，CI 的默认兼容性不变。

## 3. 设计

### 3.1 fixture

`InodeSpec` 增加默认 `nlink = 1`，`MakeInodeVal()` 对普通文件写入 `spec.nlink`；
目录仍写 `nchildren=2`，行为不变。`AddRfContentRecords()` 新增
`hardlink_alias` 参数：为真且 inode 为 60 时追加一条 drec 并把 nlink 设为 2。
`AddGoodRecords()` 透传该参数；good 镜像传 `true`，bad 镜像传 `false`，因此
`BadTree` 的 leaf 分组与既有损坏断言完全不变。

### 3.2 库层测试

`TestHardLinkAliases()` 在 `TestGoodImage()` 中、RF 内容测试之前运行。它只使用
现有 `ApfsDir::LookupName`/`GetInode`，不新增测试框架，也不复制 reader 逻辑。

### 3.3 FUSE 前台测试

`mount(..., foreground=True)` 现在执行：

```
apfs-fuse -F <image> <mnt>          # stdout -> foreground.stdout
                                    # stderr -> foreground.log
```

不包含 `-d`/`-l`。挂载就绪后先确认前台进程仍然存活。测试按操作窗口增量读取
stderr：窗口起点取 `os.path.getsize()`，操作结束后 `seek` 到该偏移读取。这样每个
open 的 OBJECT/VALIDATION 可以逐条归属，而不是在最终日志里做宽松匹配。解析只按
空格切分 `key=value`，字段集合与取值来自 PR8 已固定的 schema。

`rf-missing` 在分类阶段即被判为 MissingCarrier 并返回 EIO，尚未进入
`DecompressFile`，所以窗口内不应有任何 `APFS_DECMPFS_ERROR`；这与坏载体 `rf`
（`stage=rsrc_table`，会输出 ERROR）是两条不同的路径。

## 4. 验收

普通用户、非特权的库层验收：

```sh
export TMPDIR=/data/tmp/task
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build -j"$(nproc)"
ctest --test-dir build -R \
  '^(btree-offset|extent-reader|reader-policy|zlib-decompress|reader-integration)$' \
  --output-on-failure
python3 -I -m py_compile tests/reader_fuse_test.py
```

owner 后续在允许非 root FUSE 的主机上执行：

```sh
export TMPDIR=/data/tmp/task
APFS_FUSE_USE_SUDO=0 sh tests/reader-fuse.sh \
  build/apfs-fuse build/apfs-fixture-gen
```

必须看到：

- `reader-integration` 断言两个硬链接名解析到同一 ino 60、nlink 为 2。
- 前台窗口一：`rf-zlib-1blk` open+read 的 SHA-256 与 golden 一致，恰好一条完整
  OBJECT（ino 60，blocks/zlib/raw/native 计数正确）。
- 前台窗口二：`rf-zlib-1blk-hardlink` 仅 open+close，仍产生一条完整 OBJECT，
  `seq` 严格大于窗口一。
- `rf-missing` open 为 EIO，窗口内无 `APFS_DECMPFS_ERROR`、无 OBJECT。
- 前台 stdout 为 0 字节；既有 Unicode/zlib 诊断断言继续通过。
- 默认 daemon、backup view、bad image 测试继续通过。

本 PR 交付时只运行了上列前三条命令中的库层部分；FUSE 条目由 owner 验收。

## 5. 部署与发布条件

- 本 PR 仅含测试与文档，不合入任何 reader 生产逻辑；合入后不改变生产 reader 行为。
- 非 root FUSE 验收尚未由本实现代理执行，必须在 owner 掌控的隔离环境完成；测试
  脚本的 `APFS_FUSE_USE_SUDO=0` 只是为这项验收提供入口，不代表已完成验收。
- 真实源盘、111 键重放、生产挂载、systemd/服务隔离与 allowlist 放行均不在本 PR
  范围，仍受 owner 的既有发布条件约束。
- 只有库层测试、owner 的非 root FUSE 双路径验收、以及后续真实 manifest 重放全部
  通过后，才能声明“硬链接双路径 manifest 已覆盖”。本 PR 不能作为该声明。
- 回滚只需回退测试提交；不涉及 binary 或生产配置。

## 6. 未覆盖边界

- 未运行 FUSE、sudo、loop/dm、服务、真实源盘或生产挂载；未读取 `/data/backup`。
- 未修改 manifest 仓库、allowlist 或 reader 生产代码。
- fixture 只表达“同一 ino 两条 drec、nlink=2”的静态布局，不验证 APFS 写路径、
  链接创建或 nlink 更新。
- 双路径 OBJECT 的 seq 只断言严格递增，不断言从 1 开始的绝对序号；同一进程内
  其他对象可能先占用更小的 seq。
- 未覆盖 cross-directory hardlink、多硬链接（>2）、硬链接与 snapshot/clone 组合。
- owner 提供的已合入 reader 二进制与 `-F` 冒烟证据（同一路径重复 open、stdout 0、
  `rf-missing` 无 ERROR）只作为参考，不替代本 PR 的双路径库层断言和正式
  raid-backup 单元。
