# APFS fixture：`good-nolink` 镜像（无硬链接别名）

状态：tests-only 实现稿，供独立 review。分支 `t3/good-nolink-fixture-tests`
基于个人 fork `personal/master`（`2b0a77c`）。本 PR 只改 `tests/` 与本文档，
不修改 reader 生产代码、manifest、allowlist，也不改变既有 `good` / `bad` /
`large` 模式的语义。

## 1. 背景

raid-image-backup PR15 的 B2 独立复核（WF
`wf-7efaa9/reviews/full-manifest-b2-code-opus-20261109.md`，P2-6）指出：现有
`apfs-fixture-gen good` 镜像中，ino 60 同时有 `rf-zlib-1blk` 与
`rf-zlib-1blk-hardlink` 两条目录项，`nlink=2`。全卷 manifest planner 明确拒绝
regular 文件同一 ino 多路径，因此 runbook 的合成验收在 planner 阶段就无法通过。

planner 策略、真实 M0 和 allowlist 都不放宽；测试侧需要一个内容与 `good`
完全一致、但该 inode 只有一条路径的镜像，用于后续 B2 合成 sealed / blocking
验收。

## 2. 需求

- **R1 新模式**：`apfs-fixture-gen good-nolink <image>` 生成完整 good 内容，
  仅 `AddRfContentRecords(hardlink_alias=false)`。ino 60 不追加
  `rf-zlib-1blk-hardlink` 目录项，`nlink=1`。
- **R2 其他对象不变**：除该别名目录项与 ino 60 的 `nlink` 外，所有目录项、
  inode 号、文件字节、xattr 内容与 `good` 相同；不删除任何对象。
- **R3 既有模式不变**：`good` 仍保留双路径且 `nlink=2`；`bad` 仍是
  `hardlink_alias=false`，leaf 分组与既有损坏断言不变；`large` 不变。
- **R4 CLI**：usage 与未知模式提示包含新模式，解析失败仍返回非零。
- **R5 库层回归**：`reader-integration` 断言新镜像无别名、其余对象一致、
  `good` 双路径不变、`bad` 根目录布局不变。

## 3. 设计

### 3.1 fixture 生成器

- `ApfsFixtureKind` 增加 `GoodNoLink`。
- `CreateApfsFixture()` 中 `Good` 与 `GoodNoLink` 共用同一分支，
  `hardlink_alias = (kind == ApfsFixtureKind::Good)`；两者都调用
  `AddRfBoundsRecords()`，因此 malformed-carrier 用例也完整保留。
  `BadTree` 与 `LargeDirectory` 分支不改动。
- `AddRfContentRecords()` 已有的 `hardlink_alias` 参数就是所需开关，不新增
  fixture 框架，也不改动 `RfContent` 或 reader 侧代码。
- `ApfsFixtureGen.cpp` 解析 `good-nolink`，usage 改为
  `good|good-nolink|bad|large <image>`。

### 3.2 库层测试

`reader-integration` 增加第四个镜像 `good-nolink.img`，新增
`TestGoodNoLinkImage()`：

1. `rf-zlib-1blk` 仍解析到 ino 60；`rf-zlib-1blk-hardlink` 为 `NotFound`；
   `GetInode(60).nchildren_nlink == 1`。
2. 用 `ListDirectory(2)` 比较 `good` 与 `good-nolink` 的根目录项集合：两者
   恰好相差一个别名目录项，其余条目的 `name` / `file_id` / `flags` 完全一致。
3. 对每个共有对象比较 `GetInode` 的稳定字段、`ListAttributes` 的属性集合与
   属性字节，以及普通文件 `ReadFile` 的结果（成功与否和字节都必须一致）。
   比较时排除 ino 60 的 `nchildren_nlink`（由第 1 条单独断言）。
4. 对 `bad` 镜像断言根目录项名称集合等于固定列表（28 项），且不含
   `rf-zlib-1blk-hardlink`；既有 `TestBadImage()` 继续验证损坏 leaf 的 EIO。

既有 `TestHardLinkAliases()` 仍在 `good` 上运行，双路径断言不变。

## 4. 验收

普通用户、非特权、库层验收：

```sh
export TMPDIR=/data/tmp CLAUDE_CODE_TMPDIR=/data/tmp
cmake -S . -B /data/tmp/apfs-good-nolink-build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build /data/tmp/apfs-good-nolink-build -j"$(nproc)"
ctest --test-dir /data/tmp/apfs-good-nolink-build -R \
  '^(btree-offset|extent-reader|reader-policy|zlib-decompress|reader-integration|foreground-option)$' \
  --output-on-failure
```

生成器单独冒烟（输出路径示例，可放任意可写目录）：

```sh
/data/tmp/apfs-good-nolink-build/apfs-fixture-gen good-nolink \
  /data/tmp/apfs-fixtures/good-nolink.img
```

必须看到：

- 6 个库层测试全部通过，`reader-integration` 无新增 skip。
- `good-nolink` 根目录没有 `rf-zlib-1blk-hardlink`，ino 60 `nlink=1`。
- `good` 仍有两个名称指向 ino 60，`nlink=2`。
- `good-nolink` 其余对象与 `good` 的 inode、xattr、文件字节一致。
- `bad` 根目录项集合与固定列表一致，损坏 leaf 断言继续通过。

`reader-fuse` 与 `lookup-generation` 会触发 sudo / FUSE，本 PR 不运行。

## 5. 部署与发布条件

- 本 PR 仅含测试与文档，合入后不改变生产 reader、manifest、allowlist 或
  FUSE 行为，不涉及部署。
- 本 PR 不生成真实 M0、不读取源盘或生产挂载；`good-nolink` 只是为 owner
  后续的合成 M0 sealed / blocking 验收提供镜像入口，不能据此声明该验收已完成。
- 合入条件：独立 review 通过；上述 6 个库层测试通过；无新增 skip；CLI 帮助
  与实际模式一致。
- 回滚只需回退提交，不涉及二进制、配置或数据。

## 6. 未覆盖边界

- 未运行 FUSE、sudo、loop/dm、服务、tracefs、SMART、真实源盘或生产挂载；
  未读取 `/data/backup`。
- 未修改 planner、`REVIEWED_READERS`、allowlist 或 raid-image-backup 仓库；
  未验证端到端 sealed / blocking。
- 新镜像只表达静态“单路径、`nlink=1`”布局，不验证链接创建/删除、跨目录
  硬链接、超过两条链接或与 snapshot/clone 的组合。
- 不对整幅镜像做字节级 golden：mkapfs 元数据可能随版本变化；一致性由
  reader 层逐对象比较保证。
- 未覆盖超大文件、4 GiB 边界或并发读取。
