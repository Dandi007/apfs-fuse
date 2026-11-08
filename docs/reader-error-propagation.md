# APFS FUSE Reader：错误传播、Extent 边界与 Backup View

状态：实现稿，供 review；对应分支基于生产 commit `5fc601c`，未修改任何生产挂载或原盘。本文区分已验证行为、合成测试结果和仍未验证的现场结论。当前修订对应 review r1 的 P1/P2 处置与 T1/T2 合成镜像测试。

## 1. 背景

生产 reader 为 `5fc601c`，它是仓库 `66b86bd` 的后代，包含此前的 64 KiB BTree offset 与 lookup generation 修复。本次分支从 `5fc601c` 切出，避免把已有生产修复回退掉。

迁移方案（design r4 §2、§8）要求 reader 在备份场景中满足两类约束：

1. 任何底层读取失败、树节点失败或元数据矛盾，都不能被吞成“文件不存在”或零填充；否则备份会把不可读对象误记成成功。
2. 压缩文件的静态元数据隐藏只能通过显式 backup-view 选项启用，默认关闭；隐藏不得依赖先前的解压成功，也不得隐藏真正的用户 resource fork。

本 PR 实现这两类约束的最小集合，并附带不需要真实 APFS 镜像的合成故障测试。

## 2. 已确认需求

来自 design r4 §2、§8 和已有讨论：

- `apfs_read` / `ReadFile` / `GetAttribute` 必须传递底层失败；`getattr`、`lookup`、xattr 区分“确实不存在”和 I/O/元数据错误。
- `getxattr` 在小 buffer 时返回 `ERANGE`；超过 FUSE 接口上限的用户属性明确失败，不返回截短值。
- Unicode hash 未命中或无法可靠计算时，允许按目录原始名字字节做精确回退，以支持 `readdir` 得到的路径；I/O 失败不得进入回退并当成 not found。
- extent 边界先检查再做无符号减法；只把显式 `phys_block == 0` 的 extent 当作合法 hole。缺失 extent record 属于树损坏，必须报错，不得补零；覆盖 EOF、预分配/稀疏尾部、短读。
- 透明压缩的属性隐藏必须是静态分类，默认关闭；满足有效 `UF_COMPRESSED`、有效 decmpfs header、受支持算法、RF 型算法载体存在时，才隐藏 decmpfs；RF 型再隐藏载体。真正用户 RF 不隐藏。分类无效、未知算法、inline 长度矛盾、超过配置上限或缺载体时，backup view 的 list/getxattr 返回 `EIO`。

## 3. 非目标

- 不宣称已解决生产上的 3 条 lookup `ENOENT` 和 2 条压缩文件 `EIO`。本 PR 提供定位与读取机制，现场 5 个异常仍需在 C 阶段逐个真实读通或由用户明确放弃。
- 不替换 NAS 挂载，不改生产 binary，不重挂加密卷，不访问云数据。
- 不实现 manifest、restic 编排、xattr sidecar 或格式化；这些属于备份工具与 D/E/F 阶段。
- 不承诺大小写或 Unicode 规范化别名语义；精确回退只匹配原始字节。
- 不采用未经 APFS 兼容验证的 Unicode 码点表或恒等映射升级。

## 4. 设计

### 4.1 三态结果与树错误

新增 `IoStatus { Ok, NotFound, IoError }`。`BTree::Lookup` 增加可选的 `io_error` 出参：键不存在时返回 `false` 且不置位；根节点缺失、节点加载失败、节点 value 长度非法时置位。`BTreeIterator` 记录节点加载失败，正常到达树尾不置位。

`ApfsDir` 的 `GetInode`、`ListDirectory`、`LookupName`、`ReadFile`、`ListAttributes`、`GetAttribute`、`GetAttributeInfo` 保留原有 bool 返回值，并增加可选 `IoStatus*` 出参。现有调用者（dump 工具、Decmpfs）无需修改即可编译；FUSE 层使用三态结果决定 `ENOENT`、`ENODATA` 还是 `EIO`。

同时把 inode/drec/xattr 的 xfield 解析改为显式边界检查。原先的 `assert`（Debug 下会 abort）改为返回 `IoError`；未知 xfield 仍只告警并跳过。

### 4.2 Extent 读取

`ReadFile` 的循环抽到 `ExtentSource` 接口和 `ReadFileInternal`，`ApfsDir` 用 file-system B+tree 或 sealed-volume fext tree 实现该接口。核心规则：

- 先检查 `offs + size` 溢出、extent `logical + length` 溢出、`phys_block + block_index` / `+ block_count` 溢出。
- 查找使用“最后一个起点不大于 offs 的 extent”。若返回 extent 起点在 offs 之后，说明覆盖该位置的 record 缺失，直接 `IoError`，不做无符号减法，也不补零。
- 只把显式 `phys_block == 0` 的 extent 当作合法 hole，并按其 `length` 填零。这与 Apple APFS reference 和 `apfsck` 的处理一致：连续 extent 由 record 显式描述，缺失 record 不是稀疏。
- 查找返回 not found、extent 树查找失败、节点加载失败、设备读取失败或短读一律返回 `IoError`。最后一个 extent 之后仍未满足请求时 fail-closed 返回 `IoError`，直到有可信 fixture 证明 macOS 会写出尾部缺 record 的布局。
- `file_size` 用于 EOF clamp：越过 EOF 的读取返回 0 字节，不访问 extent；预分配尾部不会越界读取。
- 不再使用 `sparse_bytes`、`ds_alloced_size` 或 `NextExtentStart` 推断 hole。`sparse_bytes > 0` 不改变缺失 record 的错误语义。
- FUSE 层只把 inode 的 `ds_size` 作为 EOF。

### 4.3 Unicode 精确回退

`LookupName` 在 hashed 卷上先按现有 Unicode hash 查找。只有“查找未命中且没有树错误”时才回退：遍历同一目录的 drec，按 `name_len`（含结尾 NUL）和原始字节做精确比较。回退命中后使用该目录项的 file id、hash、flags 等。

回退不发生在以下情况：

- `BTree::Lookup` 报告树/设备错误；此时直接 `IoError`。
- 目录遍历中途出现树错误；`ListDirectory` 返回 `IoError`，不会返回 not found。
- 大小写不同或 NFC/NFD 不同；这些不是原始字节相等。

### 4.4 xattr 语义

`GetAttributeInfo` 只解析 xattr 元数据，返回 value 的逻辑长度，不读取流式 value。因此 FUSE 的 size 查询和超限检查不会为了拿长度而读入整个大 resource fork。

`GetAttribute` 对流式 xattr 检查 `logical_size <= alloced_size`，按 `logical_size` 分配和读取，并把 `logical_size` 作为 EOF 传给 extent 读取；读取失败返回 `IoError`。嵌入式 xattr 检查 `xdata_len` 不越过 value。流式分配捕获 `bad_alloc` / `length_error`，作为 `IoError` 返回而不是崩溃。

FUSE 层：

| 输入 | 行为 |
|---|---|
| `getxattr(size=0)`，值 ≤ 64 KiB | 返回真实长度 |
| `getxattr(size` 小于值`)` | `ERANGE` |
| 值大于 64 KiB | `EIO`，不截短、不返回 clamp 后的长度 |
| 属性不存在 | `ENODATA` |
| 树/设备/元数据错误 | `EIO` |
| `listxattr(size` 小于结果`)` | `ERANGE` |
| `listxattr` 读取失败 | `EIO` |

64 KiB 是 Linux FUSE 单个 xattr value 的接口上限。正好 64 KiB 的用户属性可以合法返回；超过时无法无损通过该接口，必须由备份工具走 sidecar/原生 reader 路线或明确放弃。

### 4.5 Backup View

新增挂载选项 `backup_view=0|1`，默认 `0`。只有显式 `backup_view=1` 才改变 xattr 视图；文件内容读取、getattr 和默认挂载语义不受隐藏规则影响。

静态分类 `CompressionMeta → CompressionClass`：

| 条件 | 分类 | 隐藏行为 |
|---|---|---|
| 无 `UF_COMPRESSED` | `None` | 不隐藏 |
| decmpfs 读取 I/O 失败 | `IoError` | list/getxattr `EIO` |
| 无 decmpfs | `MissingHeader` | `EIO` |
| header 短、magic 错误 | `InvalidHeader` | `EIO` |
| inline header 无 payload | `InvalidHeader` | `EIO` |
| inode 未压缩大小与 header 不一致 | `InvalidHeader` | `EIO` |
| 压缩后大小超过 `max_decomp_size` | `TooLarge` | `EIO` |
| 算法不受支持 | `UnsupportedAlgorithm` | `EIO` |
| RF 型算法且 RF 查找 I/O 失败 | `IoError` | `EIO` |
| RF 型算法且 RF 缺失 | `MissingCarrier` | `EIO` |
| inline 算法 | `InlineAttr` | 隐藏 decmpfs，保留 RF |
| RF 型算法且 RF 存在 | `ResourceFork` | 隐藏 decmpfs 和 RF |

分类只读取 decmpfs header 和 RF 的存在性，不解压文件。inline 算法要求 decmpfs 属性长度大于 `CompressionHeader`；若 inode 带 `INODE_HAS_UNCOMPRESSED_SIZE`，还要求它与 header 声明一致。新增挂载选项 `max_decomp_size=N`（字节，`0` 表示不限制）把 header 声明的解压大小纳入 RSS 门槛，默认不改变现有行为。

对隐藏属性的直接 `getxattr` 返回该视图的缺失语义 `ENODATA`；`listxattr` 从结果中移除相应名称。真正用户 RF（非压缩文件、或 inline 算法文件的 RF）始终保留。

默认视图不启用隐藏，行为与现有 NAS 挂载一致。解压元数据矛盾不再让默认视图的 `getattr` 返回 `EIO`：文件类型、mode、mtime 和可推导的大小仍可读，manifest 仍能看到对象；读取内容和 backup-view 的 xattr 操作才报错。`-l` 的 lax 行为保留为显式诊断开关，不用于部署。

### 4.6 FUSE 错误映射

| 场景 | 修改前 | 修改后 |
|---|---|---|
| inode 不存在 | `ENOENT` | `ENOENT` |
| inode 树/设备错误 | `ENOENT` | `EIO` |
| lookup hash 未命中 | `ENOENT` | 精确回退后再 `ENOENT` |
| lookup 树/设备错误 | `ENOENT` | `EIO` |
| getxattr 不存在 | `ENODATA` | `ENODATA` |
| getxattr 读取错误 | `ENODATA` | `EIO` |
| getxattr 小 buffer | 截短 | `ERANGE` |
| getxattr 超过 64 KiB | 截短/clamp | `EIO` |
| read extent/设备错误 | 零填充 | `EIO` |
| read 越过 EOF | 整段回复 | 0 字节或短读 |
| backup view 分类错误 | 照常列出 | `EIO` |

## 5. 测试与验收

### 5.1 合成故障测试

测试不读取真实源盘，也不依赖生产挂载：

- `extent-reader-test`：用 `FakeSource` 注入场景，覆盖连续/非对齐读取、显式 `phys_block=0` hole、缺失 record 的 leading/trailing/gap（均 `IoError` 且不零填充）、lookup 失败不得零填充、设备读取失败/短读、零长度 extent、extent 起点在 offs 之后、`offs+size` 与 `logical+length` 溢出、EOF clamp、跨块读取的 crypto id。
- `reader-policy-test`：覆盖 `getxattr` 的 size/ERANGE/64 KiB 边界、原始字节精确匹配（大小写、NFC/NFD、U+1F9E8）、压缩分类全部状态（含 `InvalidHeader`、`TooLarge`）、decmpfs header 解析。
- `btree-offset-test`：保留原有 8 种节点布局检查，并新增“未初始化树查找必须报告 I/O error”。
- `reader-integration-test`（T1）：用 mkapfs 生成 128 MiB 合法容器（兼容 apfsprogs 0.2.1 与 Ubuntu 24.04 的 2023 快照），重写 file-system tree，直接经 `ApfsContainer` / `ApfsVolume` / `ApfsDir` 读取。覆盖：
  - 错 hash 的 U+1F9E8 文件名经原始字节回退命中；大小写和 NFC/NFD 变体保持 `NotFound`；缺失名字是 `NotFound` 而不是 `IoError`。
  - 坏节点：`GetInode`、`LookupName`、`ListDirectory`、`ListAttributes`、`ReadFile` 返回 `IoError`，进程不崩溃。
  - 显式 hole 返回零，缺失 record 的 gap 返回 `IoError`，越界设备读取返回 `IoError`，EOF 读取不触碰 buffer。
  - 嵌入式 xattr、65536 字节流式 xattr 完整返回、65537 字节经 `GetAttributeInfo` 得到长度并在读取前被判为超限。
  - inline / resource-fork / 缺载体 / 未知算法 / 未压缩但带用户 RF / inline 带用户 RF / 无 payload / inode 与 header 大小不一致 / 解压上限的分类结果，以及真正的用户 RF 不被隐藏。
  - 10 万条目目录的回退未命中耗时约 67 ms，作为 Unicode 回退成本证据。
- `reader-fuse-test`（T2）：挂载同一 fixture，验证默认视图与 `backup_view=1` 的 listxattr 差集、用户 RF 保留、65537 字节 xattr 的 `EIO`、小 buffer 的 `ERANGE`、缺失名字的 `ENOENT`、坏节点的 `EIO`、缺失 extent record 的读 `EIO`，以及默认视图下压缩元数据矛盾文件的 stat 仍成功。
- `lookup-generation-test`：需要 `mkapfs`、`strace` 和免密 sudo；用 apfsprogs 0.2.1 在合成镜像上实际挂载并通过，确认 lookup generation 仍为 0、mount/lookup 未被本次改动破坏。该测试在没有依赖时按设计 skip。

T1/T2 依赖 `mkapfs`；CI 通过 `apfsprogs` 安装并设置 `APFS_FIXTURE_REQUIRED=1`，缺少依赖时测试失败而不是静默跳过。FUSE 挂载在不允许普通用户挂载的容器里会尝试免密 sudo，仍不可用则跳过。

执行：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build -j
MKAPFS=/path/to/mkapfs ctest --test-dir build --output-on-failure
```

本次 Debug 结果：`btree-offset`、`extent-reader`、`reader-policy`、`reader-integration`、`reader-fuse`、`lookup-generation` 全部通过。

### 5.2 未覆盖与现场门槛

- T1/T2 使用合成镜像，能覆盖记录的边界和错误路径，但不能证明生产卷上的具体损坏形态；生产上的 3 条 `ENOENT` 和 2 条 `EIO` 仍需在 C 阶段逐个真实读通或由用户明确放弃。
- sealed volume 的 fext 路径已编译但未用真实镜像测试。
- macOS xattr 分支未在本次 Linux 环境构建。
- 真实设备在 `ReadBlocks` 返回短读、热插拔或 I/O 挂起时的行为未在合成测试中模拟。

C 阶段验收仍需在只读生产源上逐个对象真实读通，并用独立 reader/Mac 对照；任何一个未解释异常都阻断该批备份。

## 6. 部署与回滚

- 从本分支构建到新路径，不覆盖生产 `/opt` binary；生产 NAS 挂载保持原状。
- backup view 只用于同一只读设备上的独立只读备份实例。启用前按 D 前检查项验证双实例共存、密码渠道、只读性和资源占用；不重挂或替换 NAS。
- 备份实例必须使用 `-d 1` 前台运行，将 stderr 交由 systemd journal 收集；默认 daemon 模式会将 stderr 重定向到 /dev/null，无法保留 Unicode fallback 和压缩告警。T2 验证前台精确名字回退日志。备份实例使用 `-o backup_view=1`，并按可用内存设置 `-o max_decomp_size=N`；manifest 记录 reader binary SHA、挂载选项（含上限）、卷 UUID、分类/隐藏规则版本和实例身份。manifest 与 restic 必须使用同一实例和规则版本。
- 回滚：停止备份任务并卸载独立实例，回到原 reader/原挂载；不删除源、不删除云对象、不改 manifest 证据。
- 若 backup view 分类返回 `EIO`，备份工具必须把该对象列入例外并阻断该批封存，不能用 `-l` 或过滤规则绕过。

## 7. 发布条件

1. 本 PR 的合成测试全部通过，CI build 通过。
2. Opus review 完成，关键意见已处置。
3. C 阶段在真实只读源上确认：过滤后的 5 个已知异常逐个真实读通或由用户明确放弃；未解释读错为 0。
4. 独立 reader/Mac 对照样本通过；reader SHA、挂载参数、规则版本进入 manifest。
5. 备份编排与 manifest/restic 使用同一 reader 实例和规则版本；`backup_view` 的使用范围获得部署授权。

满足以上条件后，reader 才可用于真实源备份；本 PR 本身不构成生产部署或异常闭环。
