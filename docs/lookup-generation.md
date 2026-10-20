# lookup 未初始化 generation 导致 bind mount 永久 EIO

## 需求与确认

2026-10-15 和 2026-10-20，NAS 容器两次无法读取 RAID 卷。宿主挂载点可读，容器内的 bind mount 返回 EIO，mountinfo 中 bind 源显示为 `/root//deleted`。部署侧已改为 bind FUSE 挂载根（edge-gateway#65）。用户要求在驱动层同时修复 `apfs_lookup`，并开 PR。仍禁止写盘、修复或取消加密。

## 根因

`apfs_lookup` 没有清零 `fuse_entry_param`，`generation` 字段是栈上残留。entry_timeout 为 86400s，内核每天 revalidate 一次。如果 generation 与已有 inode 不同，`fuse_stale_inode()` 判定 nodeid 被复用：内核把旧 inode 标记为 bad，再换一个新 inode（FUSE 根 inode 除外）。宿主路径重新 lookup 后正常；持有旧 inode 的 bind mount 从此只能得到 EIO。

实测：用 94dec36 只读挂载未加密卷，清 dentry cache 后对 `root` 重复 lookup。第 1 次 generation=0，之后是 0x700a… 形式的栈指针值。

另外，`apfs_stat_internal` 失败时，旧代码仍以全零 attr（mode=0）回复 entry。

## 设计

- 回复前 `memset` 整个 `fuse_entry_param`，generation 恒为 0。APFS 不复用 inode 号，0 即稳定值。
- stat 失败时回复 EIO，不再回复无效 entry。
- `LookupName` 失败仍回 ENOENT。区分 I/O 错误与名字不存在需要改 ApfsDir 接口，不在本次范围。

只改 `apfsfuse/ApfsFuse.cpp` 一处，无新增运行时依赖。

## 验收

`tests/lookup-generation.sh`（CTest `lookup-generation`）流程：用 `mkapfs` 生成 1 GiB 稀疏镜像（noble 版 mkapfs 不支持过小容器）并以 apfs-fuse 只读挂载；每次 stat `root` 前清 dentry cache，共 4 次；用 strace 截取 `/dev/fuse` 上的 `fuse_entry_out`，断言至少 3 次 lookup 且 generation 全为 0。缺少 mkapfs、strace 或无密码 sudo 时返回 77（跳过）；CI 设置 `LOOKUP_TEST_REQUIRED=1`，缺依赖直接失败。

- 修复版 Debug 与 Release 构建，两个 CTest 均通过。
- 对 94dec36 运行同一脚本失败：generation 从第 2 次 lookup 起为非零残留值。
- 实盘：修复版只读挂载未加密卷，根目录列表与现网挂载一致；同一文件前 8 MiB 的 SHA-256 一致；不存在的路径仍返回 ENOENT。块设备全程 RO=1。

## 部署与发布条件

在 64k 修复（#1）之后合并。CI 通过即为 ready，不自动合并。

部署：安装到 `/opt/apfs-fuse/<commit>/`，不覆盖现有版本。在维护窗口卸载两个现网挂载，用新二进制重挂：加密卷需交互输入密码，然后重建 NAS 容器。回滚：用旧版本路径重挂。磁盘无需回滚。
