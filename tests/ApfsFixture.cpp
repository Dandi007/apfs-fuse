#include "ApfsFixture.h"

#include "ApfsLib/Decmpfs.h"
#include "ApfsLib/DiskStruct.h"
#include "ApfsLib/ReaderPolicy.h"
#include "ApfsLib/Util.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
	const uint32_t BLOCK_SIZE = 4096;
	const uint64_t IMAGE_SIZE = 64ULL * 1024 * 1024;
	const uint32_t ROOT_PADDR = 0xAE;
	const uint64_t ROOT_OID = 0x403;
	const uint32_t FIRST_NODE_PADDR = 0x100;
	const uint32_t NODE_LIMIT_PADDR = 0x0F00;
	const uint32_t OMAP_NODE_PADDR = 0x0F00;
	// Non-root fs-tree nodes are addressed by a virtual oid, the same way real
	// APFS fs trees do it. The fixture's volume omap maps each oid to its
	// physical block.
	const uint64_t FS_NODE_OID_BASE = 0x800000;

	const uint32_t DATA_22_A = 0x1000;
	const uint32_t DATA_22_B = 0x1004;
	const uint32_t DATA_23_A = 0x1010;
	const uint32_t DATA_23_B = 0x1014;
	const uint32_t DATA_9000 = 0x2200;
	const uint32_t DATA_XATTR_64K = 0x2000;
	const uint32_t DATA_XATTR_64K1 = 0x2100;

	struct BlockRef
	{
		uint64_t oid;
		uint32_t paddr;
		std::vector<uint8_t> first_key;
		std::vector<uint8_t> last_key;
	};

	struct KeyVal
	{
		std::vector<uint8_t> key;
		std::vector<uint8_t> val;
	};

	uint16_t ReadLE16(const uint8_t *p)
	{
		return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
	}

	uint32_t ReadLE32(const uint8_t *p)
	{
		return static_cast<uint32_t>(p[0]) |
			(static_cast<uint32_t>(p[1]) << 8) |
			(static_cast<uint32_t>(p[2]) << 16) |
			(static_cast<uint32_t>(p[3]) << 24);
	}

	uint64_t ReadLE64(const uint8_t *p)
	{
		uint64_t value = 0;
		for (int k = 7; k >= 0; k--)
			value = (value << 8) | p[k];
		return value;
	}

	void WriteLE16(std::vector<uint8_t> &buf, size_t off, uint16_t value)
	{
		buf[off] = static_cast<uint8_t>(value);
		buf[off + 1] = static_cast<uint8_t>(value >> 8);
	}

	void WriteLE32(std::vector<uint8_t> &buf, size_t off, uint32_t value)
	{
		for (int k = 0; k < 4; k++)
			buf[off + k] = static_cast<uint8_t>(value >> (8 * k));
	}

	void WriteLE64(std::vector<uint8_t> &buf, size_t off, uint64_t value)
	{
		for (int k = 0; k < 8; k++)
			buf[off + k] = static_cast<uint8_t>(value >> (8 * k));
	}

	std::vector<uint8_t> MakeInodeKey(uint64_t ino)
	{
		std::vector<uint8_t> key(8);
		WriteLE64(key, 0, APFS_TYPE_ID(APFS_TYPE_INODE, ino));
		return key;
	}

	std::vector<uint8_t> MakeDrecVal(uint64_t file_id, uint16_t flags)
	{
		std::vector<uint8_t> val(18, 0);
		WriteLE64(val, 0, file_id);
		WriteLE64(val, 8, 0);
		WriteLE16(val, 16, flags);
		return val;
	}

	std::vector<uint8_t> MakeDrecKey(uint64_t parent, const std::string &name, bool wrong_hash)
	{
		const size_t name_len = name.size() + 1;
		std::vector<uint8_t> key(12 + name_len, 0);
		WriteLE64(key, 0, APFS_TYPE_ID(APFS_TYPE_DIR_REC, parent));

		uint32_t hash = HashFilename(reinterpret_cast<const uint8_t *>(name.c_str()),
			static_cast<uint16_t>(name_len), true);
		if (wrong_hash)
			hash ^= 0x400;
		hash = (hash & J_DREC_HASH_MASK) | static_cast<uint32_t>(name_len & J_DREC_LEN_MASK);
		WriteLE32(key, 8, hash);
		std::memcpy(key.data() + 12, name.c_str(), name_len);
		return key;
	}

	std::vector<uint8_t> MakeXattrKey(uint64_t ino, const std::string &name)
	{
		const size_t name_len = name.size() + 1;
		std::vector<uint8_t> key(10 + name_len, 0);
		WriteLE64(key, 0, APFS_TYPE_ID(APFS_TYPE_XATTR, ino));
		WriteLE16(key, 8, static_cast<uint16_t>(name_len));
		std::memcpy(key.data() + 10, name.c_str(), name_len);
		return key;
	}

	std::vector<uint8_t> MakeEmbeddedXattr(const std::vector<uint8_t> &value)
	{
		std::vector<uint8_t> val(4 + value.size(), 0);
		WriteLE16(val, 0, XATTR_DATA_EMBEDDED);
		WriteLE16(val, 2, static_cast<uint16_t>(value.size()));
		std::memcpy(val.data() + 4, value.data(), value.size());
		return val;
	}

	std::vector<uint8_t> MakeStreamXattr(uint64_t obj_id, uint64_t size, uint64_t alloced)
	{
		std::vector<uint8_t> val(4 + sizeof(j_xattr_dstream_t), 0);
		WriteLE16(val, 0, XATTR_DATA_STREAM);
		WriteLE16(val, 2, sizeof(j_xattr_dstream_t));
		WriteLE64(val, 4, obj_id);
		WriteLE64(val, 12, size);
		WriteLE64(val, 20, alloced);
		WriteLE64(val, 28, 0);
		WriteLE64(val, 36, 0);
		WriteLE64(val, 44, 0);
		return val;
	}

	std::vector<uint8_t> MakeExtentKey(uint64_t obj_id, uint64_t logical)
	{
		std::vector<uint8_t> key(16);
		WriteLE64(key, 0, APFS_TYPE_ID(APFS_TYPE_FILE_EXTENT, obj_id));
		WriteLE64(key, 8, logical);
		return key;
	}

	std::vector<uint8_t> MakeExtentVal(uint64_t length, uint64_t phys, uint64_t crypto)
	{
		std::vector<uint8_t> val(24);
		WriteLE64(val, 0, length & J_FILE_EXTENT_LEN_MASK);
		WriteLE64(val, 8, phys);
		WriteLE64(val, 16, crypto);
		return val;
	}

	void AddXField(std::vector<uint8_t> &table, std::vector<uint8_t> &data,
		uint8_t type, const std::vector<uint8_t> &value)
	{
		const size_t off = table.size();
		table.resize(off + sizeof(x_field_t));
		table[off] = type;
		table[off + 1] = 0;
		WriteLE16(table, off + 2, static_cast<uint16_t>(value.size()));
		data.insert(data.end(), value.begin(), value.end());
		while (data.size() % 8 != 0)
			data.push_back(0);
	}

	struct InodeSpec
	{
		uint64_t ino;
		uint64_t parent;
		uint64_t private_id;
		uint16_t mode;
		uint32_t bsd_flags;
		uint64_t internal_flags;
		uint64_t uncompressed_size;
		std::string name;
		uint64_t ds_size;
		uint64_t ds_alloced;
		uint64_t sparse_bytes;
	};

	std::vector<uint8_t> MakeInodeVal(const InodeSpec &spec)
	{
		std::vector<uint8_t> val(sizeof(j_inode_val_t), 0);
		j_inode_val_t *ino = reinterpret_cast<j_inode_val_t *>(val.data());

		ino->parent_id = spec.parent;
		ino->private_id = spec.private_id;
		ino->create_time = 0;
		ino->mod_time = 0;
		ino->change_time = 0;
		ino->access_time = 0;
		ino->internal_flags = spec.internal_flags;
		if ((spec.mode & MODE_S_IFMT) == MODE_S_IFDIR)
			ino->nchildren = 2;
		else
			ino->nlink = 1;
		ino->default_protection_class = 0;
		ino->write_generation_counter = 0;
		ino->bsd_flags = spec.bsd_flags;
		ino->owner = 1000;
		ino->group = 1000;
		ino->mode = spec.mode;
		ino->pad1 = 0;
		ino->uncompressed_size = spec.uncompressed_size;

		std::vector<uint8_t> table;
		std::vector<uint8_t> data;

		if (!spec.name.empty())
		{
			std::vector<uint8_t> name(spec.name.begin(), spec.name.end());
			name.push_back(0);
			AddXField(table, data, INO_EXT_TYPE_NAME, name);
		}

		if ((spec.mode & MODE_S_IFMT) == MODE_S_IFREG)
		{
			std::vector<uint8_t> ds(sizeof(j_dstream_t), 0);
			WriteLE64(ds, 0, spec.ds_size);
			WriteLE64(ds, 8, spec.ds_alloced);
			AddXField(table, data, INO_EXT_TYPE_DSTREAM, ds);
		}

		if (spec.sparse_bytes != 0)
		{
			std::vector<uint8_t> sparse(8, 0);
			WriteLE64(sparse, 0, spec.sparse_bytes);
			AddXField(table, data, INO_EXT_TYPE_SPARSE_BYTES, sparse);
		}

		if (!table.empty())
		{
			const size_t xf_off = sizeof(j_inode_val_t);
			val.resize(xf_off + sizeof(xf_blob_t) + table.size() + data.size(), 0);
			xf_blob_t *blob = reinterpret_cast<xf_blob_t *>(val.data() + xf_off);
			blob->xf_num_exts = static_cast<uint16_t>(table.size() / sizeof(x_field_t));
			blob->xf_used_data = static_cast<uint16_t>(data.size());
			std::memcpy(val.data() + xf_off + sizeof(xf_blob_t), table.data(), table.size());
			std::memcpy(val.data() + xf_off + sizeof(xf_blob_t) + table.size(),
				data.data(), data.size());
		}

		return val;
	}

	std::vector<uint8_t> MakeDecmpfs(uint32_t algo, uint64_t size, bool with_payload)
	{
		std::vector<uint8_t> data(sizeof(CompressionHeader), 0);
		WriteLE32(data, 0, DECMPFS_MAGIC);
		WriteLE32(data, 4, algo);
		WriteLE64(data, 8, size);
		if (with_payload)
		{
			data.push_back(0xCC);
			for (size_t k = 0; k < size; k++)
				data.push_back(static_cast<uint8_t>('A' + (k % 26)));
		}
		return data;
	}

	bool RawNameLess(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
	{
		const size_t n = std::min(alen, blen);
		const int cmp = std::memcmp(a, b, n);
		if (cmp != 0)
			return cmp < 0;
		return alen < blen;
	}

	bool KeyLess(const KeyVal &a, const KeyVal &b)
	{
		const uint64_t ka = ReadLE64(a.key.data());
		const uint64_t kb = ReadLE64(b.key.data());
		const uint64_t ra = (ka << 4) | (ka >> 60);
		const uint64_t rb = (kb << 4) | (kb >> 60);
		if (ra != rb)
			return ra < rb;

		const uint64_t type = ka >> OBJ_TYPE_SHIFT;
		if (type == APFS_TYPE_DIR_REC)
		{
			const uint32_t ha = ReadLE32(a.key.data() + 8) & J_DREC_HASH_MASK;
			const uint32_t hb = ReadLE32(b.key.data() + 8) & J_DREC_HASH_MASK;
			if (ha != hb)
				return ha < hb;
			const size_t la = ReadLE32(a.key.data() + 8) & J_DREC_LEN_MASK;
			const size_t lb = ReadLE32(b.key.data() + 8) & J_DREC_LEN_MASK;
			return RawNameLess(a.key.data() + 12, la, b.key.data() + 12, lb);
		}
		if (type == APFS_TYPE_FILE_EXTENT)
			return ReadLE64(a.key.data() + 8) < ReadLE64(b.key.data() + 8);
		if (type == APFS_TYPE_XATTR)
		{
			const size_t la = ReadLE16(a.key.data() + 8);
			const size_t lb = ReadLE16(b.key.data() + 8);
			return RawNameLess(a.key.data() + 10, la, b.key.data() + 10, lb);
		}
		return a.key < b.key;
	}

	size_t NodeSize(size_t entries, size_t key_bytes, size_t val_bytes, bool reserve_info)
	{
		size_t size = offsetof(btree_node_phys_t, btn_data);
		size += entries * sizeof(kvloc_t);
		size += key_bytes + val_bytes;
		if (reserve_info)
			size += sizeof(btree_info_t);
		return size;
	}

	size_t GroupSize(const std::vector<KeyVal> &group, bool reserve_info)
	{
		size_t keys = 0;
		size_t vals = 0;
		for (size_t k = 0; k < group.size(); k++)
		{
			keys += group[k].key.size();
			vals += group[k].val.size();
		}
		return NodeSize(group.size(), keys, vals, reserve_info);
	}

	void SetChecksum(std::vector<uint8_t> &block)
	{
		std::memset(block.data(), 0, MAX_CKSUM_SIZE);

		std::vector<uint32_t> words(BLOCK_SIZE / sizeof(uint32_t));
		std::memcpy(words.data(), block.data(), BLOCK_SIZE);

		const uint64_t rest = Fletcher64(words.data() + 2, words.size() - 2, 0);
		const uint32_t cl = static_cast<uint32_t>(rest & 0xFFFFFFFFU);
		const uint32_t ch = static_cast<uint32_t>(rest >> 32);
		uint64_t sum = static_cast<uint64_t>(cl) + ch;
		sum %= 0xFFFFFFFFULL;
		const uint32_t s1 = static_cast<uint32_t>((0xFFFFFFFFULL - sum) % 0xFFFFFFFFULL);
		const uint32_t s2 = static_cast<uint32_t>(ch % 0xFFFFFFFFULL);

		WriteLE64(block, 0, (static_cast<uint64_t>(s2) << 32) | s1);
	}

	bool MakeNode(const std::vector<KeyVal> &entries, uint16_t level, bool leaf, bool root,
		uint64_t oid, uint64_t total_keys, uint64_t total_nodes,
		uint32_t longest_key, uint32_t longest_val,
		std::vector<uint8_t> &block)
	{
		if (entries.empty())
			return false;

		const size_t table_len = entries.size() * sizeof(kvloc_t);
		const size_t keys_start = offsetof(btree_node_phys_t, btn_data) + table_len;
		// Root nodes reserve the trailing btree_info_t; value offsets are
		// measured from the end of the value area, which is the start of that
		// info block for a root and the end of the block otherwise.
		const size_t vals_start = root ? BLOCK_SIZE - sizeof(btree_info_t) : BLOCK_SIZE;

		block.assign(BLOCK_SIZE, 0);

		size_t key_cursor = keys_start;
		size_t val_cursor = vals_start;

		for (size_t k = 0; k < entries.size(); k++)
		{
			const size_t key_off = key_cursor - keys_start;
			const size_t new_val_cursor = val_cursor - entries[k].val.size();

			if (key_cursor + entries[k].key.size() > new_val_cursor)
				return false;

			std::memcpy(block.data() + key_cursor, entries[k].key.data(), entries[k].key.size());
			key_cursor += entries[k].key.size();

			val_cursor = new_val_cursor;
			std::memcpy(block.data() + val_cursor, entries[k].val.data(), entries[k].val.size());

			kvloc_t *loc = reinterpret_cast<kvloc_t *>(block.data() +
				offsetof(btree_node_phys_t, btn_data) + k * sizeof(kvloc_t));
			loc->k.off = static_cast<uint16_t>(key_off);
			loc->k.len = static_cast<uint16_t>(entries[k].key.size());
			loc->v.off = static_cast<uint16_t>(vals_start - val_cursor);
			loc->v.len = static_cast<uint16_t>(entries[k].val.size());
		}

		obj_phys_t *obj = reinterpret_cast<obj_phys_t *>(block.data());
		obj->o_oid = oid;
		obj->o_xid = 1;
		obj->o_type = root ? OBJECT_TYPE_BTREE : OBJECT_TYPE_BTREE_NODE;
		obj->o_subtype = root ? OBJECT_TYPE_FSTREE : 0;

		btree_node_phys_t *node = reinterpret_cast<btree_node_phys_t *>(block.data());
		node->btn_flags = (root ? BTNODE_ROOT : 0) | (leaf ? BTNODE_LEAF : 0);
		node->btn_level = level;
		node->btn_nkeys = static_cast<uint32_t>(entries.size());
		node->btn_table_space.off = 0;
		node->btn_table_space.len = static_cast<uint16_t>(table_len);
		node->btn_free_space.off = 0;
		node->btn_free_space.len = 0;
		node->btn_key_free_list.off = 0;
		node->btn_key_free_list.len = 0;
		node->btn_val_free_list.off = 0;
		node->btn_val_free_list.len = 0;

		if (root)
		{
			btree_info_t *info = reinterpret_cast<btree_info_t *>(block.data() +
				BLOCK_SIZE - sizeof(btree_info_t));
			info->bt_fixed.bt_flags = BTREE_KV_NONALIGNED;
			info->bt_fixed.bt_node_size = BLOCK_SIZE;
			info->bt_fixed.bt_key_size = 0;
			info->bt_fixed.bt_val_size = 0;
			info->bt_longest_key = longest_key;
			info->bt_longest_val = longest_val;
			info->bt_key_count = total_keys;
			info->bt_node_count = total_nodes;
		}

		SetChecksum(block);
		return true;
	}

	bool BuildLeafGroups(const std::vector<KeyVal> &entries,
		std::vector<std::vector<KeyVal>> &groups)
	{
		std::vector<KeyVal> group;
		for (size_t k = 0; k < entries.size(); k++)
		{
			group.push_back(entries[k]);
			if (GroupSize(group, true) > BLOCK_SIZE)
			{
				group.pop_back();
				if (group.empty())
					return false;
				groups.push_back(group);
				group.clear();
				group.push_back(entries[k]);
				if (GroupSize(group, true) > BLOCK_SIZE)
					return false;
			}
		}
		if (!group.empty())
			groups.push_back(group);
		return true;
	}

	uint32_t MaxKeySize(const std::vector<KeyVal> &entries)
	{
		uint32_t max_size = 0;
		for (size_t k = 0; k < entries.size(); k++)
			max_size = std::max<uint32_t>(max_size, entries[k].key.size());
		return max_size;
	}

	uint32_t MaxValSize(const std::vector<KeyVal> &entries)
	{
		uint32_t max_size = 0;
		for (size_t k = 0; k < entries.size(); k++)
			max_size = std::max<uint32_t>(max_size, entries[k].val.size());
		return max_size;
	}

	bool BuildTree(std::vector<KeyVal> entries, std::vector<uint8_t> &image,
		std::vector<BlockRef> &leaves, std::vector<BlockRef> &all_nodes, std::string &error)
	{
		std::sort(entries.begin(), entries.end(), KeyLess);

		const uint32_t longest_key = MaxKeySize(entries);
		const uint32_t longest_val = MaxValSize(entries);
		const uint64_t total_keys = entries.size();

		std::vector<std::vector<KeyVal>> leaf_groups;
		if (!BuildLeafGroups(entries, leaf_groups))
		{
			error = "entry does not fit in a leaf";
			return false;
		}

		uint32_t next_paddr = FIRST_NODE_PADDR;
		uint64_t node_count = 0;
		std::vector<BlockRef> refs;
		std::vector<BlockRef> built_nodes;

		for (size_t g = 0; g < leaf_groups.size(); g++)
		{
			if (next_paddr >= NODE_LIMIT_PADDR)
			{
				error = "tree needs too many nodes";
				return false;
			}
			const uint64_t oid = FS_NODE_OID_BASE + next_paddr;
			std::vector<uint8_t> block;
			if (!MakeNode(leaf_groups[g], 0, true, false, oid,
				total_keys, 0, longest_key, longest_val, block))
			{
				error = "failed to build leaf";
				return false;
			}
			std::memcpy(image.data() + static_cast<size_t>(next_paddr) * BLOCK_SIZE,
				block.data(), BLOCK_SIZE);
			BlockRef ref;
			ref.oid = oid;
			ref.paddr = next_paddr;
			ref.first_key = leaf_groups[g].front().key;
			ref.last_key = leaf_groups[g].back().key;
			refs.push_back(ref);
			leaves.push_back(ref);
			built_nodes.push_back(ref);
			next_paddr++;
			node_count++;
		}

		bool root_written = false;
		uint16_t level = 0;
		while (refs.size() > 1)
		{
			level++;
			std::vector<KeyVal> index_entries;
			for (size_t k = 0; k < refs.size(); k++)
			{
				KeyVal entry;
				entry.key = refs[k].first_key;
				entry.val.resize(8);
				WriteLE64(entry.val, 0, refs[k].oid);
				index_entries.push_back(entry);
			}

			std::vector<std::vector<KeyVal>> groups;
			if (!BuildLeafGroups(index_entries, groups))
			{
				error = "index entry does not fit";
				return false;
			}

			std::vector<BlockRef> next_refs;
			const bool final_level = (groups.size() == 1);
			for (size_t g = 0; g < groups.size(); g++)
			{
				BlockRef ref;
				ref.first_key = groups[g].front().key;
				ref.last_key = groups[g].back().key;

				std::vector<uint8_t> block;
				if (final_level)
				{
					// The last index node becomes the root, so its value
					// offsets are measured from the btree_info area.
					ref.oid = ROOT_OID;
					ref.paddr = ROOT_PADDR;
					if (!MakeNode(groups[g], level, false, true, ref.oid,
						total_keys, 0, longest_key, longest_val, block))
					{
						error = "failed to build root";
						return false;
					}
					std::memcpy(image.data() + static_cast<size_t>(ROOT_PADDR) * BLOCK_SIZE,
						block.data(), BLOCK_SIZE);
					root_written = true;
				}
				else
				{
					if (next_paddr >= NODE_LIMIT_PADDR)
					{
						error = "tree needs too many nodes";
						return false;
					}
					ref.oid = FS_NODE_OID_BASE + next_paddr;
					ref.paddr = next_paddr;
					if (!MakeNode(groups[g], level, false, false, ref.oid,
						total_keys, 0, longest_key, longest_val, block))
					{
						error = "failed to build index node";
						return false;
					}
					std::memcpy(image.data() + static_cast<size_t>(next_paddr) * BLOCK_SIZE,
						block.data(), BLOCK_SIZE);
					next_paddr++;
					node_count++;
				}
				next_refs.push_back(ref);
				built_nodes.push_back(ref);
			}
			refs.swap(next_refs);
		}

		if (refs.size() != 1)
		{
			error = "tree did not converge";
			return false;
		}

		if (!root_written)
		{
			if (level != 0)
			{
				error = "root level mismatch";
				return false;
			}
			// Everything fits in one leaf, which therefore is the root.
			std::vector<uint8_t> block;
			if (!MakeNode(leaf_groups[0], 0, true, true, ROOT_OID,
				total_keys, 0, longest_key, longest_val, block))
			{
				error = "failed to build single-leaf root";
				return false;
			}
			std::memcpy(image.data() + static_cast<size_t>(ROOT_PADDR) * BLOCK_SIZE,
				block.data(), BLOCK_SIZE);
			BlockRef ref;
			ref.oid = ROOT_OID;
			ref.paddr = ROOT_PADDR;
			ref.first_key = leaf_groups[0].front().key;
			ref.last_key = leaf_groups[0].back().key;
			refs[0] = ref;
			leaves.clear();
			leaves.push_back(ref);
			all_nodes.clear();
			all_nodes.push_back(ref);
			return true;
		}

		// Every node written above, including the promoted root, needs an
		// omap entry because fs-tree child pointers are virtual oids.
		all_nodes = built_nodes;
		return true;
	}

	// Builds the volume omap tree that maps each fs-tree node oid to its
	// physical block. Real APFS resolves fs-tree child pointers through this
	// map, so the synthetic nodes cannot simply point at each other's paddrs.
	bool WriteOmapTree(std::vector<uint8_t> &image, const std::vector<BlockRef> &nodes,
		uint64_t xid, uint32_t omap_paddr, std::string &error)
	{
		std::vector<KeyVal> entries;
		std::vector<uint64_t> seen;

		for (size_t k = 0; k < nodes.size(); k++)
		{
			bool duplicate = false;
			for (size_t n = 0; n < seen.size(); n++)
			{
				if (seen[n] == nodes[k].oid)
				{
					duplicate = true;
					break;
				}
			}
			if (duplicate)
				continue;
			seen.push_back(nodes[k].oid);

			KeyVal e;
			e.key.resize(sizeof(omap_key_t));
			WriteLE64(e.key, 0, nodes[k].oid);
			WriteLE64(e.key, 8, xid);

			e.val.resize(sizeof(omap_val_t));
			WriteLE32(e.val, 0, 0);
			WriteLE32(e.val, 4, BLOCK_SIZE);
			WriteLE64(e.val, 8, nodes[k].paddr);
			entries.push_back(e);
		}

		std::sort(entries.begin(), entries.end(),
			[](const KeyVal &a, const KeyVal &b)
			{
				return ReadLE64(a.key.data()) < ReadLE64(b.key.data());
			});

		if (entries.empty())
		{
			error = "empty omap";
			return false;
		}

		const uint32_t key_size = sizeof(omap_key_t);
		const uint32_t val_size = sizeof(omap_val_t);
		uint32_t next_paddr = OMAP_NODE_PADDR;

		struct OmapNode
		{
			std::vector<uint8_t> first_key;
			uint32_t paddr;
		};

		auto write_node = [&](const std::vector<KeyVal> &group, bool leaf, bool root,
			uint16_t level, uint32_t key_len, uint32_t value_len,
			uint32_t paddr) -> bool
		{
			const size_t table_len = group.size() * sizeof(kvoff_t);
			const size_t keys_start = offsetof(btree_node_phys_t, btn_data) + table_len;
			const size_t vals_start = root ? BLOCK_SIZE - sizeof(btree_info_t) : BLOCK_SIZE;

			std::vector<uint8_t> block(BLOCK_SIZE, 0);
			size_t key_cursor = keys_start;
			size_t val_cursor = vals_start;

			for (size_t k = 0; k < group.size(); k++)
			{
				const size_t val_pos = val_cursor - value_len;
				if (key_cursor + key_len > val_pos)
					return false;
				std::memcpy(block.data() + key_cursor, group[k].key.data(), key_len);
				std::memcpy(block.data() + val_pos, group[k].val.data(), value_len);

				kvoff_t *loc = reinterpret_cast<kvoff_t *>(block.data() +
					offsetof(btree_node_phys_t, btn_data) + k * sizeof(kvoff_t));
				loc->k = static_cast<uint16_t>(key_cursor - keys_start);
				loc->v = static_cast<uint16_t>(vals_start - val_pos);

				key_cursor += key_len;
				val_cursor = val_pos;
			}

			obj_phys_t *obj = reinterpret_cast<obj_phys_t *>(block.data());
			obj->o_oid = paddr;
			obj->o_xid = xid;
			obj->o_type = root ? OBJECT_TYPE_BTREE : OBJECT_TYPE_BTREE_NODE;
			obj->o_subtype = OBJECT_TYPE_OMAP;

			btree_node_phys_t *node = reinterpret_cast<btree_node_phys_t *>(block.data());
			node->btn_flags = BTNODE_FIXED_KV_SIZE | (root ? BTNODE_ROOT : 0) |
				(leaf ? BTNODE_LEAF : 0);
			node->btn_level = level;
			node->btn_nkeys = static_cast<uint32_t>(group.size());
			node->btn_table_space.off = 0;
			node->btn_table_space.len = static_cast<uint16_t>(table_len);

			if (root)
			{
				btree_info_t *info = reinterpret_cast<btree_info_t *>(block.data() +
					BLOCK_SIZE - sizeof(btree_info_t));
				info->bt_fixed.bt_flags = 0;
				info->bt_fixed.bt_node_size = BLOCK_SIZE;
				info->bt_fixed.bt_key_size = key_size;
				info->bt_fixed.bt_val_size = val_size;
				info->bt_longest_key = key_size;
				info->bt_longest_val = val_size;
				info->bt_key_count = entries.size();
				info->bt_node_count = 0;
			}

			SetChecksum(block);
			std::memcpy(image.data() + static_cast<size_t>(paddr) * BLOCK_SIZE,
				block.data(), BLOCK_SIZE);
			return true;
		};

		// Leaves.
		std::vector<OmapNode> refs;
		const size_t leaf_payload = BLOCK_SIZE - offsetof(btree_node_phys_t, btn_data);
		const size_t leaf_entry_size = sizeof(kvoff_t) + key_size + val_size;
		size_t leaf_capacity = leaf_payload / leaf_entry_size;
		if (leaf_capacity == 0)
		{
			error = "omap leaf too small";
			return false;
		}

		for (size_t begin = 0; begin < entries.size(); begin += leaf_capacity)
		{
			const size_t end = std::min(entries.size(), begin + leaf_capacity);
			const std::vector<KeyVal> group(entries.begin() + begin, entries.begin() + end);
			const uint32_t paddr = next_paddr++;
			if (!write_node(group, true, false, 0, key_size, val_size, paddr))
			{
				error = "failed to build omap leaf";
				return false;
			}
			OmapNode ref;
			ref.first_key = group.front().key;
			ref.paddr = paddr;
			refs.push_back(ref);
		}

		uint16_t level = 0;
		bool root_written = false;
		uint32_t root_paddr = 0;

		while (refs.size() > 1)
		{
			level++;
			std::vector<KeyVal> index_entries;
			for (size_t k = 0; k < refs.size(); k++)
			{
				KeyVal e;
				e.key = refs[k].first_key;
				e.val.resize(sizeof(uint64_t));
				WriteLE64(e.val, 0, refs[k].paddr);
				index_entries.push_back(e);
			}

			const size_t index_entry_size = sizeof(kvoff_t) + key_size + sizeof(uint64_t);
			size_t index_capacity = leaf_payload / index_entry_size;
			if (index_capacity == 0)
			{
				error = "omap index node too small";
				return false;
			}

			std::vector<OmapNode> next_refs;
			const bool final_level = (index_entries.size() <= index_capacity);
			for (size_t begin = 0; begin < index_entries.size(); begin += index_capacity)
			{
				const size_t end = std::min(index_entries.size(), begin + index_capacity);
				const std::vector<KeyVal> group(index_entries.begin() + begin,
					index_entries.begin() + end);
				const uint32_t paddr = next_paddr++;
				if (!write_node(group, false, final_level, level, key_size,
					sizeof(uint64_t), paddr))
				{
					error = "failed to build omap index node";
					return false;
				}
				OmapNode ref;
				ref.first_key = group.front().key;
				ref.paddr = paddr;
				next_refs.push_back(ref);
				if (final_level)
				{
					root_paddr = paddr;
					root_written = true;
				}
			}
			refs.swap(next_refs);
		}

		if (!root_written)
		{
			// One leaf is also the root; rebuild it at a fresh paddr so the
			// root semantics stay in one place.
			const std::vector<KeyVal> group(entries.begin(), entries.end());
			root_paddr = next_paddr++;
			if (!write_node(group, true, true, 0, key_size, val_size, root_paddr))
			{
				error = "failed to build omap root";
				return false;
			}
		}

		std::vector<uint8_t> omap_block(image.begin() + static_cast<size_t>(omap_paddr) * BLOCK_SIZE,
			image.begin() + static_cast<size_t>(omap_paddr + 1) * BLOCK_SIZE);
		omap_phys_t *omap = reinterpret_cast<omap_phys_t *>(omap_block.data());
		omap->om_tree_oid = root_paddr;
		SetChecksum(omap_block);
		std::memcpy(image.data() + static_cast<size_t>(omap_paddr) * BLOCK_SIZE,
			omap_block.data(), BLOCK_SIZE);

		return true;
	}

	void WritePatternBlocks(std::vector<uint8_t> &image, uint32_t paddr, uint32_t blocks,
		uint64_t logical_base)
	{
		for (uint32_t b = 0; b < blocks; b++)
		{
			for (uint32_t k = 0; k < BLOCK_SIZE; k++)
			{
				const uint64_t logical = logical_base + static_cast<uint64_t>(b) * BLOCK_SIZE + k;
				image[static_cast<size_t>(paddr + b) * BLOCK_SIZE + k] =
					static_cast<uint8_t>(logical & 0xFF);
			}
		}
	}

	void AddInode(std::vector<KeyVal> &entries, const InodeSpec &spec)
	{
		KeyVal e;
		e.key = MakeInodeKey(spec.ino);
		e.val = MakeInodeVal(spec);
		entries.push_back(e);
	}

	void AddDrec(std::vector<KeyVal> &entries, uint64_t parent, const std::string &name,
		uint64_t file_id, uint16_t flags, bool wrong_hash = false)
	{
		KeyVal e;
		e.key = MakeDrecKey(parent, name, wrong_hash);
		e.val = MakeDrecVal(file_id, flags);
		entries.push_back(e);
	}

	void AddEmbeddedXattr(std::vector<KeyVal> &entries, uint64_t ino,
		const std::string &name, const std::vector<uint8_t> &value)
	{
		KeyVal e;
		e.key = MakeXattrKey(ino, name);
		e.val = MakeEmbeddedXattr(value);
		entries.push_back(e);
	}

	void AddStreamXattr(std::vector<KeyVal> &entries, uint64_t ino,
		const std::string &name, uint64_t obj_id, uint64_t size, uint64_t alloced)
	{
		KeyVal e;
		e.key = MakeXattrKey(ino, name);
		e.val = MakeStreamXattr(obj_id, size, alloced);
		entries.push_back(e);
	}

	void AddExtent(std::vector<KeyVal> &entries, uint64_t obj_id, uint64_t logical,
		uint64_t length, uint64_t phys, uint64_t crypto = 0)
	{
		KeyVal e;
		e.key = MakeExtentKey(obj_id, logical);
		e.val = MakeExtentVal(length, phys, crypto);
		entries.push_back(e);
	}

	InodeSpec FileInode(uint64_t ino, const std::string &name, uint64_t size,
		uint64_t alloced = 0, uint32_t bsd_flags = 0, uint64_t internal_flags = 0,
		uint64_t uncompressed = 0, uint64_t sparse = 0)
	{
		InodeSpec spec;
		spec.ino = ino;
		spec.parent = 2;
		spec.private_id = ino;
		spec.mode = MODE_S_IFREG | 0644;
		spec.bsd_flags = bsd_flags;
		spec.internal_flags = internal_flags;
		spec.uncompressed_size = uncompressed;
		spec.name = name;
		spec.ds_size = size;
		spec.ds_alloced = alloced;
		spec.sparse_bytes = sparse;
		return spec;
	}

	void AddBaseInodes(std::vector<KeyVal> &entries)
	{
		InodeSpec root;
		root.ino = 2;
		root.parent = 1;
		root.private_id = 2;
		root.mode = MODE_S_IFDIR | 0755;
		root.bsd_flags = 0;
		root.internal_flags = 0;
		root.uncompressed_size = 0;
		root.name = "root";
		root.ds_size = 0;
		root.ds_alloced = 0;
		root.sparse_bytes = 0;
		AddInode(entries, root);
		AddDrec(entries, 1, "root", 2, DT_DIR);

		// A directory with many entries, used for the iterator error case.
		InodeSpec dir;
		dir = root;
		dir.ino = 50;
		dir.parent = 2;
		dir.private_id = 50;
		dir.name = "many";
		AddInode(entries, dir);
		AddDrec(entries, 2, "many", 50, DT_DIR);
	}

	void AddGoodRecords(std::vector<KeyVal> &entries)
	{
		AddBaseInodes(entries);

		AddDrec(entries, 2, "unicode-\xF0\x9F\xA7\xA8", 20, DT_REG, true);
		AddInode(entries, FileInode(20, "unicode-\xF0\x9F\xA7\xA8", 0));

		AddDrec(entries, 2, "CaseName.txt", 21, DT_REG);
		AddInode(entries, FileInode(21, "CaseName.txt", 0));

		AddDrec(entries, 2, "e\xCC\x81.txt", 22, DT_REG);
		AddInode(entries, FileInode(22, "e\xCC\x81.txt", 0));

		AddDrec(entries, 2, "hole.bin", 23, DT_REG);
		AddInode(entries, FileInode(23, "hole.bin", 80, 80, 0, 0, 0, 40));
		AddExtent(entries, 23, 0, 24, DATA_22_A);
		AddExtent(entries, 23, 24, 40, 0); // explicit hole
		AddExtent(entries, 23, 64, 16, DATA_22_B);

		AddDrec(entries, 2, "gap.bin", 24, DT_REG);
		AddInode(entries, FileInode(24, "gap.bin", 80, 80, 0, 0, 0, 40));
		AddExtent(entries, 24, 0, 24, DATA_23_A);
		AddExtent(entries, 24, 64, 16, DATA_23_B);

		AddDrec(entries, 2, "bad-device.bin", 41, DT_REG);
		AddInode(entries, FileInode(41, "bad-device.bin", 8, 8));
		AddExtent(entries, 41, 0, 8, 0x3FFFF);

		// Compression classification cases.
		AddDrec(entries, 2, "inline", 25, DT_REG);
		AddInode(entries, FileInode(25, "inline", 100, 100, APFS_UF_COMPRESSED, 0, 100));
		AddEmbeddedXattr(entries, 25, "com.apple.decmpfs", MakeDecmpfs(9, 100, true));

		AddDrec(entries, 2, "rf", 26, DT_REG);
		AddInode(entries, FileInode(26, "rf", 200, 200, APFS_UF_COMPRESSED, 0, 200));
		AddEmbeddedXattr(entries, 26, "com.apple.decmpfs", MakeDecmpfs(4, 200, false));
		AddEmbeddedXattr(entries, 26, "com.apple.ResourceFork",
			std::vector<uint8_t>(32, 0x55));

		AddDrec(entries, 2, "rf-missing", 27, DT_REG);
		AddInode(entries, FileInode(27, "rf-missing", 200, 200, APFS_UF_COMPRESSED, 0, 200));
		AddEmbeddedXattr(entries, 27, "com.apple.decmpfs", MakeDecmpfs(4, 200, false));

		AddDrec(entries, 2, "unknown-algo", 28, DT_REG);
		AddInode(entries, FileInode(28, "unknown-algo", 50, 50, APFS_UF_COMPRESSED, 0, 50));
		AddEmbeddedXattr(entries, 28, "com.apple.decmpfs", MakeDecmpfs(99, 50, true));

		AddDrec(entries, 2, "user-rf", 29, DT_REG);
		AddInode(entries, FileInode(29, "user-rf", 0));
		AddEmbeddedXattr(entries, 29, "com.apple.ResourceFork",
			std::vector<uint8_t>(16, 0x66));

		AddDrec(entries, 2, "inline-user-rf", 30, DT_REG);
		AddInode(entries, FileInode(30, "inline-user-rf", 100, 100, APFS_UF_COMPRESSED, 0, 100));
		AddEmbeddedXattr(entries, 30, "com.apple.decmpfs", MakeDecmpfs(9, 100, true));
		AddEmbeddedXattr(entries, 30, "com.apple.ResourceFork",
			std::vector<uint8_t>(16, 0x67));

		// Xattr host.
		AddDrec(entries, 2, "xattrs", 31, DT_REG);
		AddInode(entries, FileInode(31, "xattrs", 0));
		AddEmbeddedXattr(entries, 31, "com.apple.test.small",
			std::vector<uint8_t>{'h', 'e', 'l', 'l', 'o'});
		AddStreamXattr(entries, 31, "com.apple.test.big64k", 0x3000, 65536, 65536);
		AddStreamXattr(entries, 31, "com.apple.test.big64k1", 0x3001, 65537, 69632);
		AddExtent(entries, 0x3000, 0, 65536, DATA_XATTR_64K);
		AddExtent(entries, 0x3001, 0, 69632, DATA_XATTR_64K1);

		// Invalid inline header (no payload).
		AddDrec(entries, 2, "inline-empty", 32, DT_REG);
		AddInode(entries, FileInode(32, "inline-empty", 100, 100, APFS_UF_COMPRESSED, 0, 100));
		AddEmbeddedXattr(entries, 32, "com.apple.decmpfs", MakeDecmpfs(9, 100, false));

		// Inode/header size mismatch.
		AddDrec(entries, 2, "size-mismatch", 33, DT_REG);
		AddInode(entries, FileInode(33, "size-mismatch", 100, 100, APFS_UF_COMPRESSED,
			INODE_HAS_UNCOMPRESSED_SIZE, 99));
		AddEmbeddedXattr(entries, 33, "com.apple.decmpfs", MakeDecmpfs(9, 100, true));

		// Oversized header for the configurable limit test.
		AddDrec(entries, 2, "too-big", 34, DT_REG);
		AddInode(entries, FileInode(34, "too-big", 2000, 2000, APFS_UF_COMPRESSED, 0, 2000));
		AddEmbeddedXattr(entries, 34, "com.apple.decmpfs", MakeDecmpfs(9, 2000, true));
	}

	void AddBadRecords(std::vector<KeyVal> &entries)
	{
		AddGoodRecords(entries);

		// High keys routed to the damaged last leaf.
		AddDrec(entries, 2, "badfile", 9000, DT_REG);
		AddInode(entries, FileInode(9000, "badfile", 8, 8));
		AddExtent(entries, 9000, 0, 8, DATA_9000);

		AddDrec(entries, 2, "badattrs", 9001, DT_REG);
		AddInode(entries, FileInode(9001, "badattrs", 0));
		AddEmbeddedXattr(entries, 9001, "com.apple.test", std::vector<uint8_t>{'x'});

		InodeSpec dir;
		dir.ino = 9002;
		dir.parent = 2;
		dir.private_id = 9002;
		dir.mode = MODE_S_IFDIR | 0755;
		dir.bsd_flags = 0;
		dir.internal_flags = 0;
		dir.uncompressed_size = 0;
		dir.name = "baddir";
		dir.ds_size = 0;
		dir.ds_alloced = 0;
		dir.sparse_bytes = 0;
		AddInode(entries, dir);
		AddDrec(entries, 2, "baddir", 9002, DT_DIR);
		AddDrec(entries, 9002, "child", 9003, DT_REG);

		// Enough directory entries to span multiple leaves.
		for (int k = 0; k < 10000; k++)
		{
			char name[32];
			std::snprintf(name, sizeof(name), "many-%05d", k);
			AddDrec(entries, 50, name, 10000 + k, DT_REG);
		}
	}

	void AddLargeRecords(std::vector<KeyVal> &entries)
	{
		InodeSpec root;
		root.ino = 2;
		root.parent = 1;
		root.private_id = 2;
		root.mode = MODE_S_IFDIR | 0755;
		root.bsd_flags = 0;
		root.internal_flags = 0;
		root.uncompressed_size = 0;
		root.name = "root";
		root.ds_size = 0;
		root.ds_alloced = 0;
		root.sparse_bytes = 0;
		AddInode(entries, root);
		AddDrec(entries, 1, "root", 2, DT_DIR);

		for (int k = 0; k < 100000; k++)
		{
			char name[32];
			std::snprintf(name, sizeof(name), "file-%06d", k);
			AddDrec(entries, 2, name, 100000 + k, DT_REG);
		}
	}

	bool ReadWholeFile(const std::string &path, std::vector<uint8_t> &image, std::string &error)
	{
		std::ifstream in(path.c_str(), std::ios::binary);
		if (!in)
		{
			error = "cannot open image";
			return false;
		}
		in.seekg(0, std::ios::end);
		const std::streamoff size = in.tellg();
		in.seekg(0, std::ios::beg);
		if (size != static_cast<std::streamoff>(IMAGE_SIZE))
		{
			error = "unexpected image size";
			return false;
		}
		image.resize(IMAGE_SIZE);
		in.read(reinterpret_cast<char *>(image.data()), image.size());
		if (!in)
		{
			error = "cannot read image";
			return false;
		}
		return true;
	}

	bool WriteWholeFile(const std::string &path, const std::vector<uint8_t> &image,
		std::string &error)
	{
		std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
		if (!out)
		{
			error = "cannot write image";
			return false;
		}
		out.write(reinterpret_cast<const char *>(image.data()), image.size());
		if (!out)
		{
			error = "cannot write image";
			return false;
		}
		return true;
	}

	uint32_t FindObject(const std::vector<uint8_t> &image, uint64_t oid, uint32_t type)
	{
		const uint64_t blocks = image.size() / BLOCK_SIZE;
		for (uint64_t paddr = 0; paddr < blocks; paddr++)
		{
			const uint8_t *block = image.data() + paddr * BLOCK_SIZE;
			const uint64_t block_oid = ReadLE64(block + offsetof(obj_phys_t, o_oid));
			const uint32_t block_type = ReadLE32(block + offsetof(obj_phys_t, o_type)) & OBJECT_TYPE_MASK;
			if (block_oid == oid && block_type == type)
				return static_cast<uint32_t>(paddr);
		}
		return UINT32_MAX;
	}

	bool OmapTreeLookup(const std::vector<uint8_t> &image, uint32_t paddr,
		uint64_t target_oid, uint64_t target_xid, uint64_t &result_paddr)
	{
		if (paddr >= image.size() / BLOCK_SIZE)
			return false;

		const uint8_t *block = image.data() + static_cast<size_t>(paddr) * BLOCK_SIZE;
		const uint16_t flags = ReadLE16(block + offsetof(btree_node_phys_t, btn_flags));
		const uint16_t level = ReadLE16(block + offsetof(btree_node_phys_t, btn_level));
		const uint32_t nkeys = ReadLE32(block + offsetof(btree_node_phys_t, btn_nkeys));
		const bool root = (flags & BTNODE_ROOT) != 0;

		const size_t table_off = offsetof(btree_node_phys_t, btn_data);
		const size_t table_len = ReadLE16(block + offsetof(btree_node_phys_t, btn_table_space) + offsetof(nloc_t, len));
		const size_t keys_start = table_off + table_len;
		const size_t vals_start = BLOCK_SIZE - (root ? sizeof(btree_info_t) : 0);

		int best = -1;
		uint64_t best_xid = 0;

		for (uint32_t k = 0; k < nkeys; k++)
		{
			const size_t loc_off = table_off + k * sizeof(kvoff_t);
			const uint16_t key_off = ReadLE16(block + loc_off);
			const uint16_t val_off = ReadLE16(block + loc_off + 2);
			const uint8_t *key = block + keys_start + key_off;
			const uint8_t *val = block + vals_start - val_off;

			const uint64_t oid = ReadLE64(key);
			const uint64_t xid = ReadLE64(key + 8);
			if (oid == target_oid && xid <= target_xid && (best < 0 || xid > best_xid))
			{
				best = static_cast<int>(k);
				best_xid = xid;
			}
			(void)val;
		}

		if (best < 0)
			return false;

		const size_t loc_off = table_off + static_cast<size_t>(best) * sizeof(kvoff_t);
		const uint16_t val_off = ReadLE16(block + loc_off + 2);
		const uint8_t *val = block + vals_start - val_off;

		if (level == 0)
		{
			result_paddr = ReadLE64(val + offsetof(omap_val_t, ov_paddr));
			return result_paddr != 0;
		}

		const uint64_t child_oid = ReadLE64(val);
		return OmapTreeLookup(image, static_cast<uint32_t>(child_oid), target_oid,
			target_xid, result_paddr);
	}

	bool OmapLookup(const std::vector<uint8_t> &image, uint32_t omap_paddr,
		uint64_t target_oid, uint64_t target_xid, uint64_t &result_paddr)
	{
		if (omap_paddr >= image.size() / BLOCK_SIZE)
			return false;
		const uint8_t *block = image.data() + static_cast<size_t>(omap_paddr) * BLOCK_SIZE;
		const uint64_t tree_oid = ReadLE64(block + offsetof(omap_phys_t, om_tree_oid));
		uint32_t tree_paddr = static_cast<uint32_t>(tree_oid);
		if (tree_paddr >= image.size() / BLOCK_SIZE)
		{
			tree_paddr = FindObject(image, tree_oid, OBJECT_TYPE_BTREE);
			if (tree_paddr == UINT32_MAX)
				tree_paddr = FindObject(image, tree_oid, OBJECT_TYPE_BTREE_NODE);
		}
		if (tree_paddr == UINT32_MAX)
			return false;
		return OmapTreeLookup(image, tree_paddr, target_oid, target_xid, result_paddr);
	}
}

std::string FindMkapfs()
{
	const char *env = std::getenv("MKAPFS");
	if (env && *env && access(env, X_OK) == 0)
		return env;

	const char *paths[] = {
		"/usr/sbin/mkapfs",
		"/sbin/mkapfs",
		"/usr/bin/mkapfs",
		"/usr/local/sbin/mkapfs",
		"/usr/local/bin/mkapfs"
	};
	for (size_t k = 0; k < sizeof(paths) / sizeof(paths[0]); k++)
	{
		if (access(paths[k], X_OK) == 0)
			return paths[k];
	}
	return "";
}

bool CreateApfsFixture(const std::string &path, ApfsFixtureKind kind, std::string &error)
{
	const std::string mkapfs = FindMkapfs();
	if (mkapfs.empty())
	{
		error = "mkapfs not found";
		return false;
	}

	const int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
	{
		error = "cannot create image";
		return false;
	}
	if (ftruncate(fd, IMAGE_SIZE) != 0)
	{
		close(fd);
		error = "cannot size image";
		return false;
	}
	close(fd);

	std::ostringstream cmd;
	cmd << "\"" << mkapfs << "\" \"" << path << "\" >/dev/null 2>&1";
	if (std::system(cmd.str().c_str()) != 0)
	{
		error = "mkapfs failed";
		return false;
	}

	std::vector<uint8_t> image;
	if (!ReadWholeFile(path, image, error))
		return false;

	const uint8_t *nx = image.data();
	if (ReadLE32(nx + offsetof(nx_superblock_t, nx_magic)) != NX_MAGIC)
	{
		error = "not an APFS image";
		return false;
	}
	const uint32_t block_size = ReadLE32(nx + offsetof(nx_superblock_t, nx_block_size));
	if (block_size != BLOCK_SIZE)
	{
		error = "unexpected block size";
		return false;
	}

	const uint64_t nx_xid = ReadLE64(nx + offsetof(nx_superblock_t, nx_o) + offsetof(obj_phys_t, o_xid));
	const uint64_t nx_omap_oid = ReadLE64(nx + offsetof(nx_superblock_t, nx_omap_oid));
	const uint64_t fs_oid = ReadLE64(nx + offsetof(nx_superblock_t, nx_fs_oid));

	const uint32_t nx_omap_paddr = FindObject(image, nx_omap_oid, OBJECT_TYPE_OMAP);
	if (nx_omap_paddr == UINT32_MAX)
	{
		error = "NX omap not found";
		return false;
	}

	uint64_t volume_paddr = 0;
	if (!OmapLookup(image, nx_omap_paddr, fs_oid, nx_xid, volume_paddr))
	{
		error = "volume superblock not mapped";
		return false;
	}

	const uint8_t *volume = image.data() + volume_paddr * BLOCK_SIZE;
	if (ReadLE32(volume + offsetof(apfs_superblock_t, apfs_magic)) != APFS_MAGIC)
	{
		error = "invalid volume superblock";
		return false;
	}
	const uint64_t volume_xid = ReadLE64(volume + offsetof(apfs_superblock_t, apfs_o) + offsetof(obj_phys_t, o_xid));
	const uint64_t volume_omap_oid = ReadLE64(volume + offsetof(apfs_superblock_t, apfs_omap_oid));
	const uint64_t root_tree_oid = ReadLE64(volume + offsetof(apfs_superblock_t, apfs_root_tree_oid));

	const uint32_t volume_omap_paddr = FindObject(image, volume_omap_oid, OBJECT_TYPE_OMAP);
	if (volume_omap_paddr == UINT32_MAX)
	{
		error = "volume omap not found";
		return false;
	}

	uint64_t fs_tree_paddr = 0;
	if (!OmapLookup(image, volume_omap_paddr, root_tree_oid, volume_xid, fs_tree_paddr))
	{
		error = "file-system tree not mapped";
		return false;
	}
	if (fs_tree_paddr != ROOT_PADDR)
	{
		error = "unexpected file-system tree location";
		return false;
	}

	std::vector<KeyVal> entries;
	std::vector<BlockRef> leaves;
	std::vector<BlockRef> all_nodes;
	switch (kind)
	{
	case ApfsFixtureKind::Good:
		AddGoodRecords(entries);
		break;
	case ApfsFixtureKind::BadTree:
		AddBadRecords(entries);
		break;
	case ApfsFixtureKind::LargeDirectory:
		AddLargeRecords(entries);
		break;
	}

	if (!BuildTree(entries, image, leaves, all_nodes, error))
		return false;

	if (!WriteOmapTree(image, all_nodes, volume_xid, volume_omap_paddr, error))
		return false;

	WritePatternBlocks(image, DATA_22_A, 3, 0);
	WritePatternBlocks(image, DATA_22_B, 2, 64);
	WritePatternBlocks(image, DATA_23_A, 3, 0);
	WritePatternBlocks(image, DATA_23_B, 2, 64);
	WritePatternBlocks(image, DATA_9000, 1, 0);
	WritePatternBlocks(image, DATA_XATTR_64K, 16, 0);
	WritePatternBlocks(image, DATA_XATTR_64K1, 17, 0);

	if (kind == ApfsFixtureKind::BadTree)
	{
		// Corrupt the second leaf containing many-* entries and the last leaf
		// with the high-key sentinels.
		std::vector<uint32_t> many_leaves;
		for (size_t k = 0; k < leaves.size(); k++)
		{
			const uint64_t key = ReadLE64(leaves[k].first_key.data());
			if (key == APFS_TYPE_ID(APFS_TYPE_DIR_REC, 50))
				many_leaves.push_back(leaves[k].paddr);
		}
		if (many_leaves.size() < 2)
		{
			error = "fixture did not create enough directory leaves";
			return false;
		}
		std::memset(image.data() + static_cast<size_t>(many_leaves[1]) * BLOCK_SIZE, 0, BLOCK_SIZE);
		std::memset(image.data() + static_cast<size_t>(leaves.back().paddr) * BLOCK_SIZE, 0, BLOCK_SIZE);
	}

	if (!WriteWholeFile(path, image, error))
		return false;

	return true;
}
