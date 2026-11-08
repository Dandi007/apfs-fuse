/*
	This file is part of apfs-fuse, a read-only implementation of APFS
	(Apple File System) for FUSE.
	Copyright (C) 2017 Simon Gander

	Apfs-fuse is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	Apfs-fuse is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with apfs-fuse.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <cstddef>
#include <cstdint>

// Linux FUSE limits one xattr value to 64 KiB. A larger on-disk value cannot
// be returned through the getxattr interface; the reader must fail explicitly
// instead of truncating it.
constexpr size_t APFS_XATTR_VALUE_MAX = 65536;

enum class XattrReply
{
	Value,
	Size,
	ERange,
	TooLarge
};

XattrReply PlanXattrReply(size_t value_size, size_t user_size);

// Exact raw-byte match of a directory record name. "entry_len" includes the
// terminating NUL. This is deliberately byte-for-byte: no case folding and no
// Unicode normalization aliasing.
bool RawNameEquals(const uint8_t *entry_name, uint16_t entry_len, const char *name);

constexpr uint32_t DECMPFS_MAGIC = 0x636D7066;

struct DecmpfsHeader
{
	uint32_t signature;
	uint32_t algo;
	uint64_t uncompressed_size;
};

bool ParseDecmpfsHeader(const void *data, size_t size, DecmpfsHeader &header);

enum class CompressionClass
{
	None,
	InlineAttr,
	ResourceFork,
	MissingHeader,
	InvalidHeader,
	UnsupportedAlgorithm,
	MissingCarrier,
	TooLarge,
	IoError
};

struct CompressionMeta
{
	bool compressed_flag;
	bool decmpfs_io_error;
	bool decmpfs_found;
	bool header_valid;
	uint32_t algo;
	uint64_t uncompressed_size;
	uint64_t decmpfs_attr_size;
	bool has_inode_uncompressed_size;
	uint64_t inode_uncompressed_size;
	bool resource_fork_io_error;
	bool resource_fork_found;
};

// "max_uncompressed_size" is a configurable RSS gate. Zero means no limit.
CompressionClass ClassifyCompression(const CompressionMeta &meta, uint64_t max_uncompressed_size = 0);

// Backup-view visibility rules. A valid inline compression header hides only
// com.apple.decmpfs. A valid resource-fork algorithm hides decmpfs and its
// carrier; any other ResourceFork is a real user attribute and is kept.
bool HidesDecmpfs(CompressionClass cls);
bool HidesResourceFork(CompressionClass cls);

// True for classes that make the compression metadata unusable. The backup
// view reports EIO for these instead of pretending the attribute is absent.
bool CompressionClassIsError(CompressionClass cls);
