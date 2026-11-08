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

#include "CompressionView.h"

#include <vector>

#include "Decmpfs.h"

namespace
{
	const char *const DECMPFS_XATTR = "com.apple.decmpfs";
	const char *const RESOURCE_FORK_XATTR = "com.apple.ResourceFork";
}

CompressionClass ClassifyInodeCompression(ApfsDir &dir, const ApfsDir::Inode &rec,
	uint64_t &uncompressed_size, uint64_t &decmpfs_attr_size,
	uint64_t max_uncompressed_size)
{
	CompressionMeta meta = {};
	bool has_rsrc_algo = false;

	uncompressed_size = 0;
	decmpfs_attr_size = 0;
	meta.compressed_flag = (rec.bsd_flags & APFS_UF_COMPRESSED) != 0;
	meta.has_inode_uncompressed_size = (rec.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE) != 0;
	meta.inode_uncompressed_size = rec.uncompressed_size;

	if (!meta.compressed_flag)
		return CompressionClass::None;

	std::vector<uint8_t> decmpfs;
	IoStatus st = IoStatus::Ok;

	if (!dir.GetAttribute(decmpfs, rec.obj_id, DECMPFS_XATTR, &st))
	{
		if (st == IoStatus::IoError)
		{
			meta.decmpfs_io_error = true;
			return ClassifyCompression(meta, max_uncompressed_size);
		}
		meta.decmpfs_found = false;
		return ClassifyCompression(meta, max_uncompressed_size);
	}

	meta.decmpfs_found = true;
	meta.decmpfs_attr_size = decmpfs.size();
	decmpfs_attr_size = decmpfs.size();

	DecmpfsHeader hdr = {};
	if (ParseDecmpfsHeader(decmpfs.data(), decmpfs.size(), hdr))
	{
		meta.header_valid = true;
		meta.algo = hdr.algo;
		meta.uncompressed_size = hdr.uncompressed_size;
		uncompressed_size = hdr.uncompressed_size;

		has_rsrc_algo = hdr.algo <= 0xFFFF &&
			IsDecompAlgoInRsrc(static_cast<uint16_t>(hdr.algo));
	}

	if (has_rsrc_algo)
	{
		ApfsDir::XAttr info;
		IoStatus rst = IoStatus::Ok;

		if (dir.GetAttributeInfo(info, rec.obj_id, RESOURCE_FORK_XATTR, &rst))
			meta.resource_fork_found = true;
		else if (rst == IoStatus::IoError)
			meta.resource_fork_io_error = true;
	}

	return ClassifyCompression(meta, max_uncompressed_size);
}
