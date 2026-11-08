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

#include "ReaderPolicy.h"

#include <cstring>

#include "Decmpfs.h"

XattrReply PlanXattrReply(size_t value_size, size_t user_size)
{
	if (value_size > APFS_XATTR_VALUE_MAX)
		return XattrReply::TooLarge;

	if (user_size == 0)
		return XattrReply::Size;

	if (user_size < value_size)
		return XattrReply::ERange;

	return XattrReply::Value;
}

bool RawNameEquals(const uint8_t *entry_name, uint16_t entry_len, const char *name)
{
	if (!entry_name || !name)
		return false;

	const size_t name_len = std::strlen(name) + 1;
	if (name_len != entry_len)
		return false;

	return std::memcmp(entry_name, name, name_len) == 0;
}

bool ParseDecmpfsHeader(const void *data, size_t size, DecmpfsHeader &header)
{
	if (!data || size < sizeof(CompressionHeader))
		return false;

	const CompressionHeader *hdr = reinterpret_cast<const CompressionHeader *>(data);

	header.signature = hdr->signature;
	header.algo = hdr->algo;
	header.uncompressed_size = hdr->size;

	return header.signature == DECMPFS_MAGIC;
}

CompressionClass ClassifyCompression(const CompressionMeta &meta)
{
	if (!meta.compressed_flag)
		return CompressionClass::None;

	if (meta.decmpfs_io_error)
		return CompressionClass::IoError;

	if (!meta.decmpfs_found)
		return CompressionClass::MissingHeader;

	if (!meta.header_valid)
		return CompressionClass::InvalidHeader;

	if (meta.algo > 0xFFFF || !IsDecompAlgoSupported(static_cast<uint16_t>(meta.algo)))
		return CompressionClass::UnsupportedAlgorithm;

	if (IsDecompAlgoInRsrc(static_cast<uint16_t>(meta.algo)))
	{
		if (meta.resource_fork_io_error)
			return CompressionClass::IoError;
		if (!meta.resource_fork_found)
			return CompressionClass::MissingCarrier;

		return CompressionClass::ResourceFork;
	}

	return CompressionClass::InlineAttr;
}

bool HidesDecmpfs(CompressionClass cls)
{
	return cls == CompressionClass::InlineAttr || cls == CompressionClass::ResourceFork;
}

bool HidesResourceFork(CompressionClass cls)
{
	return cls == CompressionClass::ResourceFork;
}

bool CompressionClassIsError(CompressionClass cls)
{
	switch (cls)
	{
	case CompressionClass::MissingHeader:
	case CompressionClass::InvalidHeader:
	case CompressionClass::UnsupportedAlgorithm:
	case CompressionClass::MissingCarrier:
	case CompressionClass::IoError:
		return true;
	default:
		return false;
	}
}
