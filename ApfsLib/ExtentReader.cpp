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

#include "ExtentReader.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace
{
	bool IsPowerOfTwo(uint64_t value)
	{
		return value != 0 && (value & (value - 1)) == 0;
	}
}

IoStatus ReadFileInternal(ExtentSource &source, void *data, uint64_t ino,
	uint64_t offs, size_t size, uint64_t file_size, bool sparse_allowed)
{
	if (size == 0)
		return IoStatus::Ok;

	if (offs > UINT64_MAX - static_cast<uint64_t>(size))
		return IoStatus::IoError;

	if (file_size != UINT64_MAX)
	{
		if (offs >= file_size)
			return IoStatus::Ok;
		if (size > file_size - offs)
			size = static_cast<size_t>(file_size - offs);
	}

	const uint64_t request_end = offs + static_cast<uint64_t>(size);
	const uint32_t block_size = source.BlockSize();
	if (!IsPowerOfTwo(block_size))
		return IoStatus::IoError;

	const uint64_t block_mask = block_size - 1;
	uint8_t *out = reinterpret_cast<uint8_t *>(data);
	std::vector<uint8_t> tmp_block;

	while (size > 0)
	{
		ExtentInfo extent;
		const IoStatus lookup = source.LookupExtent(ino, offs, extent);

		if (lookup == IoStatus::IoError)
			return IoStatus::IoError;

		if (lookup == IoStatus::NotFound)
		{
			// No extent starts at or before this offset. This is either a
			// leading hole or a hole after the last extent.
			if (!sparse_allowed)
				return IoStatus::IoError;

			bool next_found = false;
			uint64_t next_start = 0;
			const IoStatus next = source.NextExtentStart(ino, offs, next_found, next_start);
			if (next == IoStatus::IoError)
				return IoStatus::IoError;

			if (next_found && next_start <= offs)
				return IoStatus::IoError;
			if (!next_found && file_size == UINT64_MAX)
				return IoStatus::IoError;

			uint64_t bound = next_found ? next_start : file_size;
			bound = std::min(bound, request_end);
			if (bound <= offs)
				return IoStatus::IoError;

			const uint64_t hole = bound - offs;
			std::memset(out, 0, static_cast<size_t>(hole));
			out += hole;
			offs += hole;
			size -= static_cast<size_t>(hole);
			continue;
		}

		if (extent.length == 0)
			return IoStatus::IoError;
		if (extent.logical_addr > UINT64_MAX - extent.length)
			return IoStatus::IoError;

		const uint64_t extent_end = extent.logical_addr + extent.length;

		if (offs < extent.logical_addr)
		{
			// The tree returned an extent after the requested offset. Treat
			// the gap as a hole only when sparse reads are allowed; never let
			// the subtraction underflow.
			if (!sparse_allowed)
				return IoStatus::IoError;

			uint64_t hole = extent.logical_addr - offs;
			hole = std::min<uint64_t>(hole, size);
			std::memset(out, 0, static_cast<size_t>(hole));
			out += hole;
			offs += hole;
			size -= static_cast<size_t>(hole);
			continue;
		}

		if (offs >= extent_end)
		{
			// The last extent starts before the request but does not cover
			// it. This is a hole between extents (or a sparse tail).
			if (!sparse_allowed)
				return IoStatus::IoError;

			bool next_found = false;
			uint64_t next_start = 0;
			const IoStatus next = source.NextExtentStart(ino, offs, next_found, next_start);
			if (next == IoStatus::IoError)
				return IoStatus::IoError;

			if (next_found && next_start <= offs)
				return IoStatus::IoError;
			if (!next_found && file_size == UINT64_MAX)
				return IoStatus::IoError;

			uint64_t bound = next_found ? next_start : file_size;
			bound = std::min(bound, request_end);
			if (bound <= offs)
				return IoStatus::IoError;

			const uint64_t hole = bound - offs;
			std::memset(out, 0, static_cast<size_t>(hole));
			out += hole;
			offs += hole;
			size -= static_cast<size_t>(hole);
			continue;
		}

		const uint64_t within = offs - extent.logical_addr;
		const uint64_t available = extent.length - within;
		const uint64_t chunk = std::min<uint64_t>(available, size);

		if (extent.phys_block == 0)
		{
			// Explicitly unmapped extent: a legitimate hole.
			std::memset(out, 0, static_cast<size_t>(chunk));
			out += chunk;
			offs += chunk;
			size -= static_cast<size_t>(chunk);
			continue;
		}

		const uint64_t block_index = within / block_size;
		const uint64_t block_offset = within & block_mask;

		if (extent.phys_block > UINT64_MAX - block_index)
			return IoStatus::IoError;
		const uint64_t phys_block = extent.phys_block + block_index;

		if (extent.crypto_id > UINT64_MAX - block_index)
			return IoStatus::IoError;
		const uint64_t crypto_id = extent.crypto_id + block_index;

		if (block_offset == 0 && chunk >= block_size)
		{
			const uint64_t full_size = chunk & ~block_mask;
			const uint64_t block_count = full_size / block_size;
			if (block_count > UINT64_MAX - phys_block)
				return IoStatus::IoError;
			if (!source.ReadBlocks(out, phys_block, block_count, crypto_id))
				return IoStatus::IoError;

			out += full_size;
			offs += full_size;
			size -= static_cast<size_t>(full_size);
			continue;
		}

		if (tmp_block.size() != block_size)
			tmp_block.resize(block_size);

		if (!source.ReadBlocks(tmp_block.data(), phys_block, 1, crypto_id))
			return IoStatus::IoError;

		const uint64_t copy_size = std::min<uint64_t>(chunk, block_size - block_offset);
		if (copy_size == 0)
			return IoStatus::IoError;

		std::memcpy(out, tmp_block.data() + block_offset, static_cast<size_t>(copy_size));
		out += copy_size;
		offs += copy_size;
		size -= static_cast<size_t>(copy_size);
	}

	return IoStatus::Ok;
}
