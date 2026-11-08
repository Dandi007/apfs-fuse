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

#include "IoStatus.h"

struct ExtentInfo
{
	uint64_t logical_addr;
	uint64_t length;
	uint64_t phys_block;
	uint64_t crypto_id;
};

// Abstract extent source. ApfsDir implements this on top of the file-system
// (or sealed-volume fext) B+tree. Tests implement it with synthetic data and
// injected failures.
class ExtentSource
{
public:
	virtual ~ExtentSource() {}

	// Returns the extent covering logical offset "offs", or the last extent
	// starting at or before it. IoStatus::NotFound is a normal answer (the
	// offset is in a hole); IoStatus::IoError means the tree or device failed.
	virtual IoStatus LookupExtent(uint64_t ino, uint64_t offs, ExtentInfo &extent) = 0;

	// Finds the first extent starting at or after "offs". NotFound means there
	// is no later extent for this inode.
	virtual IoStatus NextExtentStart(uint64_t ino, uint64_t offs, bool &found, uint64_t &start) = 0;

	// Reads blkcnt blocks. False includes short reads and device errors.
	virtual bool ReadBlocks(void *data, uint64_t paddr, uint64_t blkcnt, uint64_t crypto_id) = 0;

	virtual uint32_t BlockSize() const = 0;
};

// Reads [offs, offs + size) from an inode through an extent source.
//
// "file_size" clamps the request at EOF (pass UINT64_MAX if unknown).
// "sparse_allowed" must only be set when the inode metadata proves that holes
// are legitimate (sparse_bytes > 0 or allocated size < logical size). Without
// it, a missing extent or a gap is an I/O/metadata error, never zero-fill.
IoStatus ReadFileInternal(ExtentSource &source, void *data, uint64_t ino,
	uint64_t offs, size_t size, uint64_t file_size, bool sparse_allowed);
