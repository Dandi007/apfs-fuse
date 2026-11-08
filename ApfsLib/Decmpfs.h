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
#include <vector>

#include "ApfsDir.h"

struct CompressionHeader
{
	le_uint32_t signature;
	le_uint32_t algo;
	le_uint64_t size;
};

// Optional per-object decode metadata. Defaults keep every existing caller
// source-compatible. accepted_missing_adler is only set when at least one
// zlib block was accepted without its RFC 1950 Adler-32 trailer; such output
// is length/structure verified, not checksum verified.
//
// The remaining fields describe the APFS_DECMPFS_OBJECT summary line emitted
// on success. They are all zero on failure, including seq: the failure path
// keeps the existing "result cleared" contract and the seq is carried by the
// APFS_DECMPFS_ERROR line instead.
struct DecompressResult
{
	bool accepted_missing_adler = false;
	size_t zlib_block_count = 0;
	size_t missing_adler_block_count = 0;

	uint64_t seq = 0;
	uint64_t logical_size = 0;
	size_t block_count = 0;
	size_t raw_block_count = 0;
	size_t native_block_count = 0;
	bool checksum_verified = false;
};

bool IsDecompAlgoSupported(uint16_t algo);
bool IsDecompAlgoInRsrc(uint16_t algo);

bool DecompressFile(ApfsDir &dir, uint64_t ino, std::vector<uint8_t> &decompressed,
	const std::vector<uint8_t> &compressed, DecompressResult *result = nullptr);
