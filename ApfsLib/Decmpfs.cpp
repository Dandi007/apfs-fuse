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

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

#include "Decmpfs.h"
#include "Endian.h"

#include "Global.h"
#include "Util.h"

namespace
{

struct RsrcForkHeader
{
	be_uint32_t data_offset;
	be_uint32_t mgmt_offset;
	be_uint32_t data_size;
	be_uint32_t mgmt_size;
};

// One validated compressed block. Offsets are relative to the resource-fork
// data base used by the type-4 table (data_offset + 4).
struct RfBlockRecord
{
	size_t off;
	size_t size;
};

constexpr size_t kDecmpfsBlockSize = 0x10000;
constexpr size_t kDecmpfsMaxEncodedBlock = 0x10001;

uint32_t ReadLE32(const uint8_t *p)
{
	return static_cast<uint32_t>(p[0]) |
		(static_cast<uint32_t>(p[1]) << 8) |
		(static_cast<uint32_t>(p[2]) << 16) |
		(static_cast<uint32_t>(p[3]) << 24);
}

void EmitLine(const std::string &line)
{
	if (line.empty())
		return;
	std::cerr.write(line.data(), static_cast<std::streamsize>(line.size()));
	std::cerr.flush();
}

// Diagnostics are built completely before one write so a line cannot be
// interleaved with another thread's output. Only stable identity and sizes
// are printed: never a file name, path or payload byte.
void EmitError(uint64_t ino, uint32_t algo, size_t block, const char *stage,
	const char *reason)
{
	char line[256];
	const int n = std::snprintf(line, sizeof(line),
		"APFS_DECMPFS_ERROR ino=%llu algo=%u block=%zu stage=%s reason=%s\n",
		static_cast<unsigned long long>(ino), algo, block, stage, reason);
	if (n <= 0)
		return;
	const size_t len = std::min(sizeof(line) - 1, static_cast<size_t>(n));
	std::cerr.write(line, static_cast<std::streamsize>(len));
	std::cerr.flush();
}

std::string FormatValidation(uint64_t ino, uint32_t algo, size_t block,
	size_t compressed, size_t expected, size_t decoded, bool missing_adler)
{
	char line[320];
	const int n = std::snprintf(line, sizeof(line),
		"APFS_DECMPFS_VALIDATION ino=%llu algo=%u block=%zu compressed=%zu"
		" expected=%zu decoded=%zu validation=%s missing_adler=%u\n",
		static_cast<unsigned long long>(ino), algo, block, compressed, expected,
		decoded, missing_adler ? "structure_length_only" : "length_with_checksum",
		missing_adler ? 1u : 0u);
	if (n <= 0)
		return std::string();
	const size_t len = std::min(sizeof(line) - 1, static_cast<size_t>(n));
	return std::string(line, len);
}

bool ResizeExact(std::vector<uint8_t> &out, uint64_t size, const char **reason)
{
	if (size > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
		size > static_cast<uint64_t>(out.max_size()))
	{
		*reason = "size_range";
		return false;
	}

	try
	{
		out.resize(static_cast<size_t>(size));
	}
	catch (const std::bad_alloc &)
	{
		*reason = "allocate";
		return false;
	}
	catch (const std::length_error &)
	{
		*reason = "size_range";
		return false;
	}
	return true;
}

bool BlockCount(uint64_t size, size_t &blocks, const char **reason)
{
	const uint64_t count = size / kDecmpfsBlockSize +
		(size % kDecmpfsBlockSize != 0);
	if (count > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
	{
		*reason = "size_range";
		return false;
	}
	blocks = static_cast<size_t>(count);
	return true;
}

// Type-4 resource fork: a 16-byte classic header, then at data_offset a
// little-endian payload. The payload starts with a block count and a table of
// {offset, size} entries relative to data_offset + 4. The table has to
// describe exactly ceil(logical_size / 64K) contiguous blocks inside the
// declared data section; offsets into the count/table or outside the data
// section are rejected before any pointer is formed.
bool ParseType4Table(const std::vector<uint8_t> &rsrc, uint64_t logical_size,
	size_t &base_out, std::vector<RfBlockRecord> &records, const char **reason)
{
	if (rsrc.size() < sizeof(RsrcForkHeader))
	{
		*reason = "rsrc_header_short";
		return false;
	}

	RsrcForkHeader hdr;
	std::memcpy(&hdr, rsrc.data(), sizeof(hdr));
	const size_t data_offset = static_cast<uint32_t>(hdr.data_offset);
	const size_t data_size = static_cast<uint32_t>(hdr.data_size);

	if (data_offset > rsrc.size() || rsrc.size() - data_offset < 8)
	{
		*reason = "data_offset";
		return false;
	}
	if (data_size < 8 || data_size > rsrc.size() - data_offset)
	{
		*reason = "data_size";
		return false;
	}
	if (logical_size == 0)
	{
		*reason = "logical_size_zero";
		return false;
	}

	size_t blocks = 0;
	if (!BlockCount(logical_size, blocks, reason))
		return false;

	const size_t base = data_offset + 4;
	const uint32_t entries = ReadLE32(rsrc.data() + base);
	if (entries != blocks)
	{
		*reason = "block_count";
		return false;
	}

	// data_size covers count (4), table (8*blocks) and payload. All arithmetic
	// is subtraction-based so a wrapped size cannot look valid.
	if (blocks > (std::numeric_limits<size_t>::max() - 4) / 8)
	{
		*reason = "table_size";
		return false;
	}
	const size_t table_bytes = blocks * 8;
	if (table_bytes > data_size - 8)
	{
		*reason = "table_short";
		return false;
	}
	const size_t table_end = 4 + table_bytes; // relative to base

	try
	{
		records.resize(blocks);
	}
	catch (const std::bad_alloc &)
	{
		*reason = "table_allocate";
		return false;
	}
	catch (const std::length_error &)
	{
		*reason = "table_size";
		return false;
	}

	// The data section is [base, data_offset + data_size); its relative end
	// is data_size - 4. A block may not point into the count/table.
	const size_t data_rel_size = data_size - 4;
	size_t previous_end = table_end;

	for (size_t k = 0; k < blocks; k++)
	{
		const uint8_t *entry = rsrc.data() + base + 4 + k * 8;
		const size_t off = ReadLE32(entry);
		const size_t size = ReadLE32(entry + 4);

		if (size == 0)
		{
			*reason = "block_empty";
			return false;
		}
		if (size > kDecmpfsMaxEncodedBlock)
		{
			*reason = "block_too_large";
			return false;
		}
		if (off < table_end || off > data_rel_size)
		{
			*reason = "block_offset";
			return false;
		}
		if (size > data_rel_size - off)
		{
			*reason = "block_size";
			return false;
		}
		if (off < previous_end)
		{
			*reason = "block_overlap";
			return false;
		}

		previous_end = off + size;
		records[k].off = off;
		records[k].size = size;
	}

	base_out = base;
	return true;
}

// Algorithms 8/10/12/14 store a little-endian offset table at rsrc offset 0
// with blocks + 1 entries. Validate the table, offsets and block lengths
// before the decoder or a raw copy can touch the carrier.
bool ParseOffsetTable(const std::vector<uint8_t> &rsrc, uint64_t logical_size,
	std::vector<RfBlockRecord> &records, const char **reason)
{
	if (logical_size == 0)
	{
		*reason = "logical_size_zero";
		return false;
	}

	size_t blocks = 0;
	if (!BlockCount(logical_size, blocks, reason))
		return false;

	if (blocks > std::numeric_limits<size_t>::max() / 4 - 1)
	{
		*reason = "table_size";
		return false;
	}
	const size_t table_bytes = (blocks + 1) * 4;
	if (rsrc.size() < table_bytes)
	{
		*reason = "table_short";
		return false;
	}

	const uint32_t first = ReadLE32(rsrc.data());
	if (first < table_bytes)
	{
		*reason = "table_pointer";
		return false;
	}
	if (first > rsrc.size())
	{
		*reason = "block_offset";
		return false;
	}

	try
	{
		records.resize(blocks);
	}
	catch (const std::bad_alloc &)
	{
		*reason = "table_allocate";
		return false;
	}
	catch (const std::length_error &)
	{
		*reason = "table_size";
		return false;
	}

	uint32_t previous = first;
	for (size_t k = 0; k < blocks; k++)
	{
		const uint32_t off = ReadLE32(rsrc.data() + k * 4);
		const uint32_t next = ReadLE32(rsrc.data() + (k + 1) * 4);

		if (off != previous)
		{
			*reason = "block_order";
			return false;
		}
		if (next <= off)
		{
			*reason = "block_empty";
			return false;
		}
		if (next > rsrc.size())
		{
			*reason = "block_offset";
			return false;
		}

		const size_t size = static_cast<size_t>(next) - off;
		if (size > kDecmpfsMaxEncodedBlock)
		{
			*reason = "block_too_large";
			return false;
		}

		records[k].off = off;
		records[k].size = size;
		previous = next;
	}

	return true;
}

} // namespace

bool IsDecompAlgoSupported(uint16_t algo)
{
	switch (algo)
	{
	case 3:
	case 4:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
		return true;
	default:
		return false;
	}
}

bool IsDecompAlgoInRsrc(uint16_t algo)
{
	switch (algo)
	{
	case 4:
	case 8:
	case 10:
	case 12:
	case 14:
		return true;
	default:
		return false;
	}
}

bool DecompressFile(ApfsDir &dir, uint64_t ino, std::vector<uint8_t> &decompressed,
	const std::vector<uint8_t> &compressed, DecompressResult *result)
{
	decompressed.clear();
	if (result)
		*result = DecompressResult();

	if (compressed.size() < sizeof(CompressionHeader))
	{
		EmitError(ino, 0, 0, "header", "short");
		return false;
	}

	const CompressionHeader *hdr = reinterpret_cast<const CompressionHeader *>(compressed.data());
	const uint32_t algo = static_cast<uint32_t>(hdr->algo);
	const uint64_t logical_size = static_cast<uint64_t>(hdr->size);
	const uint8_t *cdata = compressed.data() + sizeof(CompressionHeader);
	const size_t csize = compressed.size() - sizeof(CompressionHeader);

	auto fail = [&](const char *stage, size_t block, const char *reason) -> bool {
		EmitError(ino, algo, block, stage, reason);
		decompressed.clear();
		return false;
	};

	if (logical_size == 0)
		return IsDecompAlgoSupported(algo) ? true : fail("header", 0, "unsupported_algo");

#if 1 // Disable to get compressed data
	if (g_debug & Dbg_Cmpfs)
	{
		std::cout << "DecompressFile " << compressed.size() << " => " << hdr->size << ", algo = " << hdr->algo;

		switch (hdr->algo)
		{
		case 3: std::cout << " (Zlib, Attr)"; break;
		case 4: std::cout << " (Zlib, Rsrc)"; break;
		case 7: std::cout << " (LZVN, Attr)"; break;
		case 8: std::cout << " (LZVN, Rsrc)"; break;
		case 9: std::cout << " (Uncompressed, Attr)"; break;
		case 10: std::cout << " (Uncompressed, Rsrc)"; break;
		case 11: std::cout << " (LZFSE, Attr)"; break;
		case 12: std::cout << " (LZFSE, Rsrc)"; break;
		case 13: std::cout << " (LZBITMAP, Attr)"; break;
		case 14: std::cout << " (LZBITMAP, Rsrc)"; break;
		default: std::cout << " (Unknown)"; break;
		}

		std::cout << std::endl;
	}

	if (!IsDecompAlgoSupported(hdr->algo))
	{
		if (g_debug & Dbg_Errors) {
			std::cout << "Unsupported decompression algorithm." << std::endl;
			DumpHex(std::cout, compressed.data(), compressed.size());
		}
		return fail("algorithm", 0, "unsupported");
	}

	if (IsDecompAlgoInRsrc(hdr->algo))
	{
		std::vector<uint8_t> rsrc;
		size_t k;

		bool rc = dir.GetAttribute(rsrc, ino, "com.apple.ResourceFork");

		if (!rc)
			return fail("rsrc", 0, "missing");

		std::vector<RfBlockRecord> records;
		size_t base = 0;
		const char *reason = nullptr;

		if (hdr->algo == 4)
		{
			if (!ParseType4Table(rsrc, logical_size, base, records, &reason))
				return fail("rsrc_table", 0, reason);
		}
		else
		{
			if (!ParseOffsetTable(rsrc, logical_size, records, &reason))
				return fail("rsrc_table", 0, reason);
			base = 0;
		}

		if (!ResizeExact(decompressed, logical_size, &reason))
			return fail("allocate", 0, reason);

		size_t zlib_blocks = 0;
		size_t missing_blocks = 0;
		std::vector<std::string> validation_lines;

		for (k = 0; k < records.size(); k++)
		{
			const uint64_t logical_off = static_cast<uint64_t>(k) * kDecmpfsBlockSize;
			const size_t expected = static_cast<size_t>(std::min<uint64_t>(
				kDecmpfsBlockSize, logical_size - logical_off));
			uint8_t *dst = decompressed.data() + static_cast<size_t>(logical_off);
			const uint8_t *src = rsrc.data() + base + records[k].off;
			const size_t src_len = records[k].size;
			size_t decoded_bytes = 0;

			if (hdr->algo == 4)
			{
				bool missing_adler = false;

				if (src[0] == 0x78)
				{
					decoded_bytes = DecompressZLib(dst, expected, src, src_len,
						true, &missing_adler);
					zlib_blocks++;
					if (missing_adler)
						missing_blocks++;
				}
				else if ((src[0] & 0x0F) == 0x0F)
				{
					if (src_len != expected + 1)
						return fail("block", k, "raw_marker_length");
					std::memcpy(dst, src + 1, expected);
					decoded_bytes = expected;
				}
				else
				{
					return fail("block", k, "block_marker");
				}

				if (decoded_bytes != expected)
					return fail("block", k, "decoded_length");

				if (src[0] == 0x78)
				{
					try
					{
						validation_lines.push_back(FormatValidation(ino, algo, k,
							src_len, expected, decoded_bytes, missing_adler));
					}
					catch (const std::bad_alloc &)
					{
						return fail("allocate", k, "diagnostic");
					}
				}
			}
			else
			{
				switch (hdr->algo) {
				case 8:
					if (src[0] == 0x06) {
						if (src_len != expected + 1)
							return fail("block", k, "raw_marker_length");
						std::memcpy(dst, src + 1, expected);
						decoded_bytes = expected;
					}
					else
						decoded_bytes = DecompressLZVN(dst, expected, src, src_len);
					break;
				case 10:
					if (src_len != expected + 1)
						return fail("block", k, "raw_marker_length");
					std::memcpy(dst, src + 1, expected);
					decoded_bytes = expected;
					break;
				case 12:
					decoded_bytes = DecompressLZFSE(dst, expected, src, src_len);
					break;
				case 14:
					if (src[0] == 0xFF) {
						if (src_len != expected + 1)
							return fail("block", k, "raw_marker_length");
						std::memcpy(dst, src + 1, expected);
						decoded_bytes = expected;
					}
					else
						decoded_bytes = DecompressLZBITMAP(dst, expected, src, src_len);
					break;
				default:
					return fail("block", k, "unsupported");
				}

				if (decoded_bytes != expected)
					return fail("block", k, "decoded_length");
			}
		}

		// Emit per-block validation only after the whole object decoded, so a
		// failure later in the object cannot leave a success-looking line.
		for (size_t i = 0; i < validation_lines.size(); i++)
			EmitLine(validation_lines[i]);

		if (result)
		{
			result->accepted_missing_adler = missing_blocks != 0;
			result->zlib_block_count = zlib_blocks;
			result->missing_adler_block_count = missing_blocks;
		}
	}
	else
	{
		const char *reason = nullptr;
		if (!ResizeExact(decompressed, logical_size, &reason))
			return fail("allocate", 0, reason);

		if (csize == 0)
			return fail("inline", 0, "payload_short");

		size_t decoded_bytes = 0;

		switch (hdr->algo) {
		case 3:
			if (cdata[0] == 0x78)
			{
				bool missing_adler = false;
				decoded_bytes = DecompressZLib(decompressed.data(), decompressed.size(),
					cdata, csize, true, &missing_adler);
				if (decoded_bytes == decompressed.size())
				{
					try
					{
						EmitLine(FormatValidation(ino, algo, 0, csize,
							decompressed.size(), decoded_bytes, missing_adler));
					}
					catch (const std::bad_alloc &)
					{
						return fail("allocate", 0, "diagnostic");
					}
					if (result)
					{
						result->accepted_missing_adler = missing_adler;
						result->zlib_block_count = 1;
						result->missing_adler_block_count = missing_adler ? 1 : 0;
					}
				}
			}
			else if (cdata[0] == 0xFF) {
				if (logical_size != csize - 1)
					return fail("inline", 0, "raw_marker_length");
				decompressed.assign(cdata + 1, cdata + csize);
				decoded_bytes = decompressed.size();
			}
			else
				return fail("inline", 0, "zlib_marker");
			break;

		case 7:
			if (cdata[0] == 0x06) {
				if (logical_size != csize - 1)
					return fail("inline", 0, "raw_marker_length");
				decompressed.assign(cdata + 1, cdata + csize);
				decoded_bytes = decompressed.size();
			}
			else
				decoded_bytes = DecompressLZVN(decompressed.data(), decompressed.size(), cdata, csize);
			break;

		case 9:
			if (cdata[0] != 0xCC || logical_size != csize - 1)
				return fail("inline", 0, "raw_marker_length");
			decompressed.assign(cdata + 1, cdata + csize);
			decoded_bytes = decompressed.size();
			break;

		case 11:
			// TODO uncompressed variant?
			decoded_bytes = DecompressLZFSE(decompressed.data(), decompressed.size(), cdata, csize);
			break;

		case 13:
			if (cdata[0] == 0xFF) {
				if (logical_size != csize - 1)
					return fail("inline", 0, "raw_marker_length");
				decompressed.assign(cdata + 1, cdata + csize);
				decoded_bytes = decompressed.size();
			}
			else
				decoded_bytes = DecompressLZBITMAP(decompressed.data(), decompressed.size(), cdata, csize);
			break;

		default:
			return fail("inline", 0, "unsupported");
		}

		if (decoded_bytes != logical_size)
			return fail("inline", 0, "decoded_length");
	}

#else
	if (IsDecompAlgoInRsrc(hdr->algo))
	{
		dir.GetAttribute(decompressed, ino, "com.apple.ResourceFork");
	}
	else
	{
		decompressed = compressed;
	}
#endif

	return true;
}
