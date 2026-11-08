#include "RfContent.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>

namespace
{
	const size_t kPageSize = 4096;
	const size_t kPagesPerGroup = 4;
	const char kTextAlphabet[] =
		"APFS-resource-fork golden content: 0123456789 abcdefghijklmnopqrstuvwxyz "
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ, deterministic bytes | ";
	const size_t kTextAlphabetLen = sizeof(kTextAlphabet) - 1;

	size_t BlockCount(uint64_t size)
	{
		return static_cast<size_t>((size + RF_BLOCK_SIZE - 1) / RF_BLOCK_SIZE);
	}

	uint32_t Mix32(uint32_t value)
	{
		value ^= value >> 16;
		value *= 0x7FEB352Du;
		value ^= value >> 15;
		value *= 0x846CA68Bu;
		value ^= value >> 16;
		return value;
	}

	size_t WriteBlockHeader(uint8_t *dst, size_t room, RfContentKind kind,
		size_t block, size_t blocks, size_t length)
	{
		char header[96];
		const int written = std::snprintf(header, sizeof(header),
			"RF-GOLDEN kind=%u block=%zu/%zu length=%zu;",
			static_cast<unsigned>(kind), block, blocks, length);
		if (written <= 0)
			return 0;
		const size_t copy = std::min<size_t>(room, static_cast<size_t>(written));
		std::memcpy(dst, header, copy);
		return copy;
	}

	// Single-block content stays small enough for an embedded xattr: a short
	// periodic text pattern compresses to a few hundred bytes per 64 KiB block.
	void FillTextBlock(std::vector<uint8_t> &out, RfContentKind kind,
		size_t begin, size_t end, size_t block, size_t blocks)
	{
		const size_t header = WriteBlockHeader(out.data() + begin, end - begin,
			kind, block, blocks, end - begin);
		const uint32_t salt = static_cast<uint32_t>(kind) * 13;
		for (size_t i = begin + header; i < end; i++)
			out[i] = static_cast<uint8_t>(
				kTextAlphabet[(i * 7 + salt + block * 29) % kTextAlphabetLen]);
	}

	// Multi-block content repeats each 4 KiB pseudo-random page four times.
	// The carrier therefore stays above the APFS embedded-xattr limit and is
	// stored as a dstream, like a real large resource fork, while still
	// compressing enough for zlib and LZVN to find matches.
	void FillPageBlock(std::vector<uint8_t> &out, RfContentKind kind,
		size_t begin, size_t end, size_t block, size_t blocks)
	{
		const size_t header = WriteBlockHeader(out.data() + begin, end - begin,
			kind, block, blocks, end - begin);
		for (size_t i = begin + header; i < end; i++)
		{
			const size_t page = i / kPageSize;
			const uint32_t group = static_cast<uint32_t>(page / kPagesPerGroup) +
				static_cast<uint32_t>(kind) * 1000u + static_cast<uint32_t>(block) * 7919u;
			out[i] = static_cast<uint8_t>(Mix32(static_cast<uint32_t>(i % kPageSize) ^
				(group * 0x9E3779B1u)));
		}
	}
}

uint64_t RfContentSize(RfContentKind kind)
{
	switch (kind)
	{
	case RfContentKind::ZlibSingle:
	case RfContentKind::LzvnSingle:
		return RF_SINGLE_SIZE;
	case RfContentKind::ZlibMulti:
	case RfContentKind::LzvnMulti:
		return RF_MULTI_SIZE;
	}
	return 0;
}

void FillRfContent(std::vector<uint8_t> &out, RfContentKind kind)
{
	const uint64_t size = RfContentSize(kind);
	const size_t blocks = BlockCount(size);
	const bool multi = kind == RfContentKind::ZlibMulti ||
		kind == RfContentKind::LzvnMulti;

	out.assign(static_cast<size_t>(size), 0);

	for (size_t block = 0; block < blocks; block++)
	{
		const size_t begin = block * RF_BLOCK_SIZE;
		const size_t end = std::min<size_t>(static_cast<size_t>(size),
			begin + RF_BLOCK_SIZE);
		if (multi)
			FillPageBlock(out, kind, begin, end, block, blocks);
		else
			FillTextBlock(out, kind, begin, end, block, blocks);
	}
}

const char *RfContentSha256Hex(RfContentKind kind)
{
	switch (kind)
	{
	case RfContentKind::ZlibSingle:
		return "2b47f9d9b733211adfd5b9df4a6b8c6588484460044f256cf1afd4ca4291f7ba";
	case RfContentKind::ZlibMulti:
		return "5d694d5ee57aaac2e0654e852c6a48f54f8c43cc24209ecf2dcedad3828007ba";
	case RfContentKind::LzvnSingle:
		return "9d818af1daa0ddaa4bcfc3644c3afddb9d1b96b485d3361f84b0be875295e852";
	case RfContentKind::LzvnMulti:
		return "39df88537b4c33765f79d63e1d6ce4f09b65cae0758667658da2169b94fde121";
	}
	return "";
}
