// Synthetic fault tests for extent reads. The fake source lets us inject
// tree lookup failures, device read failures, holes, malformed extents and
// boundary overflows without touching a real APFS image or block device.

#include "ApfsLib/ExtentReader.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <vector>

static void require(bool ok, const char *message)
{
	if (!ok)
	{
		std::cerr << "FAIL: " << message << std::endl;
		std::exit(1);
	}
}

class FakeSource : public ExtentSource
{
public:
	struct Extent
	{
		uint64_t logical;
		uint64_t length;
		uint64_t phys;
		uint64_t crypto;
	};

	uint32_t block_size = 8;
	std::vector<Extent> extents;
	std::map<uint64_t, std::vector<uint8_t>> blocks;

	bool fail_lookup = false;
	bool fail_next = false;
	bool fail_read = false;
	bool force_extent = false;
	Extent forced = {};

	uint64_t lookup_calls = 0;
	uint64_t next_calls = 0;
	std::vector<uint64_t> read_paddrs;
	std::vector<uint64_t> read_cryptos;

	IoStatus LookupExtent(uint64_t ino, uint64_t offs, ExtentInfo &out) override
	{
		(void)ino;
		lookup_calls++;

		if (fail_lookup)
			return IoStatus::IoError;

		if (force_extent)
		{
			out.logical_addr = forced.logical;
			out.length = forced.length;
			out.phys_block = forced.phys;
			out.crypto_id = forced.crypto;
			return IoStatus::Ok;
		}

		const Extent *best = nullptr;
		for (size_t k = 0; k < extents.size(); k++)
		{
			if (extents[k].logical <= offs && (!best || extents[k].logical > best->logical))
				best = &extents[k];
		}

		if (!best)
			return IoStatus::NotFound;

		out.logical_addr = best->logical;
		out.length = best->length;
		out.phys_block = best->phys;
		out.crypto_id = best->crypto;
		return IoStatus::Ok;
	}

	IoStatus NextExtentStart(uint64_t ino, uint64_t offs, bool &found, uint64_t &start) override
	{
		(void)ino;
		next_calls++;

		if (fail_next)
			return IoStatus::IoError;

		const Extent *best = nullptr;
		for (size_t k = 0; k < extents.size(); k++)
		{
			if (extents[k].logical >= offs && (!best || extents[k].logical < best->logical))
				best = &extents[k];
		}

		found = best != nullptr;
		if (found)
			start = best->logical;
		return IoStatus::Ok;
	}

	bool ReadBlocks(void *data, uint64_t paddr, uint64_t blkcnt, uint64_t crypto_id) override
	{
		read_paddrs.push_back(paddr);
		read_cryptos.push_back(crypto_id);

		if (fail_read)
			return false;

		for (uint64_t k = 0; k < blkcnt; k++)
		{
			std::map<uint64_t, std::vector<uint8_t>>::const_iterator it = blocks.find(paddr + k);
			if (it == blocks.end())
				return false;
			std::memcpy(reinterpret_cast<uint8_t *>(data) + k * block_size,
				it->second.data(), block_size);
		}
		return true;
	}

	uint32_t BlockSize() const override
	{
		return block_size;
	}

	void add_extent(uint64_t logical, uint64_t length, uint64_t phys, uint64_t crypto = 0)
	{
		Extent e;
		e.logical = logical;
		e.length = length;
		e.phys = phys;
		e.crypto = crypto;
		extents.push_back(e);

		// Fill data by logical offset so tests can compare read buffers
		// directly against the requested logical range.
		for (uint64_t off = 0; off < length; off += block_size)
		{
			std::vector<uint8_t> block(block_size);
			for (uint32_t k = 0; k < block_size; k++)
				block[k] = static_cast<uint8_t>((logical + off + k) & 0xFF);
			blocks[phys + off / block_size] = block;
		}
	}
};

static uint8_t pattern(uint64_t byte)
{
	return static_cast<uint8_t>(byte & 0xFF);
}

static void expect_pattern(const std::vector<uint8_t> &buf, size_t begin, size_t end,
	uint64_t logical_base = 0)
{
	for (size_t k = begin; k < end; k++)
		require(buf[k] == pattern(logical_base + k), "unexpected data byte");
}

static void expect_zero(const std::vector<uint8_t> &buf, size_t begin, size_t end)
{
	for (size_t k = begin; k < end; k++)
		require(buf[k] == 0, "expected a hole");
}

static FakeSource make_source()
{
	FakeSource src;
	src.add_extent(0, 24, 10, 100);
	src.add_extent(64, 16, 20, 200);
	return src;
}

static IoStatus read_all(FakeSource &src, uint64_t offs, size_t size, uint64_t file_size,
	bool sparse, std::vector<uint8_t> &out)
{
	out.assign(size, 0xAA);
	return ReadFileInternal(src, out.data(), 1, offs, size, file_size, sparse);
}

static void test_contiguous_read()
{
	FakeSource src = make_source();
	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 0, 24, 80, false, out);

	require(st == IoStatus::Ok, "contiguous read");
	expect_pattern(out, 0, 24);
	require(src.read_paddrs.size() == 1 && src.read_paddrs[0] == 10, "full-block read start");
	require(src.read_cryptos.size() == 1 && src.read_cryptos[0] == 100, "crypto id follows block index");
}

static void test_unaligned_read()
{
	FakeSource src = make_source();
	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 3, 5, 80, false, out);

	require(st == IoStatus::Ok, "unaligned read");
	expect_pattern(out, 0, 5, 3);
	require(src.read_paddrs.size() == 1 && src.read_paddrs[0] == 10, "partial read first block");
}

static void test_interior_hole()
{
	FakeSource src = make_source();
	std::vector<uint8_t> out;

	IoStatus st = read_all(src, 0, 80, 80, true, out);
	require(st == IoStatus::Ok, "sparse read with interior hole");
	expect_pattern(out, 0, 24);
	expect_zero(out, 24, 64);
	expect_pattern(out, 64, 80);

	st = read_all(src, 24, 40, 80, false, out);
	require(st == IoStatus::IoError, "hole without sparse metadata is an error");
}

static void test_leading_hole()
{
	FakeSource src;
	src.add_extent(64, 16, 20);

	std::vector<uint8_t> out;
	IoStatus st = read_all(src, 0, 64, 80, true, out);
	require(st == IoStatus::Ok, "leading hole");
	expect_zero(out, 0, 64);

	st = read_all(src, 0, 64, 80, false, out);
	require(st == IoStatus::IoError, "leading hole without sparse metadata");
}

static void test_trailing_hole()
{
	FakeSource src;
	src.add_extent(0, 24, 10);

	std::vector<uint8_t> out;
	IoStatus st = read_all(src, 24, 56, 80, true, out);
	require(st == IoStatus::Ok, "trailing hole");
	expect_zero(out, 0, 56);

	st = read_all(src, 24, 56, 80, false, out);
	require(st == IoStatus::IoError, "trailing hole without sparse metadata");
}

static void test_lookup_failure_is_not_a_hole()
{
	FakeSource src = make_source();
	src.fail_lookup = true;

	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 0, 16, 80, true, out);
	require(st == IoStatus::IoError, "lookup failure must be EIO");
	for (size_t k = 0; k < out.size(); k++)
		require(out[k] == 0xAA, "lookup failure must not zero-fill");
}

static void test_next_extent_failure()
{
	FakeSource src = make_source();
	src.fail_next = true;

	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 24, 8, 80, true, out);
	require(st == IoStatus::IoError, "next-extent failure inside a hole is EIO");
}

static void test_read_failure()
{
	FakeSource src = make_source();
	src.fail_read = true;

	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 0, 8, 80, false, out);
	require(st == IoStatus::IoError, "device read failure is EIO");
}

static void test_zero_length_extent()
{
	FakeSource src;
	src.force_extent = true;
	src.forced = {0, 0, 10, 0};

	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 0, 8, 80, false, out);
	require(st == IoStatus::IoError, "zero-length extent is an error");
}

static void test_extent_start_after_offset()
{
	FakeSource src;
	src.force_extent = true;
	src.forced = {100, 8, 10, 0};

	std::vector<uint8_t> out;
	IoStatus st = read_all(src, 0, 16, 200, false, out);
	require(st == IoStatus::IoError, "extent after offset without sparse metadata");

	st = read_all(src, 0, 16, 200, true, out);
	require(st == IoStatus::Ok, "sparse gap before a later extent");
	expect_zero(out, 0, 16);
}

static void test_unsigned_boundaries()
{
	FakeSource src;
	std::vector<uint8_t> out;

	IoStatus st = read_all(src, std::numeric_limits<uint64_t>::max() - 4, 16,
		std::numeric_limits<uint64_t>::max(), false, out);
	require(st == IoStatus::IoError, "offset plus size overflow");

	src.force_extent = true;
	src.forced = {std::numeric_limits<uint64_t>::max() - 4, 16, 10, 0};
	st = read_all(src, std::numeric_limits<uint64_t>::max() - 4, 2,
		std::numeric_limits<uint64_t>::max(), false, out);
	require(st == IoStatus::IoError, "extent logical plus length overflow");
}

static void test_eof_clamp()
{
	FakeSource src = make_source();
	std::vector<uint8_t> out;

	IoStatus st = read_all(src, 100, 16, 80, false, out);
	require(st == IoStatus::Ok, "read at EOF");
	require(src.lookup_calls == 0, "read at EOF must not touch the tree");

	st = read_all(src, 16, 16, 20, false, out);
	require(st == IoStatus::Ok, "read clamped to EOF");
	expect_pattern(out, 0, 4, 16);
	for (size_t k = 4; k < out.size(); k++)
		require(out[k] == 0xAA, "bytes after the clamp must stay untouched");
}

static void test_explicit_unmapped_extent()
{
	FakeSource src;
	src.force_extent = true;
	src.forced = {0, 8, 0, 0};

	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 0, 8, 8, false, out);
	require(st == IoStatus::Ok, "physical block 0 extent is a hole");
	expect_zero(out, 0, 8);
	require(src.read_paddrs.empty(), "unmapped extent must not read blocks");
}

static void test_full_read_crypto_offset()
{
	FakeSource src = make_source();
	std::vector<uint8_t> out;
	const IoStatus st = read_all(src, 8, 16, 80, false, out);

	require(st == IoStatus::Ok, "read crossing block boundary");
	expect_pattern(out, 0, 16, 8);
	require(src.read_paddrs.size() == 1 && src.read_paddrs[0] == 11, "block index included in read");
	require(src.read_cryptos.size() == 1 && src.read_cryptos[0] == 101, "crypto index included in read");
}

int main()
{
	test_contiguous_read();
	test_unaligned_read();
	test_interior_hole();
	test_leading_hole();
	test_trailing_hole();
	test_lookup_failure_is_not_a_hole();
	test_next_extent_failure();
	test_read_failure();
	test_zero_length_extent();
	test_extent_start_after_offset();
	test_unsigned_boundaries();
	test_eof_clamp();
	test_explicit_unmapped_extent();
	test_full_read_crypto_offset();

	std::cout << "extent reader tests passed" << std::endl;
	return 0;
}
