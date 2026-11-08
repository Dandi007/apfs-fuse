// Synthetic tests for the reader's error/visibility policy.
// These do not need an APFS image: they exercise the decision helpers that
// ApfsDir and the FUSE layer use for xattr replies, the Unicode fallback and
// the backup-view compression classification.

#include "ApfsLib/Decmpfs.h"
#include "ApfsLib/ReaderPolicy.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

static void require(bool ok, const char *message)
{
	if (!ok)
	{
		std::cerr << "FAIL: " << message << std::endl;
		std::exit(1);
	}
}

static void test_xattr_reply()
{
	require(PlanXattrReply(100, 0) == XattrReply::Size, "size query");
	require(PlanXattrReply(100, 50) == XattrReply::ERange, "short user buffer must be ERANGE");
	require(PlanXattrReply(100, 100) == XattrReply::Value, "exact buffer");
	require(PlanXattrReply(100, 101) == XattrReply::Value, "large buffer");
	require(PlanXattrReply(0, 0) == XattrReply::Size, "empty size query");
	require(PlanXattrReply(0, 1) == XattrReply::Value, "empty value");
	require(PlanXattrReply(APFS_XATTR_VALUE_MAX, 0) == XattrReply::Size, "64 KiB value is legal");
	require(PlanXattrReply(APFS_XATTR_VALUE_MAX + 1, 0) == XattrReply::TooLarge, "oversize size query");
	require(PlanXattrReply(APFS_XATTR_VALUE_MAX + 1, APFS_XATTR_VALUE_MAX) == XattrReply::TooLarge,
		"oversize value must not be truncated");
}

static void test_raw_name_match()
{
	const char *name = "file.txt";
	require(RawNameEquals(reinterpret_cast<const uint8_t *>(name), 9, name), "exact name");
	require(!RawNameEquals(reinterpret_cast<const uint8_t *>("File.txt"), 9, name), "case is not aliased");
	require(!RawNameEquals(reinterpret_cast<const uint8_t *>("file.txt2"), 10, name), "length mismatch");

	// U+1F9E8: the code point that triggered the original lookup ENOENTs.
	const char utf8_bear[] = "\xF0\x9F\xA7\xA8";
	require(RawNameEquals(reinterpret_cast<const uint8_t *>(utf8_bear), sizeof(utf8_bear), utf8_bear),
		"unknown code point exact bytes");
	require(!RawNameEquals(reinterpret_cast<const uint8_t *>(utf8_bear), sizeof(utf8_bear), "x"),
		"different unknown name");

	// NFC "é" (C3 A9) and NFD "e" + U+0301 (65 CC 81) are different raw bytes.
	const char nfc[] = "\xC3\xA9";
	const char nfd[] = "e\xCC\x81";
	require(!RawNameEquals(reinterpret_cast<const uint8_t *>(nfc), sizeof(nfc), nfd),
		"normalization variants are not aliased");

	uint8_t trailing[10];
	std::memcpy(trailing, "file.txt", 8);
	trailing[8] = 0;
	trailing[9] = 'x';
	require(!RawNameEquals(trailing, sizeof(trailing), name), "trailing bytes rejected");
}

static void test_compression_classification()
{
	CompressionMeta meta = {};

	require(ClassifyCompression(meta) == CompressionClass::None, "plain file");
	require(!HidesDecmpfs(CompressionClass::None), "plain file hides nothing");

	meta.compressed_flag = true;
	meta.decmpfs_io_error = true;
	require(ClassifyCompression(meta) == CompressionClass::IoError, "decmpfs I/O error");

	meta = {};
	meta.compressed_flag = true;
	require(ClassifyCompression(meta) == CompressionClass::MissingHeader, "missing decmpfs");

	meta = {};
	meta.compressed_flag = true;
	meta.decmpfs_found = true;
	require(ClassifyCompression(meta) == CompressionClass::InvalidHeader, "invalid header");

	meta = {};
	meta.compressed_flag = true;
	meta.decmpfs_found = true;
	meta.header_valid = true;
	meta.algo = 99;
	require(ClassifyCompression(meta) == CompressionClass::UnsupportedAlgorithm, "unknown algorithm");

	meta = {};
	meta.compressed_flag = true;
	meta.decmpfs_found = true;
	meta.header_valid = true;
	meta.algo = 9; // uncompressed, inline
	meta.decmpfs_attr_size = 17; // header plus payload
	require(ClassifyCompression(meta) == CompressionClass::InlineAttr, "inline algorithm");
	require(HidesDecmpfs(CompressionClass::InlineAttr), "inline hides decmpfs");
	require(!HidesResourceFork(CompressionClass::InlineAttr), "inline keeps real user RF");

	meta.decmpfs_attr_size = sizeof(CompressionHeader);
	require(ClassifyCompression(meta) == CompressionClass::InvalidHeader,
		"inline algorithm without a payload is invalid");

	meta.decmpfs_attr_size = 17;
	meta.has_inode_uncompressed_size = true;
	meta.inode_uncompressed_size = 101;
	meta.uncompressed_size = 100;
	require(ClassifyCompression(meta) == CompressionClass::InvalidHeader,
		"inode size must match the header size");

	meta.inode_uncompressed_size = 100;
	require(ClassifyCompression(meta) == CompressionClass::InlineAttr,
		"matching inode size is accepted");
	require(ClassifyCompression(meta, 50) == CompressionClass::TooLarge,
		"configured decompression limit");

	meta = {};
	meta.compressed_flag = true;
	meta.decmpfs_found = true;
	meta.header_valid = true;
	meta.algo = 4; // zlib, resource fork
	meta.decmpfs_attr_size = sizeof(CompressionHeader);
	require(ClassifyCompression(meta) == CompressionClass::MissingCarrier, "missing RF carrier");

	meta.resource_fork_found = true;
	require(ClassifyCompression(meta) == CompressionClass::ResourceFork, "RF algorithm with carrier");
	require(HidesDecmpfs(CompressionClass::ResourceFork), "RF hides decmpfs");
	require(HidesResourceFork(CompressionClass::ResourceFork), "RF hides carrier");

	meta.resource_fork_found = false;
	meta.resource_fork_io_error = true;
	require(ClassifyCompression(meta) == CompressionClass::IoError, "RF lookup I/O error");

	require(CompressionClassIsError(CompressionClass::MissingHeader), "missing header is an error");
	require(CompressionClassIsError(CompressionClass::InvalidHeader), "invalid header is an error");
	require(CompressionClassIsError(CompressionClass::UnsupportedAlgorithm), "unknown algo is an error");
	require(CompressionClassIsError(CompressionClass::MissingCarrier), "missing carrier is an error");
	require(CompressionClassIsError(CompressionClass::TooLarge), "oversize decompression is an error");
	require(CompressionClassIsError(CompressionClass::IoError), "I/O failure is an error");
	require(!CompressionClassIsError(CompressionClass::InlineAttr), "inline is not an error");
	require(!CompressionClassIsError(CompressionClass::ResourceFork), "RF is not an error");
	require(!CompressionClassIsError(CompressionClass::None), "plain is not an error");
}

static void test_header_parsing()
{
	CompressionHeader hdr;
	hdr.signature = DECMPFS_MAGIC;
	hdr.algo = 9;
	hdr.size = 12345;

	DecmpfsHeader parsed = {};
	require(ParseDecmpfsHeader(&hdr, sizeof(hdr), parsed), "valid decmpfs header");
	require(parsed.signature == DECMPFS_MAGIC, "signature");
	require(parsed.algo == 9, "algorithm");
	require(parsed.uncompressed_size == 12345, "uncompressed size");
	require(!ParseDecmpfsHeader(&hdr, sizeof(hdr) - 1, parsed), "short header rejected");

	hdr.signature = 0x12345678;
	require(!ParseDecmpfsHeader(&hdr, sizeof(hdr), parsed), "bad magic rejected");
	require(!ParseDecmpfsHeader(nullptr, 0, parsed), "null data rejected");
}

int main()
{
	test_xattr_reply();
	test_raw_name_match();
	test_compression_classification();
	test_header_parsing();

	std::cout << "reader policy tests passed" << std::endl;
	return 0;
}
