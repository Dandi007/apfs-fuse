// libapfs-level integration test over a deterministic synthetic APFS image.
// The fixture builder uses mkapfs for the container/omap/volume metadata and
// rewrites the file-system tree with the reader edge cases under test.

#include "ApfsFixture.h"
#include "RfContent.h"

#include "ApfsLib/ApfsContainer.h"
#include "ApfsLib/ApfsDir.h"
#include "ApfsLib/ApfsVolume.h"
#include "ApfsLib/CompressionView.h"
#include "ApfsLib/Decmpfs.h"
#include "ApfsLib/Device.h"
#include "ApfsLib/ReaderPolicy.h"
#include "Crypto/Sha256.h"

#include <chrono>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

static void require(bool ok, const std::string &message)
{
	if (!ok)
	{
		std::cerr << "FAIL: " << message << std::endl;
		std::exit(1);
	}
}

static std::string Sha256Hex(const std::vector<uint8_t> &data)
{
	SHA256 sha;
	uint8_t digest[32];
	static const char kHex[] = "0123456789abcdef";

	sha.Init();
	sha.Update(data.data(), data.size());
	sha.Final(digest);

	std::string out;
	for (size_t k = 0; k < sizeof(digest); k++)
	{
		out.push_back(kHex[digest[k] >> 4]);
		out.push_back(kHex[digest[k] & 0x0F]);
	}
	return out;
}

static void requireBytes(const std::vector<uint8_t> &actual,
	const std::vector<uint8_t> &expected, const std::string &what)
{
	require(actual.size() == expected.size(),
		what + ": size " + std::to_string(actual.size()) + " != " +
		std::to_string(expected.size()));
	for (size_t k = 0; k < actual.size(); k++)
	{
		if (actual[k] == expected[k])
			continue;
		char message[192];
		std::snprintf(message, sizeof(message),
			"%s: byte %zu is 0x%02X, expected 0x%02X", what.c_str(), k,
			static_cast<unsigned>(actual[k]), static_cast<unsigned>(expected[k]));
		require(false, message);
	}
}

static void TestResourceForkContent(ApfsDir &dir);
static void TestHardLinkAliases(ApfsDir &dir);
static void TestGoodNoLinkImage(const std::string &good_path,
	const std::string &nolink_path);
static void TestBadLayoutUnchanged(const std::string &bad_path);
static void TestMissingAdlerDiagnostics(ApfsDir &dir, const std::string &image_path);
static void TestRfBoundsRejects(ApfsDir &dir, const std::string &image_path);
static void TestInlineZlibContent(ApfsDir &dir, const std::string &image_path);
static void TestObjectDiagnostics(ApfsDir &dir, const std::string &image_path);
static void TestConcurrentObjectLogs(const std::string &image_path);
static size_t CountOccurrences(const std::string &text, const std::string &needle);

// Captures std::cerr for one call so the test can assert the zlib failure
// diagnostic without flooding the normal test output.
class CerrCapture
{
public:
	CerrCapture() : m_old(std::cerr.rdbuf(m_buffer.rdbuf())) {}
	~CerrCapture() { std::cerr.rdbuf(m_old); }

	std::string str() const { return m_buffer.str(); }

private:
	std::ostringstream m_buffer;
	std::streambuf *m_old;
};

static std::string FindDiagnosticLine(const std::string &log, const std::string &kind)
{
	const std::string needle = kind + " ";
	std::string found;
	size_t pos = 0;

	while ((pos = log.find(needle, pos)) != std::string::npos)
	{
		const size_t end = log.find('\n', pos);
		require(found.empty(), "multiple " + kind + " lines");
		found = log.substr(pos, end == std::string::npos ?
			std::string::npos : end - pos);
		pos = end == std::string::npos ? log.size() : end;
	}

	require(!found.empty(), "missing " + kind + " line");
	return found;
}

static std::string LineField(const std::string &line, const std::string &name)
{
	const std::string key = name + "=";
	const size_t pos = line.find(key);
	require(pos != std::string::npos, "missing field " + name + " in: " + line);
	const size_t begin = pos + key.size();
	const size_t end = line.find_first_of(" \n", begin);
	return line.substr(begin, end == std::string::npos ?
		std::string::npos : end - begin);
}

static uint64_t LineU64(const std::string &line, const std::string &name)
{
	return std::strtoull(LineField(line, name).c_str(), nullptr, 10);
}

static void CheckResultCleared(const DecompressResult &result,
	const std::string &label)
{
	require(result.seq == 0 && result.logical_size == 0 &&
		result.block_count == 0 && result.zlib_block_count == 0 &&
		result.raw_block_count == 0 && result.native_block_count == 0 &&
		result.missing_adler_block_count == 0 &&
		!result.accepted_missing_adler && !result.checksum_verified,
		label + ": failure must clear every result field");
}

// Assert the fixed object-level contract for one successful decode: exactly
// one summary, matching result metadata, consistent block accounting, one
// validation line per zlib block, and a checksum claim only when every block
// was zlib with its Adler-32 trailer.
static void CheckObjectSummary(const std::string &log,
	const DecompressResult &result, const std::string &label)
{
	require(CountOccurrences(log, "APFS_DECMPFS_ERROR") == 0,
		label + ": success logged an error");
	const std::string line = FindDiagnosticLine(log, "APFS_DECMPFS_OBJECT");

	require(result.seq != 0 && LineU64(line, "seq") == result.seq,
		label + ": object seq does not match result");
	require(LineU64(line, "logical_size") == result.logical_size,
		label + ": logical_size");
	require(LineU64(line, "blocks") == result.block_count, label + ": blocks");
	require(LineU64(line, "zlib") == result.zlib_block_count, label + ": zlib");
	require(LineU64(line, "raw") == result.raw_block_count, label + ": raw");
	require(LineU64(line, "native") == result.native_block_count,
		label + ": native");
	require(LineU64(line, "missing_adler") ==
		result.missing_adler_block_count, label + ": missing_adler");
	require(CountOccurrences(log, "APFS_DECMPFS_VALIDATION") ==
		result.zlib_block_count, label + ": validation line count");

	require(result.block_count == result.zlib_block_count +
		result.raw_block_count + result.native_block_count,
		label + ": blocks != zlib + raw + native");

	const bool checksum_verified = result.block_count > 0 &&
		result.zlib_block_count == result.block_count &&
		result.missing_adler_block_count == 0;
	require(result.checksum_verified == checksum_verified,
		label + ": result checksum flag");
	require(LineU64(line, "checksum_verified") ==
		(checksum_verified ? 1u : 0u), label + ": object checksum flag");

	const std::string expected_validation = result.block_count == 0 ? "empty" :
		(checksum_verified ? "checksum" : "structure_length_only");
	require(LineField(line, "validation") == expected_validation,
		label + ": validation class");
	require(LineField(line, "result") == "ok", label + ": result field");
}

static void CheckNoObjectOrValidation(const std::string &log,
	const std::string &label)
{
	require(log.find("APFS_DECMPFS_OBJECT") == std::string::npos,
		label + ": failure must not emit an object summary");
	require(log.find("APFS_DECMPFS_VALIDATION") == std::string::npos,
		label + ": failure must not emit a validation line");
}

struct Image
{
	Device *device;
	ApfsContainer *container;
	ApfsVolume *volume;
	ApfsDir *dir;

	Image() : device(nullptr), container(nullptr), volume(nullptr), dir(nullptr) {}

	~Image()
	{
		delete dir;
		delete volume;
		delete container;
		if (device)
		{
			device->Close();
			delete device;
		}
	}
};

static bool OpenImage(const std::string &path, Image &image, std::string &error)
{
	image.device = Device::OpenDevice(path.c_str());
	if (!image.device)
	{
		error = "cannot open device";
		return false;
	}

	image.container = new ApfsContainer(image.device, 0, image.device->GetSize());
	if (!image.container->Init(0))
	{
		error = "container init failed";
		return false;
	}

	image.volume = image.container->GetVolume(0, "", 0);
	if (!image.volume)
	{
		error = "volume init failed";
		return false;
	}

	image.dir = new ApfsDir(*image.volume);
	return true;
}

static uint8_t Pattern(uint64_t logical)
{
	return static_cast<uint8_t>(logical & 0xFF);
}

static void TestGoodImage(const std::string &path)
{
	Image image;
	std::string error;
	require(OpenImage(path, image, error), "open good image: " + error);
	ApfsDir &dir = *image.dir;

	ApfsDir::DirRec res;
	IoStatus st = IoStatus::Ok;

	const std::string unicode_name = "unicode-\xF0\x9F\xA7\xA8";
	require(dir.LookupName(res, 2, unicode_name.c_str(), &st) && st == IoStatus::Ok &&
		res.file_id == 20, "Unicode fallback exact raw name");
	require(!dir.LookupName(res, 2, "casename.txt", &st) && st == IoStatus::NotFound,
		"case variant must not alias");
	require(!dir.LookupName(res, 2, "\xC3\xA9.txt", &st) && st == IoStatus::NotFound,
		"NFC variant must not alias the NFD name");
	require(!dir.LookupName(res, 2, "missing-name", &st) && st == IoStatus::NotFound,
		"missing name must be NotFound, not IoError");

	std::vector<uint8_t> buf(80, 0xAA);
	require(dir.ReadFile(buf.data(), 23, 0, 80, &st, 80) && st == IoStatus::Ok,
		"explicit phys=0 hole read");
	for (size_t k = 0; k < 24; k++)
		require(buf[k] == Pattern(k), "hole prefix data");
	for (size_t k = 24; k < 64; k++)
		require(buf[k] == 0, "explicit hole must be zero");
	for (size_t k = 64; k < 80; k++)
		require(buf[k] == Pattern(k), "hole suffix data");

	require(!dir.ReadFile(buf.data(), 24, 0, 80, &st, 80) && st == IoStatus::IoError,
		"missing extent record must be EIO");
	require(dir.ReadFile(buf.data(), 24, 0, 24, &st, 80) && st == IoStatus::Ok,
		"read before the missing record");

	std::vector<uint8_t> short_buf(8, 0xAA);
	require(!dir.ReadFile(short_buf.data(), 41, 0, 8, &st, 8) && st == IoStatus::IoError,
		"device read failure must be EIO");

	buf.assign(16, 0xAA);
	require(dir.ReadFile(buf.data(), 23, 80, 16, &st, 80) && st == IoStatus::Ok,
		"read at EOF");
	require(buf[0] == 0xAA, "read at EOF must not touch the buffer");

	ApfsDir::XAttr info;
	require(dir.GetAttributeInfo(info, 31, "com.apple.test.small", &st) && st == IoStatus::Ok &&
		(info.flags & XATTR_DATA_EMBEDDED) && info.xdata_len == 5, "embedded xattr size");
	require(dir.GetAttributeInfo(info, 31, "com.apple.test.big64k", &st) && st == IoStatus::Ok &&
		(info.flags & XATTR_DATA_STREAM) && info.xstrm.dstream.size == 65536,
		"64 KiB stream size");
	require(dir.GetAttributeInfo(info, 31, "com.apple.test.big64k1", &st) && st == IoStatus::Ok &&
		(info.flags & XATTR_DATA_STREAM) && info.xstrm.dstream.size == 65537,
		"65537-byte stream size");
	require(PlanXattrReply(65537, 0) == XattrReply::TooLarge, "65537 must be rejected before reading");

	std::vector<uint8_t> data;
	require(dir.GetAttribute(data, 31, "com.apple.test.big64k", &st) && st == IoStatus::Ok &&
		data.size() == 65536, "64 KiB stream read");
	require(data[0] == Pattern(0) && data[65535] == Pattern(65535), "64 KiB stream contents");

	ApfsDir::Inode rec;
	require(dir.GetInode(rec, 25, &st) && st == IoStatus::Ok, "inode 25");
	uint64_t usize = 0;
	uint64_t attr_size = 0;
	require(ClassifyInodeCompression(dir, rec, usize, attr_size) == CompressionClass::InlineAttr,
		"inline compression");
	require(HidesDecmpfs(CompressionClass::InlineAttr), "inline hides decmpfs");
	require(!HidesResourceFork(CompressionClass::InlineAttr), "inline keeps user RF");

	require(dir.GetInode(rec, 26, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::ResourceFork, "resource-fork compression");
	require(HidesResourceFork(CompressionClass::ResourceFork), "RF compression hides carrier");

	require(dir.GetInode(rec, 27, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::MissingCarrier, "missing RF carrier");
	require(dir.GetInode(rec, 28, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::UnsupportedAlgorithm, "unknown algorithm");
	require(dir.GetInode(rec, 29, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::None, "uncompressed file with user RF");
	require(dir.GetInode(rec, 30, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::InlineAttr, "inline file with user RF");
	require(!HidesResourceFork(CompressionClass::InlineAttr), "inline user RF is kept");
	require(dir.GetInode(rec, 32, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::InvalidHeader, "header-only inline is invalid");
	require(dir.GetInode(rec, 33, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::InvalidHeader, "inode/header size mismatch is invalid");
	require(dir.GetInode(rec, 34, &st) && ClassifyInodeCompression(dir, rec, usize, attr_size, 1000) ==
		CompressionClass::TooLarge, "configured decompression limit");
	require(ClassifyInodeCompression(dir, rec, usize, attr_size, 0) ==
		CompressionClass::InlineAttr, "unlimited decompression accepts the same inode");

	TestHardLinkAliases(dir);
	TestResourceForkContent(dir);
	TestMissingAdlerDiagnostics(dir, path);
	TestRfBoundsRejects(dir, path);
	TestInlineZlibContent(dir, path);
	TestObjectDiagnostics(dir, path);
}

// The compressed single-block fixture inode 60 has two directory entries.
// Both names must resolve to the same inode so the FUSE-level test can model
// a manifest that opens each hardlink path independently.
static void TestHardLinkAliases(ApfsDir &dir)
{
	IoStatus st = IoStatus::Ok;
	ApfsDir::DirRec primary;
	ApfsDir::DirRec alias;

	require(dir.LookupName(primary, 2, "rf-zlib-1blk", &st) && st == IoStatus::Ok,
		"hardlink primary name lookup");
	require(primary.file_id == 60, "hardlink primary name resolves to ino 60");
	require(dir.LookupName(alias, 2, "rf-zlib-1blk-hardlink", &st) && st == IoStatus::Ok,
		"hardlink alias name lookup");
	require(alias.file_id == 60, "hardlink alias resolves to ino 60");
	require(primary.file_id == alias.file_id,
		"hardlink names must share one inode");

	ApfsDir::Inode rec;
	require(dir.GetInode(rec, 60, &st) && st == IoStatus::Ok, "hardlink inode");
	require(rec.nchildren_nlink == 2, "hardlink inode nlink");
}

struct RootEntry
{
	std::string name;
	uint64_t file_id;
	uint16_t flags;
};

static std::vector<RootEntry> ListRootEntries(ApfsDir &dir, const std::string &label)
{
	std::vector<ApfsDir::DirRec> recs;
	IoStatus st = IoStatus::Ok;
	require(dir.ListDirectory(recs, 2, &st) && st == IoStatus::Ok, label + ": list root");

	std::vector<RootEntry> entries(recs.size());
	for (size_t k = 0; k < recs.size(); k++)
	{
		entries[k].name = recs[k].name;
		entries[k].file_id = recs[k].file_id;
		entries[k].flags = recs[k].flags;
	}
	std::sort(entries.begin(), entries.end(),
		[](const RootEntry &a, const RootEntry &b) { return a.name < b.name; });
	return entries;
}

// Reads every attribute and the raw extent bytes of one object. Both images
// are generated from the same records, so any difference here means the new
// fixture mode changed an object that must stay identical.
static void RequireSameObject(ApfsDir &a, ApfsDir &b, uint64_t ino,
	const std::string &label)
{
	ApfsDir::Inode ia;
	ApfsDir::Inode ib;
	IoStatus sa = IoStatus::Ok;
	IoStatus sb = IoStatus::Ok;
	const bool inode_a = a.GetInode(ia, ino, &sa);
	const bool inode_b = b.GetInode(ib, ino, &sb);
	require(inode_a == inode_b && sa == sb, label + ": inode status differs");
	if (!inode_a)
		return;
	require(sa == IoStatus::Ok, label + ": inode unavailable");

	// nchildren_nlink is compared by the hardlink tests instead: it is the
	// only inode field the two modes intentionally differ on.
	require(ia.obj_id == ib.obj_id && ia.parent_id == ib.parent_id &&
		ia.private_id == ib.private_id && ia.mode == ib.mode &&
		ia.internal_flags == ib.internal_flags && ia.bsd_flags == ib.bsd_flags &&
		ia.owner == ib.owner && ia.group == ib.group &&
		ia.uncompressed_size == ib.uncompressed_size &&
		ia.ds_size == ib.ds_size && ia.ds_alloced_size == ib.ds_alloced_size &&
		ia.sparse_bytes == ib.sparse_bytes && ia.name == ib.name,
		label + ": inode metadata differs");

	std::vector<std::string> attrs_a;
	std::vector<std::string> attrs_b;
	IoStatus xa = IoStatus::Ok;
	IoStatus xb = IoStatus::Ok;
	const bool list_a = a.ListAttributes(attrs_a, ino, &xa);
	const bool list_b = b.ListAttributes(attrs_b, ino, &xb);
	require(list_a == list_b && xa == xb, label + ": attribute list status differs");
	if (!list_a)
		return;

	std::sort(attrs_a.begin(), attrs_a.end());
	std::sort(attrs_b.begin(), attrs_b.end());
	require(attrs_a == attrs_b, label + ": attribute names differ");

	for (size_t k = 0; k < attrs_a.size(); k++)
	{
		const std::string what = label + ": attribute " + attrs_a[k];
		ApfsDir::XAttr info_a;
		ApfsDir::XAttr info_b;
		require(a.GetAttributeInfo(info_a, ino, attrs_a[k].c_str(), &sa) &&
			sa == IoStatus::Ok &&
			b.GetAttributeInfo(info_b, ino, attrs_a[k].c_str(), &sb) &&
			sb == IoStatus::Ok, what + " info");
		require(info_a.flags == info_b.flags &&
			info_a.xdata_len == info_b.xdata_len &&
			info_a.xstrm.dstream.size == info_b.xstrm.dstream.size &&
			info_a.xstrm.dstream.alloced_size ==
				info_b.xstrm.dstream.alloced_size,
			what + " metadata");

		std::vector<uint8_t> data_a;
		std::vector<uint8_t> data_b;
		require(a.GetAttribute(data_a, ino, attrs_a[k].c_str(), &sa) &&
			sa == IoStatus::Ok &&
			b.GetAttribute(data_b, ino, attrs_a[k].c_str(), &sb) &&
			sb == IoStatus::Ok, what + " read");
		requireBytes(data_a, data_b, what);
	}

	if ((ia.mode & MODE_S_IFMT) == MODE_S_IFREG && ia.ds_size != 0)
	{
		std::vector<uint8_t> data_a(static_cast<size_t>(ia.ds_size), 0xAA);
		std::vector<uint8_t> data_b(static_cast<size_t>(ib.ds_size), 0xBB);
		IoStatus ra = IoStatus::Ok;
		IoStatus rb = IoStatus::Ok;
		const bool read_a = a.ReadFile(data_a.data(), ino, 0, data_a.size(),
			&ra, ia.ds_size);
		const bool read_b = b.ReadFile(data_b.data(), ino, 0, data_b.size(),
			&rb, ib.ds_size);
		require(read_a == read_b && ra == rb, label + ": file read status differs");
		if (read_a)
			requireBytes(data_a, data_b, label + ": file data");
	}
}

// good-nolink is the good image with a single directory name for inode 60.
// Everything else must be readable and byte-identical to the good image.
static void TestGoodNoLinkImage(const std::string &good_path,
	const std::string &nolink_path)
{
	Image good_image;
	Image nolink_image;
	std::string error;
	require(OpenImage(good_path, good_image, error), "open good image: " + error);
	require(OpenImage(nolink_path, nolink_image, error),
		"open good-nolink image: " + error);
	ApfsDir &good = *good_image.dir;
	ApfsDir &nolink = *nolink_image.dir;

	IoStatus st = IoStatus::Ok;
	ApfsDir::DirRec rec;
	ApfsDir::Inode inode;

	require(nolink.LookupName(rec, 2, "rf-zlib-1blk", &st) &&
		st == IoStatus::Ok && rec.file_id == 60,
		"good-nolink primary name must resolve to ino 60");
	require(!nolink.LookupName(rec, 2, "rf-zlib-1blk-hardlink", &st) &&
		st == IoStatus::NotFound,
		"good-nolink must not expose the hardlink alias");
	require(nolink.GetInode(inode, 60, &st) && st == IoStatus::Ok &&
		inode.nchildren_nlink == 1, "good-nolink inode 60 nlink");

	// The original good image keeps both names and nlink 2.
	require(good.LookupName(rec, 2, "rf-zlib-1blk-hardlink", &st) &&
		st == IoStatus::Ok && rec.file_id == 60,
		"good must keep the hardlink alias");
	require(good.GetInode(inode, 60, &st) && st == IoStatus::Ok &&
		inode.nchildren_nlink == 2, "good inode 60 nlink");

	const std::vector<RootEntry> good_entries = ListRootEntries(good, "good");
	const std::vector<RootEntry> nolink_entries =
		ListRootEntries(nolink, "good-nolink");
	require(good_entries.size() == nolink_entries.size() + 1,
		"good root must differ from good-nolink by exactly one entry");

	size_t gi = 0;
	for (size_t ni = 0; ni < nolink_entries.size(); ni++)
	{
		while (gi < good_entries.size() &&
			good_entries[gi].name == "rf-zlib-1blk-hardlink")
			gi++;
		require(gi < good_entries.size() &&
			good_entries[gi].name == nolink_entries[ni].name,
			"root entry sets differ at " + nolink_entries[ni].name);
		require(good_entries[gi].file_id == nolink_entries[ni].file_id &&
			good_entries[gi].flags == nolink_entries[ni].flags,
			"root entry changed: " + nolink_entries[ni].name);
		gi++;
	}
	while (gi < good_entries.size() &&
		good_entries[gi].name == "rf-zlib-1blk-hardlink")
		gi++;
	require(gi == good_entries.size(), "good has unexpected extra root entries");

	for (size_t k = 0; k < nolink_entries.size(); k++)
		RequireSameObject(good, nolink, nolink_entries[k].file_id,
			"root entry " + nolink_entries[k].name);
}

// Pins the bad-tree root layout: the new mode must not add the hardlink alias
// or change any other root record.
static void TestBadLayoutUnchanged(const std::string &bad_path)
{
	Image image;
	std::string error;
	require(OpenImage(bad_path, image, error), "open bad image: " + error);
	ApfsDir &dir = *image.dir;

	IoStatus st = IoStatus::Ok;
	ApfsDir::DirRec rec;
	require(!dir.LookupName(rec, 2, "rf-zlib-1blk-hardlink", &st) &&
		st == IoStatus::NotFound, "bad image must not gain the hardlink alias");

	const char *const expected[] = {
		"CaseName.txt",
		"bad-device.bin",
		"badattrs",
		"baddir",
		"badfile",
		"e\xCC\x81.txt",
		"gap.bin",
		"hole.bin",
		"inline",
		"inline-empty",
		"inline-user-rf",
		"inline-zlib",
		"inline-zlib-corrupt",
		"inline-zlib-truncated",
		"many",
		"rf",
		"rf-lzvn-1blk",
		"rf-lzvn-multi",
		"rf-missing",
		"rf-zlib-1blk",
		"rf-zlib-multi",
		"rf-zlib-no-adler",
		"size-mismatch",
		"too-big",
		"unicode-\xF0\x9F\xA7\xA8",
		"unknown-algo",
		"user-rf",
		"xattrs"
	};
	const size_t expected_count = sizeof(expected) / sizeof(expected[0]);

	const std::vector<RootEntry> entries = ListRootEntries(dir, "bad");
	require(entries.size() == expected_count, "bad root entry count changed");
	for (size_t k = 0; k < expected_count; k++)
		require(entries[k].name == expected[k],
			"bad root entry changed: " + std::string(expected[k]) +
			" != " + entries[k].name);
}

static void TestResourceForkContent(ApfsDir &dir)
{
	struct RfCase
	{
		const char *name;
		uint64_t ino;
		RfContentKind kind;
		uint32_t algo;
		bool stream;
	};

	const RfCase cases[] = {
		{"rf-zlib-1blk", 60, RfContentKind::ZlibSingle, 4, false},
		{"rf-zlib-multi", 61, RfContentKind::ZlibMulti, 4, true},
		{"rf-lzvn-1blk", 62, RfContentKind::LzvnSingle, 8, false},
		{"rf-lzvn-multi", 63, RfContentKind::LzvnMulti, 8, true},
	};

	ApfsDir::Inode rec;
	IoStatus st = IoStatus::Ok;
	uint64_t usize = 0;
	uint64_t attr_size = 0;

	// Inode 26 keeps its classification but has no decodable carrier. This is
	// the original negative case and must not silently start working.
	require(dir.GetInode(rec, 26, &st) && st == IoStatus::Ok, "inode 26 lookup");
	require(ClassifyInodeCompression(dir, rec, usize, attr_size) ==
		CompressionClass::ResourceFork, "inode 26 still classifies as ResourceFork");
	std::vector<uint8_t> decmpfs;
	require(dir.GetAttribute(decmpfs, 26, "com.apple.decmpfs", &st) && st == IoStatus::Ok,
		"inode 26 decmpfs header");
	std::vector<uint8_t> bogus;
	require(!DecompressFile(dir, 26, bogus, decmpfs),
		"inode 26 invalid carrier must still fail decompression");

	for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
	{
		const RfCase &c = cases[k];
		const uint64_t size = RfContentSize(c.kind);
		const std::string label = c.name;

		require(dir.GetInode(rec, c.ino, &st) && st == IoStatus::Ok, label + ": inode");
		require((rec.bsd_flags & APFS_UF_COMPRESSED) != 0, label + ": compressed flag");
		require((rec.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE) != 0,
			label + ": uncompressed-size flag");
		require(rec.uncompressed_size == size, label + ": inode size");
		require(ClassifyInodeCompression(dir, rec, usize, attr_size) ==
			CompressionClass::ResourceFork, label + ": class");
		require(usize == size, label + ": classified size");
		require(attr_size == sizeof(CompressionHeader), label + ": decmpfs attr size");

		ApfsDir::XAttr info;
		require(dir.GetAttributeInfo(info, c.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok && (info.flags & XATTR_DATA_EMBEDDED) != 0 &&
			info.xdata_len == sizeof(CompressionHeader),
			label + ": decmpfs stored embedded");

		require(dir.GetAttribute(decmpfs, c.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok, label + ": decmpfs read");
		DecmpfsHeader hdr = {};
		require(ParseDecmpfsHeader(decmpfs.data(), decmpfs.size(), hdr),
			label + ": decmpfs magic");
		require(hdr.algo == c.algo, label + ": algorithm");
		require(hdr.uncompressed_size == size, label + ": header size");

		require(dir.GetAttributeInfo(info, c.ino, "com.apple.ResourceFork", &st) &&
			st == IoStatus::Ok, label + ": carrier present");
		if (c.stream)
			require((info.flags & XATTR_DATA_STREAM) != 0 &&
				info.xstrm.dstream.size > 0, label + ": carrier dstream");
		else
			require((info.flags & XATTR_DATA_EMBEDDED) != 0 &&
				info.xdata_len <= 3802, label + ": carrier embedded");

		std::vector<uint8_t> rsrc;
		require(dir.GetAttribute(rsrc, c.ino, "com.apple.ResourceFork", &st) &&
			st == IoStatus::Ok && !rsrc.empty(), label + ": carrier read");
		require(rsrc.size() < size, label + ": carrier is actually compressed");

		std::vector<uint8_t> decoded;
		require(DecompressFile(dir, c.ino, decoded, decmpfs),
			label + ": DecompressFile");

		std::vector<uint8_t> expected;
		FillRfContent(expected, c.kind);

		requireBytes(decoded, expected, label + ": byte-for-byte content");
		require(Sha256Hex(decoded) == RfContentSha256Hex(c.kind),
			label + ": golden SHA-256");
	}

	// Real user resource forks are real attributes, not compression carriers.
	std::vector<uint8_t> user_rf;
	require(dir.GetAttribute(user_rf, 29, "com.apple.ResourceFork", &st) &&
		st == IoStatus::Ok && user_rf == std::vector<uint8_t>(16, 0x66),
		"uncompressed file keeps its user resource fork");
	require(dir.GetInode(rec, 30, &st) &&
		ClassifyInodeCompression(dir, rec, usize, attr_size) == CompressionClass::InlineAttr,
		"inline file with user RF still classifies as inline");
	require(!HidesResourceFork(CompressionClass::InlineAttr),
		"inline compression does not hide the user resource fork");
}

static size_t CountOccurrences(const std::string &text, const std::string &needle)
{
	size_t count = 0;
	size_t pos = 0;
	while ((pos = text.find(needle, pos)) != std::string::npos)
	{
		count++;
		pos += needle.size();
	}
	return count;
}

// Every RF block that zlib accepts through the missing-Adler boundary must
// produce exactly one attributable line; a normal Z_STREAM_END block must be
// labelled as checksum-verified instead. The positive control is inode 67
// (carrier stored without the trailer), the control inodes 60/61 keep it.
static void TestMissingAdlerDiagnostics(ApfsDir &dir, const std::string &image_path)
{
	IoStatus st = IoStatus::Ok;

	struct Case
	{
		uint64_t ino;
		const char *name;
		size_t lines;
		bool missing_adler;
	};

	const Case cases[] = {
		{60, "rf-zlib-1blk", 1, false},
		{61, "rf-zlib-multi", 3, false},
		{67, "rf-zlib-no-adler", 1, true},
	};

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
	{
		const Case &item = cases[c];
		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, item.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok, std::string(item.name) + ": decmpfs read");

		DecompressResult result;
		std::vector<uint8_t> decoded;
		std::string log;
		bool ok = false;

		{
			CerrCapture capture;
			ok = DecompressFile(dir, item.ino, decoded, decmpfs, &result);
			log = capture.str();
		}

		require(ok, std::string(item.name) + ": DecompressFile");
		CheckObjectSummary(log, result, item.name);
		require(result.zlib_block_count == item.lines,
			std::string(item.name) + ": zlib block count");
		require(result.missing_adler_block_count ==
			(item.missing_adler ? item.lines : 0),
			std::string(item.name) + ": missing-Adler block count");
		require(result.accepted_missing_adler == item.missing_adler,
			std::string(item.name) + ": accepted_missing_adler");

		require(CountOccurrences(log, "APFS_DECMPFS_VALIDATION") == item.lines,
			std::string(item.name) + ": validation line count");
		require(log.find("APFS_DECMPFS_ERROR") == std::string::npos,
			std::string(item.name) + ": success must not log an error");
		require(log.find("ino=" + std::to_string(item.ino)) != std::string::npos,
			std::string(item.name) + ": diagnostic ino");
		require(log.find("algo=4") != std::string::npos,
			std::string(item.name) + ": diagnostic algo");
		require(log.find("compressed=") != std::string::npos,
			std::string(item.name) + ": diagnostic compressed length");
		require(log.find("expected=") != std::string::npos,
			std::string(item.name) + ": diagnostic expected length");
		require(log.find("decoded=") != std::string::npos,
			std::string(item.name) + ": diagnostic decoded length");
		require(log.find(item.missing_adler ? "validation=structure_length_only" :
			"validation=length_with_checksum") != std::string::npos,
			std::string(item.name) + ": validation class");
		require(log.find(item.missing_adler ? "missing_adler=1" : "missing_adler=0") !=
			std::string::npos, std::string(item.name) + ": missing_adler flag");
		require(log.find(image_path) == std::string::npos,
			std::string(item.name) + ": diagnostic leaks the image path");
		require(log.find(item.name) == std::string::npos,
			std::string(item.name) + ": diagnostic leaks the file name");

		if (item.ino == 61)
		{
			for (size_t block = 0; block < item.lines; block++)
				require(log.find("block=" + std::to_string(block)) != std::string::npos,
					"rf-zlib-multi: diagnostic block index");
		}
	}
	{
		std::vector<uint8_t> attr, decoded, expected;
		require(dir.GetAttribute(attr, 91, "com.apple.decmpfs", &st), "canonical attr");
		DecompressResult result;
		CerrCapture capture;
		require(DecompressFile(dir, 91, decoded, attr, &result), "canonical mixed decode");
		CheckObjectSummary(capture.str(), result, "canonical mixed decode");
		FillRfContent(expected, RfContentKind::ZlibSingle);
		auto tail = std::vector<uint8_t>(expected.begin(), expected.begin() + 12345);
		expected.insert(expected.end(), tail.begin(), tail.end());
		require(decoded == expected, "canonical mixed independent content");
		require(result.zlib_block_count == 2 && result.missing_adler_block_count == 1,
			"canonical mixed validation counts");
		require(CountOccurrences(capture.str(), "APFS_DECMPFS_VALIDATION") == 2,
			"canonical mixed log coverage");
	}
	{
		std::vector<uint8_t> attr;
		require(dir.GetAttribute(attr, 80, "com.apple.decmpfs", &st), "empty attr");
		for (uint32_t algo : {3,4,7,8,9,10,11,12,13,14})
		{
			for (size_t j = 0; j < 4; ++j) attr[4+j] = (algo >> (8*j)) & 255;
			std::vector<uint8_t> decoded(32, 0xAA);
			DecompressResult result;
			result.accepted_missing_adler = true;
			result.zlib_block_count = result.missing_adler_block_count = 7;
			std::string log;
			bool ok = false;
			{
				CerrCapture capture;
				ok = DecompressFile(dir, 80, decoded, attr, &result);
				log = capture.str();
			}
			require(ok, "empty supported algorithm");
			require(decoded.empty() && !result.accepted_missing_adler &&
				result.zlib_block_count == 0 && result.missing_adler_block_count == 0,
				"empty output and metadata reset");
			CheckObjectSummary(log, result, "empty supported algorithm");
		}
	}

}

// Malformed carriers in the good image are real inode/xattr records. Every
// call must fail closed, leave no success diagnostic and never trust a size
// or offset that was not validated against the declared data section.
static void TestRfBoundsRejects(ApfsDir &dir, const std::string &image_path)
{
	struct Case
	{
		uint64_t ino;
		const char *name;
		uint32_t algo;
		const char *stage;
		const char *reason;
	};

	const Case cases[] = {
		{70, "rf-bad-few-blocks", 4, "rsrc_table", "block_count"},
		{71, "rf-bad-many-blocks", 4, "rsrc_table", "block_count"},
		{72, "rf-bad-short-table", 4, "rsrc_table", "table_short"},
		{73, "rf-bad-zero-block", 4, "rsrc_table", "block_empty"},
		{74, "rf-bad-block-size", 4, "rsrc_table", "block_size"},
		{75, "rf-bad-overlap", 4, "rsrc_table", "block_overlap"},
		{76, "rf-bad-table-pointer", 4, "rsrc_table", "block_offset"},
		{77, "rf-bad-raw-length", 4, "block", "raw_marker_length"},
		{78, "rf-bad-data-offset", 4, "rsrc_table", "data_offset"},
		{79, "rf-bad-huge-size", 4, "rsrc_table", "block_count"},
		{81, "rf-bad-short-header", 4, "rsrc_table", "rsrc_header_short"},
		{82, "rf-bad-empty-carrier", 4, "rsrc", nullptr},
		{83, "rf-bad-off-table-short", 8, "rsrc_table", "table_short"},
		{84, "rf-bad-off-table-pointer", 8, "rsrc_table", "table_pointer"},
		{85, "rf-bad-off-zero", 8, "rsrc_table", "block_empty"},
		{86, "rf-bad-off-beyond", 8, "rsrc_table", "block_offset"},
		{87, "rf-bad-lzvn-raw-length", 8, "block", "raw_marker_length"},
		{88, "rf-bad-raw10-length", 10, "block", "raw_marker_length"},
		{89, "rf-bad-raw14-length", 14, "block", "raw_marker_length"},
		{90, "rf-bad-partial-decode", 4, "block", "block_marker"},
		{92, "rf-bad-map-block", 4, "rsrc_table", "block_size"},
		{94, "rf-bad-data-size-beyond", 4, "rsrc_table", "data_size"},
	};

	IoStatus st = IoStatus::Ok;

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
	{
		const Case &item = cases[c];
		const std::string label = item.name;

		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, item.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok, label + ": decmpfs read");

		DecompressResult result;
		result.accepted_missing_adler = true;
		result.zlib_block_count = 99;
		result.missing_adler_block_count = 98;
		std::vector<uint8_t> decoded(32, 0xAB);
		std::string log;
		bool ok = true;

		{
			CerrCapture capture;
			ok = DecompressFile(dir, item.ino, decoded, decmpfs, &result);
			log = capture.str();
		}

		require(!ok, label + ": malformed carrier must fail closed");
		require(decoded.empty(), label + ": stale output retained");
		require(result.zlib_block_count == 0 && result.missing_adler_block_count == 0 &&
			!result.accepted_missing_adler, label + ": failure must not report success");
		CheckResultCleared(result, label);
		CheckNoObjectOrValidation(log, label);
		require(CountOccurrences(log, "APFS_DECMPFS_ERROR") == 1,
			label + ": expected exactly one error diagnostic");
		const std::string error = FindDiagnosticLine(log, "APFS_DECMPFS_ERROR");
		require(LineU64(error, "seq") != 0, label + ": error has no seq");
		require(log.find("APFS_DECMPFS_ERROR") != std::string::npos,
			label + ": missing error diagnostic");
		require(log.find("APFS_DECMPFS_VALIDATION") == std::string::npos,
			label + ": failure must not print a success diagnostic");
		require(log.find("ino=" + std::to_string(item.ino)) != std::string::npos,
			label + ": diagnostic ino");
		require(log.find("algo=" + std::to_string(item.algo)) != std::string::npos,
			label + ": diagnostic algo");
		require(log.find("block=") != std::string::npos,
			label + ": diagnostic block");
		require(log.find(std::string("stage=") + item.stage) != std::string::npos,
			label + ": diagnostic stage " + item.stage);
		if (item.reason)
			require(log.find(std::string("reason=") + item.reason) != std::string::npos,
				label + ": diagnostic reason " + item.reason);
		require(log.find(image_path) == std::string::npos,
			label + ": diagnostic leaks the image path");
		require(log.find(item.name) == std::string::npos,
			label + ": diagnostic leaks the file name");
	}
}

static void TestInlineZlibContent(ApfsDir &dir, const std::string &image_path)
{
	struct Case
	{
		const char *name;
		uint64_t ino;
		RfContentKind kind;
		bool damaged;
	};

	const Case cases[] = {
		{"inline-zlib", 64, RfContentKind::ZlibInline, false},
		{"inline-zlib-truncated", 65, RfContentKind::ZlibInlineTruncated, true},
		{"inline-zlib-corrupt", 66, RfContentKind::ZlibInlineCorrupt, true},
	};

	ApfsDir::Inode rec;
	IoStatus st = IoStatus::Ok;
	uint64_t usize = 0;
	uint64_t attr_size = 0;

	for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
	{
		const Case &c = cases[k];
		const std::string label = c.name;
		const uint64_t size = RfContentSize(c.kind);

		require(dir.GetInode(rec, c.ino, &st) && st == IoStatus::Ok, label + ": inode");
		require((rec.bsd_flags & APFS_UF_COMPRESSED) != 0, label + ": compressed flag");
		require((rec.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE) != 0,
			label + ": uncompressed-size flag");
		require(rec.uncompressed_size == size, label + ": inode size");
		require(ClassifyInodeCompression(dir, rec, usize, attr_size) ==
			CompressionClass::InlineAttr, label + ": class");
		require(usize == size, label + ": classified size");

		ApfsDir::XAttr info;
		require(dir.GetAttributeInfo(info, c.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok && (info.flags & XATTR_DATA_EMBEDDED) != 0,
			label + ": decmpfs stored embedded");

		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, c.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok, label + ": decmpfs read");
		DecmpfsHeader hdr = {};
		require(ParseDecmpfsHeader(decmpfs.data(), decmpfs.size(), hdr),
			label + ": decmpfs magic");
		require(hdr.algo == 3, label + ": algorithm");
		require(hdr.uncompressed_size == size, label + ": header size");
		require(decmpfs.size() > sizeof(CompressionHeader) + 2,
			label + ": zlib payload present");

		const uint8_t *payload = decmpfs.data() + sizeof(CompressionHeader);
		const size_t payload_size = decmpfs.size() - sizeof(CompressionHeader);
		require(payload[0] == 0x78, label + ": zlib CMF");
		require((((payload[0] << 8) | payload[1]) % 31) == 0,
			label + ": zlib header checksum");

		if (!c.damaged)
		{
			// The low-entropy text must exercise a real Huffman block. A
			// stored block (type 0) would bypass that decoder path.
			const unsigned btype = (payload[2] >> 1) & 3;
			require(btype == 1 || btype == 2,
				label + ": expected a Huffman block, not a stored block");

			std::vector<uint8_t> decoded;
			require(DecompressFile(dir, c.ino, decoded, decmpfs),
				label + ": DecompressFile");

			std::vector<uint8_t> expected;
			FillRfContent(expected, c.kind);

			requireBytes(decoded, expected, label + ": byte-for-byte content");
			require(Sha256Hex(decoded) == RfContentSha256Hex(c.kind),
				label + ": golden SHA-256");

			std::cout << label << ": payload " << payload_size
				<< " bytes, deflate BTYPE=" << btype << std::endl;
		}
		else
		{
			std::string log;
			bool ok = true;
			long long elapsed_us = 0;

			{
				CerrCapture capture;
				const std::chrono::steady_clock::time_point start =
					std::chrono::steady_clock::now();
				std::vector<uint8_t> decoded;
				ok = DecompressFile(dir, c.ino, decoded, decmpfs);
				const std::chrono::steady_clock::time_point end =
					std::chrono::steady_clock::now();
				elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
					end - start).count();
				log = capture.str();
			}

			require(!ok, label + ": damaged zlib must fail closed");
			require(elapsed_us < 5LL * 1000 * 1000,
				label + ": damaged zlib must return in bounded time");
			require(log.find("APFS_ZLIB_ERROR") != std::string::npos,
				label + ": missing APFS_ZLIB_ERROR diagnostic");

			const char *const fields[] = {
				"ret=", "total_in=", "total_out=", "src_size=", "dst_size="
			};
			for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++)
				require(log.find(fields[f]) != std::string::npos,
					label + ": diagnostic missing " + fields[f]);

			// The diagnostic must describe the stream, never the image path
			// or the file name it came from.
			require(log.find(image_path) == std::string::npos,
				label + ": diagnostic leaks the image path");
			require(log.find(c.name) == std::string::npos,
				label + ": diagnostic leaks the file name");

			std::cout << label << ": failed in " << elapsed_us
				<< " us with bounded diagnostic" << std::endl;
		}
	}
}

// Pre-fill every field so a success path has to overwrite it and a failure
// path has to clear it.
static DecompressResult DirtyResult()
{
	DecompressResult result;
	result.accepted_missing_adler = true;
	result.zlib_block_count = 91;
	result.missing_adler_block_count = 92;
	result.seq = 93;
	result.logical_size = 94;
	result.block_count = 95;
	result.raw_block_count = 96;
	result.native_block_count = 97;
	result.checksum_verified = true;
	return result;
}

static void TestObjectDiagnostics(ApfsDir &dir, const std::string &image_path)
{
	IoStatus st = IoStatus::Ok;

	// A failed/short diagnostic write must fail the object, and must not
	// poison later attempts after the sink is restored.
	for (int short_write = 0; short_write < 2; ++short_write)
	{
		class FailingBuffer : public std::streambuf {
		public:
			explicit FailingBuffer(bool short_write) : partial(short_write) {}
			std::streamsize xsputn(const char *, std::streamsize n) override
			{ return partial && n > 0 ? n - 1 : 0; }
			int_type overflow(int_type) override { return traits_type::eof(); }
		private:
			bool partial;
		} failing(short_write != 0);
		std::vector<uint8_t> attr, decoded(32, 0xAB);
		require(dir.GetAttribute(attr, 60, "com.apple.decmpfs", &st), "diagnostic failure attr");
		DecompressResult result = DirtyResult();
		auto *old = std::cerr.rdbuf(&failing);
		const bool ok = DecompressFile(dir, 60, decoded, attr, &result);
		// Deliberately preserve the failed stream state when restoring sink.
		const auto state = std::cerr.rdstate();
		std::cerr.rdbuf(old);
		std::cerr.setstate(state);
		require(!ok && decoded.empty() && result.seq == 0 && result.block_count == 0,
			"failed diagnostic write accepted object");
		std::ostringstream recovered;
		old = std::cerr.rdbuf(recovered.rdbuf());
		std::cerr.setstate(state);
		const bool recovered_ok = DecompressFile(dir, 60, decoded, attr, &result);
		std::cerr.rdbuf(old);
		require(recovered_ok && !decoded.empty(), "diagnostic sink did not recover");
		CheckObjectSummary(recovered.str(), result, "recovered diagnostic");
		const auto object = recovered.str().find("APFS_DECMPFS_OBJECT");
		require(object != std::string::npos &&
			recovered.str().find('\n', object) == recovered.str().size() - 1,
			"OBJECT must be last complete line");
	}

	struct Case
	{
		uint64_t ino;
		const char *name;
		size_t blocks;
		size_t zlib;
		size_t raw;
		size_t native;
		size_t missing;
		bool checksum;
	};

	const Case cases[] = {
		{60, "rf-zlib-1blk", 1, 1, 0, 0, 0, true},
		{61, "rf-zlib-multi", 3, 3, 0, 0, 0, true},
		{62, "rf-lzvn-1blk", 1, 0, 0, 1, 0, false},
		{63, "rf-lzvn-multi", 3, 0, 0, 3, 0, false},
		{64, "inline-zlib", 1, 1, 0, 0, 0, true},
		{67, "rf-zlib-no-adler", 1, 1, 0, 0, 1, false},
		{91, "rf-canonical-mixed", 2, 2, 0, 0, 1, false},
		{93, "rf-mixed-zlib-raw", 2, 1, 1, 0, 0, false},
	};

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
	{
		const Case &item = cases[c];
		const std::string label = item.name;

		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, item.ino, "com.apple.decmpfs", &st) &&
			st == IoStatus::Ok, label + ": decmpfs read");

		DecompressResult result = DirtyResult();
		std::vector<uint8_t> decoded(32, 0xAB);
		std::string log;
		bool ok = false;

		{
			CerrCapture capture;
			ok = DecompressFile(dir, item.ino, decoded, decmpfs, &result);
			log = capture.str();
		}

		require(ok, label + ": DecompressFile");
		require(result.logical_size == decoded.size(),
			label + ": logical size does not match output");
		require(result.block_count == item.blocks &&
			result.zlib_block_count == item.zlib &&
			result.raw_block_count == item.raw &&
			result.native_block_count == item.native &&
			result.missing_adler_block_count == item.missing &&
			result.checksum_verified == item.checksum,
			label + ": result counts");
		CheckObjectSummary(log, result, label);
		require(log.find(image_path) == std::string::npos,
			label + ": diagnostic leaks the image path");
		require(log.find(item.name) == std::string::npos,
			label + ": diagnostic leaks the file name");

		if (item.ino == 93)
		{
			// Independent expected content: one 64 KiB block plus the first
			// 123 plaintext bytes carried by the raw marker.
			std::vector<uint8_t> expected;
			FillRfContent(expected, RfContentKind::ZlibSingle);
			std::vector<uint8_t> tail(expected.begin(), expected.begin() + 123);
			expected.insert(expected.end(), tail.begin(), tail.end());
			requireBytes(decoded, expected, label + ": mixed content");
		}
	}

	// Zero-length objects still have to prove they were opened, but must
	// never claim a checksum. Output and result are dirtied first.
	{
		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, 80, "com.apple.decmpfs", &st),
			"empty object: decmpfs read");
		DecompressResult result = DirtyResult();
		std::vector<uint8_t> decoded(32, 0xAB);
		std::string log;
		bool ok = false;

		{
			CerrCapture capture;
			ok = DecompressFile(dir, 80, decoded, decmpfs, &result);
			log = capture.str();
		}

		require(ok, "empty object: DecompressFile");
		require(decoded.empty(), "empty object: output not cleared");
		require(result.seq != 0 && result.logical_size == 0 &&
			result.block_count == 0 && result.zlib_block_count == 0 &&
			result.raw_block_count == 0 && result.native_block_count == 0 &&
			result.missing_adler_block_count == 0 &&
			!result.accepted_missing_adler && !result.checksum_verified,
			"empty object: result not reset");
		CheckObjectSummary(log, result, "empty object");
	}

	// Consecutive calls get strictly increasing seq values.
	{
		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, 80, "com.apple.decmpfs", &st),
			"seq sequence: decmpfs read");
		uint64_t previous = 0;

		for (size_t i = 0; i < 32; i++)
		{
			DecompressResult result;
			std::vector<uint8_t> decoded(8, 0xAA);
			std::string log;
			bool ok = false;

			{
				CerrCapture capture;
				ok = DecompressFile(dir, 80, decoded, decmpfs, &result);
				log = capture.str();
			}

			require(ok && decoded.empty(), "seq sequence: empty decode");
			if (i == 0)
				previous = result.seq;
			else
			{
				require(result.seq == previous + 1,
					"seq sequence: not strictly increasing");
				previous = result.seq;
			}
			CheckObjectSummary(log, result, "seq sequence");
		}
	}

	// The same ino opened twice is two independent attempts with two seqs.
	{
		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, 67, "com.apple.decmpfs", &st),
			"duplicate ino: decmpfs read");
		uint64_t seqs[2] = { 0, 0 };

		for (size_t pass = 0; pass < 2; pass++)
		{
			DecompressResult result;
			std::vector<uint8_t> decoded;
			std::string log;
			bool ok = false;

			{
				CerrCapture capture;
				ok = DecompressFile(dir, 67, decoded, decmpfs, &result);
				log = capture.str();
			}

			require(ok, "duplicate ino: decode");
			CheckObjectSummary(log, result, "duplicate ino");
			seqs[pass] = result.seq;
		}

		require(seqs[0] != 0 && seqs[1] != 0 && seqs[0] != seqs[1],
			"duplicate ino must produce two distinct seq values");
	}

	// A zero-length object with an unknown algorithm is still a failure, and
	// uses the same stage/reason as the non-empty unknown-algorithm path.
	{
		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, 80, "com.apple.decmpfs", &st),
			"zero-size unknown: decmpfs read");

		const uint32_t unknown_algos[] = { 2, 99 };
		for (size_t a = 0; a < sizeof(unknown_algos) / sizeof(unknown_algos[0]); a++)
		{
			const uint32_t algo = unknown_algos[a];
			for (size_t j = 0; j < 4; j++)
				decmpfs[4 + j] = static_cast<uint8_t>((algo >> (8 * j)) & 0xFF);

			const std::string label = "zero-size unknown algo " +
				std::to_string(algo);
			DecompressResult result = DirtyResult();
			std::vector<uint8_t> decoded(16, 0xAA);
			std::string log;
			bool ok = true;

			{
				CerrCapture capture;
				ok = DecompressFile(dir, 80, decoded, decmpfs, &result);
				log = capture.str();
			}

			require(!ok, label + ": must fail");
			require(decoded.empty(), label + ": output not cleared");
			CheckResultCleared(result, label);
			CheckNoObjectOrValidation(log, label);
			require(CountOccurrences(log, "APFS_DECMPFS_ERROR") == 1,
				label + ": expected exactly one error line");
			const std::string error = FindDiagnosticLine(log,
				"APFS_DECMPFS_ERROR");
			require(LineU64(error, "seq") != 0, label + ": error has no seq");
			require(LineU64(error, "algo") == algo, label + ": error algo");
			require(LineField(error, "stage") == "algorithm",
				label + ": error stage");
			require(LineField(error, "reason") == "unsupported",
				label + ": error reason");
		}
	}

	// A valid first block followed by a bad second block: no successful
	// block line and no object summary may survive the failure.
	{
		std::vector<uint8_t> decmpfs;
		require(dir.GetAttribute(decmpfs, 90, "com.apple.decmpfs", &st),
			"second-block failure: decmpfs read");
		DecompressResult result = DirtyResult();
		std::vector<uint8_t> decoded(32, 0xAB);
		std::string log;
		bool ok = true;

		{
			CerrCapture capture;
			ok = DecompressFile(dir, 90, decoded, decmpfs, &result);
			log = capture.str();
		}

		require(!ok, "second-block failure: must fail");
		require(decoded.empty(), "second-block failure: output not cleared");
		CheckResultCleared(result, "second-block failure");
		CheckNoObjectOrValidation(log, "second-block failure");
		const std::string error = FindDiagnosticLine(log, "APFS_DECMPFS_ERROR");
		require(LineU64(error, "seq") != 0, "second-block failure: error seq");
		require(LineU64(error, "ino") == 90, "second-block failure: error ino");
		require(LineU64(error, "algo") == 4, "second-block failure: error algo");
		require(LineU64(error, "block") == 1,
			"second-block failure: error block index");
		require(LineField(error, "stage") == "block",
			"second-block failure: error stage");
		require(LineField(error, "reason") == "block_marker",
			"second-block failure: error reason");
	}

	TestConcurrentObjectLogs(image_path);
}

// Multiple threads decode independent objects from independent image
// instances. Every object's lines must stay contiguous, because the whole
// success log (validation lines plus summary) is published in one write.
static void TestConcurrentObjectLogs(const std::string &image_path)
{
	struct Spec
	{
		uint64_t ino;
		size_t zlib;
		size_t blocks;
	};

	const Spec specs[] = {
		{60, 1, 1},
		{61, 3, 3},
		{67, 1, 1},
		{91, 2, 2},
		{93, 1, 2},
	};
	const size_t count = sizeof(specs) / sizeof(specs[0]);

	std::vector<Image *> images(count, nullptr);
	for (size_t i = 0; i < count; i++)
	{
		images[i] = new Image();
		std::string error;
		require(OpenImage(image_path, *images[i], error),
			"concurrent: open image: " + error);
	}

	std::vector<bool> ok(count, false);
	std::vector<DecompressResult> results(count);
	std::vector<std::string> errors(count);
	std::string log;

	{
		CerrCapture capture;
		std::vector<std::thread> threads;

		for (size_t i = 0; i < count; i++)
		{
			threads.push_back(std::thread([&, i]() {
				try
				{
					IoStatus st = IoStatus::Ok;
					std::vector<uint8_t> attr;
					if (!images[i]->dir->GetAttribute(attr, specs[i].ino,
						"com.apple.decmpfs", &st))
					{
						errors[i] = "decmpfs attribute read";
						return;
					}
					std::vector<uint8_t> decoded;
					ok[i] = DecompressFile(*images[i]->dir, specs[i].ino,
						decoded, attr, &results[i]);
					if (!ok[i])
						errors[i] = "DecompressFile";
				}
				catch (const std::exception &e)
				{
					errors[i] = e.what();
				}
				catch (...)
				{
					errors[i] = "unknown exception";
				}
			}));
		}

		for (size_t i = 0; i < threads.size(); i++)
			threads[i].join();
		log = capture.str();
	}

	for (size_t i = 0; i < count; i++)
	{
		require(ok[i], "concurrent object " + std::to_string(specs[i].ino) +
			": " + errors[i]);
	}

	std::vector<std::string> lines;
	size_t begin = 0;
	while (begin < log.size())
	{
		const size_t end = log.find('\n', begin);
		lines.push_back(log.substr(begin, end == std::string::npos ?
			std::string::npos : end - begin));
		if (end == std::string::npos)
			break;
		begin = end + 1;
	}

	std::vector<uint64_t> group_seqs;
	std::vector<std::string> group_logs;
	uint64_t current = 0;

	for (size_t i = 0; i < lines.size(); i++)
	{
		require(lines[i].empty() ||
			lines[i].compare(0, 13, "APFS_DECMPFS_") == 0,
			"concurrent: unexpected diagnostic line: " + lines[i]);
		if (lines[i].empty())
			continue;

		const uint64_t seq = LineU64(lines[i], "seq");
		if (seq != current)
		{
			for (size_t g = 0; g < group_seqs.size(); g++)
				require(group_seqs[g] != seq,
					"concurrent: seq " + std::to_string(seq) +
					" appears in more than one contiguous block");
			current = seq;
			group_seqs.push_back(seq);
			group_logs.push_back(std::string());
		}
		group_logs.back() += lines[i] + "\n";
	}

	require(group_seqs.size() == count,
		"concurrent: expected one diagnostic block per object");

	std::vector<uint64_t> seen_inos;
	for (size_t g = 0; g < group_logs.size(); g++)
	{
		const std::string &block = group_logs[g];
		const std::string object = FindDiagnosticLine(block,
			"APFS_DECMPFS_OBJECT");
		const uint64_t ino = LineU64(object, "ino");
		const size_t zlib = static_cast<size_t>(LineU64(object, "zlib"));
		const size_t blocks = static_cast<size_t>(LineU64(object, "blocks"));

		require(CountOccurrences(block, "APFS_DECMPFS_VALIDATION") == zlib,
			"concurrent: validation lines do not match zlib count");
		require(CountOccurrences(block, "APFS_DECMPFS_") == zlib + 1,
			"concurrent: object block has extra lines");
		require(LineU64(object, "seq") == group_seqs[g],
			"concurrent: seq mismatch inside object block");
		require(std::find(seen_inos.begin(), seen_inos.end(), ino) ==
			seen_inos.end(), "concurrent: duplicate ino " +
			std::to_string(ino));
		seen_inos.push_back(ino);

		bool matched = false;
		for (size_t s = 0; s < count; s++)
		{
			if (specs[s].ino != ino)
				continue;
			matched = true;
			require(blocks == specs[s].blocks && zlib == specs[s].zlib,
				"concurrent: object counts for ino " + std::to_string(ino));
			require(results[s].seq == group_seqs[g],
				"concurrent: result seq does not match object line");
		}
		require(matched, "concurrent: unexpected ino " + std::to_string(ino));
	}

	for (size_t i = 0; i < count; i++)
		require(std::find(seen_inos.begin(), seen_inos.end(), specs[i].ino) !=
			seen_inos.end(), "concurrent: missing ino " +
			std::to_string(specs[i].ino));

	for (size_t i = 0; i < images.size(); i++)
		delete images[i];
}

static void TestBadImage(const std::string &path)
{
	Image image;
	std::string error;
	require(OpenImage(path, image, error), "open bad image: " + error);
	ApfsDir &dir = *image.dir;

	IoStatus st = IoStatus::Ok;
	ApfsDir::Inode rec;
	require(!dir.GetInode(rec, 9000, &st) && st == IoStatus::IoError,
		"damaged high leaf must make GetInode EIO");

	std::vector<ApfsDir::DirRec> list;
	require(!dir.ListDirectory(list, 50, &st) && st == IoStatus::IoError,
		"iterator crossing a damaged leaf must be EIO, not a crash");

	std::vector<std::string> names;
	require(!dir.ListAttributes(names, 9001, &st) && st == IoStatus::IoError,
		"ListAttributes on a damaged leaf must be EIO");

	std::vector<uint8_t> buf(8);
	require(!dir.ReadFile(buf.data(), 9000, 0, 8, &st, 8) && st == IoStatus::IoError,
		"ReadFile on a damaged leaf must be EIO");

	ApfsDir::DirRec res;
	require(!dir.LookupName(res, 9002, "child", &st) && st == IoStatus::IoError,
		"LookupName on a damaged leaf must be EIO");
}

static void TestLargeDirectory(const std::string &path)
{
	Image image;
	std::string error;
	require(OpenImage(path, image, error), "open large image: " + error);
	ApfsDir &dir = *image.dir;

	ApfsDir::DirRec res;
	IoStatus st = IoStatus::Ok;
	const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
	require(!dir.LookupName(res, 2, "no-such-name", &st) && st == IoStatus::NotFound,
		"large-directory fallback miss");
	const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	const long long usec = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	std::cout << "large-directory fallback miss: " << usec
		<< " us for 100000 entries" << std::endl;
	require(usec < 60LL * 1000 * 1000, "fallback miss took an unreasonable amount of time");
}

int main()
{
	const std::string mkapfs = FindMkapfs();
	if (mkapfs.empty())
	{
		if (std::getenv("APFS_FIXTURE_REQUIRED"))
		{
			std::cerr << "FAIL: mkapfs not found and APFS_FIXTURE_REQUIRED is set" << std::endl;
			return 1;
		}
		std::cout << "SKIP: mkapfs not found" << std::endl;
		return 77;
	}

	const char *tmp_root = std::getenv("TMPDIR");
	std::string templ = std::string(tmp_root && *tmp_root ? tmp_root : "/tmp") +
		"/apfs-reader-fixture-XXXXXX";
	std::vector<char> tempdir(templ.begin(), templ.end());
	tempdir.push_back(0);
	char *dir = mkdtemp(tempdir.data());
	if (!dir)
	{
		std::cerr << "FAIL: mkdtemp" << std::endl;
		return 1;
	}

	const std::string good = std::string(dir) + "/good.img";
	const std::string good_nolink = std::string(dir) + "/good-nolink.img";
	const std::string bad = std::string(dir) + "/bad.img";
	const std::string large = std::string(dir) + "/large.img";
	std::string error;

	if (!CreateApfsFixture(good, ApfsFixtureKind::Good, error) ||
		!CreateApfsFixture(good_nolink, ApfsFixtureKind::GoodNoLink, error) ||
		!CreateApfsFixture(bad, ApfsFixtureKind::BadTree, error) ||
		!CreateApfsFixture(large, ApfsFixtureKind::LargeDirectory, error))
	{
		std::cerr << "FAIL: fixture: " << error << std::endl;
		return 1;
	}

	TestGoodImage(good);
	TestGoodNoLinkImage(good, good_nolink);
	TestBadImage(bad);
	TestBadLayoutUnchanged(bad);
	TestLargeDirectory(large);

	std::remove(good.c_str());
	std::remove(good_nolink.c_str());
	std::remove(bad.c_str());
	std::remove(large.c_str());
	rmdir(dir);

	std::cout << "APFS reader integration tests passed" << std::endl;
	return 0;
}
