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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
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
static void TestMissingAdlerDiagnostics(ApfsDir &dir, const std::string &image_path);
static void TestRfBoundsRejects(ApfsDir &dir, const std::string &image_path);
static void TestInlineZlibContent(ApfsDir &dir, const std::string &image_path);

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

	TestResourceForkContent(dir);
	TestMissingAdlerDiagnostics(dir, path);
	TestRfBoundsRejects(dir, path);
	TestInlineZlibContent(dir, path);
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
			require(DecompressFile(dir, 80, decoded, attr, &result), "empty supported algorithm");
			require(decoded.empty() && !result.accepted_missing_adler &&
				result.zlib_block_count == 0 && result.missing_adler_block_count == 0,
				"empty output and metadata reset");
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
	const std::string bad = std::string(dir) + "/bad.img";
	const std::string large = std::string(dir) + "/large.img";
	std::string error;

	if (!CreateApfsFixture(good, ApfsFixtureKind::Good, error) ||
		!CreateApfsFixture(bad, ApfsFixtureKind::BadTree, error) ||
		!CreateApfsFixture(large, ApfsFixtureKind::LargeDirectory, error))
	{
		std::cerr << "FAIL: fixture: " << error << std::endl;
		return 1;
	}

	TestGoodImage(good);
	TestBadImage(bad);
	TestLargeDirectory(large);

	std::remove(good.c_str());
	std::remove(bad.c_str());
	std::remove(large.c_str());
	rmdir(dir);

	std::cout << "APFS reader integration tests passed" << std::endl;
	return 0;
}
