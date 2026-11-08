// libapfs-level integration test over a deterministic synthetic APFS image.
// The fixture builder uses mkapfs for the container/omap/volume metadata and
// rewrites the file-system tree with the reader edge cases under test.

#include "ApfsFixture.h"

#include "ApfsLib/ApfsContainer.h"
#include "ApfsLib/ApfsDir.h"
#include "ApfsLib/ApfsVolume.h"
#include "ApfsLib/CompressionView.h"
#include "ApfsLib/Device.h"
#include "ApfsLib/ReaderPolicy.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
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
