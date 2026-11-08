// Deterministic, FUSE-free tests for DecompressZLib().
//
// The old implementation only ended its inflate() loop on Z_STREAM_END. A
// truncated stream, a full output buffer, or an invalid stream made inflate()
// return Z_BUF_ERROR forever, pinning a reader thread at 100% CPU. The same
// code also forced avail_out to zero on hard errors, which made the function
// report dst_size (a plausible complete length) for damaged data.
//
// These cases pin the fail-closed contract:
//   * every incomplete or damaged stream returns 0 and returns promptly;
//   * valid zlib data returns the exact byte count and identical bytes;
//   * trailing bytes after Z_STREAM_END remain legal (APFS chunk protocol).

#include "ApfsLib/Util.h"
#include "Crypto/Sha256.h"

#include <csignal>
#include <csetjmp>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <climits>
#include <zlib.h>

static int g_case_count = 0;

static void require(bool ok, const char *message)
{
	if (!ok)
	{
		std::cerr << "FAIL: " << message << std::endl;
		std::exit(1);
	}
}

static void begin(const char *name)
{
	g_case_count++;
	std::cout << "case " << g_case_count << ": " << name << std::endl;
}

static sigjmp_buf g_timeout_env;

static void on_alarm(int)
{
	siglongjmp(g_timeout_env, 1);
}

// Run one DecompressZLib() call under a wall-clock guard. The guard exists so
// a regression to the old infinite loop fails the test instead of hanging CI.
template <typename Fn>
static bool run_with_timeout(int seconds, Fn fn, size_t &result)
{
	struct sigaction action;
	struct sigaction old_action;

	std::memset(&action, 0, sizeof(action));
	action.sa_handler = on_alarm;
	sigemptyset(&action.sa_mask);

	if (sigaction(SIGALRM, &action, &old_action) != 0)
		return false;

	if (sigsetjmp(g_timeout_env, 1) == 0)
	{
		alarm(static_cast<unsigned int>(seconds));
		result = fn();
		alarm(0);
		sigaction(SIGALRM, &old_action, nullptr);
		return true;
	}

	// The call did not return in time. Every object the lambda touches is a
	// plain buffer, so abandoning the call through siglongjmp is safe here.
	alarm(0);
	sigaction(SIGALRM, &old_action, nullptr);
	return false;
}

static std::vector<uint8_t> make_pattern(size_t size, uint32_t seed)
{
	std::vector<uint8_t> data(size);
	uint32_t state = seed;

	for (size_t k = 0; k < size; k++)
	{
		state = state * 1103515245U + 12345U;
		// Mix repeated runs with noise so deflate emits both matches and
		// literals instead of a single stored block.
		data[k] = static_cast<uint8_t>((state >> 16) ^ (k / 97));
	}

	return data;
}

static std::vector<uint8_t> zlib_compress(const std::vector<uint8_t> &input)
{
	uLongf bound = compressBound(static_cast<uLong>(input.size()));
	std::vector<uint8_t> out(bound);
	int rc = compress2(out.data(), &bound, input.data(),
		static_cast<uLong>(input.size()), Z_BEST_COMPRESSION);

	require(rc == Z_OK, "compress2 failed");
	out.resize(bound);
	return out;
}

static void sha256_of(const uint8_t *data, size_t size, uint8_t digest[32])
{
	SHA256 sha;
	sha.Init();
	sha.Update(data, size);
	sha.Final(digest);
}

static std::string sha256_hex(const uint8_t *data, size_t size)
{
	uint8_t digest[32];
	static const char digits[] = "0123456789abcdef";
	std::string out;

	sha256_of(data, size, digest);
	out.reserve(64);
	for (int k = 0; k < 32; k++)
	{
		out.push_back(digits[digest[k] >> 4]);
		out.push_back(digits[digest[k] & 0x0F]);
	}
	return out;
}

static void require_same_content(const std::vector<uint8_t> &expected,
	const std::vector<uint8_t> &actual, size_t decoded, const char *context)
{
	require(decoded == expected.size(), "decoded length differs from the source");
	require(std::memcmp(actual.data(), expected.data(), expected.size()) == 0,
		"decoded bytes differ from the source");
	uint8_t expected_digest[32];
	uint8_t actual_digest[32];
	sha256_of(expected.data(), expected.size(), expected_digest);
	sha256_of(actual.data(), decoded, actual_digest);
	require(std::memcmp(expected_digest, actual_digest, sizeof(expected_digest)) == 0,
		context);
}

// One compression unit of a 64 KiB type-4 (zlib, resource fork) file as
// written by Apple's own filesystem compression support. Captured from
// AppleFSCompression.framework on macOS 27.0.1 (build 26A434), SDK 27.0.
// Provenance: deploymenttheory/go-apfs-v2, testdata/appledouble/native/
// compression-writer.json.gz (Apache-2.0), selection requested type 4.
//
// The block is a zlib header plus complete DEFLATE data and ends at the
// final block; the four Adler-32 trailer bytes are absent. Its uncompressed
// SHA-256 is the independent golden anchor for the decoder.
static const uint8_t kNativeDecmpfsBlock[] = {
	0x78, 0x5e, 0xed, 0xc3, 0x01, 0x0d, 0x00, 0x00,
	0x08, 0x03, 0xa0, 0x6c, 0xd7, 0xf7, 0xcf, 0x64,
	0x10, 0x61, 0x23, 0xb3, 0x8d, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xef, 0x1f,
};

static const char kNativeDecmpfsSha256[] =
	"ba1e423063874c1bc997e1fe7aa9971477f851b118cc9ad92921b953dd27c309";

int main()
{
	// 1. Exact 64KiB chunk: the common single-entry resource fork layout.
	{
		begin("valid 64KiB chunk, exact output");
		std::vector<uint8_t> plain = make_pattern(0x10000, 7);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		std::vector<uint8_t> out(plain.size());
		size_t decoded = 0;
		bool completed = run_with_timeout(5, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
		}, decoded);

		require(completed, "64KiB zlib stream did not finish");
		require_same_content(plain, out, decoded, "64KiB zlib stream SHA-256 mismatch");
	}

	// 2. Multi-entry resource fork: three 64KiB chunks plus a short tail.
	{
		begin("valid multi-block with short tail");
		std::vector<uint8_t> plain;
		std::vector<uint8_t> joined;

		for (int block = 0; block < 4; block++)
		{
			size_t block_size = (block == 3) ? 12345 : 0x10000;
			std::vector<uint8_t> part = make_pattern(block_size, 11 + block);
			plain.insert(plain.end(), part.begin(), part.end());

			std::vector<uint8_t> compressed = zlib_compress(part);
			std::vector<uint8_t> out(0x10000);
			size_t decoded = 0;
			bool completed = run_with_timeout(5, [&]() {
				// All chunks use a 64KiB output buffer, including the tail.
				return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
			}, decoded);

			require(completed, "multi-block zlib stream did not finish");
			require(decoded == block_size, "multi-block zlib stream returned the wrong length");
			joined.insert(joined.end(), out.begin(), out.begin() + block_size);
		}

		require_same_content(plain, joined, joined.size(),
			"multi-block zlib stream SHA-256 mismatch");
	}

	// 3. Trailing bytes after Z_STREAM_END are legal and must be ignored.
	{
		begin("valid stream with trailing bytes");
		std::vector<uint8_t> plain = make_pattern(4096, 23);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		compressed.insert(compressed.end(), {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11});

		std::vector<uint8_t> out(plain.size());
		size_t decoded = 0;
		bool completed = run_with_timeout(5, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
		}, decoded);

		require(completed, "zlib stream with trailing bytes did not finish");
		require(decoded == plain.size(), "trailing bytes changed the decoded length");
		require_same_content(plain, out, decoded,
			"zlib stream with trailing bytes SHA-256 mismatch");
	}

	// 4. Truncated input. The old loop never ended on Z_BUF_ERROR.
	{
		begin("truncated stream fails closed");
		std::vector<uint8_t> plain = make_pattern(0x10000, 31);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		compressed.resize(compressed.size() / 2);

		std::vector<uint8_t> out(plain.size(), 0xAA);
		size_t decoded = 123;
		bool completed = run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
		}, decoded);

		require(completed, "truncated zlib stream hung instead of failing");
		require(decoded == 0, "truncated zlib stream reported a plausible length");
	}

	// 5. Damaged Adler-32 after the full output was produced. The old code
	// forced avail_out to zero and returned dst_size (65536) although only
	// 4096 bytes were valid.
	{
		begin("bad checksum fails closed");
		std::vector<uint8_t> plain = make_pattern(4096, 41);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		compressed.back() ^= 0xFF;

		std::vector<uint8_t> out(0x10000, 0xAA);
		size_t decoded = 123;
		bool completed = run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
		}, decoded);

		require(completed, "bad-checksum zlib stream hung instead of failing");
		require(decoded == 0, "bad-checksum zlib stream reported dst_size as success");
	}

	// 6. Corrupted deflate payload. Must not be accepted as complete data.
	{
		begin("corrupt deflate payload fails closed");
		std::vector<uint8_t> plain = make_pattern(0x10000, 43);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		compressed[compressed.size() / 2] ^= 0x5A;

		std::vector<uint8_t> out(plain.size(), 0xAA);
		size_t decoded = 123;
		bool completed = run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
		}, decoded);

		require(completed, "corrupt zlib stream hung instead of failing");
		require(decoded == 0, "corrupt zlib stream reported a plausible length");
	}

	// 7. Output buffer one byte too small. The old loop spun on Z_BUF_ERROR.
	{
		begin("output buffer too small fails closed");
		std::vector<uint8_t> plain = make_pattern(4096, 47);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		std::vector<uint8_t> out(plain.size() - 1, 0xAA);

		size_t decoded = 123;
		bool completed = run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(), compressed.size());
		}, decoded);

		require(completed, "oversized-output zlib stream hung instead of failing");
		require(decoded == 0, "oversized-output zlib stream reported a plausible length");
	}

	// 8. Preset-dictionary stream: inflate returns Z_NEED_DICT, which must not
	// be turned into success. 0x78 0x20 is a valid zlib header with FDICT set.
	{
		begin("preset dictionary fails closed");
		const uint8_t src[] = {0x78, 0x20, 0x00, 0x00, 0x00, 0x01};
		std::vector<uint8_t> out(1024, 0xAA);

		size_t decoded = 123;
		bool completed = run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), src, sizeof(src));
		}, decoded);

		require(completed, "need-dict zlib stream hung instead of failing");
		require(decoded == 0, "need-dict zlib stream reported a plausible length");
	}

	// 9. Empty input cannot produce a complete stream.
	{
		begin("empty input fails closed");
		std::vector<uint8_t> out(1024, 0xAA);
		std::vector<uint8_t> empty;

		size_t decoded = 123;
		bool completed = run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), empty.data(), 0);
		}, decoded);

		require(completed, "empty zlib input hung instead of failing");
		require(decoded == 0, "empty zlib input reported a plausible length");
	}

	// 10. zlib's avail_in/avail_out are uInt. Larger size_t values must be
	// rejected before they are truncated.
	if (sizeof(size_t) > sizeof(unsigned int))
	{
		begin("size_t overflow rejected");
		std::vector<uint8_t> small(16, 0);
		std::vector<uint8_t> out(16, 0);
		const size_t too_big = static_cast<size_t>(UINT_MAX) + 1;

		size_t result = 1;
		require(run_with_timeout(2, [&]() { return DecompressZLib(out.data(), out.size(), small.data(), too_big); }, result), "oversized input timed out");
		require(result == 0,
			"oversized input size was truncated instead of rejected");
		require(run_with_timeout(2, [&]() { return DecompressZLib(out.data(), too_big, small.data(), small.size()); }, result), "oversized output timed out");
		require(result == 0,
			"oversized output size was truncated instead of rejected");
	}

	// 11. Native APFS decmpfs zlib block without the Adler-32 trailer.
	{
		begin("native decmpfs block without Adler-32");
		std::vector<uint8_t> out(0x10000, 0xAA);
		size_t decoded = 0;

		require(run_with_timeout(5, [&]() {
			return DecompressZLib(out.data(), out.size(), kNativeDecmpfsBlock,
				sizeof(kNativeDecmpfsBlock));
		}, decoded), "native trailer-less block hung");

		require(decoded == 0x10000, "native trailer-less block was not accepted");
		require(sha256_hex(out.data(), decoded) == kNativeDecmpfsSha256,
			"native trailer-less block decoded to the wrong bytes");
	}

	// 12. The same native block with bytes removed from the end is not a
	// complete DEFLATE stream and must still fail closed.
	{
		for (size_t removed = 1; removed <= 4; removed++)
		{
			begin("native block truncated before the final block fails closed");
			std::vector<uint8_t> out(0x10000, 0xAA);
			size_t decoded = 123;
			const size_t size = sizeof(kNativeDecmpfsBlock) - removed;

			require(run_with_timeout(2, [&]() {
				return DecompressZLib(out.data(), out.size(),
					kNativeDecmpfsBlock, size);
			}, decoded), "truncated native block hung");
			require(decoded == 0,
				"truncated native block reported a plausible length");
		}
	}

	// 13. A wrong four-byte trailer is corruption, not the missing-trailer
	// form, and must not be accepted.
	{
		begin("native block with a wrong trailer fails closed");
		std::vector<uint8_t> src(kNativeDecmpfsBlock,
			kNativeDecmpfsBlock + sizeof(kNativeDecmpfsBlock));
		src.insert(src.end(), {0x00, 0x00, 0x00, 0x00});

		std::vector<uint8_t> out(0x10000, 0xAA);
		size_t decoded = 123;

		require(run_with_timeout(2, [&]() {
			return DecompressZLib(out.data(), out.size(), src.data(), src.size());
		}, decoded), "wrong-trailer native block hung");
		require(decoded == 0, "wrong trailer was accepted as success");
	}

	// 14. A regular zlib stream whose four Adler-32 bytes were removed is
	// the same on-disk form and must decode exactly.
	{
		begin("zlib stream with its trailer removed decodes exactly");
		std::vector<uint8_t> plain = make_pattern(4096, 59);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		compressed.resize(compressed.size() - 4);

		std::vector<uint8_t> out(0x10000, 0xAA);
		size_t decoded = 0;

		require(run_with_timeout(5, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(),
				compressed.size());
		}, decoded), "trailer-less zlib stream hung");
		require(decoded == plain.size(), "trailer-less zlib length mismatch");
		require_same_content(plain, out, decoded,
			"trailer-less zlib SHA-256 mismatch");
	}

	// 15. Exact 64 KiB output with no trailer: the output buffer is full when
	// the checksum state is reached, which is the boundary that a naive
	// "needs free output space" check would reject.
	{
		begin("exact 64KiB output without trailer decodes exactly");
		std::vector<uint8_t> plain = make_pattern(0x10000, 61);
		std::vector<uint8_t> compressed = zlib_compress(plain);
		compressed.resize(compressed.size() - 4);

		std::vector<uint8_t> out(plain.size(), 0xAA);
		size_t decoded = 0;

		require(run_with_timeout(5, [&]() {
			return DecompressZLib(out.data(), out.size(), compressed.data(),
				compressed.size());
		}, decoded), "exact 64KiB trailer-less stream hung");
		require(decoded == plain.size(), "exact 64KiB trailer-less length mismatch");
		require_same_content(plain, out, decoded,
			"exact 64KiB trailer-less SHA-256 mismatch");
	}

	// 16. Multi-block resource fork with a short tail, every block missing
	// its trailer, like the real files that failed with EIO.
	{
		begin("multi-block trailer-less stream with short tail");
		std::vector<uint8_t> joined;
		std::vector<uint8_t> plain;

		for (int block = 0; block < 3; block++)
		{
			size_t block_size = (block == 2) ? 16650 : 0x10000;
			std::vector<uint8_t> part = make_pattern(block_size, 71 + block);
			std::vector<uint8_t> compressed = zlib_compress(part);
			compressed.resize(compressed.size() - 4);
			plain.insert(plain.end(), part.begin(), part.end());

			std::vector<uint8_t> out(0x10000, 0xAA);
			size_t decoded = 0;

			require(run_with_timeout(5, [&]() {
				return DecompressZLib(out.data(), out.size(), compressed.data(),
					compressed.size());
			}, decoded), "multi-block trailer-less stream hung");
			require(decoded == block_size,
				"multi-block trailer-less stream returned the wrong length");
			joined.insert(joined.end(), out.begin(), out.begin() + block_size);
		}

		require_same_content(plain, joined, joined.size(),
			"multi-block trailer-less SHA-256 mismatch");
	}

	std::cout << g_case_count << " DecompressZLib cases passed" << std::endl;
	return 0;
}
