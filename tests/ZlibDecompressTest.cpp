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

		require(DecompressZLib(out.data(), out.size(), small.data(), too_big) == 0,
			"oversized input size was truncated instead of rejected");
		require(DecompressZLib(out.data(), too_big, small.data(), small.size()) == 0,
			"oversized output size was truncated instead of rejected");
	}

	std::cout << g_case_count << " DecompressZLib cases passed" << std::endl;
	return 0;
}
