#pragma once

#include <cstdint>
#include <vector>

// Uncompressed content of the valid resource-fork compression fixtures.
// The fixture builder and the tests both derive the expected bytes from here,
// so the SHA-256 constants in RfContent.cpp are the independent golden anchor:
// any accidental change to this generator makes the assertions fail.
enum class RfContentKind : uint32_t
{
	ZlibSingle = 0,
	ZlibMulti = 1,
	LzvnSingle = 2,
	LzvnMulti = 3
};

constexpr uint64_t RF_BLOCK_SIZE = 0x10000;
constexpr uint64_t RF_MULTI_TAIL = 12345;
constexpr uint64_t RF_SINGLE_SIZE = RF_BLOCK_SIZE;
constexpr uint64_t RF_MULTI_SIZE = 2 * RF_BLOCK_SIZE + RF_MULTI_TAIL;

uint64_t RfContentSize(RfContentKind kind);

// Fills "out" with the deterministic golden bytes for "kind".
void FillRfContent(std::vector<uint8_t> &out, RfContentKind kind);

// Lower-case SHA-256 of the bytes produced by FillRfContent().
const char *RfContentSha256Hex(RfContentKind kind);
