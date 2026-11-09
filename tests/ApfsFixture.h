#pragma once

#include <string>

enum class ApfsFixtureKind
{
	Good,
	// Same content as Good, but inode 60 keeps a single directory name.
	GoodNoLink,
	BadTree,
	LargeDirectory
};

// Finds mkapfs from MKAPFS or common locations. Empty if unavailable.
std::string FindMkapfs();

// Creates a deterministic APFS image. The container/omap/volume metadata comes
// from mkapfs; the file-system tree is rewritten by this builder so tests can
// inject exact names, xattrs, extents and damaged nodes.
bool CreateApfsFixture(const std::string &path, ApfsFixtureKind kind, std::string &error);
