// Command-line wrapper around the fixture builder, used by the FUSE test.
#include "ApfsFixture.h"

#include <cstring>
#include <iostream>
#include <string>

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		std::cerr << "usage: " << argv[0]
			<< " good|good-nolink|bad|large <image>" << std::endl;
		return 2;
	}

	ApfsFixtureKind kind;
	if (std::strcmp(argv[1], "good") == 0)
		kind = ApfsFixtureKind::Good;
	else if (std::strcmp(argv[1], "good-nolink") == 0)
		kind = ApfsFixtureKind::GoodNoLink;
	else if (std::strcmp(argv[1], "bad") == 0)
		kind = ApfsFixtureKind::BadTree;
	else if (std::strcmp(argv[1], "large") == 0)
		kind = ApfsFixtureKind::LargeDirectory;
	else
	{
		std::cerr << "unknown fixture kind: " << argv[1] << std::endl;
		return 2;
	}

	std::string error;
	if (!CreateApfsFixture(argv[2], kind, error))
	{
		std::cerr << "fixture error: " << error << std::endl;
		return 1;
	}

	return 0;
}
