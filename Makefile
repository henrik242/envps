OS := $(shell uname)
COMPILER := $(shell test "${OS}" = "Linux" -a -x "/bin/g++" && echo "_gpp")

BUILD_Darwin = clang++ envps.cpp process.cpp -o envps -std=c++17 -Wall -arch arm64 -arch x86_64
BUILD_Linux_gpp = g++ envps.cpp process.cpp -o envps -std=c++17 -Wall -static-libgcc -static-libstdc++ -static
BUILD_Linux = clang++ envps.cpp process.cpp -o envps -std=c++17 -Wall
BUILD_FreeBSD = clang++ envps.cpp process.cpp -o envps -std=c++17 -Wall -lelf -lkvm -lpthread -static
BUILD_DragonFly = g++ envps.cpp process.cpp -o envps -std=c++17 -Wall -static-libgcc -static-libstdc++ -lkvm -lpthread -static
BUILD_NetBSD = g++ envps.cpp process.cpp -o envps -std=c++17 -Wall -static-libgcc -static-libstdc++ -lkvm -lpthread -static
BUILD_OpenBSD = clang++ envps.cpp process.cpp -o envps -std=c++17 -Wall -lkvm -lpthread -static
BUILD_SunOS = g++ envps.cpp process.cpp -o envps -std=c++17 -Wall -static-libgcc -lkvm
BUILD_Windows = g++ envps.cpp process.cpp -o envps.exe -std=c++17 -Wall -static-libgcc -static-libstdc++ -static -lntdll

BUILD = ${BUILD_${OS}${COMPILER}}

envps: envps.cpp process.cpp process.hpp Makefile
ifeq (${BUILD},)
	@echo "Unsupported OS/compiler combination: ${OS}${COMPILER}"
	@exit 1
endif
	${BUILD}

clean:
	rm -f envps envps.exe
