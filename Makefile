OS := $(shell uname)
COMPILER := $(shell test "${OS}" = "Linux" -a -x "/bin/g++" && echo "_gcc")

BUILD_Darwin = clang++ procenv.cpp process.cpp -o procenv -g -std=c++17 -Wall -arch arm64 -arch x86_64
BUILD_Linux_gcc = g++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall -static-libgcc -static-libstdc++ -static
BUILD_Linux = clang++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall
BUILD_FreeBSD = clang++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall -lelf -lkvm -lpthread -static
BUILD_DragonFly = g++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall -static-libgcc -static-libstdc++ -lkvm -lpthread -static
BUILD_NetBSD = g++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall -static-libgcc -static-libstdc++ -lkvm -lpthread -static
BUILD_OpenBSD = clang++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall -lkvm -lpthread -static
BUILD_SunOS = g++ procenv.cpp process.cpp -o procenv -std=c++17 -Wall -static-libgcc -lkvm
BUILD_Windows = g++ procenv.cpp process.cpp -o procenv.exe -std=c++17 -Wall -static-libgcc -static-libstdc++ -static -lntdll

BUILD = ${BUILD_${OS}${COMPILER}}

procenv: procenv.cpp process.cpp process.hpp Makefile
ifeq (${BUILD},)
	@echo "Unsupported OS/compiler combination: ${OS}${COMPILER}"
	@exit 1
endif
	${BUILD}

clean:
	rm -f procenv procenv.exe