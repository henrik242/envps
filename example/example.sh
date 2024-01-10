#!/bin/sh
cd "${0%/*}"
if [ $(uname) = "Darwin" ]; then
  clang++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -arch arm64 -arch x86_64 && ../procenv $1;
elif [ $(uname) = "Linux" ]; then
  if [ -f "/bin/g++" ]; then
    g++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -static-libgcc -static-libstdc++ -static && ../procenv $1;
  else
    clang++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall; ../procenv;
  fi
elif [ $(uname) = "FreeBSD" ]; then
  clang++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -lelf -lkvm -lpthread -static && ../procenv $1;
elif [ $(uname) = "DragonFly" ]; then
  g++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -static-libgcc -static-libstdc++ -lkvm -lpthread -static && ../procenv $1;
elif [ $(uname) = "NetBSD" ]; then
  g++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -static-libgcc -static-libstdc++ -lkvm -lpthread -static && ../procenv $1;
elif [ $(uname) = "OpenBSD" ]; then
  clang++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -lkvm -lpthread -static && ../procenv $1;
elif [ $(uname) = "SunOS" ]; then
  g++ example.cpp ../process.cpp -o ../procenv -std=c++17 -Wall -static-libgcc -lkvm && ../procenv $1;
else
  g++ example.cpp ../process.cpp -o ../procenv.exe -std=c++17 -Wall -static-libgcc -static-libstdc++ -static -lntdll && ../procenv $1;
fi
