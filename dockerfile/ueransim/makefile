GREEN=\033[0;1;92m
NC=\033[0m

build: FORCE
	rm -fr logs # Old version log files
	mkdir -p build
	rm -fr build/*
	
	# /home/ubuntu/cmake-3.22.0-linux-x86_64/bin/cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" . -B cmake-build-debug
	/home/ubuntu/cmake-3.22.0-linux-x86_64/bin/cmake -DCMAKE_BUILD_TYPE=Release -G "CodeBlocks - Unix Makefiles" . -B cmake-build-release
	# /home/ubuntu/cmake-3.22.0-linux-x86_64/bin/cmake --build cmake-build-debug --target all
	/home/ubuntu/cmake-3.22.0-linux-x86_64/bin/cmake --build cmake-build-release --target all
	
	cp cmake-build-release/nr-gnb build/
	cp cmake-build-release/nr-ue build/
	cp cmake-build-release/nr-cli build/
	cp cmake-build-release/libdevbnd.so build/
	cp tools/nr-binder build/

	@printf "${GREEN}UERANSIM successfully built.${NC}\n"

FORCE: