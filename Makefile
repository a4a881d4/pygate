sha256_xmm_amd64.o:sha256_xmm_amd64.asm
	yasm -f elf64 sha256_xmm_amd64.asm

sha256_sse2_amd64.o:sha256_sse2_amd64.cpp
	g++ -fPIC -c -o sha256_sse2_amd64.o sha256_sse2_amd64.cpp

libsha256.so:sha256_sse2_amd64.o sha256_xmm_amd64.o
	ld -shared -L /usr/lib/gcc/x86_64-linux-gnu/4.7 -lcrypto -lgmp -lssl -l stdc++ -o libsha256.so sha256_sse2_amd64.o sha256_xmm_amd64.o
	
clean:
	rm sha256_xmm_amd64.o
	rm sha256_sse2_amd64.o
	rm libsha256.so

so:libsha256.so	
	