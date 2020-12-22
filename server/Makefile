
all: server mkcert
server: server.cpp
	g++ -Wall server.cpp -o server -lcrypto -lssl 
extract.o: extract.cpp
	g++ -c extract.cpp -std=c++17
encrypt.o: encrypt.cpp
	g++ -c encrypt.cpp -std=c++17
mkcert:
	gcc -o mkcert mkcert.c -lssl -lcrypto
