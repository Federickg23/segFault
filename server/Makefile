
all: server

server: server.o mkcert.o crypto.o remove.o cstore_utils.o
	g++ -Wall server.o mkcert.o crypto.o remove.o cstore_utils.o -o server -lcrypto -lssl 
crypto.o:
	g++ -c crypto.cpp -std=c++17
mkcert.o:
	gcc -c mkcert.c -lssl -lcrypto
remove.o:
	g++ -c remove.cpp -std=c++17
cstore_utils.o:
	g++ -c cstore_utils.cpp -std=c++17
