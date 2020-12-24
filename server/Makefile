all: server

server: server.o mkcert.o crypto.o cstore_utils.o list.o mail_utils.o
	g++ -Wall server.o mkcert.o crypto.o list.o cstore_utils.o mail_utils.o -o server -lcrypto -lssl 
crypto.o:
	g++ -c crypto.cpp -std=c++17
mkcert.o:
	gcc -c mkcert.c -lssl -lcrypto
list.o:
	g++ -c list.cpp -std=c++17
cstore_utils.o:
	g++ -c cstore_utils.cpp -std=c++17
mail_utils.o:
	g++ -c mail_utils.cpp -std=c++17
