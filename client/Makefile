
main: client.cpp login.cpp
	g++ -Wall client.cpp -o client -lcrypto -lssl
	g++ -Wall login.cpp -o login -lcrypt -lssl	
	rm -f *.o
	sudo chown root ./client
	sudo chmod u+s ./client
	sudo chmod g-w ./client
	sudo chmod o-w ./client
