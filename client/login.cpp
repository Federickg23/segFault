#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"
#include "login.h"
#include <vector>
#include <stdio.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <crypt.h>

using namespace std;

int main(int argc, char* argv[])
{
	string username = request_username();
	cout << login(username) << endl;	
}

string request_username()
{
	string username;
	cout << "Enter Username: ";
	cin >> username;
	return username;
}


int login(string username)
{
	// Check if username exists
	fstream file;
	string filename = "../server/private/hashed_passwords/" + username + ".txt";
   	file.open(filename, ios::in);  
   	if(!file.is_open()) //checking whether the file is open
   	{
		cout << "Username not found" << endl;
		return 0;
      	}
	
	string hashed_password;
      	getline(file, hashed_password);  // Should only be one line
        file.close();

	char* password = getpass("Enter Password: ");
	char* c = crypt(password, hashed_password.c_str());
	
	if (strcmp(c, hashed_password.c_str()) != 0) 
	{
		cout << "Incorrect Password" << endl;
		return 0;
	}

	cout << "Login Success" << endl;
	return 1;
}
