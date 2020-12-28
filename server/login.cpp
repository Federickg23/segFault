#include <vector>
#include <stdio.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <crypt.h>

using namespace std;

string login(string username, string password)
{
	// Check if username exists
	fstream file;
	string filename = "hashed_passwords/" + username + ".txt";
   	file.open(filename, ios::in);  
   	if(!file.is_open()) //checking whether the file is open
   	{
		return "Username not found";
      	}
	
	string hashed_password;
      	getline(file, hashed_password);  // Should only be one line
        file.close();

	char* c = crypt(password.c_str(), hashed_password.c_str());
	
	if (strcmp(c, hashed_password.c_str()) != 0) 
	{
		return "Incorrect Password";
	}

	return "Login Success";
}
