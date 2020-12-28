#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <vector>
#include<algorithm>

using namespace std;

void send(string recipient, string message) {

    string line;
    struct stat dirstats;
    string path = "mail/" + recipient;
    stat(path.c_str(), &dirstats);

    if (S_ISDIR(dirstats.st_mode) == 0) {
        exit(1);
    }

    // Find the smallest file value
    DIR* dirp = opendir(path.c_str());
    struct dirent* dp;
    vector <int> files;

    while((dp = readdir(dirp)) != NULL) {
	string dname = string(dp->d_name);
	if(dname == "." || dname == "..") 
	{
		continue;
	}
        files.push_back(atoi(dp->d_name));
    }

    sort(files.begin(), files.end());
    int i;           // The filename to append to the directory      
    for(i = 0; i < (int) files.size(); i++) {
        if (files[i] != i+1) 
            break;
    }
    i += 1;

    char filename[6];
    sprintf(filename, "%05d", i); 

    // Now we just create a new file with the message and that filename
    
    fstream file;
    string filepath = path + '/' + string(filename);
    file.open(filepath.c_str(), ios::out);
    file << message; 
    file.close();
}
