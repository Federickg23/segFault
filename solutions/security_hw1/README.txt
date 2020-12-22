===== DIRECTORY CONTENTS =====
1) tests: a directory that includes all the tests we may run using make test. These are bash scripts for each 
functionality of cstore. Each file shows off basic functionality, such as adding/deleting/listing files from the 
archive in the both the cases where the user is authenticated and the user is not. Run all at once using make test.
If you want to run them individually, test_setup.sh must be run first. Then, the tests can be run in any order.
    - test_setup.sh
    - add_test.sh
    - delete_test.sh
    - extract_test.sh
    - list_test.sh
    - test_cleanup.sh
    
2) crypto_lib: includes the open source files used for this project, from the Github link suggested 
(https://github.com/B-Con/crypto-algorithms). We use only the aes.c, aes.h, sha256.c, and sha256.h 
functions in our program.

3) cstore.cpp + cstore.h: Where the magic happens. The main function that calls all the other cstore functionality.

4) cstore_utils.cpp + cstore_utils.h: Utilities used in our functions to help with encrypting, decrypting, converting
datatypes, etc. Called by each of our other files.

5) cstore_add.cpp + cstore_add.h / cstore_delete.cpp + cstore_delete.h / cstore_extract.cpp + cstore_extract.h /
cstore_list.cpp + cstore_list.h: Each implement their respective cstore operation. All called by cstore.cpp.

6) Makefile: Makefile for the program, with the following available commands:
    - make
    - make install
    - make uninstall
    - make test
    - make testclean
    - make clean

===== HOW TO RUN/TEST =====
Making the executable is simple. Execute the following command:
    $ make

Installing/uninstalling cstore to the user's system is simple, although we opted to
unambiguously determine that this command is for installing to /usr/bin. Therefore,
sudo access might be needed (note that it is not needed for make test, which just
creates a temporary bin and temporarily adds it to $PATH). To install:
    $ sudo make install
To uninstall:
    $ sudo make uninstall
After installing, all commands outlined by the spec should be available:
	cstore list archivename
	cstore add [-p password] archivename file
	cstore extract [-p password] archivename file
	cstore delete [-p password] archivename file
For more information about each of these commands (and the assumptions made for each), please
scroll down to CSTORE COMMANDS section.

Executing all the tests is simple. Execute the following command (a make before calling make test is not needed):
    $ make test
make test writes the executable to a temporary bin directory in the working directory and changes the $PATH 
for the duration of make test. Then, the PATH is changed back and the bin directory is deleted. All the tests
should be printed to the terminal, along with their status (PASS/FAIL) and a description of the test. Files used
for testing are automatically created and cleaned up.

To get rid of all the .o files, run:
    $ make clean
Note this does NOT delete any existing archives the user might have created. 

===== DESIGN CHOICES =====
### (1) Archive Design ###
I opted for a simple design of the archive format. The beginning 32 bytes of any properly formatted archive (created
by cstore add) is the HMAC authentication code, calculated on the entire archive after each change to the archive. Per 
Prof. Bellovin's answer in Piazza @125, it was acceptable to calculate one HMAC of the entire archive (besides the HMAC 
itself of course), not on the individual files as well, so we opted for this approach. 

Then, each file is stored in 4 parts: (1) Filename Size (2) Filename (3) Content Size (4) Content. The Filename Size (1)
and Content Size (3) are each stored as single ints, so the maximum filename length and content size is the maximum possible
value of an int in bytes (2147483647 in C++). The Filename (2) and the Content (4) vary from file to file (though by AES CBC, 
is Content is always a multiple of 16). We DO NOT allow adding empty files to the archive (files with a filename but no contents 
in them).

In summary, each archive with N files is formatted as follows:

    - HMAC Code (32 bytes)
    - File1 name size (4 bytes or sizeof(int) on the system)
    - File1 name (Variable length)
    - File1 content size (4 bytes or sizeof(int) on system)
    - File1 content (Variable length and ENCRYPTED)
    - File2 name size
    - File2 name 
    .
    .
    .
    - FileN name size 
    - FileN name
    - FileN content size
    - FileN content

Note that the names are unencrypted, while the content is encrypted. Another design choice (that may not be optimal, but is sufficient
for this assignment) is that when a file with a duplicate name is added to the archive (perhaps an update), that duplicate file is 
appended to the end of the archive, and the earlier one is not deleted. Each of my functionalities handle this design choice fine by 
making sure to delete/extract/list the latest one.

### (2) Integrity Protection ###
Per Piazza @125, one HMAC code is calculated at for each archive, always the first 32 bytes of the file. We use SHA-256 to implement
HMAC, meaning the output of the HMAC is always 32 bytes. The process for integrity protection for each of the functions is as follows:

    - cstore list: No integrity check needed (per Piazza @130, it is acceptable to have a list that is also not robust to potentially
    tampered metadata).
    - cstore add: Authenticate in the beginning of the function using existing 32 byte HMAC. Then, encrypt the file(s) and append the
    file(s) and metadata to the archive. Finally, generate new HMAC code on the updated archive and insert to the first 32 bytes of the 
    updated archive that new HMAC.
    - cstore extract: Authenticate in the beginning of the function using existing 32 byte HMAC. Then, decrypt the file(s) and place
    each in working directory. No new HMAC needed because archive is unaltered.
    - cstore delete: Authenticate in the beginning of the function using existing 32 byte HMAC. Then, delete the requested file(s) and 
    metadata from the archive. Finally, generate new HMAC code on the updated archive and insert to the first 32 bytes of the updated
    archive that new HMAC.

### (3) AES Mode of Operation ###
I opted to use CBC mode for this assignment, as it is a trusted method (as opposed to ECB) when used with AES and it was suggested 
numerous times on Piazza. We use block size 16. There are a couple of finer points in my implementation of CBC worth pointing out:

    - The IV was sampled independently from dev/urandom, as requested, at the standard 16 bytes of randomness.
    - The padding for each plaintext was done in the way Ruth suggested in Piazza. For our particular blocksize (16),
    we added 16 - (length mod 16) bytes of padding, where each byte added is the padding length. For example, for a 
    message of length 10 bytes, we add 0x060606060606 because it is 6 bytes off from 16. For messages that are already
    16 bytes, we add 16 additional bytes of padding so there is no ambiguity when unpadding.

===== CSTORE COMMANDS =====
Below, we briefly outline the expected behavior of each cstore function.

### cstore list ###
Run by executing:

    $ cstore list archivename

This lists the archive name, the size of the entire archive (including the HMAC and metadata),
and the name(s) of the file(s) in the archive. Adding any other arguments doesn't do anything,
and the archivename must be immediately after 'list' in the command. For example:

    $ cstore list archivename hi hi hi 

has the same functionality as the first command above. Per Piazza post @130, it was safe to 
assume that the cstore list command would only be executed on well-formatted archives. Therefore,
this functionality is defined for well-defined archives (created by cstore add).

### cstore add ###
Run by executing:

    $ cstore add [-p password] archivename file

This adds the file(s) after 'archivename' to the archive, creating a new archive if one does 
not already exist. To add multiple files, simply:

    $ cstore add [-p password] archivename file1 file2 file3

By integrity check, a wrong password or adding to a tampered archive will fail. A successful 
add will always print:

    $ Add operation success.

New files with the same filename overwrite the existing files in the archive. For instance:

    $ cstore add -p password archive file1
    $ echo "hi" >> file1
    $ cstore add -p password archive file1

will give us the updated file1 with the "hi" when we extract the file. This is implemented in 
the tests for cstore add. NOTE: We DO NOT accept empty files (files with 0 bytes of content),
and throw an appropriate error notifying the user that they cannot supply empty files:

    $ Archive does not accept empty files. Please check that your file contains at least one byte of content.

### cstore delete ###
Run by executing:

    $ cstore delete [-p password] archivename file

This will delete the indicated file(s) from the archive. If a file in the archive was overwritten,
it will delete all the contents of files with the indicated name in the archive, as expected. For
multiple files:

    $ cstore delete [-p password] archivename file1 file2 file3

When deleting a file, we provide the user with a confirmation, for instance:

    $ file1 deleted from archive.

When deleting multiple overriden files, this is printed multiple times to allow the user to see how 
many updates were made to the file. For files that do NOT exist in the archive, no harm is done to the
archive and nothing is printed to the terminal -- only successful deletes are acknowledged from this
function. NOTE: If all files are deleted from an archive, we allow the archive to still exist as an
empty archive. It is STILL authenticated and thus contains only a 32 byte HMAC in the file. The same
authentication rules apply for adding/extracting/deleting from this existing empty archive.

### cstore extract ###
Run by executing: 

    $ cstore extract [-p password] archivename file

This will extract the indicated file(s) from the archive to the current working directory with the 
same filename it was given when it was added to the archive. To extract multiple files:

    $ cstore extract [-p password] archivename file1 file2 file3

If a file in the archive was updated (the same filename was added), the latest update will be extracted.
Successful extracts prints a message like follows, showing the filename and the size of its contents:

    $ file1 (3 bytes) successfully extracted.

A file that the user attempts to extract that is not in the archive will be met with a message like:

    $ file1 not found in archive.

Obviously, the extract only works if the user is able to provide the correct password, as the HMAC in
the beginning of the file is compared in order to begin extraction.









