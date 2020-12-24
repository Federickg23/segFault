#!/bin/bash

echo
echo "##### CSTORE ADD TESTS #####"
### Test 1 
echo "== Test 1: Create new archive with single file. =="
cstore add test_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 0 ]
then 
    echo "## Test 1 PASSED. ##"
else
    echo "## Test 1 FAILED. ##"
fi
rm test_archive
echo

### Test 2
echo "== Test 2: Create new archive with multiple files. =="
cstore add test_archive -p pass file1.txt file2.c
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 0 ]
then 
    echo "## Test 2 PASSED. ##"
else
    echo "## Test 2 FAILED. ##"
fi
rm test_archive
echo

### Test 3
echo "== Test 3: Add single file to an existing archive with correct password. =="
cstore add test_archive -p pass file1.txt
cstore add test_archive -p pass file2.c
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 0 ]
then 
    echo "## Test 3 PASSED. ##"
else
    echo "## Test 3 FAILED. ##"
fi
rm test_archive
echo

### Test 4
echo "== Test 4: Add multiple files to an existing archive with correct password. =="
cstore add test_archive -p pass file1.txt
cstore add test_archive -p pass file2.c file3
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 0 ]
then 
    echo "## Test 4 PASSED. ##"
else
    echo "## Test 4 FAILED. ##"
fi
rm test_archive
echo

### Test 5
echo "== Test 5: Error thrown trying to add to an archive not created with cstore. =="
cstore add fake_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 3 PASSED. ##"
else
    echo "## Test 3 FAILED. ##"
fi
echo

### Test 6
echo "== Test 6: Error thrown when trying to add an empty file to new archive. =="
cstore add test_archive -p pass emptyfile
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 6 PASSED. ##"
else
    echo "## Test 4 FAILED. ##"
fi
echo

### Test 7
echo "== Test 7: Error thrown when trying to add an empty file to existing archive. =="
cstore add test_archive -p pass file1.txt
cstore add test_archive -p pass emptyfile
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 7 PASSED. ##"
else
    echo "## Test 5 FAILED. ##"
fi
echo

### Test 8
echo "== Test 8: Error thrown when trying to add to archive with wrong password. =="
cstore add test_archive -p pass file1.txt
cstore add test_archive -p wrong_pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 8 PASSED. ##"
else
    echo "## Test 8 FAILED. ##"
fi
rm test_archive
echo

### Test 9
echo "== Test 9: Error thrown when archive is tampered with by adversary. =="
cstore add test_archive -p pass file1.txt
echo "tamper" >> test_archive
cstore add test_archive -p pass file2.c
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 9 PASSED. ##"
else
    echo "## Test 9 FAILED. ##"
fi
rm test_archive
echo
