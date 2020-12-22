#!/bin/bash

echo
echo "##### CSTORE LIST TESTS #####"
### Test 1 
echo "== Test 1: List the file in an archive with single file. =="
cstore add test_archive -p pass file1.txt
cstore list test_archive 
RETURN=$?
if [ $RETURN -eq 0 ]
then 
    echo "## Test 1 PASSED. ##"
else
    echo "## Test 1 FAILED. ##"
fi
rm test_archive
echo

### Test 2
echo "== Test 2: List the files of an archive with multiple files. =="
cstore add test_archive -p pass file1.txt file2.c
cstore list test_archive 
RETURN=$?
if [ $RETURN -eq 0 ]
then 
    echo "## Test 2 PASSED. ##"
else
    echo "## Test 2 FAILED. ##"
fi
rm test_archive
echo

### Test 3
echo "== Test 3: Error when trying to list a file that doesn't exist. =="
cstore list archive_doesnt_exist 
RETURN=$?
if [ $RETURN -eq 1 ]
then 
    echo "## Test 3 PASSED. ##"
else
    echo "## Test 3 FAILED. ##"
fi
echo
