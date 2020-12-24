#!/bin/bash

echo
echo "##### CSTORE DELETE TESTS #####"
### Test 1 
echo "== Test 1: Delete single file from existing archive. =="
cstore add test_archive -p pass file1.txt
cstore delete test_archive -p pass file1.txt
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
echo "== Test 2: Delete multiple files from existing archive. =="
cstore add test_archive -p pass file1.txt file2.c
cstore delete test_archive -p pass file1.txt file2.c
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
echo "== Test 3: Delete single file from archive with multiple files. =="
cstore add test_archive -p pass file1.txt file2.c
cstore delete test_archive -p pass file1.txt
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
echo "== Test 4: Delete updated file in existing archive. =="
cstore add test_archive -p pass file1.txt
echo "update" >> file1.txt
cstore add test_archive -p pass file1.txt
cstore delete test_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 0 ]
then 
    echo "## Test 4 PASSED. ##"
else
    echo "## Test 4 FAILED. ##"
fi
rm test_archive
rm file1.txt
echo "Hi!" >> file1.txt
echo

### Test 5
echo "== Test 5: Delete file, add file, then delete again. =="
cstore add test_archive -p pass file1.txt
cstore delete test_archive -p pass file1.txt
cstore add test_archive -p pass file1.txt
cstore delete test_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 0 ]
then 
    echo "## Test 5 PASSED. ##"
else
    echo "## Test 5 FAILED. ##"
fi
rm test_archive
echo

### Test 6
echo "== Test 6: Error thrown when deletion attempted with wrong password. =="
cstore add test_archive -p pass file1.txt
cstore delete test_archive -p wrong_pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 6 PASSED. ##"
else
    echo "## Test 6 FAILED. ##"
fi
rm test_archive
echo

### Test 7
echo "== Test 7: Error thrown when deletion attempted on tampered archive. =="
cstore add test_archive -p pass file1.txt
echo "tamper" >> test_archive
cstore delete test_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 7 PASSED. ##"
else
    echo "## Test 7 FAILED. ##"
fi
rm test_archive
echo

### Test 8
echo "== Test 8: Error thrown when trying to delete from an archive not written by cstore. =="
cstore delete fake_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN -eq 1 ]
then 
    echo "## Test 8 PASSED. ##"
else
    echo "## Test 8 FAILED. ##"
fi
echo
