#!/bin/bash

echo
echo "##### CSTORE EXTRACT TESTS #####"
### Test 1 
echo "== Test 1: Extract single file from archive. =="
cstore add test_archive -p pass file1.txt
cstore extract test_archive -p pass file1.txt
value1=$(<file1.txt)
echo "$value1"
RETURN=$?
cstore list test_archive 
if [ $value1 = 'Hi!' ] 
then 
    echo "## Test 1 PASSED. ##"
else
    echo "## Test 1 FAILED. ##"
fi
rm test_archive
echo

### Test 2
echo "== Test 2: Extract multiple files from archive. =="
cstore add test_archive -p pass file1.txt file2.c 
cstore extract test_archive -p pass file1.txt file2.c
value1=$(<file1.txt)
value2=$(<file2.c)
echo "$value1"
echo "$value2"
RETURN=$?
cstore list test_archive 
if [ $value1 = "Hi!" ] && [ $value2 = "Test!" ]
then 
    echo "## Test 2 PASSED. ##"
else
    echo "## Test 2 FAILED. ##"
fi
rm test_archive
echo

### Test 3
echo "== Test 3: Upate file in archive and extract updated file. =="
cstore add test_archive -p pass file1.txt
rm file1.txt
echo "I am updated" >> file1.txt 
cstore add test_archive -p pass file1.txt
cstore extract test_archive -p pass file1.txt
value1=$(<file1.txt)
echo "$value1"
RETURN=$?
cstore list test_archive 
if [ "$value1" = 'I am updated' ] 
then 
    echo "## Test 3 PASSED. ##"
else
    echo "## Test 3 FAILED. ##"
fi
rm test_archive
echo

### Test 4
echo "== Test 4: Extract a file that doesn't exist in archive (user is notified). =="
cstore add test_archive -p pass file1.txt
cstore extract test_archive -p pass notexist.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN = 0 ] 
then 
    echo "## Test 4 PASSED. ##"
else
    echo "## Test 4 FAILED. ##"
fi
rm test_archive
echo

### Test 5
echo "== Test 5: Error thrown when trying to extract with wrong password. =="
cstore add test_archive -p pass file1.txt
cstore extract test_archive -p wrongpass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN = 1 ] 
then 
    echo "## Test 5 PASSED. ##"
else
    echo "## Test 5 FAILED. ##"
fi
rm test_archive
echo


### Test 6
echo "== Test 6: Error thrown when trying to extract from tampered archive. =="
cstore add test_archive -p pass file1.txt
echo "tamper" >> test_archive
cstore extract test_archive -p pass file1.txt
RETURN=$?
cstore list test_archive 
if [ $RETURN = 1 ] 
then 
    echo "## Test 6 PASSED. ##"
else
    echo "## Test 6 FAILED. ##"
fi
rm test_archive
echo
