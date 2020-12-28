#!/bin/bash
input="../logins.txt"
rm -rf hashed_passwords
mkdir hashed_passwords

while IFS= read -r line
do
	IFS=' ' # space is set as delimiter
  	read -ra ADDR <<< "$line" # line  is read into an array as tokens separated by IFS
  	k=1
	filename=""
	crypto=""
  	for i in "${ADDR[@]}"; do # access each element of array
		if [ $k == 1 ]; then
			filename=$i
		        k=2	
		elif [ $k == 2 ]; then
			crypto=$i
			k=3
		else
			k=1
		fi	
	done

	echo $crypto > hashed_passwords/$filename.txt 

done < "$input"
