#!/bin/bash 

# make new directory
if [ -d "$1" ]
then
  echo "Directory already exists"
  exit 1
fi

mkdir $1
make
cp mail-in $1/
cp mail-out $1/
cd $1
mkdir bin mail inputs tmp lib
cd mail
sudo mkdir addleness analects annalistic anthropomorphologically blepharosphincterectomy corector durwaun dysphasia encampment endoscopic exilic forfend gorbellied gushiness muermo neckar outmate outroll overrich philosophicotheological pockwood polypose refluxed reinsure repine scerne starshine unauthoritativeness unminced unrosed untranquil urushinic vegetocarbonaceous wamara whaledom
cd ..
cd bin
mv ../mail-in .
mv ../mail-out .

# set perms
cd ../mail
sudo addgroup -gid 2050 mailout
for dir in ./
do
  sudo adduser --disabled-password --quiet $dir
  sudo -u $dir chmod u=rw,g=rw,o= $dir
  sudo chown $dir:mailout $dir
done
