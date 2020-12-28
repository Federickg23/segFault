#!/bin/bash

for i in {1..13}
do
  fname=$(printf "./tests-%s.sh" $i)
  chmod +x $fname
  eval $fname
done