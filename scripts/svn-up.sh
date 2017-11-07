#!/bin/bash

git stash

TRUNK=1521
SUCCESS=true

while [ $SUCCESS == true ]; do
	SUCCESS=false
	let TRUNK+=1
	[ $TRUNK = 1520 ] && exit 0
	echo "Getting patch to svn $TRUNK"
	wget -nv -O modern${TRUNK}.patch "http://www.streamboard.tv/oscam-addons/changeset/${TRUNK}/modern?format=diff&new=${TRUNK}"
	[ $? == 0 ] && cat modern${TRUNK}.patch | sed 's:modern/:src/:gi' | patch -p0 -l -s && SUCCESS=true
done
