#!/bin/bash

#git stash

TRUNK=$(cat src/.trunk-svn)
SUCCESS=true

while [ $SUCCESS == true ]; do
	SUCCESS=false
	let TRUNK+=1
	echo "Getting patch to svn $TRUNK"
	wget -nv -O svn${TRUNK}.patch "http://www.streamboard.tv/oscam/changeset/${TRUNK}?format=diff&new=${TRUNK}"
	[ $? == 0 ] && cat svn${TRUNK}.patch | sed 's:/trunk:./src:gi' | patch -p0 -l -s && SUCCESS=true && echo ${TRUNK} > src/.trunk-svn
done
