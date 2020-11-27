#!/bin/bash
TAGPATTERN="refs/tags/.*"
echo $1
if [[ "$1" =~ $TAGPATTERN ]]; then
	gradle publish
else
	echo "skip as not release tag!"
fi
