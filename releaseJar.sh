#/bin/bash
TAGPATTERN="refs/tags/v.*"
echo $1
if [[ "$1" =~ $TAGPATTERN ]]; then
  gradle publish
else
	echo "skip as not relase tag!"
fi