#/bin/bash
TAGPATTERN="refs/tags/v.*"
echo $1
if [[ "$1" =~ $TAGPATTERN ]]; then
  gradle publish -Dtoken=$2 -Drepo=$3 -Dusername=$4
else
	echo "skip as not relase tag!"
fi