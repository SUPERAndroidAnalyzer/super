#!/bin/sh

if [ -d downloads ] ; then
    for file in downloads/*.apk
    do
        file=$(basename $file)
        app_id="${file%.*}"

        echo "Analyzing $app_id"

        target/release/super --force $app_id
    done
else
	echo "Error: downloads folder does not exist or has been renamed"
	exit 1
fi
