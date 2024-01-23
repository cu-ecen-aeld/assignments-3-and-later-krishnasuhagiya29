#!/bin/bash
# A script to display the count of occurrences of a specified string and the number of files in which the string is present within a directory.
# Usage: ./finder.sh <filesdir> <searchstr>

# Check the validity of the arguments
if [[ "$1" == "" || "$2" == "" ]] ; then
echo "Exit 1: Any of the filesdir or searchstr arguments are not specified"
echo "Usage: ./finder.sh <filesdir> <searchstr>"
exit 1
fi

# Check if the specified directory exists
if [ ! -d "$1" ]; then
echo "Exit 1: The specified filesdir does not exist"
exit 1
fi

# Find recursively in the directory specified and count the total number of lines
LINES_COUNT=`grep -r "$2" "$1" | wc -l`

# Find recursively in the directory specified and count only the number of files
FILES_COUNT=`grep -rl "$2" "$1" | wc -l`

echo "The number of files are $FILES_COUNT and the number of matching lines are $LINES_COUNT"
