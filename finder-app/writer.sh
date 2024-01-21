#!/bin/bash
# A script to write a string within a file.
# Usage: ./writer.sh <writefile> <writestr>

# Check the validity of the arguments
if [[ "$1" == "" || "$2" == "" ]] ; then
echo "Any of the writefile or writestr arguments are not specified"
exit 1
fi

# Create the directory path if it doesn't exist
mkdir -p "$(dirname "$1")"

# Write content to the file, overwrite if it already exists
echo "$2" > "$1"

# Check exit status of the last executed command
if [ $? -ne 0 ]; then
    echo "Could not create file $1."
    exit 1
fi
