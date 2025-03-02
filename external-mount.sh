#!/bin/bash

# Create mount points in the user's home directory
mkdir -p ~/external/1 ~/external/2 ~/external/3

# Mount the partitions
sudo mount -t ntfs-3g -o uid=$(id -u),gid=$(id -g) /dev/sdc1 ~/external/1
sudo mount -t ntfs-3g -o uid=$(id -u),gid=$(id -g) /dev/sdc2 ~/external/2
sudo mount -t ntfs-3g -o uid=$(id -u),gid=$(id -g) /dev/sdc3 ~/external/3

# Check if mounting was successful
if [ $? -eq 0 ]; then
    echo "External HDD mounted successfully."
    echo "Mounted partitions:"
    df -h | grep "$HOME/external"
else
    echo "There was an error mounting one or more partitions."
    echo "Please check the output above for more details."
fi
