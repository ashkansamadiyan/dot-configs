#!/bin/bash

# Unmount the partitions
sudo umount ~/external/1
sudo umount ~/external/2
sudo umount ~/external/3

# Check if unmounting was successful
if [ $? -eq 0 ]; then
    echo "External HDD unmounted successfully."
    
    # Remove mount points
    rmdir ~/external/1 ~/external/2 ~/external/3
    rmdir ~/external
    
    echo "Mount points removed."
else
    echo "There was an error unmounting one or more partitions."
    echo "Please check if any files or applications are still using the drive."
fi
