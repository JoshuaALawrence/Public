# Video Library Maintenance

<b>Use with caution, any and all misuse is your responsibility. Always backup files before running a destructive program such as this. This is just a fun side project.</b>

<small>**Note**: If there's multiple videos in the same directory, and one of them is shorter than the other (length) and below the minimum; it's possible they will both be removed.</small>

The Video Content Maintainer is designed for users with limited storage space or those who wish to retain only a specific number of videos in their collection.

By executing this script, it intelligently manages your video collection by removing either the oldest or newest videos, as specified in the configuration file.

The script respects the maximum file limit set, ensuring you always have the desired number of videos available.

Usage:

    Configure your preferences in the provided configuration file.
    Execute the script.
    The script will manage your video collection based on the criteria set in the configuration.

Your video collection, optimized.

# Configuration
#### MaxSize
The maximum allowed directories with videos in them before deletion will start.
***
#### DeleteMethod
The method of deletion, you have 2 options: Oldest and Newest. It's based off of creation date of the directory.
***
#### DeleteShort
Enables or disables deleting videos if they're below the specified time limit.

To disable this, change

    "DeleteShort": {
        "Enabled": "true",
        "MinimumLength": "10M"
    },   

to

    "DeleteShort": {
        "Enabled": "false",
        "MinimumLength": "10M"
    },
***
#### IgnoredVideos
Any string in this will be ignored from the deletion cycle (still counted towards the maximum). You can use * and the like to delete anything before or after a string.

Usage

	"IgnoredVideos": [
	    "Grandmas Birth*",
	    "Weekend Trip"
	],

 This will ignore any videos that start with 'Grandmas Birth', and any videos named exactly 'Weekend Trip'.
 ***
 #### IgnoredIfFiles
 Any string in this array will cause videos to be ignored if they contain the exact (case sensitive) file.

 Usage

	"IgnoreIfFiles": [
        "Ignore",
        "DoIgnore.txt"
	],

 This will ignore all videos and directories that contain the files: Ignore or DoIgnore.txt
***
 #### Logging

 This will enable logging for any errors, removals etc. You can disable this by changing "Enabled" to "false".
***
 #### ContentDirectory
 The location of the videos. They should be sorted in directories.

 Example:

     Folder >
          Content >
                  This directory is what it's asking for
                  VideoDir1 > VideoDir1.mov
                  VideoDir2 > VideoDir2.mov
 
# How To Run/Execute
Run in PowerShell:

    powershell -ExecutionPolicy Bypass -File "Start Maintenance.ps1"
