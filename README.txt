Most antivirus programs use a combination of heuristics and hash searching. This antivirus scanner uses md5 hashes to find known viruses. 
The virus hash codes are kept in the md5.txt file and should be in the same directory as your HensonAntiVirus.py file. 
When you run HensonAntiVirus.py the first time, it will create a log file in the current working directory called currentSnapshot.log
This log file will contain a list of all files in the specified directory (C: by default) and run them through the scanner.
If there is already a non-empty currentSnapshot.log in your current working directory, it will create a log file named newSnapshot.log with a list of all files in the specified directory that have been modified within the last 2 days or so (I added a little wiggle room, but its less than 2.5 days).
newSnapshot.log is then copied into currentSnapshot.log and currentSnapshot.log is run through the scanner.
HensonAntiVirus.py will also generate a file called infectedFiles.txt that will contain a list of files that tested positive for a virus hash (will be blank if no virus is found).

P.S. I included the full md5.txt that i got off of https://virusshare.com/hashes.4n6 (file 153).
There are a lot of hashes in there, so I tested my code with only 5 lines.