###############################################################################
# This program will write down every file (other than .dll)                   #
# in the specified directory if currentSnapshot.1og is blank or non-existant. #
# If it does exist, it will only write down files that have been modified     #
# within the last couple days.                                                #
###############################################################################

import os                       #file path & stuff
import time                     #file dates
import sys                      #encode the file names
from os.path import join        #for full pathname
from shutil import copyfile     #put new log into current log
import binascii                 #turns files into hex
import timeit                   #times the code
import codecs                   #for encoding and decoding file names (some had special characters)
from itertools import islice                #for dividing the currentSnapshot (to save memory)

chunk_size = 41943040            #this number might have to be adjust according to ram (smaller number is slower)

filesTemp = []
fileTime = []
curSnap = "currentSnapshot.log"
newSnap = "newSnapshot.log"
newDir = "C:"   #C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/Common7/IDE/Extensions/uhuqfcub.t3o   test path
logDir = os.getcwd()

virusDB = 'md5.txt'  # known virus hexcode

#Creates a logfile with the name of every file in the newDir directory------------------------------------------------------------------------------------------------------
def createLogFile (snapshot, num):
    os.chdir(newDir)
    count = 0
    for (c, dirs, files) in os.walk('.'):
        try:
            for filename in files:
                curFile = os.path.join(c, filename)
                fUpdated = os.path.getmtime(curFile)
                if (time.mktime(time.localtime()) - fUpdated) < num:   #checks how new a file is
                    fileTime.append(fUpdated)
                    if (curFile.find(',') > 0):
                        filename = filename.replace(',','##!##')
                    filesTemp.append(os.path.abspath(join(c, filename)))
                    count += 1

        #Some .dll files can't be read, their names will be printed
        except FileNotFoundError:
            print('Can\'t find the file (expected .dll):',curFile)
    allFiles = ([filesTemp], [fileTime])   #stores filenames in a lost of lists
    os.chdir(logDir)

#opens or creates the log file
    logFile = open(snapshot, 'w')
    for item in allFiles:  # writes the list of lists to the log file
        if sys.stdout.encoding != 'cp850':
            logFile.write(str(("%s\n" % item).encode(sys.stdout.encoding, errors='replace')))
        else:
            logFile.write(str(item))

    #sync the logFile to be used on first creation
    logFile.flush()
    os.fsync(logFile)
    logFile.close()
    return count

#---------------------------end createLogFile------------------------------------------------------------------------------------------------

#Reads the files from currentSnapshot.log, turns them into hex code, then compares them to the known virus hex code specified in virusDB-----
def virusScanner(virusTxt,count):
    start = timeit.default_timer()

    counter = 0
    rekt = 0

    with codecs.open(curSnap, 'r') as filepaths:
        line = filepaths.readline()

        # manipulations to make the filenames readable
        line = line.strip('b')  #
        line = line.strip('[\\]\'\"')  #
        line = line.encode("utf-8")  #
        line = line.decode("utf-8").replace(u'\\xe2\\x80\\xa6', '…')  #
        line = line.encode("utf-8")  #
        line = line.decode("utf-8").replace(u'\\xe2\\x80\\x94', '—')  #
        line = line.replace('\\\'', '\'')  #
        if(line.find('\']]\\n"b\'[[') > 0):  #
            line = line.replace('\']]\\n"b\'[[','\', ')
        line = line.replace('##!##', ',')
        line = line.rstrip('1234567890.\']]\\n ,')   #this has a chance of messing up the scanner if the last file scanned ends in a number such as .mp3
        line = line.replace('\'','')                 #I haven't run into this problem while testing so I'm not sure what the error code would be
        line = line.replace('\"','')
        line = line.replace(']]\\nb[[','')

        #seperate the lines into a list
        lineTemp = line.split(', ')

        plsCheck = open('infectedFilesList.txt', 'w')

        # manipulations to split filenames
        for linetemp in lineTemp:

            try:#turning the file into Hex code and compare it to known virus hex code from md5.txt
                with open(linetemp, 'rb') as f2Hex:
                    while True:
                        tempHex = f2Hex.read(chunk_size)
                        if not tempHex:
                            break
                        hexCode = (binascii.hexlify(tempHex))
                        hexCode = hexCode.decode("utf-8")
                        counter += 1                   #files checked counter
                        with open(virusTxt, 'r') as hexCheck:
                            virHex = hexCheck.readlines()
                            for virus in virHex:
                                virus = virus.strip()
                                if (hexCode.rfind(virus) > 0):                              # tells you filename where virus is found but
                                    print("I found a virus in file", linetemp, "\n")        # doesn't do anything with it (in case of false positive)
                                    rekt += 1                                 # infected files counter
                                    plsCheck.write(linetemp)                  # wrote the name to file because the print statement will get lost in the general scan outputs
                        print("Scanning file", counter, "of", count, ":", linetemp)

            # Error handling
            except PermissionError:
                print("You don't have permission to scan this file!")
            except FileNotFoundError:
                print("File doesn't exist!?")

        print("Scanning file", counter, "of", count, ":", linetemp)

    plsCheck.close()
    filepaths.close()

    #Scanner outputs
    print("Found", rekt, "viruses.")
    print("Checked", counter, "files.")
    stop = timeit.default_timer()
    time = (stop - start)
    time = time / 86400
    time *= 1440
    print("Scanned for", int(time), "minutes.")

# -------------------------------end virusScanner-------------------------------------------------

#------------------------------main function start------------------------------------------------

totalFiles = 0

    #creates a snapshot if the log file is empty or non-existant
if not os.path.isfile(curSnap) or (os.stat(curSnap).st_size == 0):
    totalFiles = createLogFile(snapshot = curSnap, num = 99999999999999) #arbitrarily large number to check


    #creates a snapshot of files about 2 or less days old
else:
    totalFiles = createLogFile(snapshot = newSnap, num = 175000)  #slightly more than 2 days
    copyfile(newSnap, curSnap)                       #updates the current log file

#runs the virus scanner
virusScanner(virusDB,totalFiles)