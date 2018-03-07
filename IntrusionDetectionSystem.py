#!/bin/python3

'''
File: IntrusionDetectionSystem.py
Date: March 05, 2018
Designers: Huu Khang Tran, Anderson Phan
Description: This script creates and deploys an IDS that will detect
             password guessing attempts against a service and block 
             that IP using Netfilter.
             
Use Linux Crontab (Optional) - a process in Linux that schedules commands periodically. 
                    It allows tasks to be automatically run in the background 
                    at specified intervals. In this case, we want every second.
                    
Passord guessing on SSH
Important file: /var/log/secure
"Failed password for root from 192.168.0.xx port XXXX ssh2"
Then you use Netfilter and block that IP
tail -f secure

system time

User Input
a) Number of attempts before blocking IP   
b) Time limit for blocking the IP. Default setting = block indefinitely

Optional --> Monitor a log file of users choice.  
'''

import time
import os
import threading
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
#   re --> Python 3 library for regular expression, specifies a set of strings 
#          that matches it
import re 

'''
function crontab takes in 3 arguments
    a) attemptsNUM = Total numbers of failed password attempts before blocking IP 
    b) timeSlowScan = meaning several password guessing attempts, but spaced 
       far enough apart in time so that your application will miss the attack
    c) banTime = how long you will ban the IP for
    
What does this function do?
    Creates a cronjob for the IDS script to be run everytime, but first we must 
    check the currrent crontab file to see if this script is already running
'''

def crontab(attemptsNum, timeSlowScan, banTime):
    #   commandExist checks to see if cronjob is present or not
    #   0 --> Not present
    #   1 --> Present
    commandExist = 0
    #   filepath gets the current direct path to the file
    #   filename gets the current script name
    filepath =  os.path.dirname(os.path.realpath(__file__))
    filename = os.path.basename(__file__)
    #   %s --> insert a string into th
    cronjob = '@reboot /usr/bin/python %s/%s' % (filepath,filename)
    #   now we need to check if this cronjob exists in the current crontab file
    #   open --> a better approach of opening and closing a file
    #   for line in --> reads line-for-line in file
    with open('/etc/crontab','r') as crontab:
        for line in crontab:
            if cronjob not in line:
                if commandExist != 1:
                    commandExist = 0
                else:
                    commandExist = 1
    
    if commandExist == 0:
        #   crontab --> file pointer
        #   a --> open for writing, appending to the end of the file if it exists
        #   seek --> sets the files current position 
        #   [0] = ref point is the beginning of the file
        #   [2] = ref point is the end of the file
        crontab = open('/etc/crontab', a)
        crontab.seek(0,2)
        command = '@reboot /usr/bin/python %s/%s' % (filepath,filename)
        crontab.write(command)
        crontab.close()
    #os.system('crontab /etc/crontab')


'''
Class userProfile --> is what sets up the UserProfile object that represents
                      two attributes: Their IP Address + time of attempt
'''
class userProfile(object):
    clientAddress = ""
    timestamps = []
    
    '''
	__init__ is considered a constructor just like in Java.
	self represents the instance of that object we declared 
	this constructor will be our base of what a user should 
        be made up of --> Their IP Address + all timestamps for 
        that attempt for that user
    '''
        
    def __init__(self, clientAddress, timestamps):
        self.clientAddress = clientAddress
        self.timestamps = timestamps


'''
Function createUserProfile --> pretty much creates a userProfile object by calling
                               on the userProfile class that creates the user whp
                               tries to logon to your machine. The class will be
                               binding their IP address as well as the timestamp
'''
def createUserProfile(clientAddress, timestamps):
    userID = userProfile(clientAddress,timestamps)
    return userID


'''
Function calculateTotalTime() --> convert the X:X:X timestamp format taken from
                                  /var/log/secure and convert it to seconds to
                                  get the total time for each attempt. We need
                                  to convert it one value (seconds) for useful
                                  comparison when we calculate the difference in
                                  time between each attempt.
'''
def calculateTotalTime(timeEntry):
    #   Timestamp format --> HH:MM:SS
    #   we need to split the stamp into different segments, convert it to 
    #   seconds, and then add everything together to get the totalTimeAttempt
    #   1 hour = 3600 seconds
    #   1 minute = 60 seconds
    timeSegment = timeEntry.split(':')
    
    hour = int(timeSegment[0])
    hour = hour * 3600
    minute = int(timeSegment[1])
    minute = minute * 60
    second = int(timeSegment[2])
    
    totalTimePerAttempt = hour + minute + second
    
    return totalTimePerAttempt


'''
Function addTimesForUser --> Reference the user object and add the new timestamp
                             for the failed attempt to user's timestamps dictionary.
'''
def addTimesForUser(timestamp):
    userID.timestamps.append(timestamp)
    
    
def blockIP(clientIP):
    global banTime
    #   Make sure ban time is set to XX minutes
    if banTime != 0:
        netFilterCommand = "iptables -A INPUT -s %s -j DROP" % str(clientIP)
        os.system(netFilterCommand)
        #   here we are checking for banTime seconds using a thread timer
        #   more efficient for system handling. Once the time is reached, 
        #   the thread will call on the unblock function
        #   threading.timer(Time,function to call, argument)
        timer = threading.timer(banTime,unblockIP(),clientIP)
        timer.start()
        print ("User: " + str(clientIP) + " has been banned from logging into you machine for " + banTime + " minutes")


def unblockIP(clientIP):
    #   -D --> Removes/Deletes this current netfilter rule
    removeNetfilterCommand = "iptables -D INPUT -s %s -j DROP" % str(clientIP)
    os.system(removeNetfilterCommand)


'''
For this IDS, we will use an event handler to deal with specific IP addresses
or clients who take too many attempts to login via SSH. 
Will read from /var/log/secure

def on_modified --> Called when a file or directory is modified. Soo since 
                    secure will always concatenate with entries if a client tries
                    to connect whether or not it was successful or a fail, we 
                    need to "action" it once there is a change to that file.
'''
class Event(LoggingEventHandler):
    global failedAttempts
    global totalAttempts
    #  global bannedClients
    connectionFilepath = "/var/log/secure"
    #   we set this var as 0 to set the newClient flag off
    
    def on_modified(self, event):
        #   src_path = Source path of the file system object that triggered this event.
        #   we need to make sure the trigggered event was in the /var/log/secure
        if event.src_path == str(connectionFilepath):
            openFile = open(connectionFilepath)
            #   readlines() returns a list containing the lines from the file
            #   LFF = Line From File
            line = openFile.readlines()
            #   here we assume that the last 4 lines of the /var/log/secure is
            #   is the entry that includes the action, time, status, target, and
            #   IP address
            lastLFF = line[len(line) - 1]
            secondLFF = line[len(line) - 2]
            #thirdLFF = line[len(line) - 3]
            #fourthLFF = line[len(line) - 4]
            
            if "Failed password for" in lastLFF:
                '''
                findall() --> The string is scanned left-to-right, 
                              and matches are returned in the order found
                r' --> The 'r' at the start of the pattern string designates 
                a python "raw" string which passes through backslashes 
                without change which is very handy for regular expressions
                '''
                timestamps = []
                clientAddress = re.findall(r'[0-9]+(?:\.[0-9]+){3}', lastLFF)
                timestamp = re.findall(r'\d{2}:\d{2}:\d{2}', lastLFF)
                #   if not --> if failedAttempts is [], then execute
                #   means a new IP Address has failed logging into machine, will always increment for different users
                if not failedAttemtps:
                    userID = createUserProfile(clientAddress[0], timestamps)
                    addTimesForUser(userID, timestamp[0])
                    print (clientAddress + " attempted to login to your machine. New client is added to the dictionary of failed attempts.")
                    #  now we want to add this user to our list of failed attempts
                    failedAttempts.append(userID)
                    if len(userID.timestamps) > attemptsLimit:
                        IP = str(userID.clientAddress[0])
                        blockIP(IP)
                # That means this is a re-occuring attempt from the same client user
                else:
                    newClient = 0
                    for client in failedAttempts:
                        if client.clientAddress == clientAddress[0]:
                            #   client user already exists --> adding timestamp in dictionary
                            if timestamp[0] not in timestamps:
                                addTimesForUser(client,timestamp[0])
                                print ("Existing client --> " + str(clientAddress) + " attempted to login to your machine. New client is added to the dictionary of failed attempts.")
                                #   now we turn on the newClient flag
                                newClient = 1
                                print ("Number of attempts: " + str(attemptsLimit))
                                if len(client.timestamps) > attemptsLimit:
                                    timestampsLen = len(client.timestamps)
                                    firstTimestamp = client.timestamps[(timestampsLen - attemptsLimit)]
                                    lastTimestamp = client.timestamps[(timestampsLen - 1)]
                                    firstStamp = calculateTotalTime(firstTimestamp)
                                    lastStamp = calculateTotalTime(lastTimestamp)
                                    differenceBetweenFail = (lastStamp - firstStamp)
                                    
                                    if differenceBetweenFail <= timeSlowScan:
                                        IP = str(client.clientAddress)
                                        blockIP(IP)
                    if newClient == 0:
                        userID = createUserProfile(clientAddress[0], timestamps)
                        addTimesForUser(userID, timestamp[0])
                        failedAttemps.append(userID)
                        print (clientAddress + " attempted to login to your machine. New client is added to the dictionary of failed attempts.")
                        
            #   if the client gets it right after the failed attempt, this will clear all records of client failed attempts by clearing the timestamps array            
            elif ("Accepted password for" in lastLFF) or ("Accepted password for" in secondLFF):
                clientAddress = re.findall(r'[0-9]+(?:\.[0-9]+){3}', secondLFF)
                for client in incorrectAttempts:
                    if client.clientAddress == clientAddress[0]:
                        client.timestamps = []
                
def main():
    print ("Welcome to our IDS! Unforunately for testing, crontab's limits to only minutes rather than seconds.")
    #attemptsLimit = raw_input("What's the maximum number of failed password attempts you want to set the bar at? ")
    #timeSlowScan = int(raw_input("What are the intervals between each password attempt? (minute) "))
    #banTime = int(raw_input("How long do you want to ban the IP from logging back in? (minute) "))
    attemptsLimit = 3
    timeSlowScan = 1
    banTime = 1
    crontab(attemptsLimit, timeSlowScan, banTime)
    eventHandler = Event()
    
    #   observer is a library used to monitor any events/changes from /var/log
    #   if an event is triggered, it will launch the event handler
    observer = Observer()
    observer.schedule(eventHandler, path='/var/log', recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    
    failedAttempts = []
    

if __name__ == "__main__": main()
