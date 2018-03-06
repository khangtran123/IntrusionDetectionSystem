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
    
def blockIP():
    return

def unblockIP():
    return

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
    failedAttempts
    totalAttempts
    connectionFilepath = "/var/log/secure"
    
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
            thirdLFF = line[len(line) - 3]
            fourthLFF = line[len(line) - 4]
            
            if "more authentication failures" in lastLFF:
                #lastLFF = thirdLFF
                #secondLFF = fourthLFF
                return
            if "Failed password for" in lastLFF:
                '''
                findall() --> The string is scanned left-to-right, 
                              and matches are returned in the order found
                r' --> The 'r' at the start of the pattern string designates 
                a python "raw" string which passes through backslashes 
                without change which is very handy for regular expressions
                '''
                clientAddress = re.findall(r'[0-9]+(?:\.[0-9]+){3}', lastLFF)
                timestamp = re.findall()
                

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
    
    observer = Observer()
    observer
    observer.schedule()


if __name__ == "__main__": main()
