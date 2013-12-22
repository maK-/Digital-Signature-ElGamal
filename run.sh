#!/bin/bash

#Compile each time
javac -cp "./argparser.jar:." Crypto2.java

#run program with arguments
java -cp "./argparser.jar:." Crypto2 $*
