# This makefile assumes you have JAVA_HOME set to your JDK directory
INCLUDES=$(JAVA_HOME)/include
CC = g++
CFLAGS = -Wall -pedantic -fPIC -shared

JCC = javac

default: all

all: buildtests buildagent

buildtests: 
	cd SecurityManagerTestCases/src/isr/cmu/edu/smf/test; \
	$(JCC) Main.java; \
	cd ../../../../../../; \
	mkdir -p bin/isr/cmu/edu/smf/test; \
	mv src/isr/cmu/edu/smf/test/Main.class bin/isr/cmu/edu/smf/test/Main.class
	cd ..;

buildagent:
	cd smf_agent; \
	$(CC) $(CFLAGS) -I$(INCLUDES) -o libsmf.so main.cpp; \
	cd ..;

run:
	LD_LIBRARY_PATH=smf_agent java -agentlib:smf -classpath SecurityManagerTestCases/bin isr.cmu.edu.smf.test.Main

clean:
	-rm -f smf_agent/libsmf.so
	-rm -rf SecurityManagerTestCases/bin

