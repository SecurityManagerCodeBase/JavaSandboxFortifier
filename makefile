# This makefile assumes you have JAVA_HOME set to your JDK directory
INCLUDES=$(JAVA_HOME)/include
CC = g++
CFLAGS = -Wall -pedantic -fPIC -shared
CLIBS = -llog4cpp -lboost_program_options

JCC = javac

default: all

all: buildtests buildagent

buildtests: 
	cd SecurityManagerTestCases/src/isr/cmu/edu/smf/test; \
	$(JCC) Main.java; \
	cd ../../../../../../; \
	mkdir -p bin/isr/cmu/edu/smf/test; \
	mv src/isr/cmu/edu/smf/test/*.class bin/isr/cmu/edu/smf/test/
	cd ..;

buildagent:
	cd smf_agent; \
	$(CC) -I$(INCLUDES) $(CFLAGS) -o libsmf.so main.cpp $(CLIBS); \
	cd ..;

run:
	java -agentpath:smf_agent/libsmf.so -classpath SecurityManagerTestCases/bin -Djava.security.policy=test.policy isr.cmu.edu.smf.test.Main

clean:
	-rm -f smf_agent/libsmf.so
	-rm -rf SecurityManagerTestCases/bin

