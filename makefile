# This makefile assumes you have JAVA_HOME set to your JDK directory
INCLUDES=$(JAVA_HOME)/include
CC = g++
CFLAGS = -Wall -pedantic -fPIC -shared -O3
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
	cd jsf_agent; \
	$(CC) -I$(INCLUDES) $(CFLAGS) -o libjsf.so main.cpp $(CLIBS); \
	cd ..;

run:
	java -agentpath:jsf_agent/libjsf.so -classpath SecurityManagerTestCases/bin -Djava.security.policy=test.policy isr.cmu.edu.smf.test.Main

clean:
	-rm -f jsf_agent/libjsf.so
	-rm -rf SecurityManagerTestCases/bin

