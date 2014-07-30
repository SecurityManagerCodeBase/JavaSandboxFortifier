SecurityManagerFortifier
========================

A JVMTI agent that monitors the System SecurityManager for changes and stops potentially malicious operations.

Dependencies:
--------------------------------

lib4cpp (sudo apt-get install liblog4cpp5-dev)
Boost (sudo apt-get install libboost-all-dev) -- for Boost.Program_options

Building on Linux:
--------------------------------

To build both the tests and the agent run: make
To build just the agent run: make buildagent
To build just the tests run: make buildtests
To run the agent onthe test cases and see the results run: make run

Building on Windows:
--------------------------------

With Visual Studio installed, open the Developer Command Prompt (Start -> All Program -> Microsoft Visual Studio -> Visual Studio tools).

Note: For a 64-bit build ensure you open the x64 version of the Developer Command Prompt

Fill in the <blanks> in the following command line and run it in the smf_agent directory:

cl main.cpp /EHsc /GS /DYNAMICBASE /I "%JAVA_HOME%\include" /I "%JAVA_HOME%\include\win32" /I <path_to_log4cpp_includes> /I <path_to_boost_folder> /link /LIBPATH:<path_to_boost_folder>\stage\lib /LIBPATH:<path_holding_log4cppLIB.lib> log4cppLIB.lib Advapi32.lib Ws2_32.lib /DLL /OUT:libsmf.dll

Always Running SecurityManagerFortifier
--------------------------------
To ensure the agent is run with every Java application on a particular system, set the JAVA_TOOL_OPTIONS (http://docs.oracle.com/javase/6/docs/platform/jvmti/jvmti.html#tooloptions) environment variable to set the -agentpath switch to point to the agent (e.g. JAVA_TOOL_OPTIONS=-agentpath:C:\smf\libsmf.dll). 

Configuration
--------------------------------

The log.properties, smf.properties, and libsmf.(dll|so) files should all be in the same directory and this directory should be set as the value of an environment variable called SMF_HOME (e.g. SMF_HOME=C:\smf). SMF_HOME is required by SMF to find its properties files because the current working directory (CWD) changes depending on what application SMF is attached to. If you do not set this environment variable, SMF will attempt to find the properties files in the CWD.

SMF uses log4cpp for logging purposes, which is configured via the log.properties file. See:

http://log4cpp.sourceforge.net/#propfile
http://log4cpp.sourceforge.net/api/hierarchy.html

Finally, SMF itself is configured via smf.properties. This file only has one setting: mode. Mode can be set to either monitor or enforce. In monitor mode SMF will log messages about changes to the SecurityManager. In enforce mode, SMF will log changes and forcibly shutdown any application that modifes the SecurityManager in a way that is malicious.