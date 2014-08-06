SecurityManagerFortifier
========================

SecurityManagerFortifier (SMF) is a JVMTI agent that monitors changes to the System class’s SecurityManager for a running Java application and stops potentially malicious operations.

Build Dependencies
--------------------------------

lib4cpp (sudo apt-get install liblog4cpp5-dev)
Boost (sudo apt-get install libboost-all-dev) -- for Boost.Program_options

Building on Linux
--------------------------------

To build both the tests and the agent run: make
To build just the agent run: make buildagent
To build just the tests run: make buildtests
To run the agent on the test cases and see the results run: make run

Building on Windows
--------------------------------

With Visual Studio installed, open the Developer Command Prompt (Start -> All Program -> Microsoft Visual Studio -> Visual Studio tools).

Note: For a 64-bit build ensure you open the x64 version of the Developer Command Prompt

Fill in the [blanks] in the following command line and run it in the smf_agent directory:

cl main.cpp /EHsc /GS /DYNAMICBASE /I "%JAVA_HOME%\include" /I "%JAVA_HOME%\include\win32" /I [path_to_log4cpp_includes] /I [path_to_boost_folder] /link /LIBPATH:[path_to_boost_folder]\stage\lib /LIBPATH:[path_holding_log4cppLIB.lib] log4cppLIB.lib Advapi32.lib Ws2_32.lib /DLL /OUT:libsmf.dll

Install on Windows
--------------------------------

You can quickly set the necessary environment variables to cause SMF to attach to every executed Java application by running setenv.bat in the smf_agent directory. This batch file sets the SMF_HOME and JAVA_TOOL_OPTIONS environment variables by assuming SMF_HOME is the directory the batch file is located in. Note that if you run this script it will wipe out anything that is already set in JAVA_TOOL_OPTIONS. The environment variables are only set for the user that runs the batch file.

You can uninstall SMF by removing these environment variables. Running unsetenv.bat performs this operation.

Always Attach SecurityManagerFortifier
--------------------------------

To ensure the agent is attached to every Java application that is executed on a particular system, set the JAVA_TOOL_OPTIONS (http://docs.oracle.com/javase/6/docs/platform/jvmti/jvmti.html#tooloptions) environment variable to set the -agentpath switch to point to the agent (e.g. JAVA_TOOL_OPTIONS=-agentpath:C:\smf\libsmf.dll). 

Configuring SecurityManagerFortifier
--------------------------------

The log.properties, smf.properties, and libsmf.(dll|so) files should all be in the same directory and this directory should be set as the value of an environment variable called SMF_HOME (e.g. SMF_HOME=C:\smf). SMF_HOME is required by SMF to find its properties files because the current working directory (CWD) changes depending on what application SMF is attached to. If you do not set this environment variable, SMF will attempt to find the properties files in the CWD.

SMF uses log4cpp for logging purposes, which is configured via the log.properties file. See:

http://log4cpp.sourceforge.net/#propfile
http://log4cpp.sourceforge.net/api/hierarchy.html

Finally, SMF itself is configured via smf.properties. This file has two settings: mode and popups.show: 

-mode can be set to either monitor or enforce. In monitor mode SMF will log messages about changes to the SecurityManager*. In enforce mode, SMF will log changes and forcibly shutdown any application that modifies the SecurityManager in a way that is malicious. Enforce mode follows several rules:
--If the SecurityManager was never set, setting it to NULL produces a log message, but SMF takes no further actions because this case represent a no-op.
--If the SecurityManager is not currently set but is being set to a SecurityManager that is permissive (i.e. one that allows operations that would let even code subject the manager's security policy disable or change the manager or change the policy), SMF drops to monitor mode. If an application sets its initial manager to one that is permissive, there is nothing SMF can do to protect it in enforce mode.
--Assuming the SecurityManager was set to one that is not permissive, any further changes to the manager result in termination of the Java application.
-popups.show can be set to either true or false. If true, SMF will show the user a popup describing why a Java application is being terminated before it is terminated. Servers should set this option to false.

*Note that SMF will only monitor changes to the SecurityManager stored in java.lang.System's security field. If manager is stored some other way, it is not an official manager and will not be utilized by JRE classes.