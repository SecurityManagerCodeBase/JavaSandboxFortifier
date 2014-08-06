REM this sets the SMF_HOME and JAVA_TOOL_OPTIONS environment
REM variables using the directory the batch file is in.

setx SMF_HOME %~dp0
setx JAVA_TOOL_OPTIONS -agentpath:\"%~dp0\libsmf.dll\"