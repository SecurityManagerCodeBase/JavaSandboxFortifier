REM this unsets the SMF_HOME and JAVA_TOOL_OPTIONS environment variables

reg delete HKCU\Environment /v JSF_HOME /f
reg delete HKCU\Environment /v JAVA_TOOL_OPTIONS /f