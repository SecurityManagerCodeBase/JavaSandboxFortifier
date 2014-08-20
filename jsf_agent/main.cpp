// Copyright (c) 2014 Carnegie Mellon University and Others
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/** 
 * @file	main.cpp
 * @brief 	This JVMTI agent monitors applications for Privilege Escalation and changes to the 
 *			SecurityManager.
 *
 * To spot Privilege Escalation, this agent compares the ProtectionDomain for every class that is
 * loaded by a non-bootstrap ClassLoader to the ProtectionDomains for every class in the call stack
 * that caused the class to be loaded that also was loaded by a non-boostrap ClassLoader. If
 * a ProtectionDomain for a caller is weaker than the ProtectionDomain of the loaded class, we
 * have privilege escalation.
 *
 * The Java SecurityManager is responsible for enforcing a security policy for the execution of a
 * Java application. The SecurityManager is stored in java.lang.System's security field.
 * This agent sets up read/write watch on the that field. These watches are used to detect that
 * a non-permissive SecurityManager is being nulled or changed or that a type confusion attack
 * was used to modify the SecurityManager.
 */
#include <jvmti.h>
#include <string>
#include <iostream>
#include <fstream>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <boost/program_options.hpp>

#if defined(__linux__)
  #include <dlfcn.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  #include <direct.h>
  #define getcwd _getcwd
  #define strcasecmp _stricmp
#else
  #include <unistd.h>
  #define MAX_PATH 255
#endif

void JNICALL VMInit(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread);
bool GetOptions();
void check_jvmti_error(jvmtiEnv *jvmti, jvmtiError errnum, const char *str);
void check_jni_error(jvmtiEnv* jvmti, JNIEnv* jni_env, void* retval, const char* str);
void GetCallerInfo(jvmtiEnv* jvmti, jthread thread, char** source_file, char** method_name, jint* line_number);
bool IsPermissiveSecurityManager(jvmtiEnv* jvmti, JNIEnv* jni_env, jobject SecurityManagerObject);
bool RunPermissionCheck(JNIEnv* jni_env, jobject sm_object, jmethodID check_method, jstring param, 
	const char* perm_name);
void ShowMessageDialog(JNIEnv* jni_env, const char* message, const char* title);
void TerminateJVM(jvmtiEnv* jvmti, JNIEnv* jni_env, std::string message);
void JNICALL FieldModification(jvmtiEnv *jvmti_env, JNIEnv* jni_env,
                jthread thread, jmethodID method, jlocation location,
                jclass field_klass, jobject object, jfieldID field,
                char signature_type, jvalue new_value);
void JNICALL FieldAccess(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread, jmethodID method,
		jlocation location, jclass field_klass, jobject object, jfieldID field);
jobject GetProtectionDomain(jvmtiEnv* jvmti, JNIEnv* jni_env, jclass klass);
bool IsCallerElevatingPrivileges(JNIEnv* jni_env, const jobject loaded_pd, const jobject caller_pd);
bool IsRestrictedAccessPackage(JNIEnv* jni_env, const char* class_sig);
void JNICALL ClassPrepare(jvmtiEnv* jvmti, JNIEnv* jni_env, jthread thread, jclass klass);

enum jsf_mode_t {MONITOR, ENFORCE};

struct options {
	jsf_mode_t mode;
	bool popups_show; 
	bool paranoid_checks;
};

options opt;

char cwd[MAX_PATH+1];
log4cpp::Category* logger = NULL;
char* JSF_HOME = NULL;
jobject lastSecurityManagerRef = NULL;

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* jvm, char* options, void* reserved) {
	jvmtiEnv* jvmti = NULL;
	jvmtiCapabilities capabilities;
	jvmtiError error;
	jvmtiEventCallbacks callbacks;
	
	memset(&capabilities, 0, sizeof(capabilities));
	memset(&callbacks, 0, sizeof(callbacks));

	if (getcwd(cwd, MAX_PATH)) {
		// Get the JSF_HOME environment variable
		JSF_HOME = getenv("JSF_HOME");
	} else {
		printf("Unable to get the CWD.\n");
	}

	// Build path to log properties
	std::string logProperties;
	if (JSF_HOME != NULL) {
		logProperties += JSF_HOME;
	} else {
		printf("The environment variable JSF_HOME is not set. Attempting to use . as JSF_HOME.\n");
		logProperties += ".";
	}

	logProperties += "/log4cpp.properties";

	std::ifstream propertiesFile(logProperties.c_str());
	if (!propertiesFile) {
		printf("The log properties file (%s) does not exist. Terminating...\n", logProperties.c_str());
		return -1;
	}
	propertiesFile.close();

	// Start the logger
	log4cpp::PropertyConfigurator::configure(logProperties);
	logger = &log4cpp::Category::getRoot();

	if (logger == NULL) {
		printf("Failed to get logger. Terminating...\n");
		return -1;
	}

	// Get the options
	if (!GetOptions()) {
		return -1;
	}

	// Get JVMTI environment
	jint env_error = jvm->GetEnv((void **)&jvmti, JVMTI_VERSION_1_0);
	if (env_error != JNI_OK || jvmti == NULL) {
		logger->fatal("[%s] Failed to get JVMTI environment.", cwd);
		return env_error;
	}

	// Enable capability to get source code line numbers and source file
	capabilities.can_get_line_numbers = 1;
	capabilities.can_get_source_file_name = 1;

	if (opt.paranoid_checks == true) {
		// Enable capability to receive events for field modifications/reads and 
		// the events themselves                
		capabilities.can_generate_field_modification_events = 1;
		capabilities.can_generate_field_access_events = 1;
	}
	
	error = jvmti->AddCapabilities(&capabilities);
	check_jvmti_error(jvmti, error, "Unable to get necessary JVMTI capabilities.");

	if (opt.paranoid_checks == true) {
		error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_FIELD_MODIFICATION, NULL);
		check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_FIELD_MODIFICATION.");
	}
	
	// Enable VMInit event so that we know when the JVM is initialized and we 
	// can finish the rest of the setup
	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
	check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_VM_INIT.");
	
	callbacks.VMInit = &VMInit;

	if (opt.paranoid_checks == true) {
		// Set a callback to receive events when the security field of System is set or read.
		// This will let us see when the security manager is being changed or when a type
		// confusion attack may be taking place.
		callbacks.FieldModification = &FieldModification;
		callbacks.FieldAccess = &FieldAccess;
	}
	
	// Set a callback to receive events when a class is prepared to check for privilege
	// escalation.
	callbacks.ClassPrepare = &ClassPrepare;
	
	error = jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));
	check_jvmti_error(jvmti, error, "Unable to register callback for field modification events.");

	return JNI_OK;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM* jvm)
{
	log4cpp::Category::shutdown();
}

void JNICALL VMInit(jvmtiEnv *jvmti, JNIEnv* jni_env, jthread thread) {
	jclass System;
	jfieldID securityID; 
	jvmtiError error;
	
	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, NULL);
	check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_CLASS_PREPARE.");

	// This is called once here to initialize static values
	IsRestrictedAccessPackage(jni_env, "");
	
	if (opt.paranoid_checks == false) return;
	
	// Get the security field of the System class (holds the SecurityManager)
	System = jni_env->FindClass("Ljava/lang/System;");
	check_jni_error(jvmti, jni_env, System, "Unable to get System class.");

	securityID = jni_env->GetStaticFieldID(System, "security", "Ljava/lang/SecurityManager;");
	check_jni_error(jvmti, jni_env, securityID, "Unable to get security field of the System class.");

	// Check to see if there is already a SecurityManager set. This only happens
	// if one is set from the command line (e.g. -Djava.security.manager)
	jmethodID getSecurityManager = jni_env->GetStaticMethodID(System, "getSecurityManager", 
						"()Ljava/lang/SecurityManager;");
	jobject SecurityManager = jni_env->CallStaticObjectMethod(System, getSecurityManager);
	
	if (SecurityManager != NULL) {
		lastSecurityManagerRef = SecurityManager;

		logger->debug("[%s] A security manager was set on the command line.", cwd);
	}

	// Set a modification and access (read) watch on the System.security field
	error = jvmti->SetFieldModificationWatch(System, securityID);
	check_jvmti_error(jvmti, error, "Unable to set a watch on modifications of security field of System class.");

	error = jvmti->SetFieldAccessWatch(System, securityID);
	check_jvmti_error(jvmti, error, "Unable to set a watch on reads of security field of System class.");
}

/**
 * @brief	reads the jsf properties file and populates the global opt struct with the correct values
 *
 * @retval	true if all of the options in the properties are valid, false and a fatal log message otherwise
 */
bool GetOptions() {
	std::string mode;
	std::string popups_show;
	std::string paranoid_checks;
	
	// Build path to jsf properties
	std::string jsfProperties;
	if (JSF_HOME != NULL) {
		jsfProperties += JSF_HOME;
	} else {
		jsfProperties += ".";
	}

	jsfProperties += "/jsf.properties";

	std::ifstream propertiesFile(jsfProperties.c_str());
	if (!propertiesFile) {
		logger->fatal("[%s] The JSF properties file (%s) does not exist. Terminating...\n", cwd, 
			jsfProperties.c_str());
		return false;
	}
	propertiesFile.close();
	
	std::ifstream settings_file(jsfProperties.c_str());
	boost::program_options::options_description desc("Options");
	desc.add_options()
		("mode", boost::program_options::value<std::string>(&mode), "mode")
		("popups.show", boost::program_options::value<std::string>(&popups_show), "popups.show")
		("paranoid.checks", boost::program_options::value<std::string>(&paranoid_checks), "paranoid.checks");
	boost::program_options::variables_map vm = boost::program_options::variables_map();

	boost::program_options::store(boost::program_options::parse_config_file(settings_file , desc), vm);
	boost::program_options::notify(vm);  
	settings_file.close();

	if (strcasecmp(mode.c_str(), "MONITOR") == 0) {
		opt.mode = MONITOR;
	} else if (strcasecmp(mode.c_str(), "ENFORCE") == 0) {
		opt.mode = ENFORCE;
	} else {
		logger->fatal("[%s] Option value unknown: %s. Terminating...", cwd);
		return false;
	}

	if (strcasecmp(popups_show.c_str(), "TRUE") == 0) {
		opt.popups_show = true;
	} else if (strcasecmp(popups_show.c_str(), "FALSE") == 0) {
		opt.popups_show = false;
	} else {
		logger->fatal("[%s] Option value unknown: %s. Terminating...", cwd);
		return false;
	}

	if (strcasecmp(paranoid_checks.c_str(), "TRUE") == 0) {
		opt.paranoid_checks = true;
	} else if (strcasecmp(paranoid_checks.c_str(), "FALSE") == 0) {
		opt.paranoid_checks = false;
	} else {
		logger->fatal("[%s] Option value unknown: %s. Terminating...", cwd);
		return false;
	}
	
	return true;
}

void check_jvmti_error(jvmtiEnv* jvmti, jvmtiError errnum, const char* str)
{
	if (errnum != JVMTI_ERROR_NONE)
	{
		char* errnum_str = NULL;

		jvmti->GetErrorName(errnum, &errnum_str);

		logger->error("[%s] JVMTI: %d(%s): %s", cwd, errnum, errnum_str == NULL ? "Unknown" : errnum_str, 
			str == NULL ? "" : str);

		jvmti->Deallocate((unsigned char*)errnum_str);
	}
}

void check_jni_error(jvmtiEnv* jvmti, JNIEnv* jni_env, void* retval, const char* str) {
	// This method is to be used for JNI method calls that return NULL
	// when an error occurs.
	if (retval == NULL) {
		jthrowable exception = jni_env->ExceptionOccurred();
		
		if (exception == NULL) {
			logger->error("JNI Error: %s", str);
		} else {
			char* exception_sig = NULL;
			
			jclass exception_class = jni_env->GetObjectClass(exception);
			jvmtiError error = jvmti->GetClassSignature(exception_class, &exception_sig, NULL);
			check_jvmti_error(jvmti, error, "A JNI error occurred and an exception was thrown, but failed "
				"to get the exception's class signature.");
				
			if (error == JVMTI_ERROR_NONE) {
				logger->error("JNI Error: %s %s", exception_sig, str);
				jvmti->Deallocate((unsigned char*)exception_sig);
			} else {
				logger->error("JNI Error: %s", str);
			}
		}
	}
}

/**
 * @brief	inspects the most recent frame for the passed in thread to determine the name and location of 
 *		the most recent caller. This function is used to determine who called System.setSecurityManager.
 * 
 * @param	[in] the JVMTI environment used to access the JVMTI API
 * @param	[in] the Java thread whose most recent frame should be inspected
 * @param	[out] a pointer that will be set to point to the source file name for the class containing the caller
 * @param	[out] a pointer that will be set to point to the name of the most recent caller method
 * @param	[out] a pointer to an integer that will be set the line number in source_file where the call was made
 *
 * @retval	a JVMTI error code if one is returned by any of the JVMTI API calls
 */
void GetCallerInfo(jvmtiEnv* jvmti, jthread thread, char** source_file, char** method_name, jint* line_number) {
	jvmtiError error;
	jvmtiFrameInfo caller_frame;
	jint frame_count = 0;
	jint line_count = 0;
	jvmtiLineNumberEntry* line_table = NULL;	
	jclass caller_class = NULL;

	// Get caller (we have to do this because we are in setSecurityManager when
	// this method is called);
	error = jvmti->GetStackTrace(thread, 2, 1, &caller_frame, &frame_count);
	check_jvmti_error(jvmti, error, "Unable to get stack frame to look up location of SecurityManager change.");

	if (error != JVMTI_ERROR_NONE) return;

	// Get caller's line number	
	error = jvmti->GetLineNumberTable(caller_frame.method, &line_count, &line_table);	
	check_jvmti_error(jvmti, error, "Unable to get line number for SecurityManager change.");

	for (int i = 0; i < line_count; i++) {
		if (line_table[i].start_location > caller_frame.location)
			break;

		*line_number = line_table[i].line_number;
	}

	// Get caller's method name
	error = jvmti->GetMethodName(caller_frame.method, method_name, NULL, NULL);
	check_jvmti_error(jvmti, error, "Unable to get caller's method name for SecurityManager change.");

	// Get the caller's class and source file name
	error = jvmti->GetMethodDeclaringClass(caller_frame.method, &caller_class);
	check_jvmti_error(jvmti, error, "Unable to get caller's class for SecurityManager change.");

	error = jvmti->GetSourceFileName(caller_class, source_file);
	check_jvmti_error(jvmti, error, "Unable to get caller's source file name for SecurityManager change.");
	
	jvmti->Deallocate((unsigned char*)line_table);
}

/**
 * @brief	determines whether or not a SecurityManager is permissive by checking for permissions that would
 *		allow any code running under the manager to disable or change the manager or the enforced policy.
 * 
 * @param	[in] the JNI environment used to access the JNI API
 * @param	[in] the Java object for the SecurityManager we want to check
 *
 * @retval	true of the SecurityManager is permissive, false otherwise
 */
bool IsPermissiveSecurityManager(jvmtiEnv* jvmti, JNIEnv* jni_env, jobject SecurityManagerObject) {
	// Note that we do not have to explicitly check for AllPermissions because if
	// it is set any of the other overly-permissive permissions we check for will
	// be set.
	jclass SecurityManager = jni_env->GetObjectClass(SecurityManagerObject);

	// If the signature of the class is for an Applet or JWS SM we assume it's non-permissive. 
	// This is a workaround because this method is not getting exceptions from Java applets 
	// when ExceptionOccured is called even if the permission is definitely not there.
	char* sm_sig = NULL;
	jvmtiError error = jvmti->GetClassSignature(SecurityManager, &sm_sig, NULL);
	logger->debug("[%s] New SecurityManager signature: %s", cwd, sm_sig);
	check_jvmti_error(jvmti, error, "Unable to get class signature for  new SecurityManager." 
		" Assuming applet or Java Web Start...");
	
	if (error != JVMTI_ERROR_NONE || strcmp(sm_sig, "Lsun/applet/AppletSecurity;") == 0 || 
		strcmp(sm_sig, "Lsun/plugin2/applet/AWTAppletSecurityManager;") == 0 ||
		strcmp(sm_sig, "Lcom/sun/javaws/security/JavaWebStartSecurity;") == 0) {
		
		logger->debug("[%s] New SecurityManager is for an applet or Java Web Start."
			" Assuming non-permissive...", cwd);
		return false;
	}
	
	jvmti->Deallocate((unsigned char*)sm_sig);
	
	// Check for RuntimePermission(createClassLoader)
	jmethodID checkCreateClassLoader = jni_env->GetMethodID(SecurityManager, "checkCreateClassLoader", "()V");
	if (RunPermissionCheck(jni_env, SecurityManagerObject, checkCreateClassLoader, NULL, 
		"RuntimePermission(createClassLoader)")) return true;	

	// Check for RuntimePermission(accessClassInPackage.sun)
	jmethodID checkPackageAccess = jni_env->GetMethodID(SecurityManager, "checkPackageAccess", "(Ljava/lang/String;)V");
	jstring sun_package = jni_env->NewStringUTF("sun");
	if (RunPermissionCheck(jni_env, SecurityManagerObject, checkPackageAccess, sun_package, 
		"RuntimePermission(accessClassInPackage.sun)")) return true;

	// Check for RuntimePermission(setSecurityManager)
	jclass RuntimePermission = jni_env->FindClass("java/lang/RuntimePermission");
	jmethodID runtime_constructor = jni_env->GetMethodID(RuntimePermission, "<init>", "(Ljava/lang/String;)V");
	jstring setSecurityManager = jni_env->NewStringUTF("setSecurityManager");
	jobject RuntimePermissionObject = jni_env->NewObject(RuntimePermission, runtime_constructor, setSecurityManager);
	jmethodID checkPermission = jni_env->GetMethodID(SecurityManager, "checkPermission", "(Ljava/security/Permission;)V");
	jni_env->CallVoidMethod(SecurityManagerObject, checkPermission, RuntimePermissionObject);
	jthrowable SecurityException = jni_env->ExceptionOccurred();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows RuntimePermission(setSecurityManager)", cwd);
		return true;
	} else {
		jni_env->ExceptionClear();
	}

	// Check for ReflectPermission(suppressAccessChecks)
	jclass ReflectPermission = jni_env->FindClass("java/lang/reflect/ReflectPermission");
	jmethodID reflect_constructor = jni_env->GetMethodID(ReflectPermission, "<init>", "(Ljava/lang/String;)V");
	jstring suppressAccessChecks = jni_env->NewStringUTF("suppressAccessChecks");
	jobject ReflectPermissionObject = jni_env->NewObject(ReflectPermission, reflect_constructor, suppressAccessChecks);
	jni_env->CallVoidMethod(SecurityManagerObject, checkPermission, ReflectPermissionObject);
	SecurityException = jni_env->ExceptionOccurred();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows ReflectPermission(suppressAccessChecks)", cwd);
		return true;
	} else {
		jni_env->ExceptionClear();
	}

	// Check for FilePermission(ALL FILES, write | execute)
	jmethodID checkExec = jni_env->GetMethodID(SecurityManager, "checkExec", "(Ljava/lang/String;)V");
	jstring all_files = jni_env->NewStringUTF("<<ALL FILES>>");
	if (RunPermissionCheck(jni_env, SecurityManagerObject, checkExec, all_files, 
		"FilePermission(<<ALL FILES>>, exec)")) return true;
	
	jmethodID checkWrite = jni_env->GetMethodID(SecurityManager, "checkWrite", "(Ljava/lang/String;)V");
	if (RunPermissionCheck(jni_env, SecurityManagerObject, checkWrite, all_files, 
		"FilePermission(<<ALL FILES>>, write)")) return true;

	// Check for SecurityPermission(setPolicy)
	jmethodID checkSecurityAccess = jni_env->GetMethodID(SecurityManager, "checkSecurityAccess", 
		"(Ljava/lang/String;)V");
	jstring setPolicy = jni_env->NewStringUTF("setPolicy");
	if (RunPermissionCheck(jni_env, SecurityManagerObject, checkSecurityAccess, setPolicy, 
		"SecurityPermission(setPolicy)")) return true;
		
	return false;
}

/**
 * @brief	runs a method on a specific SecurityManager object to check if a permission 
 *			is allowed.
 * 
 * @param	[in] the JNI environment used to access the JNI API
 * @param	[in] the Java object for the SecurityManager we want query
 * @param	[in] the check method (e.g. checkPermission) we want to call
 * @param	[in] the parameter to the check method (ignored if NULL)
 * @param	[in] a pretty printed version of the permission name to print to the log
 *
 * @retval	true of the permission is allowed, false otherwise
 */
bool RunPermissionCheck(JNIEnv* jni_env, jobject sm_object, jmethodID check_method, jstring param, 
	const char* perm_name) {
	
	if (param == NULL) {
		jni_env->CallVoidMethod(sm_object, check_method);
	} else {
		jni_env->CallVoidMethod(sm_object, check_method, param);
	}
	
	jthrowable SecurityException = jni_env->ExceptionOccurred();
	
	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows %s", cwd, perm_name);
		return true;
	} else {
		jni_env->ExceptionClear();
	}
	
	return false;
}

void ShowMessageDialog(JNIEnv* jni_env, const char* message, const char* title) {
	// This method uses Java's message dialog to display messages otherwise 
	// we'd have to complicate the build process by using a toolkit such as wxWidgets
	// to display it in a cross-platform manner.
	jclass JOptionPane = jni_env->FindClass("javax/swing/JOptionPane");
	jmethodID showMessageDialog = jni_env->GetStaticMethodID(JOptionPane, "showMessageDialog", 
		"(Ljava/awt/Component;Ljava/lang/Object;Ljava/lang/String;I)V");
	jobject parent = NULL;
	jstring jmessage = jni_env->NewStringUTF(message);
	jstring jtitle = jni_env->NewStringUTF(title);
	jni_env->CallStaticVoidMethod(JOptionPane, showMessageDialog, parent, jmessage, jtitle, 0);
}

void TerminateJVM(jvmtiEnv* jvmti, JNIEnv* jni_env, std::string message) {
	jvmtiEventCallbacks callbacks;
	memset(&callbacks, 0, sizeof(callbacks));
	jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));

	if (opt.popups_show) {
		ShowMessageDialog(jni_env, message.c_str(), "Terminating Java Application");
	}

	exit(-1);
}

void JNICALL FieldModification(jvmtiEnv* jvmti, JNIEnv* jni_env,
                jthread thread, jmethodID method, jlocation location,
                jclass field_klass, jobject object, jfieldID field,
                char signature_type, jvalue new_value) {

	char* source_file = NULL;	
	char* method_name = NULL;
	jint line_number = 0;

	GetCallerInfo(jvmti, thread, &source_file, &method_name, &line_number);

	// If the last SecurityManager was null and the new one is too the operation
	// is a no-op. Log it and ignore it.
	if (lastSecurityManagerRef == NULL && new_value.l == NULL) {
		logger->info("[%s] The SecurityManager is being disabled, but it was already disabled: %s, %s, %d."
			" No action will be taken.", 
			cwd, source_file, method_name, line_number);
		return;
	}
	
	logger->info("[%s] The SecurityManager is being changed: %s, %s, %d", cwd, source_file, method_name, line_number);

	// If new_value is a null SecurityManager raise a red flag
	if ((long)new_value.j == 0) {
		if (opt.mode == MONITOR) {
			logger->warn("[%s] The SecurityManager is being disabled.\n", cwd);
		} else if (opt.mode == ENFORCE) {
			logger->fatal("[%s] The SecurityManager is being disabled. Terminating the running application...",
				cwd);

			std::string popup_message("Terminating the application started in ");
				popup_message += cwd;
				popup_message += ":\nApplication attempting to disable the Java Sandbox.";
				
			TerminateJVM(jvmti, jni_env, popup_message);
		}

	// If we are setting our first SecurityManager and it is overly permissive (allows
	// the user to perform enough options that anyone subject to the SM can trivially
	// turn it off), warn and drop to monitor mode.
	} else if (lastSecurityManagerRef == NULL && 
		IsPermissiveSecurityManager(jvmti, jni_env, new_value.l)) {
		
		if (opt.mode == ENFORCE) {
			logger->warn("[%s] JSF was configured to run in ENFORCE mode, but a permissive SecurityManager was set as the initial SecurityManager for this application. JSF cannot stop malicious applications in the presence of a permissive SecurityManager. Dropping to MONITOR mode.", 
				cwd);
			opt.mode = MONITOR;
		}

	// In any other case where a SecurityManager already exists, a change to the SecurityManager
	// is considered malicious
	} else if (lastSecurityManagerRef != NULL) {
		if (opt.mode == ENFORCE) {
			logger->fatal("[%s] A non-permissive SecurityManager is currently set and it is about to be malicously changed." 
				" Terminating the running application...",
				cwd);

			std::string popup_message("Terminating the application started in ");
				popup_message += cwd;
				popup_message += ":\nApplication attempting to perform a malicious operation against the Java Sandbox.";
				
			TerminateJVM(jvmti, jni_env, popup_message);
		} else {
			logger->warn("[%s] A non-permissive SecurityManager is currently set and it is about to be malicously changed.",
				cwd);
		}
		
	// New non-permissive SecurityManager so start checking for type confusion
	} else {
		logger->info("[%s] A restrictive SecurityManager has been set. Turning on type confusion detection...",
			cwd);
		
		jvmtiError error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_FIELD_ACCESS, NULL);
		check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_FIELD_ACCESS.");
	}

	// Store the current reference to the SecurityManager. We want to store this
	// so that when System.security is read we can compare the value being read from
	// the last value we saw being written to it.
	if (lastSecurityManagerRef != NULL)
		jni_env->DeleteGlobalRef(lastSecurityManagerRef);
	
	lastSecurityManagerRef = jni_env->NewGlobalRef(new_value.l);

	jvmti->Deallocate((unsigned char*)method_name);
	jvmti->Deallocate((unsigned char*)source_file);
}

void JNICALL FieldAccess(jvmtiEnv *jvmti, JNIEnv* jni_env, jthread thread, jmethodID method,
		jlocation location, jclass field_klass, jobject object, jfieldID field) {

	// We need a flag to see if the access to the field is from this method otherwise
	// we end up with infinite recursion. We have to read the field via jni->GetStaticLongField
	// so that we see the current value of the field.
	static bool ourRead = false;

	// Nothing to do if last SM was null because FieldModification will take care of it
	// if it was malicious
	if (ourRead || lastSecurityManagerRef == NULL) return;

	// FieldAccess is only set for the security field of the System class. If
	// the current value of System.security doesn't match the last value we saw
	// written to System.security we have detected a type confusion attack on
	// the SecurityManager.
	ourRead = true;
	jobject currentSecurityManagerRef = jni_env->GetStaticObjectField(field_klass, field);
	
	jboolean isSameManager = jni_env->IsSameObject(currentSecurityManagerRef, lastSecurityManagerRef);
	
	if (!isSameManager) {
		if (opt.mode == ENFORCE) {
			logger->fatal("[%s] A type confusion attack against the SecurityManager has been detected."
				" Terminating the running application...",
				cwd);

			std::string popup_message("Terminating the application started in ");
				popup_message += cwd;
				popup_message += ":\nThe application is attempting to bypass the Java Sandbox.";
				
			TerminateJVM(jvmti, jni_env, popup_message);
		} else {
			logger->warn("[%s] A type confusion attack against the SecurityManager has been detected.",
				cwd);
		}
	}

	ourRead = false;
}

jobject GetProtectionDomain(jvmtiEnv* jvmti, JNIEnv* jni_env, jclass klass, const char* class_sig) {
	// We have to get the protection domain by calling the JVM's 
	// get JVM_GetProtectionDomain as it's the only way we found to
	// accurately get it. Calling class.getProtectionDomain (on a java.lang.Class)
	// would throw a SecurityException do to a lack of the getProtectionDomain
	// permission and performing the same action in a Java class of our own creation
	// that would call getProtectionDomain via doPrivilege would always return
	// a ProtectionDomain with AllPermissions.
	
	#if defined(_WIN32) || defined(_WIN64)
		typedef jobject (*PJVM_GetProtectionDomain)(JNIEnv*, jclass);

		HMODULE jvm = GetModuleHandle("jvm.dll");
		
		if (jvm == NULL) {
			logger->debug("[%s] Failed to get handle to jvm.dll", cwd);
			return NULL;
		}
		
		PJVM_GetProtectionDomain JVM_GetProtectionDomain = (PJVM_GetProtectionDomain)GetProcAddress(jvm,
							"JVM_GetProtectionDomain");
			
		jobject ProtectionDomainObject = NULL;
			
		// Sometimes the function name is manged in 32-bit versions of the JRE
		if (JVM_GetProtectionDomain == NULL) {
			logger->debug("[%s] Name of JVM_GetProtectionDomain is mangled in jvm.dll", cwd);
			
			typedef jobject (__stdcall *_stdcall_PJVM_GetProtectionDomain)(JNIEnv*, jclass);
			_stdcall_PJVM_GetProtectionDomain _stdcall_JVM_GetProtectionDomain = 
				(_stdcall_PJVM_GetProtectionDomain)GetProcAddress(jvm, "_JVM_GetProtectionDomain@8");
			ProtectionDomainObject = _stdcall_JVM_GetProtectionDomain(jni_env, klass);
		} else {
			ProtectionDomainObject = JVM_GetProtectionDomain(jni_env, klass);
		}
	#elif defined(__linux__)
		void* jvm = dlopen("libjvm.so", RTLD_LAZY);
		
		if (jvm == NULL) {
			logger->debug("[%s] Failed to get the handle to libjvm.so", cwd);
			return NULL;
		}

		jobject (*JVM_GetProtectionDomain)(JNIEnv*, jclass);
		*(void **)(&JVM_GetProtectionDomain) = dlsym(jvm, "JVM_GetProtectionDomain");
		
		jobject ProtectionDomainObject = JVM_GetProtectionDomain(jni_env, klass);
	#endif
	
	if (ProtectionDomainObject == NULL) {
		logger->debug("[%s] Failed to retrieve the ProtectionDomain for %s.", cwd, class_sig);
	} else {
		logger->debug("[%s] Got ProtectionDomain for %s", cwd, class_sig);
	}
	
	return ProtectionDomainObject;
}

bool IsCallerElevatingPrivileges(JNIEnv* jni_env, const jobject loaded_pd, const jobject caller_pd) {
	if (loaded_pd == NULL && caller_pd != NULL) {
		logger->debug("[%s] Can't access the loaded class's ProtectionDomain but we can access the caller's."
			" Privilege escalation.", cwd);
		return true;
	} else if ((loaded_pd == NULL && caller_pd == NULL) || (loaded_pd != NULL && caller_pd == NULL)) {
		return false;
	}

	if (jni_env->IsSameObject(loaded_pd, caller_pd)) {
		logger->debug("[%s} The loaded class and the caller have the same ProtectionDomain."
			" No privilege escalation.",
			cwd);
		return false;
	}
	
	// We need to check to see if every Permission in the loaded class's PermissionCollection
	// is implied by the caller's PermissionCollection. If not, we have privilege escalation
	// because a class (the caller) is loading a class more privileged than itself.
	jclass ProtectionDomain = jni_env->FindClass("Ljava/security/ProtectionDomain;");
	jmethodID implies = jni_env->GetMethodID(ProtectionDomain, "implies", "(Ljava/security/Permission;)Z");
	
	// If the caller does not have AllPermissions but the loaded class does
	// we have priviledge escalation
	jclass AllPermission = jni_env->FindClass("Ljava/security/AllPermission;");
	jmethodID constructor = jni_env->GetMethodID(AllPermission, "<init>", "()V");
	jobject AllPermissionObject = jni_env->NewObject(AllPermission, constructor);
	
	if (jni_env->CallBooleanMethod(loaded_pd, implies, AllPermissionObject) &&
		!jni_env->CallBooleanMethod(caller_pd, implies, AllPermissionObject)) {

		jmethodID ProtectionDomain_toString = jni_env->GetMethodID(ProtectionDomain, "toString", 
												"()Ljava/lang/String;");
		jobject LoadedPDString = jni_env->CallObjectMethod(loaded_pd, ProtectionDomain_toString);
		const char* loaded_pd_string = jni_env->GetStringUTFChars((jstring)LoadedPDString, NULL);
		jobject CallerPDString = jni_env->CallObjectMethod(caller_pd, ProtectionDomain_toString);
		const char* caller_pd_string = jni_env->GetStringUTFChars((jstring)CallerPDString, NULL);								
		logger->debug("[%s] Loaded Class's ProtectionDomain:\n%s", cwd, loaded_pd_string);
		logger->debug("[%s] Calling Class's ProtectionDomain:\n%s", cwd, caller_pd_string);

		jni_env->ReleaseStringUTFChars((jstring)LoadedPDString, loaded_pd_string);
		jni_env->ReleaseStringUTFChars((jstring)CallerPDString, caller_pd_string);
		
		return true;
	}
	
	return false;
}

bool IsRestrictedAccessPackage(JNIEnv* jni_env, const char* class_sig) {
	static jobject ValueObject = NULL;
	std::string sig(class_sig);
	
	if (ValueObject == NULL) {
		jclass Security = jni_env->FindClass("Ljava/security/Security;");
		jmethodID getProperty = jni_env->GetStaticMethodID(Security, "getProperty", 
									"(Ljava/lang/String;)Ljava/lang/String;");
		jstring PropertyString = jni_env->NewStringUTF("package.access");
		ValueObject = jni_env->NewGlobalRef(
			jni_env->CallStaticObjectMethod(Security, getProperty, PropertyString));
		
		if (jni_env->ExceptionOccurred() != NULL) {
			logger->debug("[%s] Failed to get the package.access property.", cwd);
			jni_env->ExceptionClear();
		}
	}
	
	if (ValueObject == NULL) return false;
	
	const char* restrictedAccessPackages = jni_env->GetStringUTFChars((jstring)ValueObject, NULL);

	// Split the restricted packages list on , then prepend an L and replace . with /
	char* token = strtok((char*)restrictedAccessPackages, ",");
	
	while (token != NULL) {
		std::string package(token);
		package = "L" + package;
		std::replace(package.begin(), package.end(), '.', '/');
		
		if (sig.compare(0, package.size(), package) == 0) return true;
		
		token = strtok(NULL, ",");
	}
	
	jni_env->ReleaseStringUTFChars((jstring)ValueObject, restrictedAccessPackages);
	
	return false;
}

bool IsSecurityManagerSet(jvmtiEnv* jvmti, JNIEnv* jni_env) {
	if (opt.paranoid_checks) {
		if (lastSecurityManagerRef == NULL) return false;
		else return true;
	} else {
		static jclass System = NULL;
		static jmethodID getSecurityManager = NULL;
		jvmtiError error;
		
		if (System == NULL) {
			System = jni_env->FindClass("Ljava/lang/System;");
			check_jni_error(jvmti, jni_env, System, "Unable to get System class to call getSecurityManager.");

			getSecurityManager = jni_env->GetStaticMethodID(System, "getSecurityManager", 
				"()Ljava/lang/SecurityManager;");
			check_jni_error(jvmti, jni_env, getSecurityManager, "Unable to ID for getSecurityManager.");
		}
		
		jobject SecurityManagerObject = jni_env->CallStaticObjectMethod(System, getSecurityManager);
			
		if (SecurityManagerObject == NULL) return false;
		else return true;
	}
}

void JNICALL ClassPrepare(jvmtiEnv* jvmti, JNIEnv* jni_env, jthread thread, jclass klass)
{
	jboolean is_interface, is_array;
	char* class_sig = NULL;
	jobject class_loader_object = NULL;
	jobject KlassProtectionDomainObject = NULL;
	jint frame_count = 0;
	jint retrieved_frame_count = 0;
	jvmtiError error; 
	jobject CallerProtectionDomainObject = NULL;
	
	// No point in checking for privilege escalation if there is no SecurityManager
	// causing a division in privileges.
	if (!IsSecurityManagerSet(jvmti, jni_env)) return; 
		
	jvmti->IsInterface(klass, &is_interface);
	jvmti->IsArrayClass(klass, &is_array);
	if (is_interface || is_array) return;
			
	jvmti->GetFrameCount(thread, &frame_count);
	jvmtiFrameInfo* frames = new jvmtiFrameInfo[frame_count];

	// We only care about classes that have a ClassLoader because the rest
	// are bootstrap classes
	jvmti->GetClassSignature(klass, &class_sig, NULL);
	jvmti->GetClassLoader(klass, &class_loader_object);
	if (class_loader_object == NULL) goto exit;

	logger->debug("[%s] A new class is being loaded by a non-bootstrap ClassLoader: %s", cwd, class_sig);
	
	// We don't worry about sun classes because the JRE protects them
	// under most conditions where a non-permissive manager is set.
	if (IsRestrictedAccessPackage(jni_env, class_sig)) {
		logger->debug("[%s] Skipping comparison of ProtectionDomains for %s because the loaded class is in a"
			" package the JRE protects.", cwd, class_sig);
		goto exit;
	}
	
	KlassProtectionDomainObject = GetProtectionDomain(jvmti, jni_env, klass, class_sig);
	
	// Get the protection domain for any class in the stack frame that
	// led to this class being loaded that has a ClassLoader. If a caller
	// has a weaker ProtectionDomain than the loaded class does, we have
	// detected privilege escalation.
	error = jvmti->GetStackTrace(thread, 0, frame_count, frames, &retrieved_frame_count);
	check_jvmti_error(jvmti, error, "Failed to get stack frames when checking for privilege escalation.");
	
	if (error == JVMTI_ERROR_NONE && retrieved_frame_count > 1) {
		jclass method_class = NULL;
		jobject method_class_loader = NULL;
		char* method_class_sig = NULL;
		
		for (int i = 0; i < retrieved_frame_count; i++) {
			jvmti->GetMethodDeclaringClass(frames[i].method, &method_class);
			
			jvmti->IsInterface(method_class, &is_interface);
			jvmti->IsArrayClass(klass, &is_array);
			if (is_interface || is_array) return;
			
			jvmti->GetClassLoader(method_class, &method_class_loader);
			if (method_class_loader == NULL) continue;
			
			jvmti->GetClassSignature(method_class, &method_class_sig, NULL);
			if (IsRestrictedAccessPackage(jni_env, method_class_sig)) {
				goto continue_loop;
			}
			
			CallerProtectionDomainObject = GetProtectionDomain(jvmti, jni_env, method_class, 
												method_class_sig);
			
			logger->debug("[%s] %s is a non-bootstrap class in the stack frame that loaded %s. Comparing ProtectionDomains...", cwd, method_class_sig, class_sig);
			
			if (IsCallerElevatingPrivileges(jni_env, KlassProtectionDomainObject, 
				CallerProtectionDomainObject)){
				
				if (opt.mode == ENFORCE) {
					logger->fatal("[%s] A privilege escalation attack has been detected. %s tried"
						" to elevate the privileges of %s."
						" Terminating the running application...",
						cwd, method_class_sig, class_sig);
						
					std::string popup_message("Terminating the application started in ");
						popup_message += cwd;
						popup_message += ":\nThe application is escalating its privileges to bypass the Java Sandbox.";
					
					TerminateJVM(jvmti, jni_env, popup_message);
				} else {
					logger->warn("[%s] A privilege escalation attack has been detected. %s tried"
						" to elevate the privileges of %s.",
						cwd, method_class_sig, class_sig);
				}
			}
			
continue_loop:
			jni_env->DeleteLocalRef(method_class_loader);
			jvmti->Deallocate((unsigned char*)method_class_sig);
		}
	}
	
exit:
	delete [] frames;
	jni_env->DeleteLocalRef(class_loader_object);
	jvmti->Deallocate((unsigned char*)class_sig);
}
