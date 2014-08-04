/** 
 * @file	main.cpp
 * @brief 	This JVMTI agent monitors applications for changes to the SecurityManager.
 *
 * The Java SecurityManager is responsible for enforcing a security policy for the thread
 * it is assigned to. The SecurityManager is stored in java.lang.System's security field.
 * This agent sets up a watch on that field and prints out the source file, function name,
 * and line number of the code that initiates any changes to it.
 */
#include <jvmti.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <boost/program_options.hpp>

#if defined(_WIN32) || defined(_WIN64)
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
jvmtiError GetClassBySignature(jvmtiEnv* jvmti, const char* signature, jclass* klass);
jvmtiError GetFieldIDByName(jvmtiEnv* jvmti, jclass klass, const char* name, jfieldID* fieldID);
void GetCallerInfo(jvmtiEnv* jvmti, jthread thread, char** source_file, char** method_name, jint* line_number);
bool IsPermissiveSecurityManager(JNIEnv* jni_env, jobject SecurityManagerObject);
void JNICALL FieldModification(jvmtiEnv *jvmti_env, JNIEnv* jni_env,
                jthread thread, jmethodID method, jlocation location,
                jclass field_klass, jobject object, jfieldID field,
                char signature_type, jvalue new_value);
void JNICALL FieldAccess(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread, jmethodID method,
		jlocation location, jclass field_klass, jobject object, jfieldID field);

enum smf_mode_t {MONITOR, ENFORCE};

struct options {
  smf_mode_t mode;
};

options opt;

char cwd[MAX_PATH+1];
log4cpp::Category* logger = NULL;
char* SMF_HOME = NULL;
jobject lastSecurityManagerRef = NULL;

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* jvm, char* options, void* reserved) {
	jvmtiEnv* jvmti = NULL;
	jvmtiCapabilities capabilities;
	jvmtiError error;
	jvmtiEventCallbacks callbacks;
	
	memset(&capabilities, 0, sizeof(capabilities));
	memset(&callbacks, 0, sizeof(callbacks));

	getcwd(cwd, MAX_PATH);

	// Get the SMF_HOME environment variable
	SMF_HOME = getenv("SMF_HOME");

	// Build path to log properties
	std::string logProperties;
	if (SMF_HOME != NULL) {
		logProperties += SMF_HOME;
	} else {
		printf("The environment variable SMF_HOME is not set. Attempting to use . as SMF_HOME.\n");
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

	// Enable capability to receive events for field modifications/reads and the events themselves                
	capabilities.can_generate_field_modification_events = 1;
	capabilities.can_generate_field_access_events = 1;

	error = jvmti->AddCapabilities(&capabilities);
	check_jvmti_error(jvmti, error, "Unable to get necessary JVMTI capabilities.");

	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_FIELD_MODIFICATION, NULL);
	check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_FIELD_MODIFICATION.");

	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_FIELD_ACCESS, NULL);
	check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_FIELD_ACCESS.");

	// Enable VMInit event so that we know when the JVM is initialized and we 
	// can finish the rest of the setup
	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
	check_jvmti_error(jvmti, error, "Unable to set JVMTI_EVENT_VM_INIT.");

	callbacks.VMInit = &VMInit;

	// Set a callback to receive events when the security field of System is set or read.
	// This will let us see when the security manager is being changed or when a type
	// confusion attack may be taking place.
	callbacks.FieldModification = &FieldModification;
	callbacks.FieldAccess = &FieldAccess;

	error = jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));
	check_jvmti_error(jvmti, error, "Unable to register callback for field modification events.");

	return JNI_OK;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM* jvm)
{
	log4cpp::Category::shutdown();
}

void JNICALL VMInit(jvmtiEnv *jvmti, JNIEnv* jni_env, jthread thread) {
	jclass system_class;
	jfieldID securityID; 
	jvmtiError error;

	// Get the security field of the System class (holds the SecurityManager) and
	// set a modification and access (read) watch on it
	error = GetClassBySignature(jvmti, "Ljava/lang/System;", &system_class);
	check_jvmti_error(jvmti, error, "Unable to get System class.");

	error = GetFieldIDByName(jvmti, system_class, "security", &securityID);
	check_jvmti_error(jvmti, error, "Unable to get security field of the System class.");

	error = jvmti->SetFieldModificationWatch(system_class, securityID);
	check_jvmti_error(jvmti, error, "Unable to set a watch on modifications of security field of System class.");

	error = jvmti->SetFieldAccessWatch(system_class, securityID);
	check_jvmti_error(jvmti, error, "Unable to set a watch on reads of security field of System class.");
}

/**
 * @brief	reads the smf properties file and populates the global opt struct with the correct values
 *
 * @retval	true if all of the options in the properties are valid, false and a fatal log message otherwise
 */
bool GetOptions() {
	std::string mode;

	// Build path to smf properties
	std::string smfProperties;
	if (SMF_HOME != NULL) {
		smfProperties += SMF_HOME;
	} else {
		smfProperties += ".";
	}

	smfProperties += "/smf.properties";

	std::ifstream propertiesFile(smfProperties.c_str());
	if (!propertiesFile) {
		logger->fatal("[%s] The SMF properties file (%s) does not exist. Terminating...\n", cwd, 
			smfProperties.c_str());
		return false;
	}
	propertiesFile.close();
	
	std::ifstream settings_file(smfProperties.c_str());
	boost::program_options::options_description desc("Options");
	desc.add_options()
		("mode", boost::program_options::value<std::string>(&mode), "mode");
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

	return true;
}

void log_jvmti_error(jvmtiEnv* jvmti, jvmtiError errnum, const char* str)
{
	char* errnum_str = NULL;

	jvmti->GetErrorName(errnum, &errnum_str);

	logger->error("[%s] JVMTI: %d(%s): %s", cwd, errnum, errnum_str == NULL ? "Unknown" : errnum_str, 
		str == NULL ? "" : str);

	jvmti->Deallocate((unsigned char*)errnum_str);
}

void check_jvmti_error(jvmtiEnv* jvmti, jvmtiError errnum, const char* str)
{
	if (errnum != JVMTI_ERROR_NONE)
		log_jvmti_error(jvmti, errnum, str);
}

/**
 * @brief	looks up and returns the reference for a class based on a user specified Java type signature
 * 
 * @param	[in] the JVMTI environment used to access the JVMTI API
 * @param	[in] the Java type signature for the class we'd like to retrieve a reference to
 * @param	[out] a pointer that will be set to reference the class whose signature was specified
 *
 * @retval	a JVMTI error code if one is returned by any of the JVMTI API calls
 */
jvmtiError GetClassBySignature(jvmtiEnv* jvmti, const char* signature, jclass* klass) {
	jint class_count = 0;
	jclass* classes = NULL;
	jvmtiError error;

	error = jvmti->GetLoadedClasses(&class_count, &classes);
	if (error != JVMTI_ERROR_NONE)
		return error;


	for (int i = 0; i < class_count; i++) {
		char* class_signature = NULL;

		error = jvmti->GetClassSignature(classes[i], &class_signature, NULL);
		if (error != JVMTI_ERROR_NONE)
			return error;

		if (strcmp(class_signature, signature) == 0) {
			*klass = classes[i];
			break;
		}

		jvmti->Deallocate((unsigned char*)class_signature);
	}

	jvmti->Deallocate((unsigned char*)classes);

	return JVMTI_ERROR_NONE;
}

/**
 * @brief	looks up and returns the ID for a field in a class based on a user specified field name and class
 * 
 * @param	[in] the JVMTI environment used to access the JVMTI API
 * @param	[in] the Java class we want to retrieve a field ID from
 * @param	[in] the name of the field whose ID we want to retrieve
 * @param	[out] a pointer to a jfieldID that will be set to the named field's ID
 *
 * @retval	a JVMTI error code if one is returned by any of the JVMTI API calls
 */
jvmtiError GetFieldIDByName(jvmtiEnv* jvmti, jclass klass, const char* name, jfieldID* fieldID) {
	jint field_count = 0;
	jfieldID* fields = NULL;
	jvmtiError error;

	error = jvmti->GetClassFields(klass, &field_count, &fields);
	if (error != JVMTI_ERROR_NONE)
		return error;

	for (int i = 0; i < field_count; i++) {
		char* field_name = NULL;

		error = jvmti->GetFieldName(klass, fields[i], &field_name, NULL, NULL);
		if (error != JVMTI_ERROR_NONE)
			return error;

		if (strcmp(field_name, name) == 0) {
			*fieldID = fields[i];
			break;
		}

		jvmti->Deallocate((unsigned char*)field_name);
	}

	jvmti->Deallocate((unsigned char*)fields);

	return JVMTI_ERROR_NONE;
}

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

bool IsPermissiveSecurityManager(JNIEnv* jni_env, jobject SecurityManagerObject) {
	// Note that we do not have to explicitly check for AllPermissions because if
	// it is set any of the other overly-permissive permissions we check for will
	// be set.
	jclass SecurityManager = jni_env->GetObjectClass(SecurityManagerObject);

	// Check for RuntimePermission(createClassLoader)
	jmethodID checkCreateClassLoader = jni_env->GetMethodID(SecurityManager, "checkCreateClassLoader", "()V");
	jni_env->CallVoidMethod(SecurityManagerObject, checkCreateClassLoader);
	jthrowable SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	// We expect to get an exception otherwise the permission is allowed and the SecurityManager is permissive
	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows RuntimePermission(createClassLoader)", cwd);
		return true;
	}

	// Check for RuntimePermission(accessClassInPackage.sun)
	jmethodID checkPackageAccess = jni_env->GetMethodID(SecurityManager, "checkPackageAccess", "(Ljava/lang/String;)V");
	jstring sun_package = jni_env->NewStringUTF("sun");
	jni_env->CallVoidMethod(SecurityManagerObject, checkPackageAccess, sun_package);
	SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows RuntimePermission(accessClassInPackage.sun)", cwd);
		return true;
	}

	// Check for RuntimePermission(setSecurityManager)
	jclass RuntimePermission = jni_env->FindClass("java/lang/RuntimePermission");
	jmethodID runtime_constructor = jni_env->GetMethodID(RuntimePermission, "<init>", "(Ljava/lang/String;)V");
	jstring setSecurityManager = jni_env->NewStringUTF("setSecurityManager");
	jobject RuntimePermissionObject = jni_env->NewObject(RuntimePermission, runtime_constructor, setSecurityManager);
	jmethodID checkPermission = jni_env->GetMethodID(SecurityManager, "checkPermission", "(Ljava/security/Permission;)V");
	jni_env->CallVoidMethod(SecurityManagerObject, checkPermission, RuntimePermissionObject);
	SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows RuntimePermission(setSecurityManager)", cwd);
		return true;
	}

	// Check for ReflectPermission(suppressAccessChecks)
	jclass ReflectPermission = jni_env->FindClass("java/lang/reflect/ReflectPermission");
	jmethodID reflect_constructor = jni_env->GetMethodID(ReflectPermission, "<init>", "(Ljava/lang/String;)V");
	jstring suppressAccessChecks = jni_env->NewStringUTF("suppressAccessChecks");
	jobject ReflectPermissionObject = jni_env->NewObject(ReflectPermission, reflect_constructor, suppressAccessChecks);
	jni_env->CallVoidMethod(SecurityManagerObject, checkPermission, ReflectPermissionObject);
	SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows ReflectPermission(suppressAccessChecks)", cwd);
		return true;
	}

	// Check for FilePermission(ALL FILES, write | execute)
	jmethodID checkExec = jni_env->GetMethodID(SecurityManager, "checkExec", "(Ljava/lang/String;)V");
	jstring all_files = jni_env->NewStringUTF("<<ALL FILES>>");
	jni_env->CallVoidMethod(SecurityManagerObject, checkExec, all_files);
	SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows FilePermission(<<ALL FILES>>, exec)", cwd);
		return true;
	}
	
	jmethodID checkWrite = jni_env->GetMethodID(SecurityManager, "checkWrite", "(Ljava/lang/String;)V");
	jni_env->CallVoidMethod(SecurityManagerObject, checkWrite, all_files);
	SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows FilePermission(<<ALL FILES>>, write)", cwd);
		return true;
	}

	// Check for SecurityPermission(setPolicy)
	jmethodID checkSecurityAccess = jni_env->GetMethodID(SecurityManager, "checkSecurityAccess", "(Ljava/lang/String;)V");
	jstring setPolicy = jni_env->NewStringUTF("setPolicy");
	jni_env->CallVoidMethod(SecurityManagerObject, checkSecurityAccess, setPolicy);
	SecurityException = jni_env->ExceptionOccurred();
	jni_env->ExceptionClear();

	if (SecurityException == NULL) {
		logger->info("[%s] The new SecurityManager is permissive: allows SecurityPermission(setPolicy)", cwd);
		return true;
	}
		
	return false;
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
		logger->info("[%s] The SecurityManager is being disabled, but it was already disabled: %s, %s, %d. No action will be taken.", 
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
			exit(-1);
		}

	// If we are setting our first SecurityManager and it is overly permissive (allows
	// the user to perform enough options that anyone subject to the SM can trivially
	// turn it off), warn and drop to monitor mode.
	} else if (lastSecurityManagerRef == NULL && IsPermissiveSecurityManager(jni_env, new_value.l)) {
		if (opt.mode == ENFORCE) {
			logger->warn("[%s] SMF was configured to run in ENFORCE mode, but a permissive SecurityManager was set as the initial SecurityManager for this application. SMF cannot stop malicious applications in the presence of a permissive SecurityManager. Dropping to MONITOR mode.", 
				cwd);
			opt.mode = MONITOR;
		}

	// In any other case where a SecurityManager already exists, a change to the SecurityManager
	// is considered malicious
	} else if (lastSecurityManagerRef != NULL) {
		if (opt.mode == ENFORCE) {
			logger->fatal("[%s] A non-permissive SecurityManager is currently set and it is about to be malicously changed. Terminating the running application...",
				cwd);
			exit(-1);
		} 
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
	ourRead = false;
	
	jboolean isSameManager = jni_env->IsSameObject(currentSecurityManagerRef, lastSecurityManagerRef);
	
	if (!isSameManager) {
		logger->fatal("[%s] A type confusion attack against the SecurityManager has been detected. Terminating the running application...",
			cwd);
		exit(-1);
	}
}
