package isr.cmu.edu.smf.test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Main {
	public static void main(String[] args) throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, ClassNotFoundException, NoSuchFieldException {
		// Null Directly
		System.setSecurityManager(null);

		// Null Reflective Method Call
		Class<?> c = Class.forName("java.lang.System");
		Method setSecurityManager = c.getDeclaredMethod("setSecurityManager", SecurityManager.class);
		setSecurityManager.invoke(null, (SecurityManager)null);
		
		// Null On another thread
		Thread thread = new Thread(){
			public void run(){
				System.setSecurityManager(null);
		    }
		};

		thread.start();
		
		// Set manager to new manager
		SecurityManager blankManager = new SecurityManager();
		System.setSecurityManager(blankManager);
	} 
}