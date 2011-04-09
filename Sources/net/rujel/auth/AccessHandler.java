//  AccessHandler.java

/*
 * Copyright (c) 2008, Gennady & Michael Kushnir
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 * 	•	Redistributions of source code must retain the above copyright notice, this
 * 		list of conditions and the following disclaimer.
 * 	•	Redistributions in binary form must reproduce the above copyright notice,
 * 		this list of conditions and the following disclaimer in the documentation
 * 		and/or other materials provided with the distribution.
 * 	•	Neither the name of the RUJEL nor the names of its contributors may be used
 * 		to endorse or promote products derived from this software without specific 
 * 		prior written permission.
 * 		
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package net.rujel.auth;
import java.lang.reflect.*;

public abstract class AccessHandler {
	public static final String  CLASSNAME= "accessHandlerClass";
//	public static final String ownNotificationName = "Own created object";
	
//	public AccessHandler(UserPresentation aUser);
	protected UserPresentation user = null;
	
	public void setUser (UserPresentation aUser) {
		user = aUser;
	}
	
	public boolean userIs(UserPresentation aUser) {
		return (aUser == user);//aUser.equals(user);
	}
	
	public abstract int accessLevel (Object obj) throws UnlistedModuleException;
	public abstract int accessLevel(Object obj, Integer section) throws UnlistedModuleException;
	
	public boolean canLogin() {
		try {
			return (accessLevel("login") > 0);
		} catch (AccessHandler.UnlistedModuleException e) {
			return true;
		}
	}
	
	public static String interpret(Object obj) {
		if(obj instanceof com.webobjects.eocontrol.EOEnterpriseObject) {
			return ((com.webobjects.eocontrol.EOEnterpriseObject)obj).entityName();
		} else if(obj instanceof com.webobjects.appserver.WOComponent) {
			String name = ((com.webobjects.appserver.WOComponent)obj).name();
			int idx = name.lastIndexOf('.');
			return (idx <0)?name:name.substring(idx +1);
		} else if (obj instanceof String) {
			return (String)obj;
		} else if(obj != null) {
			return obj.toString();
		}
		return null;
	}
	
		
		public static AccessHandler generateForUser(UserPresentation user) {
			AccessHandler ah = null;
			try {
				String ahClassName = net.rujel.reusables.SettingsReader.stringForKeyPath("auth." + CLASSNAME,"net.rujel.auth.PrefsAccessHandler");
//				String ahClassName = prefs.get(CLASSNAME,"net.rujel.auth.PrefsAccessHandler");
				Class ahClass = Class.forName(ahClassName);
				Constructor ahConstuctor = ahClass.getConstructor();
				ah = (AccessHandler)ahConstuctor.newInstance();
			} catch (Exception ex) {
				throw new RuntimeException("Could not instantiate login handler",ex);
			}
			ah.setUser(user);
			return ah;
		}
	
	public static class UnlistedModuleException extends Exception {
		public UnlistedModuleException(String message) {
			super(message);
		}
	}

}
