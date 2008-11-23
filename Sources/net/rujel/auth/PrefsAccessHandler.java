//  PrefsAccessHandler.java

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

import net.rujel.reusables.SettingsReader;

public class PrefsAccessHandler implements AccessHandler {
//	protected Preferences prefs = Preferences.systemNodeForPackage(LoginProcessor.class).node("access");
	protected static final SettingsReader prefs = SettingsReader.settingsForPath("auth.access",true);
	protected UserPresentation user = null;
	
	public PrefsAccessHandler() {
		super();
	}
	
	public void setUser (UserPresentation aUser) {
		user = aUser;
	}
	
	public boolean userIs(UserPresentation aUser) {
		return (aUser == user);//aUser.equals(user);
	}

	
	public int accessLevel (Object obj) throws AccessHandler.UnlistedModuleException {
		if(obj instanceof com.webobjects.eocontrol.EOEnterpriseObject) {
			obj = ((com.webobjects.eocontrol.EOEnterpriseObject)obj).entityName();
		} else if(obj instanceof com.webobjects.appserver.WOComponent) {
			String name = ((com.webobjects.appserver.WOComponent)obj).name();
			int idx = name.lastIndexOf('.');
			obj = (idx <0)?name:name.substring(idx +1);
		}
		if(obj == null || obj.toString().length() == 0)
			throw new IllegalArgumentException ("Non empty String required"); 
		if(user == null) {
		//	if(!prefs.getBoolean("allowNone",false))
				return 0;
			
		}
		//Object[] found = null;
		//Preferences node = null;
		SettingsReader node = SettingsReader.settingsForPath("auth.access." + obj,false);
		
		//try {
		if(node == null) //(!prefs.nodeExists(obj.toString()))
			throw new AccessHandler.UnlistedModuleException("Access to this module is not described");
		/*	node = prefs.node(obj.toString());
		String[] grps = node.keys();
		//			int len = grps.length;
		found = user.filterMyGroups(grps);
		} catch (java.util.prefs.BackingStoreException bex) {
			throw new IllegalStateException("Could not read preferences",bex);
		}
		if(found.length == 0)
			return 0;*/
		java.util.Enumeration enu = node.keyEnumerator();
		int result = 0;
		int curr = 0;
		while (enu.hasMoreElements()) {
			String key = (String)enu.nextElement();
		//for (int i = 0; i < found.length; i++) {
			curr = node.getInt(key,0);
			if(user.isInGroup(key))
				result = result | curr;
		}
		return result;
	}
	
	public boolean canLogin() {
		if (user == null) {
			if(prefs.getBoolean("allowNone",false))
				return true;
			else
				return false;
		}
		try {
			return (accessLevel("login") > 0);
		} catch (AccessHandler.UnlistedModuleException e) {
			return true;
		}
	}
}
