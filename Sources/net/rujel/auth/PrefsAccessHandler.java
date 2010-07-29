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
	protected final SettingsReader prefs = SettingsReader.settingsForPath("auth.access",true);
	protected static SettingsReader mapping;
	protected UserPresentation user = null;
	protected static boolean tryUnmapped = false;
	
	public PrefsAccessHandler() {
		super();
		if(mapping == null) {
			mapping = SettingsReader.settingsForPath("auth.groupMapping",false);
			if(mapping == null)
				mapping = SettingsReader.DUMMY;
		}
		tryUnmapped = SettingsReader.boolForKeyPath("auth.tryUnmappedGroups", false);
	}
	
	public void setUser (UserPresentation aUser) {
		user = aUser;
	}
	
	public boolean userIs(UserPresentation aUser) {
		return (aUser == user);//aUser.equals(user);
	}

	public int accessLevel (Object obj) throws AccessHandler.UnlistedModuleException {
		String nodeName = null;
		if(obj instanceof com.webobjects.eocontrol.EOEnterpriseObject) {
			nodeName = ((com.webobjects.eocontrol.EOEnterpriseObject)obj).entityName();
		} else if(obj instanceof com.webobjects.appserver.WOComponent) {
			String name = ((com.webobjects.appserver.WOComponent)obj).name();
			int idx = name.lastIndexOf('.');
			nodeName = (idx <0)?name:name.substring(idx +1);
		} else if (obj instanceof String) {
			nodeName = (String)obj;
		} else if(obj != null) {
			nodeName = obj.toString();
			if(nodeName.length() == 0)
				nodeName = null;
		}
		if(nodeName == null)
			throw new IllegalArgumentException ("Non empty String required"); 
		if(user == null) {
			return 0;
		}
		String modifier = null;
		int idx = nodeName.indexOf('@');
		if(idx > 0) {
			modifier = nodeName.substring(idx + 1);
			nodeName = nodeName.substring(0,idx);
		}
		SettingsReader node = prefs.subreaderForPath(nodeName, false);
		if(node == null)
			throw new AccessHandler.UnlistedModuleException(
					"Access to this module is not described");
		return accessLevel(node, modifier, user);
	}
	
	public static int accessLevel (SettingsReader node, String modifier,UserPresentation user) {
		int result = 0;
		int curr = 0;
		java.util.Enumeration enu = null;
		if(modifier != null) {
			SettingsReader mod = node.subreaderForPath("modifiers." + modifier, false);
			if(mod != null) {
				boolean found = false;
				enu = mod.keyEnumerator();
				while (enu.hasMoreElements()) {
					String key = (String)enu.nextElement();
					curr = mod.getInt(key,0);
					if(curr == 0)
						continue;
					if(tryUnmapped && key.equals("*") || user.isInGroup(key)) {
						found = true;
						result = result | curr;
					} else {
						key = mapping.get(key, key);
						if(key.equals("*") || user.isInGroup(key)) {
							found = true;
							result = result | curr;
						}
					}
				}
				if(found)
					return result;
			} else {
				System.err.println("Undescribed modifier: " + modifier);
			}
		}
		enu = node.keyEnumerator();
		while (enu.hasMoreElements()) {
			String key = (String)enu.nextElement();
			if(key.equals("modifiers"))
				continue;
			curr = node.getInt(key,0);
			if(curr == 0)
				continue;
			if(tryUnmapped && key.equals("*") || user.isInGroup(key)) {
				result = result | curr;
			} else {
				key = mapping.get(key, key);
				if(key.equals("*") || user.isInGroup(key))
					result = result | curr;
			}
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
