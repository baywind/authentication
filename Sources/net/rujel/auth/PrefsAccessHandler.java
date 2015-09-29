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

public class PrefsAccessHandler extends AccessHandler {
	protected final SettingsReader prefs = SettingsReader.settingsForPath("auth.access",true);
	public static SettingsReader _defaultSettings;
	
	public PrefsAccessHandler() {
		super();
	}
	
	public int accessLevel (Object obj)  throws AccessHandler.UnlistedModuleException {
		return accessLevel(obj,null);
	}
	
	public int accessLevel(Object obj, Integer section)
					throws AccessHandler.UnlistedModuleException {
		String nodeName = interpret(obj);
		if(nodeName == null || nodeName.length() <= 0)
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
		return accessLevel(node, modifier, user,section);
	}
	
	public static int defaultLevel(UserPresentation user, Object obj, Integer section)
											throws AccessHandler.UnlistedModuleException{
		if(_defaultSettings == null)
			throw new IllegalStateException("Access defaults not initialized");
		String nodeName = interpret(obj);
		if(nodeName == null || nodeName.length() <= 0)
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
		SettingsReader node = _defaultSettings.subreaderForPath(nodeName, false);
		if(node == null)
			throw new AccessHandler.UnlistedModuleException(
					"Access to this module is not described");
		return accessLevel(node, modifier, user,section);
	}
	
	public static int accessLevel (SettingsReader node, String modifier,
			UserPresentation user,Integer section) {
		int result = 0;
		int curr = 0;
		java.util.Enumeration enu = null;
		java.util.HashSet modified = new java.util.HashSet();;
		if(modifier != null) {
			SettingsReader mod = node.subreaderForPath("modifiers." + modifier, false);
			if(mod != null) {
				enu = mod.keyEnumerator();
				while (enu.hasMoreElements()) {
					String key = (String)enu.nextElement();
					curr = mod.getInt(key,0);
					if(curr == 0)
						continue;
					if(key.equals("*") || user.isInGroup(key,section)) {
						modified.add(key);
						result = result | curr;
					}
				}
			} else {
				System.err.println("Undescribed modifier: " + modifier);
			}
		}
		enu = node.keyEnumerator();
		while (enu.hasMoreElements()) {
			String key = (String)enu.nextElement();
			if(key.equals("modifiers") || modified.contains(key))
				continue;
			curr = node.getInt(key,0);
			if(curr == 0)
				continue;
			if(key.equals("*") || user.isInGroup(key,section)) {
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
			try {
				return (defaultLevel(user,"login",null) > 0);
			} catch (AccessHandler.UnlistedModuleException e1) {
				return true;
			}
		}
	}
}
