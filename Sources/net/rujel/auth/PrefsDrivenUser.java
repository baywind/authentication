//  PrefsDrivenUser.java

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

import java.util.logging.Logger;
import java.util.logging.Level;

public class PrefsDrivenUser extends UserPresentation.DefaultImplementation implements LoginHandler, UserPresentation {
	protected SettingsReader prefs = SettingsReader.settingsForPath("auth.usersList",true);
//	protected Preferences user;
	protected String uname;
	protected String allGroups;
//	protected String[] groups;
	protected static Logger logger = Logger.getLogger("login");
	
	public PrefsDrivenUser() {
		super();
	}
	/*
	public PrefsDrivenUser(SettingsReader root) {
		super();
		prefs = root;
		allGroups = toString() + ";" + prefs.get("groups","");
		//groups = allGroups.split(",");
	}*/
	
	public String[] args() {
		return new String[] {"username", "password"};
	}
	
	public String identityArg() {
		return "username";
	}

	public UserPresentation authenticate (Object [] args) throws AuthenticationFailedException, IllegalArgumentException {
		String user;
		String password;
		try {
			user = (String) args[0];
			user = user.trim();
			password = (String) args[1];
		} catch (Exception exc) {
			throw new IllegalArgumentException("Only two String argumens supported: username and password.",exc);
		}
		//DirContext ctx = authenticate(user, password);
		return authenticate(user, password);//delegate.getIntegerPresentation(ctx);
	}
	
	public PrefsDrivenUser authenticate(String username, String pass) throws AuthenticationFailedException {
//	public UserPresentation processLogin(WORequest req) throws AuthenticationFailedException, IllegalArgumentException {
		try {
			//String username = req.stringFormValueForKey("username");
			if (username==null || username.length() == 0) 
				return null;
			SettingsReader user = prefs.subreaderForPath(username,false);
			if (user == null) {
				AuthenticationFailedException e = new AuthenticationFailedException (IDENTITY, "No such user  found.");
				e.setUserId(username);
				throw e;
			}
				 
			//Preferences user = prefs.node(username);
			//String pass = req.stringFormValueForKey("password");
			String credential = user.get("password",null);
			if((credential == null && pass != null && pass.length() > 0) || (credential != null && !credential.equals(pass))) {
				AuthenticationFailedException e = new AuthenticationFailedException (CREDENTIAL,"Wrong password for user " + username);
				e.setUserId(username);
				throw e;
			}
			PrefsDrivenUser result = new PrefsDrivenUser();
			result.prefs = user;
			result.uname = username; 
			result.allGroups = username + ";" + user.get("groups","");
			return result;
		} catch (AuthenticationFailedException aex) {
			//logger.throwing("PrefsDrivenUser","authenticate",aex);
			throw aex;
		} catch (Exception ex) {
			logger.log(Level.SEVERE,"Error resolving user",ex);
			throw new AuthenticationFailedException (ERROR, "User lookup failed.", ex);
		}
	}

	public String toString() {
		return uname;
		//return prefs.name();
	}
	
	public Object propertyNamed(String property) {
		return prefs.get(property,null);
	}
	
	public boolean isInGroup (String group,Integer section) {
		return group.equals("*") || group.equals("any") || allGroups.contains(group);
	}
	
	public String[] listGroups(Integer section) {
		return allGroups.split(";");
	}
	
	public String present() {
		String name = prefs.get("fullName", null);
		if(name == null)
			name = prefs.get("sn", uname);
		return name;
	}
}