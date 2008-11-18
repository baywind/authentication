//  LdapUser.java

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

package net.rujel.auth.ldap;

import net.rujel.auth.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import java.util.Vector;
import java.util.logging.Logger;

public class LdapUser extends UserPresentation.DefaultImplementation {
	protected static Logger logger = Logger.getLogger("auth");
	public static final String ATTR = "securityEquals";
	protected Name[] myGroups;
	
	protected DirContext dirContext;
//	protected String userDn; 
	
	public LdapUser (Name[] groups) {
		myGroups = groups;
	}
	
	public LdapUser (DirContext context, String dn, String groupAttibute) {
		dirContext = context;
		//userDn = dn;
		if(groupAttibute == null) groupAttibute = ATTR;
		Attribute grps = null;
		try {
			grps = context.getAttributes(dn,new String[] {groupAttibute}).get(groupAttibute);
		} catch (javax.naming.NamingException ex) {
			logger.throwing("LdapUser","<init>",ex);
		} finally {
			myGroups = getGroups(dn,grps);
		}
		/*} catch (Exception ex) {//(javax.naming.NamingException ex) {
			myGroups = new Name[] { new LdapName (dn) };
		}*/
	}
	
	public static Name[] getGroups(String fullDn,Attribute grps) {//throws NamingException{
		Name[] result = null;
		try {
			Name dn = new LdapName (fullDn);
			result = new Name[] { dn };
			if(grps != null && grps.size() > 0) {
				Vector<Name> collect = new Vector(2,3);
				collect.add(dn);
				javax.naming.NamingEnumeration groupNames = grps.getAll();
				while(groupNames.hasMore()) {
					collect.add(new LdapName ((String)groupNames.next()));
				}
				result = collect.toArray(new Name[0]);
			}
		} finally {
			return result;
		}
	}
	
	public Object propertyNamed(String property) {
		try {
			if(dirContext == null) return null;
			Attributes atrs = dirContext.getAttributes(myGroups[0],new String[] {property});
			if(atrs == null) return null;
			Attribute atr = atrs.get(property);
			if(atr == null) return null;
			return atr.get();
			//return dirContext.getAttributes(myGroups[0],new String[] {property}).get(property).get();
		} catch (javax.naming.NamingException ex) {
			logger.throwing("LdapUser","propertyNamed",ex);
			return null;
		}
	}	
	
	public String toString() {
		return myGroups[0].toString();
	}
	
	public String shortName() {
		String fin = myGroups[0].get(myGroups[0].size() - 1);
		int poz = fin.indexOf('=');
		if (poz > 0) {
			fin = fin.substring(poz + 1);
		}
		return fin;
	}
	
	public String present() {
		Object result = propertyNamed("fullName");
		if(result == null)
			result = propertyNamed("sn");
		if(result == null)
			result = shortName();
		return result.toString();
	}	
	
	public boolean isInGroup (Object group) {
		Name check;
		 if (group instanceof Name)
			 check = (Name)group;
		else {
			try {
				check = new LdapName(group.toString());
			} catch (InvalidNameException ex) {
				return false;
				//throw new IllegalArgumentException("Group argument could not be parced", ex);
			}
		}
		for (int i = 0; i < myGroups.length; i++) {
			if(myGroups[i].startsWith(check))
				return true;
		}
		return false;
	}
	
	public Object[] listGroups() {
		/*
		 if(myGroups == null || myGroups.length == 0) {
			try {
				myGroups = new Name[] {new LdapName (context.getNameInNamespace())};
				
				Attribute grps = context.getAttributes("",new String[] {ATTR}).get(ATTR);
				javax.naming.NamingEnumeration groupNames = grps.getAll();
				for (int i = 1; groupNames.hasMore(); i++) {
					myGroups[i] = new LdapName ((String)groupNames.next());
				}
			} catch (javax.naming.NamingException ex) {
				return null;
			}
		}*/
		return myGroups.clone();
	}
	
	public Object[] filterMyGroups(Object[] groups) {
		Vector result = new Vector(0,2);
		for (int i = 0; i < groups.length; i++) {
			if(isInGroup(groups[i])) {
				result.add(groups[i]);
			}
		}
		return result.toArray();
	}
	/*	
	protected AccessHandler accessHandler = null;
	public void setAccessHandler (AccessHandler ah) {
		accessHandler = ah;
		if(!accessHandler.userIs(this))
			accessHandler.setUser(this);
	}

	public int accessLevel(Object obj)  throws AccessHandler.UnlistedModuleException{
		return accessHandler.accessLevel(obj);
	} */
	
}
