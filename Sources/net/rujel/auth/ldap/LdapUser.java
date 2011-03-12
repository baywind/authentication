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
import java.util.logging.Level;
import java.util.logging.Logger;

public class LdapUser extends UserPresentation.DefaultImplementation {
	protected static Logger logger = Logger.getLogger("auth");
	protected Name[] myGroups;
	
	protected DirContext dirContext;
//	protected String userDn; 
	
	public LdapUser (Name[] groups) {
		myGroups = groups;
	}
	
	public LdapUser (DirContext context, String dn) {
		dirContext = context;
		//userDn = dn;
		myGroups = getGroups(dn);
	}
	
	protected Name[] getGroups(String fullDn) {//throws NamingException{
		Vector<Name> collect = new Vector(2,3);
		try {
			Name dn = new LdapName (fullDn);
			Name baseDN = LdapAuthentication.baseDN();
			if(dn.startsWith(baseDN)) {
				dn = dn.getSuffix(baseDN.size());
			}
			collect.add(dn);
			String groupAttibute = LdapAuthentication.prefs.get("groupAttribute", null);
			if (groupAttibute != null) {
				Attribute grps = dirContext.getAttributes(dn,
						new String[] {groupAttibute}).get(groupAttibute);
				if(grps != null && grps.size() > 0) {
					NamingEnumeration groupNames = grps.getAll();
					while(groupNames.hasMore()) {
						Name name = new LdapName ((String)groupNames.next());
						if(name.startsWith(baseDN)) {
							name = name.getSuffix(baseDN.size());
						}
						collect.add(name);
					}
					groupNames.close();
				}
			}
			groupAttibute = LdapAuthentication.prefs.get("memberAttribute", null);
			if (groupAttibute != null) {
				String membName = null;
				if(LdapAuthentication.prefs.getBoolean("fullMemberDN", false))
					membName = fullDn;
				else
					membName = dn.get(dn.size() -1).split("=")[1];
				SearchControls ctrls = new SearchControls(
						SearchControls.SUBTREE_SCOPE,0,1000,new String[] {},false,false);
				NamingEnumeration grps = dirContext.search("",
						groupAttibute + '=' + membName, ctrls);
				if(grps != null) {
					while(grps.hasMore()) {
						SearchResult res = (SearchResult)grps.next();
						LdapName name = new LdapName(res.getName());
						collect.add(name);
					}
					grps.close();
				}
			}
		} catch (Exception ex) {
			logger.log(Level.INFO,"Error getting groups for user",new Object[] {fullDn, ex});
		} finally {
			return collect.toArray(new Name[0]);
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
		} catch (javax.naming.NamingException ex) {
			logger.throwing("LdapUser","propertyNamed",ex);
			return null;
		}
	}	
	
	public String toString() {
		Name name = LdapAuthentication.baseDN();
		if(name != null) {
			try {
				name = (Name)name.clone();
				name.addAll(myGroups[0]);
			} catch (Exception e) {
				name = myGroups[0];
			}
		} else {
			name = myGroups[0];
		}
		return name.toString();
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
		String prop = LdapAuthentication.prefs.get("presentAttribute", "cn");
		Object result = null;
		if(prop.indexOf(' ') > 0) {
			String[] props = prop.split(" ");
			for (int i = 0; i < props.length; i++) {
				result = propertyNamed(props[i]);
				if(result != null)
					break;
			}
		} else {
			result = propertyNamed(prop);
		}
		if(result == null)
			result = shortName();
		return result.toString();
	}
	
	public boolean isInGroup (String group,Integer section) {
		Name check = null;
		try {
			check = new LdapName(group);
		} catch (InvalidNameException ex) {
			return false;
			//throw new IllegalArgumentException("Group argument could not be parced", ex);
		}
		if(check.startsWith(LdapAuthentication.baseDN()))
			check = check.getSuffix(LdapAuthentication.baseDN().size());
		for (int i = 0; i < myGroups.length; i++) {
			if(myGroups[i].startsWith(check))
				return true;
		}
		return false;
	}
	
	public String[] listGroups(Integer section) {
		String[] result = new String[myGroups.length];
		for (int i = 0; i < result.length; i++) {
			result[i] = myGroups[i].toString();
		}
		return result;
	}
	
	public String[] filterMyGroups(String[] groups) {
		Vector<String> result = new Vector<String>(0,2);
		for (int i = 0; i < groups.length; i++) {
			if(isInGroup(groups[i])) {
				result.add(groups[i]);
			}
		}
		return result.toArray(new String[result.size()]);
	}
}
