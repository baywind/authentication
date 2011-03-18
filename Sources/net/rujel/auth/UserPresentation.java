//  UserPresentation.java

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
import java.util.Vector;

public interface UserPresentation {

	/** Returns string representation that uniquely identifies this user
	 * and may be used for user authentication in compatimle LoginHandler */
	public String toString();
	
	public String shortName();
	
	public String present();
	
	public boolean isInGroup (String group);
	public boolean isInGroup (String group, Integer section);
	
	public String[] listGroups(Integer section);
	
	public String[] filterMyGroups(String[] groups,Integer section);
	
	public void setAccessHandler (AccessHandler ah);
	
	public int accessLevel(Object obj) throws AccessHandler.UnlistedModuleException;
	
	public Object propertyNamed(String property);
	
	/** This may be used as superclass when implementing UserPresentation */
	public static abstract class DefaultImplementation implements UserPresentation {
		
		public boolean isInGroup (String group) {
			return isInGroup(group, null);
		}
		/** Checks whether supplied group is in array returned from listGroups*/
		public boolean isInGroup (String group,Integer section) {
			if(group.equals("*"))
				return true;
			Object[] groups = listGroups(section);
			for (int i = 0; i < groups.length; i++) {
				if(group.equals(groups[i])) {
					return true;
				}
			}
			return false;
		}
		
		/** Invokes isInGroup in every group in the list */
		public String[] filterMyGroups(String[] groups,Integer section) {
			Vector<String> result = new Vector<String>(0,2);
			for (int i = 0; i < groups.length; i++) {
				if(isInGroup(groups[i])) {
					result.add(groups[i]);
				}
			}
			return result.toArray(new String[result.size()]);
		}
		
		protected AccessHandler accessHandler = null;
		public void setAccessHandler (AccessHandler ah) {
			accessHandler = ah;
			if(!accessHandler.userIs(this))
				accessHandler.setUser(this);
		}
		
		/** Invokes accessLevel on attached accessHandler*/
		public int accessLevel(Object obj)  throws AccessHandler.UnlistedModuleException {
			return accessHandler.accessLevel(obj);
		}
		
		/** Returns toString*/
		public String shortName() {
			return toString();
		}
		
		/** Returns toString*/
		public String present() {
			return toString();
		}
		
		
		/** Returns null*/
		public Object propertyNamed(String property) {
			return null;
		}
	}
	
	public static class DummyUser implements UserPresentation {
		boolean allow;
		
		public DummyUser (boolean fullAccess) {
			allow = fullAccess;
		}
		
		public String toString() {
			return "DummyUser : " + ((allow)?"Full Access":"No Access");
		}
		
		public String shortName() {
			return "dummy" + ((allow)?"Full":"None");
		}
		
		public String present() {
			return toString();
		}
		
		public boolean isInGroup (String group,Integer section) {
			return allow || group.equals("*") || group.equals("any");
		}
		public boolean isInGroup (String group) {
			return isInGroup(group, null);
		}
		
		public String[] listGroups(Integer section) {
			if(allow) return new String[0];
			else return null;
		}
		
		public String[] filterMyGroups(String[] groups,Integer section) {
			if(allow) return groups.clone();
			else return null;
		}
		
		public void setAccessHandler (AccessHandler ah) {
			;
		}
		
		public int accessLevel(Object obj) throws AccessHandler.UnlistedModuleException {
			return (allow)?-1:0;
		}
		
		public Object propertyNamed(String property) {
			return null;
		}		
	}
	
	public static class Guest extends DefaultImplementation {
		
		public Guest() {
			super();
			accessHandler = AccessHandler.Generator.generateForUser(this);
		}

		public String[] listGroups(Integer section) {
			return null;
		}
		
		public String toString() {
			return "GUEST";
		}
		
		public boolean isInGroup(String grp,Integer section) {
			return grp.equals("*") || grp.equals("any");
		}
	}
}
