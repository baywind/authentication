//  AccessSchemeAssistant.java

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

//import net.rujel.interfaces.*;
import net.rujel.reusables.*;

import com.webobjects.foundation.*;
import com.webobjects.eocontrol.*;

@ Deprecated
public class AccessSchemeAssistant implements NSKeyValueCoding {
	protected NSMutableSet _schemes = new NSMutableSet();
	protected UserPresentation user;
	protected NSArray accessKeys = UseAccess.accessKeys;
	protected int sumAcc = -1;
	
	public AccessSchemeAssistant(UserPresentation user) {
		this.user = user;
	}
	
	public void addScheme(EOAccessHandler.SchemeRequest sr) {
		_schemes.addObject(sr);
		sumAcc = -1;
	}
	
	public void addScheme(EOEnterpriseObject eo, String attribute) {
		EOAccessHandler.SchemeRequest sr = new EOAccessHandler.SchemeRequest(eo,attribute);
		addScheme(sr);
	}
	
	public void setAccessKeys(NSArray newKeys) {
		accessKeys = newKeys;
	}
	
	public void takeValueForKey(Object value, String key) {
		sumAcc = -1;
		if(value instanceof EOAccessHandler.SchemeRequest)
			_schemes.addObject(value);
		
		else if(value instanceof NSSet)
			_schemes.unionSet((NSSet)value);
		
		else if(value instanceof NSArray) {
			if(key.equals("accessKeys"))
				accessKeys = (NSArray)value;
			else
				_schemes.addObjectsFromArray((NSArray)value);
		}
		
		
		else if(value instanceof EOEnterpriseObject) {
			/* if(key.equals("this")) {
				_schemes.addObject(value);
			} else { */
				EOAccessHandler.SchemeRequest elem = new EOAccessHandler.SchemeRequest((EOEnterpriseObject)value,key);
				_schemes.addObject(elem);
	//		}
		}
	}
	
	public Object valueForKey(String key) {
		return NSKeyValueCoding.DefaultImplementation.valueForKey(this, key);
	}
	
	public int sumSchemeAccess () {
		if(sumAcc  < 0) {
			if (_schemes == null || _schemes.count() == 0) return 0;
			
			java.util.Enumeration enumerator = _schemes.allObjects().objectEnumerator();
			sumAcc = 0;
			int acc = 0;
			Object elem = null;
			while (enumerator.hasMoreElements()) {
				elem = enumerator.nextElement();
				if(elem instanceof EOAccessHandler.SchemeRequest) {
					try {
						acc = user.accessLevel(elem);
					} catch (AccessHandler.UnlistedModuleException umex) {
						acc = 0;
					}
				}
					
				else
					acc = -1;
				
				if(acc <= 0) {
					_schemes.removeObject(elem);
				} else {
					sumAcc = sumAcc | acc;
				}
			}
		}
		return sumAcc;
	}
	
	public AccessSchemeAssistant prolong(String suffix) {
		AccessSchemeAssistant result = new AccessSchemeAssistant(user);
		
		java.util.Enumeration enumerator = _schemes.objectEnumerator();
		Object elem = null;
		while (enumerator.hasMoreElements()) {
			elem = enumerator.nextElement();
			if(elem instanceof EOAccessHandler.SchemeRequest)
				result.addScheme(((EOAccessHandler.SchemeRequest)elem).prolongScheme(suffix));
			if(elem instanceof EOEnterpriseObject) {
				elem = new EOAccessHandler.SchemeRequest((EOEnterpriseObject)elem,suffix);
				result.addScheme((EOAccessHandler.SchemeRequest)elem);
			}
		}
		return result;
	}
	
	public AccessSchemeAssistant prolong(String suffix, EOEnterpriseObject eo) {
		AccessSchemeAssistant result = prolong(suffix);
		if(eo == null) return result;
		EOAccessHandler.SchemeRequest elem = new EOAccessHandler.SchemeRequest(eo,suffix);
		result.addScheme(elem);
		return result;
	}
	
	public NamedFlags accessToObject(Object eo) {
		if(eo == null) {
			return new ImmutableNamedFlags(sumSchemeAccess(),accessKeys);
		}
		if(eo instanceof UseAccess) {
			return ((UseAccess)eo).access().or(sumSchemeAccess());
		} else {
			int acc = 0;
			try {
				acc = user.accessLevel(eo);
			} catch (AccessHandler.UnlistedModuleException umex) {
				acc = 0;
			}
			acc = acc | sumSchemeAccess();
			return new ImmutableNamedFlags(acc,accessKeys);
		}
	}
}
