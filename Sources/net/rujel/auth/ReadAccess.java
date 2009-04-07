// ReadAccess.java

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

import java.util.logging.Level;
import java.util.logging.Logger;

import net.rujel.reusables.DegenerateFlags;
import net.rujel.reusables.ImmutableNamedFlags;
import net.rujel.reusables.NamedFlags;

import com.webobjects.appserver.*;
import com.webobjects.eocontrol.EOEditingContext;
import com.webobjects.eocontrol.EOEnterpriseObject;
import com.webobjects.foundation.*;

public class ReadAccess implements NSKeyValueCodingAdditions {
	public static final NSArray accessKeys = new NSArray (new String[] {"read","create","edit","delete"});

	protected WOSession ses;
	protected UserPresentation _user;
	protected NamedFlags defaultAccess = DegenerateFlags.ALL_TRUE;
	
	public ReadAccess(WOSession session) {
		ses = session;
	}
	
	protected UserPresentation user() {
		if(_user == null) {
			_user = (UserPresentation)ses.valueForKey("user");
			if(_user != null) {
				defaultAccess = accessForObject("default");
			}
		}
		return _user;
	}
	
	public NamedFlags accessForObject(Object obj) {
		if(user() == null) {
			throw new IllegalStateException ("Can't get user to determine access");
		} else {
			try {
				int level = user().accessLevel(obj);
				NamedFlags result = new ImmutableNamedFlags(level,accessKeys);
				return result;
			} catch (AccessHandler.UnlistedModuleException e) {
				Object [] args = new Object[] {ses,obj,e};
				Logger.getLogger("auth").log(Level.WARNING,"Undefined access to module : returning default access",args);
				return defaultAccess;
			}
		}
	}
	
	protected NSMutableDictionary accessCache = new NSMutableDictionary();
	
	public NamedFlags cachedAccessForObject(Object obj) {
		if(obj == null)
			return defaultAccess;
		NamedFlags result = defaultAccess; 
		if(obj instanceof String) {
			result = (NamedFlags)accessCache.objectForKey(obj);
			if(result == null) {
				result = accessForObject(obj);
				accessCache.setObjectForKey(result, obj);
			}
		} else if (obj instanceof EOEnterpriseObject) {
			EOEnterpriseObject eo = (EOEnterpriseObject) obj;
			//TODO: qualified access for specific objects
			result = cachedAccessForObject(eo.entityName());
			if(result.flagForKey("create")) {
				EOEditingContext ec = eo.editingContext();
				if(ec == null || ec.insertedObjects().contains(eo))
					result = DegenerateFlags.ALL_TRUE;
			}
		} else if(obj instanceof WOComponent) {
			String name = ((com.webobjects.appserver.WOComponent)obj).name();
			int idx = name.lastIndexOf('.');
			obj = (idx <0)?name:name.substring(idx +1);
			result = cachedAccessForObject(obj);
		} else {
			result = accessForObject(obj);
		}
		return result;
	}
	
	public NamedFlags cachedAccessForObject(Object obj, String subPath) {
		//TODO: employ subPath
		return cachedAccessForObject(obj);
	}


	public void takeValueForKeyPath(Object keyPath, String value) {
		throw new UnsupportedOperationException("This is read-only value");
	}

	public Object valueForKeyPath(String keyPath) {
		int dotIdx = keyPath.indexOf('.');
		String flag = (dotIdx <0)?keyPath:keyPath.substring(0, dotIdx);
		Object obj = null;
		String subPath = null;
		if(dotIdx > 0) {
			int atIdx = keyPath.indexOf('@');
			if (atIdx > 0)
				subPath = keyPath.substring(atIdx +1);
			String path = (atIdx <0)?keyPath.substring(dotIdx +1)
					:keyPath.substring(dotIdx +1, atIdx -1);
			WOComponent component = ses.context().component(); 
			while(component != null) {
				try {
					obj = component.valueForKeyPath(path);
					break;
				} catch (NSKeyValueCoding.UnknownKeyException e) {
					component = component.parent();
				}
			}
			if(component == null)
				obj = path;
			if(obj == null) {
			//TODO: nullValue behaviour
			}
		} else {
			obj = ses.context().component();
		}
		NamedFlags result = cachedAccessForObject(obj,subPath);
		if(flag.equals("FLAGS"))
			return result;
		return result.valueForKey(flag);
	}

	public void takeValueForKey(Object key, String value) {
		takeValueForKeyPath(key, value);
	}

	public Object valueForKey(String key) {
		return valueForKeyPath(key);
	}

}
