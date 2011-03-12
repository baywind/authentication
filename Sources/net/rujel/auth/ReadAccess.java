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

import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.rujel.auth.UserPresentation.DummyUser;
import net.rujel.reusables.DegenerateFlags;
import net.rujel.reusables.ImmutableNamedFlags;
import net.rujel.reusables.NamedFlags;
import net.rujel.reusables.PlistReader;
import net.rujel.reusables.Various;

import com.webobjects.appserver.*;
import com.webobjects.eocontrol.EOEditingContext;
import com.webobjects.eocontrol.EOEnterpriseObject;
import com.webobjects.foundation.*;

public class ReadAccess implements NSKeyValueCodingAdditions {
	public static final NSArray accessKeys = new NSArray (new String[] {"read","create","edit","delete"});
	public static interface Modifier {
		public String interpret(Object obj, String subPath, WOContext ctx);
//		public String validate(Object obj, String subPath, WOContext ctx);
		public Number sort();
		public String message();
	}

	protected WOSession ses;
	protected UserPresentation _user;
	protected NamedFlags defaultAccess = DegenerateFlags.ALL_TRUE;
	protected static PlistReader defaults;
	protected Modifier[] modifiers;
	protected String message;
	
	public ReadAccess(WOSession session) {
		ses = session;
		NSArray mods = (NSArray)ses.valueForKeyPath("modules.accessModifier");
		if(mods != null && mods.count() > 0) {
			modifiers = new Modifier[mods.count()];
			for (int i = 0; i < modifiers.length; i++) {
				try {
					modifiers[i] = (Modifier) mods.objectAtIndex(i);
				} catch (ClassCastException e) {
					Logger.getLogger("auth").log(Level.WARNING,"Illegal modifier provided",
							new Object[] {ses,mods.objectAtIndex(i),e});
				}
			}
		}
	}
	
	public static void mergeDefaultAccess(NSDictionary toMerge) {
		if(defaults == null)
			defaults = new PlistReader(toMerge);
		else
			defaults.mergeValueToKeyPath(toMerge, null);
	}
	
	protected UserPresentation user() {
		if(_user == null) {
			_user = (UserPresentation)ses.valueForKey("user");
			if(_user != null) {
				defaultAccess = accessForObject("default");
				if(_user instanceof DummyUser) {
					defaultAccess = new DegenerateFlags(_user.isInGroup(null));
					accessCache = null;
				}
			}
		}
		return _user;
	}
	
	public NamedFlags accessForObject(String obj) {
		if(user() == null) {
			throw new IllegalStateException ("Can't get user to determine access");
		} else {
			if(accessCache == null)
				return defaultAccess;
			int level = -1;
			try {
				level = user().accessLevel(obj);
			} catch (AccessHandler.UnlistedModuleException e) {
				if(defaults != null && obj instanceof String) {
					String nodeName = (String)obj;
					String modifier = null;
					int idx = nodeName.indexOf('@');
					if(idx > 0) {
						modifier = nodeName.substring(idx + 1);
						nodeName = nodeName.substring(0,idx);
					}
					PlistReader acc = defaults.subreaderForPath(nodeName, false);
					if(acc != null)
						level = PrefsAccessHandler.accessLevel(acc, modifier, user(),null);
				}
				if(level < 0) {
					Object [] args = new Object[] {ses,obj,
							ses.valueForKeyPath("context.component.name"),e};
					Logger.getLogger("auth").log(Level.WARNING,
							"Undefined access to module : returning default access",args);
					return defaultAccess;
				}
			}
			NamedFlags result = new ImmutableNamedFlags(level,accessKeys);
			return result;
		}
	}
	
	protected NSMutableDictionary accessCache = new NSMutableDictionary();
	
	public NamedFlags cachedAccessForObject(String obj) {
		if(obj == null || accessCache == null)
			return defaultAccess;
		NamedFlags result = defaultAccess; 
		result = (NamedFlags)accessCache.objectForKey(obj);
		if(result == null) {
			result = accessForObject(obj);
			if(accessCache == null)
				return defaultAccess;
			accessCache.setObjectForKey(result, obj);
		}
		return result;
	}

	public NamedFlags cachedAccessForObject(Object obj, String subPath) {
		message = null;
		if(accessCache == null || obj == null)
			return defaultAccess;
		String acc = null;
		if(modifiers != null) {
			WOContext ctx = ses.context();
			for (int i = 0; i < modifiers.length; i++) {
				if(modifiers[i] == null)
					continue;
				acc = modifiers[i].interpret(obj, subPath, ctx);
				if(acc != null) {
					message = modifiers[i].message();
					break;
				}
			}
		}
		if (acc == null) {
			if (obj instanceof EOEnterpriseObject) {
				EOEnterpriseObject eo = (EOEnterpriseObject) obj;
				acc = eo.entityName();
				if(subPath != null)
					acc = acc + '@' + subPath;
				NamedFlags result = cachedAccessForObject(acc);
				if(result.flagForKey("create")) {
					EOEditingContext ec = eo.editingContext();
					if(ec == null || ec.globalIDForObject(eo).isTemporary())
						result = DegenerateFlags.ALL_TRUE;
				}
				return result;
			} else if(obj instanceof WOComponent) {
				acc = ((com.webobjects.appserver.WOComponent)obj).name();
				int idx = acc.lastIndexOf('.');
				if(idx > 0)
					acc = acc.substring(idx +1);
			} else if(obj instanceof NSKeyValueCodingAdditions) {
				acc = (String)((NSKeyValueCodingAdditions)obj).valueForKey("entityName");
			} else {
				acc = obj.toString();
			}
			if(subPath != null)
				acc = acc + '@' + subPath;
		}
		return cachedAccessForObject(acc);
	}

/*	public Boolean validate(Object obj, String subPath) {
		if(modifiers == null)
			return Boolean.TRUE;
		WOContext ctx = ses.context();
		boolean result = true;
		for (int i = 0; i < modifiers.length; i++) {
			if(modifiers[i] == null)
				continue;
			String res = modifiers[i].validate(obj, subPath, ctx);
			if(res != null) {
				result = false;
				ses.takeValueForKey(res, "message");
			}
		}
		return Boolean.valueOf(result);
	}*/

	public void takeValueForKeyPath(Object value, String keyPath) {
		throw new UnsupportedOperationException("This is read-only value");
	}

	public Object valueForKeyPath(String keyPath) {
		if(keyPath.equals("message"))
			return message;
		int dotIdx = keyPath.indexOf('.');
		String flag = (dotIdx <0)?keyPath:keyPath.substring(0, dotIdx);
//		if(flag.equals("validate") && modifiers == null) {
//			return Boolean.TRUE;
//		}
		if(flag.equals("modifier")) {
			if(modifiers == null)
				return null;
			flag = keyPath.substring(dotIdx+1);
			for (int i = 0; i < modifiers.length; i++) {
				if(modifiers[i].getClass().getName().endsWith(flag))
					return modifiers[i];
			}
			return null;
		}
		Object obj = null;
		String subPath = null;
		if(dotIdx > 0) {
			int atIdx = keyPath.indexOf('@');
			if (atIdx > 0)
				subPath = keyPath.substring(atIdx +1);
			String path = (atIdx <0)?keyPath.substring(dotIdx +1)
					:keyPath.substring(dotIdx +1, atIdx -1);
			WOComponent component = (path.equals("session"))?null:ses.context().component(); 
			while(component != null) {
				try {
					obj = component.valueForKeyPath(path);
					if(obj == null) {
						obj = component;
						atIdx = path.lastIndexOf('.');
						if(atIdx > 0) {
							obj = component.valueForKeyPath(path.substring(0,atIdx));
							path = path.substring(atIdx +1);
						}
						Class objClass = obj.getClass();
						try {
							java.lang.reflect.Field field = objClass.getField(path);
							objClass = field.getType();
						} catch (Exception e) {
							try {
								java.lang.reflect.Method method = objClass.getMethod(
										path, (Class[])null);
								objClass = method.getReturnType();
							} catch (Exception e2) {
								Logger.getLogger("auth").log(Level.WARNING,
										"Could not get Class for null value: '" +
										keyPath + "' in component " + component.name(),
										new Object[] {ses,e2});
								return defaultAccess;
							}
						}
						path = objClass.getName();
						atIdx = path.lastIndexOf('.');
						if(atIdx > 0)
							path = path.substring(atIdx +1);
						obj = path;
					}
					break;
				} catch (NSKeyValueCoding.UnknownKeyException e) {
					component = component.parent();
				}
			}
			if(component == null)
				obj = ses.objectForKey("readAccess");
			if(obj == null)
				obj = path;
		} else {
			obj = ses.context().component();
		}
		if(flag.equals("save") || flag.equals("_save")) {
			boolean negate = (flag.charAt(0) == '_');
			subPath = (subPath==null)?"save":"save:" + subPath;
			flag = "edit";
			if(obj instanceof EOEnterpriseObject) {
				EOEnterpriseObject eo = (EOEnterpriseObject)obj;
				EOEditingContext ec = eo.editingContext();
				if(ec == null) {
					flag = "create";
				} else {
					if(ec.insertedObjects().contains(eo)) {
						flag = "create";
					} else if(ec.deletedObjects().contains(eo)) {
						flag = "delete";
					} else if(ec.updatedObjects().contains(eo)) {
						NSDictionary snapshot = ec.committedSnapshotForObject(eo);
						snapshot = eo.changesFromSnapshot(snapshot);
						Enumeration enu = snapshot.objectEnumerator();
						flag = "read";
						while (enu.hasMoreElements()) {
							if(!(enu.nextElement() instanceof NSArray))
								flag = "edit";
						}
					} else {
						flag = "read";
					}
				}
			}
			if(negate)
				flag = '_' + flag;
//			return validate(obj, subPath);
		}
		NamedFlags result = cachedAccessForObject(obj,subPath);
		if(flag.equals("FLAGS"))
			return result;
		return result.valueForKey(flag);
	}

	public void takeValueForKey(Object value, String key) {
		if("dummyUser".equals(key)) {
			if(value == null) {
				_user = null;
				accessCache.removeAllObjects();
				defaultAccess = DegenerateFlags.ALL_TRUE;
			} else {
				defaultAccess = new DegenerateFlags(Various.boolForObject(value));
				accessCache = null;
			}
		} else {
			takeValueForKeyPath(value,key);
		}
	}

	public Object valueForKey(String key) {
		return valueForKeyPath(key);
	}
}
