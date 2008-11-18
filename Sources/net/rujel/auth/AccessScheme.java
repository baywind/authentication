// AccessScheme.java

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


import com.webobjects.foundation.*;
import com.webobjects.eocontrol.*;
import com.webobjects.eoaccess.EOUtilities;

public class AccessScheme extends EOCustomObject
{
	private String _schemeName = null;
	private NSArray _entries = null;
	private NSArray _keys = null;
	
    public AccessScheme() {
        super();
    }

    public String schemeName() {
		willRead();
        return _schemeName;
    }
	
    public void setSchemeName(String aValue) {
		willChange();
		_schemeName = aValue;
    }
	
    public NSArray entries() {
		willRead();
		willReadRelationship(_entries);
        return _entries;
    }
	
    public void setEntries(NSArray aValue) {
		willChange();
//		_values = null;
        _entries = aValue;
		_keys = (NSArray)_entries.valueForKey("attribute");
    }
	
    public void addToEntries(EOEnterpriseObject object) {
		includeObjectIntoPropertyWithKey(object, "entries");
//		values().setObjectForKey(object,object.valueForKey("attribute"));
    }
	
    public void removeFromEntries(EOEnterpriseObject object) {
		excludeObjectFromPropertyWithKey(object, "entries");
//		values().removeObjectForKey(object.valueForKey("attribute"));
    }
	/*
    // If you add instance variables to store property values you
    // should add empty implementions of the Serialization methods
    // to avoid unnecessary overhead (the properties will be
    // serialized for you in the superclass).
    private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    }

    private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, java.lang.ClassNotFoundException {
    }
*/
	/*
	private transient NSMutableDictionary _values;
	protected NSDictionary values() {
		if(_values == null) {
			NSArray relatedEntries = entries();
			NSArray entryKeys = (NSArray)relatedEntries.valueForKey("attribute");
			_values = new NSMutableDictionary(relatedEntries,entryKeys);
		}
		return _values;
	}*/

	public Object valueForKey(String key) {
		if(key.equals("schemeName"))
			return schemeName();
		int idx = _keys.indexOfObject(key);
		if(idx == NSArray.NotFound) return null;
		EOEnterpriseObject entry = (EOEnterpriseObject)_entries.objectAtIndex(idx);
		return entry.storedValueForKey("access");
	}
	
	public Object valueForKeyPath(String keyPath) {
		int dotIdx = keyPath.indexOf('.');
		if(dotIdx < 0)
			return valueForKey(keyPath);
		String key = keyPath.substring(0,dotIdx);
		int idx = _keys.indexOfObject(key);
		Integer zero = new Integer(0);
		if(idx == NSArray.NotFound) return zero;
		EOEnterpriseObject entry = (EOEnterpriseObject)_entries.objectAtIndex(idx); //(EOEnterpriseObject)values().objectForKey(key);
		//if(entry == null) return zero;
		AccessScheme nextScheme = (AccessScheme)entry.storedValueForKey("sub");
		if(nextScheme == null) return zero;
		
		return nextScheme.valueForKeyPath(keyPath.substring(dotIdx + 1));
	}
	
	public void takeValueForKey(Object value,String key) {
		if(key.equals("schemeName"))
			setSchemeName((String)value);
		int idx = _keys.indexOfObject(key);
		EOEnterpriseObject entry;
		if(value == null) {
			entry = (EOEnterpriseObject)_entries.objectAtIndex(idx);
			removeFromEntries(entry);
			return;
		}
		if(!(value instanceof Integer))
			throw new IllegalArgumentException("Only integer values accepted");
		if(idx == NSArray.NotFound) {
			entry = EOUtilities.createAndInsertInstance(editingContext(),"SchemeEntry");
			entry.takeStoredValueForKey(key,"attribute");
			addObjectToBothSidesOfRelationshipWithKey(entry,"entries");
		} else {
			entry = (EOEnterpriseObject)_entries.objectAtIndex(idx);
		}
			entry.takeStoredValueForKey(value,"access");
	}
	
	public void takeValueForKeyPath(Object value,String keyPath) {
		int dotIdx = keyPath.indexOf('.');
		if(dotIdx < 0) {
			takeValueForKey(value,keyPath);
		}
		String key = keyPath.substring(0,dotIdx);
		int idx = _keys.indexOfObject(key);
		if(idx == NSArray.NotFound) {
			throw new UnknownKeyException("Access not specified for key " + key,value,key);
		}
		EOEnterpriseObject entry = (EOEnterpriseObject)_entries.objectAtIndex(idx);
		AccessScheme nextScheme = (AccessScheme)entry.storedValueForKey("sub");
		if(nextScheme == null)
			throw new UnknownKeyException("Scheme not defined for key " + key,value,key);
		nextScheme.takeValueForKey(value,keyPath.substring(dotIdx + 1));
	}
}
