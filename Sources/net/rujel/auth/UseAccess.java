//  UseAccess.java

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

import net.rujel.reusables.*;
import com.webobjects.foundation.NSArray;
import com.webobjects.eocontrol.*;
import java.util.logging.Logger;
import java.util.logging.Level;

public interface UseAccess {
	public static final NSArray accessKeys = new NSArray (new String[] {"read","create","edit","delete"});
	
	public static final NamedFlags readOnly = new NamedFlags(1,accessKeys);

	/** As implied should return new NamedFlags(user.accessLevel(this),accessKeys);*/
	public NamedFlags access();
	
//	public NamedFlags schemeAccess(String schemePath);
	
	/** Should return true if access to this object differs from access to this object class.
		user.accessLevel(this) == user.accessLevel(entityName());*/
	public boolean isOwned();
	
	public static class StaticImplementation {
		public static NamedFlags access(EOEnterpriseObject eo,NSArray keys) {
			UserPresentation user = (UserPresentation)eo.valueForKeyPath("editingContext.session.user");
			if(user == null) {
				throw new IllegalStateException ("Can't get user to determine access");
			} else {
				try {
					int level = user.accessLevel(eo);
					NamedFlags result = new ImmutableNamedFlags(level,accessKeys);
					if(result.flagForKey("create")) {
						EOEditingContext ec = eo.editingContext();
						if(ec == null || ec.insertedObjects().contains(eo))
							return DegenerateFlags.ALL_TRUE;
					}
					return result;
				} catch (AccessHandler.UnlistedModuleException e) {
					Logger.getLogger("auth").logp(Level.WARNING,"UseAccess.StaticImplementation","access","Undefined access to module : returning full access",new Object[] {eo.valueForKeyPath("editingContext.session"),eo});
					return  DegenerateFlags.ALL_TRUE;
				}
			}
		}
		/*
		public static NamedFlags schemeAccess(EOEnterpriseObject eo, String schemePath) {
			UserPresentation user = (UserPresentation)eo.valueForKeyPath("editingContext.session.user");
			if(user == null) {
				throw new IllegalStateException ("Can't get user to determine access");
			} else {
				EOAccessHandler.SchemeRequest sr = new EOAccessHandler.SchemeRequest(eo,schemePath);
				try {
					int level = user.accessLevel(sr);
					return new ImmutableNamedFlags(level,accessKeys);
				} catch (AccessHandler.UnlistedModuleException e) {
					Logger.getLogger("auth").logp(Level.WARNING,"UseAccess.StaticImplementation","schemeAccess","Undefined access to module : returning full access", new Object[] {eo.valueForKeyPath("editingContext.sesion"),eo,e});
					return DegenerateFlags.ALL_TRUE;
				}
			}
		} */
		
		public static boolean isOwned(EOEnterpriseObject eo) {
			NamedFlags _access = ((UseAccess)eo).access();
			if(_access == null || _access == DegenerateFlags.ALL_TRUE)
				return false;
			int entityLevel = 0;
			UserPresentation user = (UserPresentation)eo.valueForKeyPath("editingContext.session.user");
			if(user == null) return false;
			try {
				entityLevel = user.accessLevel(eo.entityName());
			} catch (AccessHandler.UnlistedModuleException e) {
				return false;
			}
			return (entityLevel != _access.intValue());
		}
		
	}
}