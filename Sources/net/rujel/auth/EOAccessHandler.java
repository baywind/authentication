//  EOAccessHandler.java

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
import com.webobjects.foundation.*;
import com.webobjects.eocontrol.*;
import com.webobjects.eoaccess.EOUtilities;
import java.util.Enumeration;
import java.util.logging.Logger;
import net.rujel.reusables.WOLogLevel;

public class EOAccessHandler implements AccessHandler {
	// Static section
	protected static final String OWNKEY = "owned";
	protected static Logger logger = Logger.getLogger("auth");
	
	protected static NSMutableDictionary entityGroups = new NSMutableDictionary();
	protected static EOSharedEditingContext shec = new EOSharedEditingContext();
	public static void dropCaches() {
		entityGroups.removeAllObjects();
	}
	
	protected static Object[] groupsForEntity (String entity) {
		Object obj = entityGroups.objectForKey(entity);
		if(obj == null) {
			NSArray attribList = new NSArray("userGroup");
			EOQualifier qual = new EOKeyValueQualifier("entity",EOQualifier.QualifierOperatorEqual,entity);
			EOFetchSpecification fspec = new EOFetchSpecification("AccessList",qual,null);
			fspec.setRefreshesRefetchedObjects(true);
			fspec.setRawRowKeyPaths(attribList);
			fspec.setUsesDistinct(true);
			NSArray tmp = shec.objectsWithFetchSpecification(fspec);
			if(tmp == null || tmp.count() == 0) {
				obj = NSKeyValueCoding.NullValue;
				logger.logp(WOLogLevel.CONFIG,"EOAccessHandler","groupsForEntity","No access level defined for entity '" + entity + '\'');
			} else {
				obj = tmp.valueForKey("userGroup");
			}			
			entityGroups.setObjectForKey(obj,entity);
		}
		if(NSKeyValueCoding.NullValue.equals(obj)) {
			return null;
		} else {
			return ((NSArray)obj).objects();
		}
	}
	
	// Instance section
	protected UserPresentation user = null;

	protected EOEditingContext ec;
//	protected EOQualifier groupQualifier;
	protected NSMutableDictionary accessCache = new NSMutableDictionary();
	protected NSMutableDictionary schemeCache = new NSMutableDictionary();
	protected NSMutableDictionary entityQualifiers = new NSMutableDictionary();
	
	public EOAccessHandler() {
		super();
		ec = new EOEditingContext();
		ec.setSharedEditingContext(shec);
	}

	public void setUser (UserPresentation aUser) {
		user = aUser;
/*		NSMutableArray tmp = new NSMutableArray();
		Object[] grps = user.listGroups();
		for (int i = 0; i < grps.length; i++) {
			tmp.addObject(new EOKeyValueQualifier("userGroup",EOQualifier.QualifierOperatorEqual,grps[i]));
		}
		groupQualifier = new EOOrQualifier(tmp); */
		NSSelector sel = new NSSelector("processOwnNotification",new Class [] {NSNotification.class});
		NSNotificationCenter.defaultCenter().addObserver(this,sel,ownNotificationName,user);
	}
	
	public boolean userIs(UserPresentation aUser) {
		return aUser.equals(user);//(aUser == user);//
	}
	public int accessLevel (Object obj) throws UnlistedModuleException {
		String entity;
		EOGlobalID gid = null;
		if (obj instanceof EOEnterpriseObject) {
			entity = ((EOEnterpriseObject)obj).entityName();
			EOEditingContext ctx = ((EOEnterpriseObject)obj).editingContext();
			if(ctx != null)
				gid = ctx.globalIDForObject((EOEnterpriseObject)obj);
		} else {
			if (obj instanceof SchemeRequest) {
				return processSchemeRequest((SchemeRequest)obj);
			}
		} 
		entity = obj.toString();
		return accessLevel(entity,gid,null);
	}
	
	public int accessLevel (String entity, EOGlobalID gid, NSDictionary pKey) throws UnlistedModuleException {
		
		Object fromCache = null;
		if (gid != null) {
			fromCache = accessCache.objectForKey(gid);
			if(fromCache != null) {
				if(fromCache instanceof Number) {
					return ((Number)fromCache).intValue();
				}
				fromCache = accessCache.objectForKey(fromCache);
				return ((Number)fromCache).intValue();
			}
		}
		
		EOQualifier entQual = qualifierForEntity(entity);
		if(entQual == null) {
			return 0;
		}
		fromCache = accessCache.objectForKey(entity);
		int result = 0;
		if(fromCache == null) {
			EOQualifier qual = EOQualifier.qualifierWithQualifierFormat("primaryKey = 0 AND qualifier = nil",null);
			NSArray found = useEntityQualifierWithOther(entQual,qual);
			if(found != null && found.count() >= 0) {
				result = evaluateFoundWithObj(found,null,entity);
			}
				accessCache.setObjectForKey(new Integer(result),entity);
		} else {
			result = ((Number)fromCache).intValue();
		}
		
		if (gid != null) {
			EOEnterpriseObject eo = ec.objectForGlobalID(gid);
			if(pKey == null)
				pKey = EOUtilities.primaryKeyForObject(ec,eo);
			EOQualifier qual = EOQualifier.qualifierWithQualifierFormat("primaryKey = 0 AND qualifier != nil AND qualifier != %@",new NSArray(OWNKEY));
			if(pKey != null) {
				NSArray qarr = new NSArray(new Object[] {qual,EOQualifier.qualifierWithQualifierFormat("primaryKey = %@",pKey.allValues())});
				qual = new EOOrQualifier(qarr);
				//EOQualifier.qualifierWithQualifierFormat("primaryKey = %@ OR (primaryKey = 0 AND qualifier != nil)",pKey.allValues());
			}
			
			NSArray found = useEntityQualifierWithOther(entQual,qual);
			if(found != null && found.count() > 0) {
				result = result | evaluateFoundWithObj(found,eo,gid);
			}
			accessCache.setObjectForKey(new Integer(result),gid);
		}
		
		return result;
	}
	
	protected NSArray useEntityQualifierWithOther (EOQualifier entQual,EOQualifier other) {
		EOQualifier qual = entQual;
		if(other != null) 
			qual = new EOAndQualifier(new NSArray(new Object[] {qual,other}));
		EOFetchSpecification fspec = new EOFetchSpecification("AccessList",qual,null);
		fspec.setRefreshesRefetchedObjects(true);
		return ec.objectsWithFetchSpecification(fspec);
	}

	protected int evaluateFoundWithObj (NSArray array, EOEnterpriseObject obj,Object key) {
		int result = 0;
		Number currAcc = null;
		Enumeration enumerator = array.objectEnumerator();
		NSMutableSet schemeList = (NSMutableSet)schemeCache.objectForKey(key);
		if(schemeList == null) {
			schemeList = new NSMutableSet();
			schemeCache.setObjectForKey(schemeList,key);
		}
		//NSArray attrs = new NSArray(userPersonLink());
		while(enumerator.hasMoreElements()) {
			EOEnterpriseObject acl = (EOEnterpriseObject)enumerator.nextElement();
			currAcc = (Number)acl.valueForKey("access");
			/*
			if(obj != null) {
				String qualFmt = (String)acl.valueForKey("qualifier");
				if(qualFmt != null && qualFmt.length() > 0 && !qualFmt.equals(OWNKEY)) {
					try {
						EOQualifier testQual = EOQualifier.qualifierWithQualifierFormat(qualFmt,attrs);
						if(!testQual.evaluateWithObject(obj)) {
							currAcc = null;
						}
					} catch (Throwable t) {
						currAcc = null;
					}
				}
			}*/
			AccessScheme currScheme = (AccessScheme)acl.storedValueForKey("accessScheme");
			if(currScheme != null) {
				schemeList.addObject(currScheme);
			}
			if (currAcc != null) {
				result = result | currAcc.intValue();
			}
		}
		if(obj != null && key instanceof EOGlobalID) {
			NSSet entitySchemes = (NSSet)schemeCache.objectForKey(obj.entityName());
			if(entitySchemes == null)
				entitySchemes = NSSet.EmptySet;
			if(schemeList.count() == 0) {
				schemeCache.setObjectForKey(entitySchemes,key);
			} else {
				schemeList.unionSet(entitySchemes);
			}
		} else {
			if(schemeList.count() == 0) {
				schemeCache.setObjectForKey(NSSet.EmptySet,key);
			}
		}
			return result;
	}

	protected int processSchemeRequest(SchemeRequest req) throws UnlistedModuleException {
		Number cached = (Number)accessCache.objectForKey(req);
		if(cached != null)
			return cached.intValue();
		
		EOGlobalID gid = req.rootEOgid();
		NSSet schemes = (NSSet)schemeCache.objectForKey(gid);
		if(schemes == null) { //no schemes cached
			if(accessCache.objectForKey(gid) == null) { // access to root EO not cached
				if(accessLevel(req.rootEntity(),req.rootEOgid(),req.rootEOprimaryKey()) > 0)
					return processSchemeRequest(req); // retry
				else
					return 0;
			} else { //no schemas cached for GID
				schemes = (NSSet)schemeCache.objectForKey(req.rootEntity());
				if(schemes == null) {
					return 0;
				} else {
					schemeCache.setObjectForKey(schemes,gid);
				}
			}
		}
		if(schemes.count() == 0)
			return 0;
		
		NSArray values = (NSArray)schemes.allObjects().valueForKeyPath(req.attributePath());
		Enumeration enumerator = values.objectEnumerator();
		int result = 0;
		while (enumerator.hasMoreElements()) {
			result = result | ((Number)enumerator.nextElement()).intValue();
		}
		accessCache.setObjectForKey(new Integer(result),req);
		return result;
	}
	
	public boolean canLogin() {
		try {
			EOQualifier qual = qualifierForEntity("login");
			if(qual == null) return false;
			EOFetchSpecification fspec = new EOFetchSpecification("AccessList",qual,null);
			NSArray found = ec.objectsWithFetchSpecification(fspec);
			if(found == null || found.count() == 0)
				return false;
			//Enumeration enumerator = found.objectEnumerator();
			for(int i = 0; i < found.count(); i ++) {
				EOEnterpriseObject acl = (EOEnterpriseObject)found.objectAtIndex(i);
				Number acc = (Number)acl.storedValueForKey("access");
				if(acc.intValue() > 0)
					return true;
			}
		} catch (UnlistedModuleException umex) {
			return true;
		}
		return false;
	}
	
	protected EOQualifier qualifierForEntity(String entity) throws UnlistedModuleException {
		Object result = entityQualifiers.objectForKey(entity);
		if(result != null) {
			if(result instanceof EOQualifier)
				return (EOQualifier)result;
			if(result instanceof UnlistedModuleException)
				throw (UnlistedModuleException)result;
			if(result.equals(NSKeyValueCoding.NullValue))
				return null;
		} 
		
		Object[] grps = groupsForEntity(entity);
		if(grps == null) {
			UnlistedModuleException umex = new UnlistedModuleException(entity);
			entityQualifiers.setObjectForKey(umex,entity);
			throw umex;
		}
		grps = user.filterMyGroups(grps);
		if(grps == null || grps.length == 0) {
			entityQualifiers.setObjectForKey(NSKeyValueCoding.NullValue,entity);
			return null;
		}
		EOQualifier entQual = new EOKeyValueQualifier("entity",EOQualifier.QualifierOperatorEqual,entity);
		NSMutableArray tmp = new NSMutableArray(EOQualifier.qualifierWithQualifierFormat("userGroup = nil",null));
		for (int i = 0; i < grps.length; i++) {
			tmp.addObject(new EOKeyValueQualifier("userGroup",EOQualifier.QualifierOperatorEqual,grps[i]));
		}
		result = new EOAndQualifier(new NSArray(new Object[] { entQual,new EOOrQualifier(tmp) }));
		entityQualifiers.setObjectForKey(result,entity);
		return (EOQualifier)result;
	}
	/*
	private PersonLink personLink;
	public PersonLink userPersonLink() {
		if (personLink != null) return personLink;
		//UserPresentation user = (UserPresentation)session().valueForKey("user");
		//Person result = null;
		Object pid = user.propertyNamed("teacherID");//.toString();
			String className = Teacher.entityName;
			if (pid == null) {
				pid = user.propertyNamed("studentID");//.toString();
				className = Student.entityName;
				//			isStudent = true;
			}
			
			if (pid == null) return null;
			
			Object pKey = null;
			if(pid instanceof Number)
				pKey = pid;
		else {
			try {
				pKey = Integer.valueOf(pid.toString());
			} catch (NumberFormatException ex) {
				pKey = pid;
			}
		}
		
		try {
			personLink = (PersonLink)EOUtilities.objectWithPrimaryKeyValue(ec,className, pKey);
			//person = pLink.person();
		} catch (Exception ex) {
			return null;
		}
		return personLink;
	}
	*/
	public void processOwnNotification(NSNotification ntf) {
		EOEnterpriseObject eo = (EOEnterpriseObject)ntf.userInfo().objectForKey("eo");
		if(eo == null) return;
		NSArray array = null;
		try {
			EOQualifier entQual = qualifierForEntity(eo.entityName());
			if(entQual == null) return;
			array = useEntityQualifierWithOther(entQual,EOQualifier.qualifierWithQualifierFormat("primaryKey = 0 AND qualifier = %@",new NSArray(OWNKEY)));
			if(array == null || array.count() == 0) return;
		} catch (Throwable umex) {
			if(!(umex instanceof UnlistedModuleException)) {
				Object[] args = new Object[] {eo,user,umex};
				logger.logp(WOLogLevel.WARNING,"EOAccessHandler","processOwnNotification","Error processing own notification",args);
			}
			return;
		}
		int acc = 0;
		EOEnterpriseObject tmp = null;
		EOEnterpriseObject longest = null;
		Enumeration enumerator = array.objectEnumerator();
		while (enumerator.hasMoreElements()) {
			tmp = (EOEnterpriseObject)enumerator.nextElement();
			acc = acc | ((Number)tmp.valueForKey("access")).intValue();
			if(longest == null) {
				longest = tmp;
			} else {
				if(tmp.valueForKey("accessScheme") != null) {
					String tmpGroup = (String)tmp.valueForKey("userGroup");
					String longestGroup = (String)longest.valueForKey("userGroup");
					if(longestGroup == null || (tmpGroup != null && tmpGroup.length() > longestGroup.length()))
						longest = tmp;
				}
			}
		}
		if(acc == 0) return;
		EOEnterpriseObject owned = EOUtilities.createAndInsertInstance(ec,"AccessList");
		owned.takeValueForKey(eo.entityName(),"entity");
		owned.takeValueForKey(new Integer(acc),"access");
		owned.takeValueForKey(user.listGroups()[0],"userGroup");
		owned.takeValueForKey(OWNKEY,"qualifier");
		
		NSDictionary pkey = EOUtilities.primaryKeyForObject(eo.editingContext(),eo);
		if(pkey != null) {
			owned.takeValueForKey(pkey.allValues().objectAtIndex(0),"primaryKey");
		}

		if(longest != null) {
			owned.takeValueForKey(longest.valueForKey("accessScheme"),"accessScheme");
		}
		
		try {
			ec.saveChanges();
			Object[] args = new Object[] {eo,user};
			logger.logp(WOLogLevel.UNOWNED_EDITING,"EOAccessHandler","processOwnNotification","Owned acces to object in notification",args);
		} catch (Throwable ex) {
			Object[] args = new Object[] {eo,user,ex};
			logger.logp(WOLogLevel.WARNING,"EOAccessHandler","processOwnNotification","Error saving owned access",args);
			try {
				ec.revert();
			} catch (Throwable reex) {
				logger.logp(WOLogLevel.SEVERE,"EOAccessHandler","processOwnNotification","Error reverting editing context in EOAccessHandler",reex);
			}
		}
	}
	
	public static class SchemeRequest {
		//private EOEnterpriseObject eo;
		private String entity;
		private NSDictionary pKey;
		private EOGlobalID gid;
		private String attr;
		
		protected SchemeRequest(String entity, NSDictionary pKey, EOGlobalID gid, String attr) {
			this.entity = entity;
			this.pKey = pKey;
			this.gid = gid;
			this.attr = attr;
		}
		
		public SchemeRequest(EOEnterpriseObject rootEO, String attributePath) {
			if(rootEO.editingContext() == null)
				throw new IllegalArgumentException("Enterprise object should be inserted into EditingContext");
			entity = rootEO.entityName();
			pKey = EOUtilities.primaryKeyForObject(rootEO.editingContext(),rootEO);
			gid = rootEO.editingContext().globalIDForObject(rootEO);
			attr = attributePath;
		}
		
		public String rootEntity() {
			return entity;
		}
		
		public NSDictionary rootEOprimaryKey() {
			return pKey.immutableClone();
		}
		
		public int rootEOpKeyValue() {
			Number result = (Number)pKey.allValues().objectAtIndex(0);
			return result.intValue();
		}
		
		public EOGlobalID rootEOgid() {
			return gid;
		}
		
		public String attributePath() {
			return attr;
		}
		
		public boolean equals(Object obj) {
			if(obj instanceof SchemeRequest) {
				SchemeRequest tmp = (SchemeRequest)obj;
				return ((attr.equals(tmp.attr)) && rootEOgid().equals(tmp.rootEOgid()));
			} else return false;
		}
		
		public SchemeRequest prolongScheme(String suffix) {
			return new SchemeRequest(entity, pKey, gid, attr + '.' + suffix);
		}
		
		public String toString() {
			return entity + '.' + attr;
		}
	}

}
