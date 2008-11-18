//
//  LdapAuthentication.java
//  Advance
//
//  Created by Gennady Kushnir on 6.2.07.
//  Copyright (c) 2007 __MyCompanyName__. All rights reserved.
//
package net.rujel.auth.ldap;

import net.rujel.auth.*;
import net.rujel.reusables.SettingsReader;

import javax.naming.*;
import javax.naming.directory.*;

import java.util.Hashtable;
import java.util.logging.Logger;
import java.util.logging.Level;


public class LdapAuthentication implements LoginHandler {
	protected static Logger logger = Logger.getLogger("auth");
	protected static final SettingsReader prefs = SettingsReader.settingsForPath("auth.ldap",true);
		/*public static void syncPrefs () {
		try {
			prefs.sync();
		} catch (Exception e) {
			
		}
	}
	
	protected AttributeReaderDelegate delegate = defaultDelegate;
	public static final AttributeReaderDelegate defaultDelegate  = new AttributeReaderDelegate() {
		public Integer getIntegerPresentation(DirContext context) {
			int result = 0;
			try {
				Hashtable environment = context.getEnvironment();
				String username = (String)environment.get(Context.SECURITY_PRINCIPAL);
				result = (username == null || username.equals(prefs.get("proxyUserDn",null)))?0:1;
			} catch (NamingException nex) {
				result = 0;
			}
				return new Integer (result);
		}
	};
	public static interface AttributeReaderDelegate {
		public Integer getIntegerPresentation(DirContext context);
	}
	
	
	public void setAttributeReaderDelegate (AttributeReaderDelegate deleg) {
		delegate = deleg;
	} */
	
	public LdapAuthentication() {
		super();
		//prefs.refresh();
	}

	
/*	public UserPresentation processLogin(WORequest req) throws AuthenticationFailedException {
		//WORequest req = aContext.request();
		String user = req.stringFormValueForKey("username");
//		if (user==null) throw new IllegalArgumentException("No username provided.");
		String pass = req.stringFormValueForKey("password");
		return authenticate(user,pass);
	} */
	
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
			password = (String) args[1];
		} catch (Exception exc) {
			throw new IllegalArgumentException("Only two String argumens supported: username and password.",exc);
		}
		//DirContext ctx = authenticate(user, password);
		return authenticate(user, password);//delegate.getIntegerPresentation(ctx);
	} 
	
	public static LdapUser authenticate(String user, String password) throws AuthenticationFailedException {
		if (password==null || password.length() == 0) return null;
		if (user==null || user.length() == 0) throw new AuthenticationFailedException(IDENTITY, "No username provided.");
		String userDn = user;
		if (user.indexOf('=') == -1) {
			try {
				userDn = getUserDn(user);
			} catch (Exception exc) {
				logger.logp(Level.SEVERE,"LdapAuthentication","getUserDn","Error resolving user " + user,exc);
				AuthenticationFailedException aex = new AuthenticationFailedException (ERROR, "User lookup failed.", exc);
				aex.setUserId(user);
				throw aex;
			}
			if(userDn == null) {
				AuthenticationFailedException aex = new AuthenticationFailedException (IDENTITY, "No such user found.");
				aex.setUserId(user);
				throw aex;
			}
		}
		return authenticateWithDn(userDn,password);
	}
	
	public static LdapUser authenticateWithDn (String userDn, String password) throws AuthenticationFailedException {
		// Set up environment for creating initial context
		if (password == null)
			password = "";
		Hashtable env = initEnvironment(null);
		
		env.put(Context.SECURITY_AUTHENTICATION, prefs.get("authentication","simple"));
		
		env.put(Context.SECURITY_PRINCIPAL, userDn);
		env.put(Context.SECURITY_CREDENTIALS, password);
		DirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
			/* Attributes at = ctx.getAttributes(userDn,new String[] {attr});
			Attribute grps = at.get(attr); */
		} catch (NamingException ex) {
			AuthenticationFailedException e = new AuthenticationFailedException (CREDENTIAL,"Could not authenticate", ex);
			e.setUserId(userDn);
			throw e;
		}
			String attr = prefs.get("groupAttribute","securityEquals");
			return new LdapUser (ctx,userDn,attr);//(LdapUser.getGroups(userDn,grps));
	//	return null;
	}
	
	public static Hashtable initEnvironment(String node) {
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, prefs.get("contextFactory","com.sun.jndi.ldap.LdapCtxFactory"));
		String url = prefs.get("providerUrl","ldap://localhost:389");
		if (node != null)
			url = url + "/" + node;
		env.put(Context.PROVIDER_URL,url);
		String proto = prefs.get("securityProtocol",null);
		if(prefs.getBoolean("useSSL", false)) {
			if (proto != null)
				env.put(Context.SECURITY_PROTOCOL,proto);
			String factory = prefs.get("socketFactory", null);
			if(factory != null && factory.length() > 0) {
				env.put("java.naming.ldap.factory.socket", factory);
			} else if(prefs.valueForKey("ssl") != null) {
				env.put("java.naming.ldap.factory.socket", LdapSocketFactory.class.getName());
			}
		}
		return env;
	}
	
	public static String getUserDn (String cn) throws NamingException {
		String proxyDn = prefs.get("proxyUserDn",null);
		Hashtable env = initEnvironment(null);
		if (proxyDn != null) {
			String proxyPasswd = prefs.get("proxyPassword",null);
			env.put(Context.SECURITY_AUTHENTICATION, prefs.get("authentication","simple"));
			env.put(Context.SECURITY_PRINCIPAL,proxyDn);
			env.put(Context.SECURITY_CREDENTIALS,proxyPasswd);
		} else {
			env.put(Context.SECURITY_AUTHENTICATION, "none");
		}
//		try {
			// Create initial context
			DirContext ctx = null;
//		try {
			ctx = new InitialDirContext(env);
/*		} catch (javax.naming.CommunicationException exc) {
			if(!(exc.getCause() instanceof javax.net.ssl.SSLHandshakeException))
				throw exc;
		}*/
			SearchControls ctrls = new SearchControls(SearchControls.SUBTREE_SCOPE,1,1000,new String[] {},false,false);
			String usersNode = prefs.get("usersNode","");
			NamingEnumeration results = ctx.search(usersNode,"cn=" + cn, ctrls);
			if(usersNode != null && usersNode.length() > 1)
				usersNode = ", " + usersNode;
			if (results.hasMore()) {
				SearchResult res = (SearchResult)results.next();
				results.close();
				return usersNode + res.getName();
			} else {
				return null;
			}
/*		} catch (Exception ex) {
			return null;
		} */
	}
}
