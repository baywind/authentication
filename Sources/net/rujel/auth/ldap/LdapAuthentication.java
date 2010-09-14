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

import com.sun.jndi.ldap.LdapName;

import java.util.Hashtable;
import java.util.logging.Logger;
import java.util.logging.Level;


public class LdapAuthentication implements LoginHandler {
	protected static Logger logger = Logger.getLogger("auth");
	public static final SettingsReader prefs = SettingsReader.settingsForPath("auth.ldap",true);
	protected static LdapName baseDN;
	
	public LdapAuthentication() {
		super();
	}
	
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
		Hashtable env = initEnvironment();
		
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
		return new LdapUser (ctx,userDn);
	}
	
	public static Hashtable initEnvironment() {
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, prefs.get("contextFactory","com.sun.jndi.ldap.LdapCtxFactory"));
		String url = prefs.get("providerUrl","ldap://localhost:389");
		if (baseDN != null && baseDN.size() > 0) {
			StringBuilder buf = new StringBuilder(url);
			if(buf.charAt(buf.length() -1) != '/')
				buf.append('/');
			buf.append(baseDN.toString());
			url = buf.toString();
		}
		env.put(Context.PROVIDER_URL,url);
		if(prefs.getBoolean("useSSL", false)) {
			String proto = prefs.get("securityProtocol",null);
			if (proto != null)
				env.put(Context.SECURITY_PROTOCOL,proto);
			String factory = prefs.get("socketFactory", null);
			if(factory != null && factory.length() > 0) {
				env.put("java.naming.ldap.factory.socket", factory);
			} else if(prefs.valueForKey("ssl") != null) {
				env.put("java.naming.ldap.factory.socket", LdapSocketFactory.class.getName());
			}
		}
//		For Active Directory:
//		env.put(Context.REFERRAL, "follow");
		return env;
	}
	
	public static LdapName baseDN() {
		return baseDN;
	}
	
	public static String getUserDn (String cn) throws NamingException {
		if(baseDN == null) {
			String dn = prefs.get("baseDN",null);
			if(dn != null)
				baseDN = new LdapName(dn);
		}
		Hashtable env = initEnvironment();
		String proxyDn = prefs.get("proxyUserDn",null);
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
			SearchControls ctrls = new SearchControls(SearchControls.SUBTREE_SCOPE,1,1000,new String[] {},false,false);
			String uid = prefs.get("uidAttribute","uid");
			NamingEnumeration results = null;
			if(baseDN == null) {
				Attributes attrs = ctx.getAttributes("",
						new String[] { "objectclass=*", "NamingContexts"});
				Attribute attr = attrs.get("NamingContexts");
				NamingEnumeration all = attr.getAll();
				while (all.hasMore()) {
					String node = all.nextElement().toString();
					try {
						results = ctx.search(node,uid + '=' + cn, ctrls);
						if(results.hasMore()) {
							baseDN = new LdapName(node);
							logger.log(Level.CONFIG,"Found base DN: " + node);
							break;
						}
					} catch (NamingException e) {
						logger.log(Level.CONFIG,"Skipping base DN: " + node,e.toString());
					}
				}
				all.close();
			} else {
				results = ctx.search("",uid + '=' + cn, ctrls);
			}
			if (results != null && results.hasMore()) {
				SearchResult res = (SearchResult)results.next();
				results.close();
				if(baseDN.size() > 0)
					return res.getName() + ',' + baseDN;
				else
					return res.getName();
			} else {
				return null;
			}
/*		} catch (Exception ex) {
			return null;
		} */
	}
}
