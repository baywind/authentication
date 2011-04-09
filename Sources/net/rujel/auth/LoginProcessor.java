//  LoginProcessor.java

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

//import net.rujel.reusables.*;
//import net.rujel.core.*;
import net.rujel.reusables.SettingsReader;
import net.rujel.reusables.Various;

import com.apress.practicalwo.practicalutilities.WORequestAdditions;
import com.webobjects.foundation.*;
import com.webobjects.appserver.*;

import java.security.MessageDigest;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.Enumeration;

public class LoginProcessor {
	protected static Logger logger = Logger.getLogger("login");
	
	protected static final SettingsReader prefs = SettingsReader.settingsForPath("auth",true);
	protected static LoginHandler loginHandler = LoginHandler.Generator.generate();
	protected static BruteforceProtection bfp = new BruteforceProtection();
	static {
		logger.config("LoginHandler: " + loginHandler.getClass().getName());
	}
	
	public static WOComponent loginComponent(WOContext aContext, String message) {
//		WORedirect redirect;
		String pageName = prefs.get("loginPageName","LoginDialog");
		WOComponent loginPage = WOApplication.application().pageWithName(pageName,aContext);
		if(message != null) {
			try {
				loginPage.takeValueForKey(message,"message");
			} catch (NSKeyValueCoding.UnknownKeyException e) {

			}
		}
			return loginPage;
	}

	public static WOComponent loginComponent(WOContext aContext) {
		return loginComponent(aContext,null);
	}
	
	public static WOComponent enterLogin(WOContext ctx) {
		return enterLogin(ctx, prefs.get("welcomeMessage",null));
	}
	
	public static WOComponent enterLogin(WOContext ctx, String message) {
		if(prefs.getBoolean("useHTTPS",true) && !WORequestAdditions.isSecure(ctx.request()))
			return secureRedirect(null,ctx,Boolean.TRUE);
		
		WOComponent nextPage = loginComponent(ctx, message);
		return nextPage;
	}
	
	public static WORedirect secureRedirect(String action, WOContext ctx, Boolean secure) {
		WORequest req = ctx.request();
		String host = null;
		if(secure != null) {
		String customUrlNode = "customURL." + ((secure)?"secure":"insecure");
		SettingsReader urlsNode = prefs.subreaderForPath(customUrlNode,false);
		
		if(urlsNode != null) {
			Enumeration enu = urlsNode.keyEnumerator();
			if(enu.hasMoreElements()) {
				String sourceHost = WORequestAdditions.originatingIPAddress(req);
				int len = 0;
				if(sourceHost != null && sourceHost.length() >= 7) {
					String curr;
ipSelection:
					while (enu.hasMoreElements()) {
						curr = (String)enu.nextElement();//ips[i];
						if(sourceHost.equalsIgnoreCase(curr)) {
							host = urlsNode.get(curr,host);
							len = curr.length();
							break ipSelection;
						} else {
							int l = curr.length() - 1;
							if(l > len && curr.charAt(l) == '*' &&
									sourceHost.startsWith(curr.substring(0,l))) {
								host = urlsNode.get(curr,host);
								len = l;
							}
						}
					} //ipSelection
				} //has sourceHost
				if(len == 0) {
					host = urlsNode.get("*",host);
					host = urlsNode.get("default",host);
				}
			} //has list of IPs 
		} else { //custom URLs defined
			host = WORequestAdditions.hostName(req);
			if(host != null)
				host = ((secure)?"https://":"http://") + host;
		}
		}
		NSMutableDictionary formValues = req.formValues().mutableClone();
		formValues.removeObjectsForKeys(new NSArray(loginHandler.args()));
		formValues.removeObjectForKey(WOContext.SessionIDBindingKey);
		String uri;
		if (action==null) {
			uri = req.uri();
			if(ctx.hasSession() && !ctx.session().isTerminating() &&
					ctx.session().storesIDsInURLs() &&
							!uri.contains(WOContext.SessionIDBindingKey + '=')) {
				char amp = (uri.indexOf('?') > 0)?'&':'?';
				uri = uri + amp + WOContext.SessionIDBindingKey + '=' + ctx.session().sessionID();
			}
		} else {
			uri = ctx.directActionURLForActionNamed(action,formValues);
		}
		uri = Various.cleanURL(uri);
		String url = (host==null)?uri:host +  uri;
		WORedirect result = new WORedirect(ctx);
		result.setUrl(url);
		return result; 
	}
	
	public static UserPresentation processLogin(WORequest req) 
						throws LoginHandler.AuthenticationFailedException {
		String id = loginHandler.identityArg();
		if(id != null && prefs.getBoolean("bruteforcingProtect",true)) {
			bfp.checkAttempt(WORequestAdditions.originatingIPAddress(req),
					req.formValueForKey(id));
		}
		String[] args = loginHandler.args();
		Object[] values = new Object[args.length];
		for (int i = 0; i < args.length; i++) {
				values[i] = req.formValueForKey(args[i]);
		}
		return loginHandler.authenticate(values);
	}
	
	public static String treatAuthenticationException 
												(LoginHandler.AuthenticationFailedException ex) {
		String message = prefs.get("authFailedMessage","Authentication failed");
		switch (ex.getReason()) {
			case LoginHandler.ERROR:
				message = message + ": " + prefs.get("authErrorMessage","An error occured");
				break;
			case LoginHandler.IDENTITY:
				message = message + ": " + prefs.get("badIdentityMessage","User unknown");
				break;
			case LoginHandler.CREDENTIAL:
				message = message + ": " + prefs.get("badCredentialMessage","Invalid Credential");
				break;
			case LoginHandler.REFUSED:
				message = message + ": " + 
								prefs.get("loginRefusedMessage","Your login attempt was refused");
				break;
			default:
				break;
		}
		return message;
	}
	
	/**
	 * Analyses information in <code>ctx</code> to decide whether accept 
	 * login attempt or return some other page
	 * @param ctx - WOContext containing login information in request
	 * @return in case of successful login UserPresentation object,
	 * otherwise - WOComponent to show in response 
	 */
	public static Object validUserForLogin (WOContext ctx) {
		WORequest req = ctx.request();
		//WOComponent nextPage = null;
		String message = null;
		UserPresentation user = null;
		//String username = req.stringFormValueForKey(loginHandler.identityArg());
		try {
//			bfp.checkAttempt(WORequestAdditions.originatingIPAddress(req),
//					req.formValueForKey(loginHandler.identityArg()));
			user = processLogin(req);
			if (user == null && !prefs.getBoolean("allowNone",false)) {
				message = prefs.get("denyNoneMessage","User should be specified");
				logger.finer("Guest access refused");
				return loginComponent(ctx,message);
			}
		} catch (LoginHandler.AuthenticationFailedException ex) {
			message = treatAuthenticationException(ex);
			if(ex.getReason() == LoginHandler.ERROR)
				logger.log(Level.WARNING,message,ex);
			else
				logger.log(Level.FINE,message,ex.getUserId());
			Integer timeout = bfp.badAttempt(WORequestAdditions.originatingIPAddress(req),ex);
			WOComponent nextPage = loginComponent(ctx,message);
			try {
				nextPage.takeValueForKey(timeout,"timeout");
			} catch (NSKeyValueCoding.UnknownKeyException e) {
				
			}
			return nextPage;
		}
		
		/*
		if(message != null) {
			nextPage = loginComponent(ctx,message);
			//nextPage.takeValueForKey(message,"message");
		} else {*/
			bfp.success(WORequestAdditions.originatingIPAddress(req),user.toString());
			//WOApplication appl = WOApplication.application();
			//initialise session here
			AccessHandler ah = AccessHandler.generateForUser(user);//accessHandler(user);
			String actionName;
			//boolean retSecure = false;
			if (ah.canLogin()) {
				user.setAccessHandler(ah);
				logger.log(Level.FINER,"Login successful",user);
				return user;
/*				WOSession ses = ctx.session();//appl.createSessionForRequest(req);
				ses.takeValueForKey(user,"user");
				//ses.setStoresIDsInCookies(true);

				actionName = prefs.get("welcomeAction","default");
				retSecure = prefs.getBoolean("sessionSecure",false);*/
			} else {
				logger.finer("Login refused: " + user.shortName());
				actionName = prefs.get("refuseUrl",null);
				if(actionName != null) {
					WORedirect rdr = new WORedirect(ctx);
					if(!actionName.startsWith("http") && WORequestAdditions.isSecure(req)) {
						actionName = "http://" + WORequestAdditions.hostName(req) + actionName;
					}
					rdr.setUrl(actionName);
					return rdr;
					//nextPage = rdr;
				} else {
					actionName = prefs.get("refuseAction","refuse");
					return secureRedirect(actionName,ctx,null);				
				}
			}
		//}
		//return nextPage;
	}
	
	public static WOComponent loginAction (WOContext ctx, String welcomeAction) {
		//prefs.refresh();
		//loginHandler = LoginHandler.Generator.generate();
		WORequest req = ctx.request();
		/*if(req.method().equalsIgnoreCase("GET"))
			return enterLogin(ctx);
		else*/
			if(loginHandler.identityArg() != null &&
					req.formValueForKey(loginHandler.identityArg()) == null)
				return enterLogin(ctx);
		
		Object result = validUserForLogin(ctx);
		if(result instanceof WOComponent)
			return (WOComponent)result;
		
		WOSession ses = ctx.session();
		ses.takeValueForKey(result,"user");
		
		NSMutableArray formValueKeys = req.formValueKeys().mutableClone();
		formValueKeys.removeObjects(loginHandler.args());
		formValueKeys.removeObject(WOContext.SessionIDBindingKey);
		
		if (formValueKeys.count() > 0) {
			NSMutableDictionary queryDictionary = new NSMutableDictionary();
			java.util.Enumeration enumerator = formValueKeys.objectEnumerator();
			while (enumerator.hasMoreElements()) {
				String key = (String)enumerator.nextElement();
				queryDictionary.setObjectForKey(req.formValueForKey(key),key);
			}
			ses.setObjectForKey(queryDictionary.immutableClone(),"queryDictionary");
		}
		return welcomeRedirect(ctx, welcomeAction);
	}
	
	public static WORedirect welcomeRedirect(WOContext ctx, String welcomeAction) {
		Boolean retSecure = null;
		if(prefs.getBoolean("sessionSecure",false)) {
			if(!WORequestAdditions.isSecure(ctx.request()))
				retSecure = Boolean.TRUE;
		} else if(prefs.getBoolean("useHTTPS",true)) {
				retSecure = Boolean.FALSE;
		}
		return secureRedirect(welcomeAction,ctx,retSecure);
	}

	public static WOComponent loginAction (WOContext ctx) {
		return loginAction(ctx,prefs.get("welcomeAction","default"));
	}

	public static String getPasswordDigest(String password) {
		if(password == null) return null;
		String algorithm = SettingsReader.stringForKeyPath(
				"auth.passwordDigestAlgorithm", "MD5");
		if(algorithm == null || algorithm.length() == 0 || algorithm.equalsIgnoreCase("none"))
			return password;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] digest = md.digest(password.getBytes());
			StringBuilder buf = new StringBuilder(digest.length * 2);
			for (int i = 0; i < digest.length; i++) {
				buf.append(Character.forDigit((digest[i] & 0xf0) >>> 4, 16));
				buf.append(Character.forDigit(digest[i] & 0xf,16));
			}
			return buf.toString();
		} catch (Exception e) {
			throw new IllegalStateException("Error digesting password", e);
		}
	}
}