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

import com.apress.practicalwo.practicalutilities.WORequestAdditions;
import com.webobjects.foundation.*;
import com.webobjects.appserver.*;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.Enumeration;

public class LoginProcessor {
	protected static Logger logger = Logger.getLogger("login");
	
//	protected static Preferences prefs = Preferences.systemNodeForPackage(LoginProcessor.class);
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
		prefs.refresh();
		if(prefs.getBoolean("useHTTPS",true) && !WORequestAdditions.isSecure(ctx.request()))
			return secureRedirect(null,ctx,true);
		
		WOComponent nextPage = loginComponent(ctx, message);
/*		String welcomeMessage = prefs.get("welcomeMessage",null);
		if (message != null)
			try {
			nextPage.takeValueForKey(message,"message");
			} catch (NSKeyValueCoding.UnknownKeyException e) {
				
			}*/
		return nextPage;
	}
	/*	
	public static WOComponent loginComponent(WOContext aContext, LoginHandler.AuthenticationFailedException ex) {
		return loginComponent(aContext,treatAuthenticationException(ex));
	}*/
	
	public static WORedirect secureRedirect(String action, WOContext ctx, boolean secure) {
		WORequest req = ctx.request();
		String host = null;
		String customUrlNode = "customURL." + ((secure)?"secure":"insecure");
		SettingsReader urlsNode = prefs.subreaderForPath(customUrlNode,false);
		
		//if(prefs.nodeExists(customUrlNode)) {
		if(urlsNode != null) {
			//Preferences urlsNode = prefs.node(customUrlNode);
			//String[] ips = urlsNode.keys();
			Enumeration enu = urlsNode.keyEnumerator();
			//if(ips != null && ips.length > 0) {
			if(enu.hasMoreElements()) {
				String sourceHost = WORequestAdditions.originatingIPAddress(req);
				int len = 0;
				if(sourceHost != null && sourceHost.length() >= 7) {
					String curr;
					//for (int i = 0; i < ips.length; i++) 
ipSelection:
					while (enu.hasMoreElements()) {
						curr = (String)enu.nextElement();//ips[i];
						if(sourceHost.equalsIgnoreCase(curr)) {
							host = urlsNode.get(curr,host);
							len = curr.length();
							break ipSelection;
						} else {
							int l = curr.length() - 1;
							if(l > len && curr.charAt(l) == '*' && sourceHost.startsWith(curr.substring(0,l))) {
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
		
		NSMutableDictionary formValues = req.formValues().mutableClone();
		formValues.removeObjectsForKeys(new NSArray(loginHandler.args()));
		String uri;
		if (action==null) {
			uri = req.uri();
			if(ctx.hasSession() && ctx.session().storesIDsInURLs() && !uri.contains("wosid=")) { //req.stringFormValueForKey("wosid") == null
				char amp = (uri.indexOf('?') > 0)?'&':'?';
				uri = uri + amp + "wosid=" + ctx.session().sessionID();
			}
		} else {
			uri = ctx.directActionURLForActionNamed(action,formValues);
		}
		if(host!= null && uri.startsWith("http:")) {
			int idx = uri.indexOf('/', 8);
			uri = uri.substring(idx);
		}
		String url = (host==null)?uri:host +  uri;
		/*
		 boolean same = (action == null);
		 String requestHandlerKey = (same)?req.requestHandlerKey():"wa";
		 String aRequestHandlerPath = (same)?req.requestHandlerPath():action;
		 String aQueryString = (same)?req.queryString():null;
		 if (ctx.hasSession() && ctx.session().storesIDsInURLs() && (aQueryString == null || aQueryString.length() < 1)) {
			 aQueryString = WORequest.SessionIDKey + "=" + ctx.session().sessionID();
		 }
		 String url = ctx.completeURLWithRequestHandlerKey(requestHandlerKey,aRequestHandlerPath,aQueryString,secure,0);
		 */
		WORedirect result = new WORedirect(ctx);
		result.setUrl(url);
		return result; 
		
		}
	/*
	 protected static CoreApplication appl() {
		 return ((CoreApplication)WOApplication.application());
	 } */
	
	public static UserPresentation processLogin(WORequest req) throws LoginHandler.AuthenticationFailedException {
		String[] args = loginHandler.args();
		Object[] values = new Object[args.length];
		for (int i = 0; i < args.length; i++) {
			/*			if(agrs[i].equals(LoginHandler.STREAM && req.isMultipartFormData()) {
			values[i] = req.contentInputStream();
			} else { */
				values[i] = req.formValueForKey(args[i]);
//			}
		}
/*
		if(prefs.getBoolean("bruteforcingProtect",true)) {
			String sourceHost = WORequestAdditions.originatingIPAddress(req);
			Number counter = (Number)suspiciousHosts.objectForKey(sourceHost);
			int hostCounter = (counter==null)?0:counter.intValue();
			
			String userId = values[0].toString();
			counter = (Number)suspiciousUsers.objectForKey(userId);
			int userCounter = (counter==null)?0:counter.intValue();
			
			int min = StrictMath.min(hostCounter,userCounter);
			if(min < 0) {
				Integer result = new Integer (min * 2);
				suspiciousUsers.setObjectForKey(result,"");
			}
		}*/
		String id = loginHandler.identityArg();
		if(id != null && prefs.getBoolean("bruteforcingProtect",false)) {
			bfp.checkAttempt(WORequestAdditions.originatingIPAddress(req),req.formValueForKey(id));
		}
		
		return loginHandler.authenticate(values);
	}
	
	public static String treatAuthenticationException (LoginHandler.AuthenticationFailedException ex) {
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
				message = message + ": " + prefs.get("loginRefusedMessage","Your login attempt was refused");
				break;
			default:
				break;
		}
		return message;
	}
	
/*	public static boolean userCanLogin(UserPresentation user) {
		AccessHandler ah = AccessHandler.Generator.generateForUser(user);
		if(ah.canLogin()) {
			user.setAccessHandler(ah);
			return true;
		} else {
			return false;
		}
	} */

	//public static WOComponent processLogin (WOContext ctx) {
	public static Object validUserForLogin (WOContext ctx) {
		WORequest req = ctx.request();
		//WOComponent nextPage = null;
		String message = null;
		UserPresentation user = null;
		//String username = req.stringFormValueForKey(loginHandler.identityArg());
		try {
			bfp.checkAttempt(WORequestAdditions.originatingIPAddress(req),req.formValueForKey(loginHandler.identityArg()));
			user = processLogin(req);
			if (user == null && !prefs.getBoolean("allowNone",false)) {
				message = prefs.get("denyNoneMessage","User should be specified");
				logger.finer("Guest access refused");
				return loginComponent(ctx,message);
			}
		} catch (LoginHandler.AuthenticationFailedException ex) {
			message = treatAuthenticationException(ex);
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
			AccessHandler ah = AccessHandler.Generator.generateForUser(user);//accessHandler(user);
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
					return secureRedirect(actionName,ctx,false);				
				}
			}
		//}
		//return nextPage;
	}
	
	public static WOComponent loginAction (WOContext ctx, String welcomeAction) {
		//prefs.refresh();
		loginHandler = LoginHandler.Generator.generate();
		WORequest req = ctx.request();
		/*if(req.method().equalsIgnoreCase("GET"))
			return enterLogin(ctx);
		else*/
			if(loginHandler.identityArg() != null && req.formValueForKey(loginHandler.identityArg()) == null)
				return enterLogin(ctx);
		
		Object result = validUserForLogin(ctx);
		if(result instanceof WOComponent)
			return (WOComponent)result;
		
		WOSession ses = ctx.session();
		ses.takeValueForKey(result,"user");
		
		NSMutableArray formValueKeys = req.formValueKeys().mutableClone();
		formValueKeys.removeObjects(loginHandler.args());
		
		if (formValueKeys.count() > 0) {
			NSMutableDictionary queryDictionary = new NSMutableDictionary();
			java.util.Enumeration enumerator = formValueKeys.objectEnumerator();
			while (enumerator.hasMoreElements()) {
				String key = (String)enumerator.nextElement();
				queryDictionary.setObjectForKey(req.formValueForKey(key),key);
			}
			ses.setObjectForKey(queryDictionary.immutableClone(),"queryDictionary");
		}
		
				
		//String actionName = prefs.get("welcomeAction","default");
		boolean retSecure = prefs.getBoolean("sessionSecure",false);
		
		return secureRedirect(welcomeAction,ctx,retSecure);
	}

	public static WOComponent loginAction (WOContext ctx) {
		return loginAction(ctx,prefs.get("welcomeAction","default"));
	}
}