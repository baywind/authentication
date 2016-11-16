//  BruteforceProtection.java

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

import com.webobjects.appserver.WORequest;
import com.webobjects.foundation.NSMutableDictionary;

import net.rujel.auth.SimpleBruteforceProtection.TimeoutTask;

import java.util.Timer;
import java.util.logging.Logger;
import java.util.logging.Level;
//import com.apple.cocoa.application.*;


abstract public class BruteforceProtection {
	protected static Logger logger = Logger.getLogger("auth");

	protected boolean bruteforcingProtect = net.rujel.reusables.SettingsReader.boolForKeyPath(
			"auth.bruteforcingProtect",true);
	protected String[] trustedProxies;
	
	@SuppressWarnings("rawtypes")
	protected NSMutableDictionary suspiciousUsers = 
			new NSMutableDictionary();		// Is used directly by Reset procedures
	
	@SuppressWarnings("rawtypes")
	protected NSMutableDictionary suspiciousHosts = 
			new NSMutableDictionary();		// Is used directly by Reset procedures
	
	public abstract int hostCounter(String host);	// Returns lock-down timer for user
	public abstract int userCounter(String user);	// Returns lock-down timer for host
	
	@SuppressWarnings("rawtypes")
	public abstract int raiseCounter(NSMutableDictionary dict, String key);	//Returns new counter
	
	public abstract void resetCounter(NSMutableDictionary dict,String key);
	
	
	public String hostID(WORequest req) {
		String hostIP = com.apress.practicalwo.practicalutilities.
										WORequestAdditions.originatingIPAddress(req);
		String forwarded = req.headerForKey("x-forwarded-for");
		if(hostIP == null)
			return null;
		String test = (forwarded == null)?hostIP:forwarded + '@' + hostIP;
		if(trustedProxies == null) {
			String list = net.rujel.reusables.SettingsReader.stringForKeyPath(
					"auth.trustedProxies", null);
			if(list == null) {
				trustedProxies = new String[0];
			} else {
				trustedProxies = list.split("\\s*[,;| ]\\s*");
			}
		}
		for (int i = 0; i < trustedProxies.length; i++) {
			if(test.equals(trustedProxies[i]))
				return null;
			if(hostIP.equals(trustedProxies[i])) {
				hostIP = test;
			}
		}
		return hostIP;		
	}

	public void checkAttempt(WORequest req,Object uid)
				throws LoginHandler.AuthenticationFailedException {
		if(bruteforcingProtect)
			checkAttempt(hostID(req), uid);
	}
	
	public abstract void checkAttempt(String host,Object uid) 
				throws LoginHandler.AuthenticationFailedException;
	
	public Integer badAttempt(WORequest req,LoginHandler.AuthenticationFailedException aex) {
		if(bruteforcingProtect) {
			return badAttempt(hostID(req), aex);
		} else {
			return new Integer(0);
		}
	}
	
	public abstract Integer badAttempt(String host,LoginHandler.AuthenticationFailedException aex);
		// Not sure what this returns and where is the result used

	public void success (WORequest req, String user) {
		success(hostID(req), user);
	}
	
	public abstract void success (String host, String user); 
	// Resets counters for people who were able to login
}
