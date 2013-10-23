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
import java.util.Timer;
import java.util.logging.Logger;
import java.util.logging.Level;
//import com.apple.cocoa.application.*;


public class BruteforceProtection {
	protected static Logger logger = Logger.getLogger("auth");
	protected Timer timer = new Timer(true);
	
	protected boolean bruteforcingProtect = net.rujel.reusables.SettingsReader.boolForKeyPath(
			"auth.bruteforcingProtect",true);
	protected String[] trustedProxies;
	
	protected NSMutableDictionary suspiciousUsers = new NSMutableDictionary();
	protected NSMutableDictionary suspiciousHosts = new NSMutableDictionary();
	
	public int hostCounter(String host) {
		Object counter = suspiciousHosts.objectForKey(host);
		if(counter instanceof TimeoutTask) {
			return -((TimeoutTask)counter).getCount();
		} else {
			return (counter==null)?0:((Integer)counter).intValue();
		}
	}
	
	
	public int userCounter(String user) {
		Object counter = suspiciousUsers.objectForKey(user);
		if(counter instanceof TimeoutTask) {
			return -((TimeoutTask)counter).getCount();
		} else {
			return (counter==null)?0:((Integer)counter).intValue();
		}
	}
	
	public int raiseCounter(NSMutableDictionary dict,String key) {
		if(key == null) return 0;
		Object counter = dict.objectForKey(key);
		int result;
		if(counter instanceof TimeoutTask) {
			result = -((TimeoutTask)counter).recycle().getCount();
		} else {
			result = (counter==null)?1:((Integer)counter).intValue() + 1;
			TimeoutTask task = new TimeoutTask(dict,key,result);
			dict.setObjectForKey(task, key);
		}
		return result;
	}
	
	public void resetCounter(NSMutableDictionary dict,String key) {
		Object counter = dict.objectForKey(key);
		if(counter != null) {
			if(counter instanceof TimeoutTask) {
				((TimeoutTask)counter).cancel();
			} else {
				dict.removeObjectForKey(key);
			}
		}
	}
	
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

	//public void checkHost(String host) throws LoginHandler.AuthenticationFailedException {
	public void checkAttempt(WORequest req,Object uid)
				throws LoginHandler.AuthenticationFailedException {
		checkAttempt(hostID(req), uid);
	}
	
	public void checkAttempt(String host,Object uid) 
				throws LoginHandler.AuthenticationFailedException {
		if(bruteforcingProtect) {
			if(uid != null) {
				Object counter = suspiciousUsers.objectForKey(uid);
				if(counter instanceof TimeoutTask) {
					raiseBoth(host, uid.toString());
					logger.log(Level.WARNING,"Bruteforcing attempt from user: " + uid +
							" host: " + host);
					LoginHandler.AuthenticationFailedException ex =
						new LoginHandler.AuthenticationFailedException(
								LoginHandler.REFUSED,"Too many login attempts for user");
					ex.setUserId(uid.toString());
					throw ex;
				}
			} else {
				Object counter = suspiciousHosts.objectForKey(host);
				if(counter instanceof TimeoutTask) {
					((TimeoutTask)counter).recycle();
					logger.warning("Bruteforcing attempt from host: " + host);
					throw new LoginHandler.AuthenticationFailedException(LoginHandler.REFUSED);
				}
			}
		}
	}
	
	public Integer badAttempt(WORequest req,LoginHandler.AuthenticationFailedException aex) {
		return badAttempt(hostID(req), aex);
	}
	
	public Integer badAttempt(String host,LoginHandler.AuthenticationFailedException aex) {
		int result = 0;
		if(bruteforcingProtect) {
			if(aex.getReason() == LoginHandler.IDENTITY) {
				int count = raiseCounter(suspiciousHosts,host);
				result = StrictMath.abs(count);
			}
			if(aex.getReason() == LoginHandler.CREDENTIAL) {
				String user = aex.getUserId();
				result = raiseBoth(host, user);
			}
			if(aex.getReason() == LoginHandler.REFUSED) {
				if(host != null)
					result = new Integer(StrictMath.abs(hostCounter(host)));
				else
					result = new Integer(StrictMath.abs(userCounter(aex.getUserId())));
			}
		}
		return new Integer(result);
	}


	public int raiseBoth(String host, String user) {
		int byHost = StrictMath.abs(raiseCounter(suspiciousHosts,host));
		int byUser = StrictMath.abs(raiseCounter(suspiciousUsers,user));
		int result = StrictMath.max(byHost,byUser);
		if(host != null) {
			if(byUser < result) {
				resetCounter(suspiciousUsers,user);
				new TimeoutTask(suspiciousUsers,user,result);
			} else if(byHost < result) {
				resetCounter(suspiciousHosts,host);
				new TimeoutTask(suspiciousHosts,host,result);
			}
		}
		return result;
	}
	
	public void success (WORequest req, String user) {
		success(hostID(req), user);
	}
	
	public void success (String host, String user) {
		if(bruteforcingProtect) {
			Object hm = suspiciousHosts.objectForKey(host);
			if(hm instanceof Integer) {
				resetCounter(suspiciousHosts,host);
			} else if (hm instanceof TimeoutTask) {
				logger.log(Level.INFO,"Login succeded on first attempt for user \"" + user +
						"\" while the host " + host + " was still on quaranteen for " +
						((TimeoutTask)hm).getCount());
				resetCounter(suspiciousUsers,user);
				return;
			}
			Object um = suspiciousUsers.objectForKey(user);
			if(hm != null || um != null) {
				if(!(hm == null || (hm instanceof Number && ((Number)hm).intValue() <= 3)) ||
				   !(um == null || (um instanceof Number && ((Number)um).intValue() <= 3)))
				logger.logp(Level.INFO,"BruteforceProtection","success",
						"Login succeded after several attempts- user: " + um +"; host: " + hm);
				resetCounter(suspiciousUsers,user);
			}
		}
	}
	
		protected class TimeoutTask extends java.util.TimerTask {
			private NSMutableDictionary inDict;
			private String key;
			private int count;
			
			public TimeoutTask(NSMutableDictionary dict, String dictKey, int timeout) {
				super();
				inDict = dict;
				key = dictKey;
				if(key == null)
					key = "null";
				count = timeout;
				timer.schedule(this,(long)timeout*1000);
				inDict.setObjectForKey(this,key);
			}
			
			public void run() {
				inDict.setObjectForKey(new Integer(count),key);
				cancel();
			}
			
			public TimeoutTask recycle() {
				int nextCount = (count < Integer.MAX_VALUE / 2)? count*2 : Integer.MAX_VALUE;
				TimeoutTask newTask = new TimeoutTask(inDict,key,nextCount);
				//timer.shedule(newTask,count*2000);
				//inDict.setObjectForKey(newTask,key);
				cancel();
				return newTask;
			}
			
			public int getCount() {
				return count;
			}
			
			public String toString() {
				return "timeout -" + count;
			}
		}
}
