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

import com.webobjects.foundation.NSMutableDictionary;
import java.util.Timer;
import java.util.logging.Logger;
import java.util.logging.Level;
//import com.apple.cocoa.application.*;


public class BruteforceProtection {
	protected static Logger logger = Logger.getLogger("auth");
	protected Timer timer = new Timer(true);
	
	protected boolean bruteforcingProtect = net.rujel.reusables.SettingsReader.boolForKeyPath("auth.bruteforcingProtect",true);
	
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
			result = -2*((TimeoutTask)counter).getCount();
			((TimeoutTask)counter).recycle();
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

	//public void checkHost(String host) throws LoginHandler.AuthenticationFailedException {
	public void checkAttempt(String host,Object uid) 
				throws LoginHandler.AuthenticationFailedException {
		if(bruteforcingProtect) {
			Object counter = suspiciousHosts.objectForKey(host);
			if(counter instanceof TimeoutTask) {
				((TimeoutTask)counter).recycle();
				logger.warning("Bruteforcing attempt from host: " + host +
						" user: " + uid);
				throw new LoginHandler.AuthenticationFailedException(LoginHandler.REFUSED);
			}
			if(uid != null) {
				counter = suspiciousUsers.objectForKey(uid);
				if(counter instanceof TimeoutTask) {
					int result = ((TimeoutTask)counter).getCount();
					if(result > 10) {
						((TimeoutTask)counter).recycle();
						counter = new TimeoutTask(suspiciousHosts,host,result*2);
						logger.log(Level.WARNING,"Bruteforcing attempt from user. host: ",uid);
						throw new LoginHandler.AuthenticationFailedException(LoginHandler.REFUSED,"Too many login attempts for user");
					}
				}
			}
		}
	}
	
	public Integer badAttempt(String host,LoginHandler.AuthenticationFailedException aex) {
		Integer result = new Integer(0);
		if(bruteforcingProtect) {
			if(aex.getReason() == LoginHandler.IDENTITY) {
				int count = raiseCounter(suspiciousHosts,host);
				result = new Integer(StrictMath.abs(count));
			}
			if(aex.getReason() == LoginHandler.CREDENTIAL) {
				int byHost = raiseCounter(suspiciousHosts,host);
				String user = aex.getUserId();
				int byUser = raiseCounter(suspiciousUsers,user);
				if (byUser < 0 && host != null && StrictMath.abs(byHost) < StrictMath.abs(byUser)) {
					resetCounter(suspiciousHosts,host);
					new TimeoutTask(suspiciousHosts,host,-byUser);
				}
				result = new Integer(StrictMath.max(StrictMath.abs(byHost),StrictMath.abs(byUser)));
			}
			if(aex.getReason() == LoginHandler.REFUSED) {
				result = new Integer(StrictMath.abs(hostCounter(host)));
			}
		}
		return result;
	}
	
	public void success (String host, String user) {
		if(bruteforcingProtect) {
			Object hm = suspiciousHosts.objectForKey(host);
			Object um = suspiciousUsers.objectForKey(user);
			if(hm != null || um != null) {
				if(!(hm == null || (hm instanceof Number && ((Number)hm).intValue() <= 3)) ||
				   !(um == null || (um instanceof Number && ((Number)um).intValue() <= 3)))
				logger.logp(Level.INFO,"BruteforceProtection","success","Login succeded after several attempts- user: " + um +"; host: " + hm);
				resetCounter(suspiciousUsers,user);
				resetCounter(suspiciousHosts,host);
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
				TimeoutTask newTask = new TimeoutTask(inDict,key,count*2);
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
