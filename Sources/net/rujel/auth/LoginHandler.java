//  LoginHandler.java

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
import java.lang.reflect.*;

public interface LoginHandler {
	public static final String  CLASSNAME= "loginHandlerClass";
	public static final int ERROR = 0;
	public static final int IDENTITY = 1;
	public static final int CREDENTIAL = 2;
	public static final int REFUSED = 3;
	
	public String[] args ();
	
	public String identityArg();
	
	public UserPresentation authenticate (Object [] args)
				throws AuthenticationFailedException, IllegalArgumentException;
	
	public static final LoginHandler DUMMY = new LoginHandler() {
		public String[] args () {
			return new String[0];
		}
		
		public String identityArg() {
			return null;
		}
		
		public UserPresentation authenticate (Object [] args)
					throws AuthenticationFailedException, IllegalArgumentException {
			return new UserPresentation.DummyUser(true);
		}
	};
	
	public static class AuthenticationFailedException extends Exception {
		protected int reason = -1;
		//
		protected String userId = null;
		
		public String getUserId () {
			return userId;
		}
		
		public void setUserId (String newUserId) {
			userId = newUserId;
		} //
		
		public AuthenticationFailedException(int reas) {
			super ();
			reason = reas;
		}
		
		public AuthenticationFailedException(int reas, String message) {
			super (message);
			reason = reas;
		}

		public AuthenticationFailedException(int reas, String message, Throwable cause) {
			super (message, cause);
			reason = reas;
		}
		
		public int getReason() {
			return reason;
		}
		
		public String getMessage() {
			StringBuilder buf = new StringBuilder();
			switch (reason) {
			case ERROR:
				buf.append(" <ERROR> ");
				break;
			case IDENTITY:
				buf.append(" <IDENTITY> ");
				break;
			case CREDENTIAL:
				buf.append(" <CREDENTIAL> ");
				break;
			case REFUSED:
				buf.append(" <REFUSED> ");
				break;

			default:
				buf.append(" <UNKNOWN> ");
				break;
			}
			buf.append(super.getMessage());
			if (getCause() != null)
				buf.append(" (").append(getCause().toString()).append(')');
			return buf.toString();
		}
	}
	
	public static class Generator {

		public static LoginHandler generate() {
			LoginHandler loginHandler = null;
			try {
				String lhClassName = net.rujel.reusables.SettingsReader.stringForKeyPath(
						"auth." + LoginHandler.CLASSNAME,null);
				if(lhClassName == null) return DUMMY;
				Class lhClass = Class.forName(lhClassName);
				Constructor lhConstuctor = lhClass.getConstructor();
				loginHandler = (LoginHandler)lhConstuctor.newInstance();
			} catch (Exception ex) {
				throw new RuntimeException("Could not instantiate login handler",ex);
			}
			return loginHandler;
		}
	}
}