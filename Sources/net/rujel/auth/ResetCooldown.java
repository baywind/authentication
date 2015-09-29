package net.rujel.auth;

import java.util.logging.Level;

import net.rujel.auth.AccessHandler.UnlistedModuleException;
import net.rujel.reusables.Counter;
import net.rujel.reusables.SettingsReader;
import net.rujel.reusables.Various;

import com.webobjects.appserver.WOActionResults;
import com.webobjects.appserver.WOApplication;
import com.webobjects.appserver.WOContext;
import com.webobjects.appserver.WOComponent;
import com.webobjects.appserver.WORequest;
import com.webobjects.appserver.WOSession;
import com.webobjects.foundation.NSArray;
import com.webobjects.foundation.NSDictionary;
import com.webobjects.foundation.NSMutableDictionary;

public class ResetCooldown extends WOComponent {
    public ResetCooldown(WOContext context) {
        super(context);
    }
    
    protected static NSMutableDictionary attempts = new NSMutableDictionary();
    public String message;
    public boolean authorized = false;
    public boolean inFrame = false;
    public String keyItem;
    
    public boolean loginRequired() {
    	if(!context().hasSession())
    		return true;
    	UserPresentation user = (UserPresentation)session().valueForKey("user");
    	try {
			if(user == null || user.accessLevel("Maintenance", null) == 0)
				return true;
		} catch (UnlistedModuleException e) {
			return true;
		}
    	return false;
    }
    
    public static WOComponent action (WOContext ctx) {
    	ResetCooldown result = (ResetCooldown)WOApplication.application().pageWithName(
    			"ResetCooldown",ctx);
		WORequest req = ctx.request();
		LoginHandler loginHandler = LoginProcessor.loginHandler;
		String id = loginHandler.identityArg();
		if(id == null) {
			result.message = "Oops!";
			return result;
		}
		id = req.stringFormValueForKey(id);
		if(id == null) {
			result.message = "Only root level user can login";
			return result;
		}
		Counter attempt = (Counter)attempts.valueForKey(id);
		int maxAttempts = SettingsReader.intForKeyPath("auth.resetLoginAttempts", 3);
		if(LoginProcessor.bfp.userCounter(id) < 0)
			maxAttempts = SettingsReader.intForKeyPath("auth.compromisedUserLoginAttempts", 1);
		else if(LoginProcessor.bfp.hostCounter(LoginProcessor.bfp.hostID(req)) < 0)
			maxAttempts = SettingsReader.intForKeyPath("auth.compromisedHostLoginAttempts", 2);
		if(attempt != null && attempt.intValue() >= maxAttempts) {
			result.message = " No more attempts allowed!";
			return result;
		}
		UserPresentation user = null;
		try {
			String[] args = loginHandler.args();
			Object[] values = new Object[args.length];
			for (int i = 0; i < args.length; i++) {
					values[i] = req.formValueForKey(args[i]);
			}
			user = loginHandler.authenticate(values);
			if(user == null) {
				result.message = "Unknown user";
				return result;
			}
		} catch (LoginHandler.AuthenticationFailedException ex) {
			result.message = LoginProcessor.treatAuthenticationException(ex);
			NSDictionary identity = Various.clientIdentity(req);
			if(ex.getReason() == LoginHandler.ERROR)
				LoginProcessor.logger.log(Level.WARNING,result.message,new Object[] {ex,identity});
			else
				LoginProcessor.logger.log(Level.FINE,result.message,new Object[] {
						identity,ex.getUserId()});
			if(ex.getReason() == LoginHandler.CREDENTIAL) {
				if(attempt == null) {
					attempt = new Counter(1);
					attempts.takeValueForKey(attempt, id);
				} else {
					attempt.raise();
				}
				if(attempt.intValue() >= maxAttempts)
					result.message += " No more attempts allowed!";
			}
		}
		try {
			AccessHandler ah = AccessHandler.generateForUser(user);//accessHandler(user);
			int level = 0;
			try {
				level = ah.accessLevel("Maintenance", null);
			} catch (UnlistedModuleException e) {
				if(ah instanceof PrefsAccessHandler) {
					try {
						level = PrefsAccessHandler.defaultLevel(user, "Maintenance", null);
					} catch (UnlistedModuleException e1) {}
				}
			}
			if(level == 0) {
				result.message = "Access not allowed";
				LoginProcessor.logger.log(Level.INFO,
						"Unauthorized user attempted to login into ResetCooldown",user);
				return result;
			}
			user.setAccessHandler(ah);
			LoginProcessor.logger.log(Level.FINER,"Login to cooldown reset successful",user);
			WOSession ses = ctx.session();
			ses.takeValueForKey(user,"user");
			result.authorized = true;

		} catch (Exception e) {
			result.message = "Oops! " + e;
		}    	
    	return result;
    }
    
    protected NSArray _suspiciousUsers;
    public NSArray suspiciousUsers() {
    	if(_suspiciousUsers == null) {
    		_suspiciousUsers = LoginProcessor.bfp.suspiciousUsers.allKeys();
    	}
    	return _suspiciousUsers;
    }
    
    protected NSArray _suspiciousHosts;
    public NSArray suspiciousHosts() {
    	if(_suspiciousHosts == null) {
    		_suspiciousHosts = LoginProcessor.bfp.suspiciousHosts.allKeys();
    	}
    	return _suspiciousHosts;
    }
    
    protected NSArray _attempts;
    public NSArray attempts() {
    	if(_attempts == null) {
    		_attempts = attempts.allKeys();
    	}
    	return _attempts;
    }
    
    public int userCounter() {
    	return LoginProcessor.bfp.userCounter(keyItem);
    }

    public int hostCounter() {
    	return LoginProcessor.bfp.hostCounter(keyItem);
    }

    public int attemptCounter() {
    	Counter attempt = (Counter)attempts.valueForKey(keyItem);
    	return attempt.intValue();
    }
    
    public boolean resetUser() {
    	return false;
    }
    public void setResetUser(boolean val) {
    	if(val && keyItem != null)
    		LoginProcessor.bfp.resetCounter(LoginProcessor.bfp.suspiciousUsers, keyItem);
    }
    
    public boolean resetHost() {
    	return false;
    }
    public void setResetHost(boolean val) {
    	if(val && keyItem != null)
    		LoginProcessor.bfp.resetCounter(LoginProcessor.bfp.suspiciousHosts, keyItem);
    }
    
    public boolean resetAttempt() {
    	return false;
    }
    public void setResetAttempt(boolean val) {
    	if(val && keyItem != null)
    		attempts.removeObjectForKey(keyItem);
    }
    
    public WOActionResults doReset() {
    	_suspiciousUsers = LoginProcessor.bfp.suspiciousUsers.allKeys();
    	_suspiciousHosts = LoginProcessor.bfp.suspiciousHosts.allKeys();
		_attempts = attempts.allKeys();
		return null;
    }
}