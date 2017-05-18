package eu.geoffhayward.security;

import com.sun.appserv.security.AppservPasswordLoginModule;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;
import net.eisele.security.glassfishrealm.UserRealm;

/**
 *
 * @author Geoff Hayward (www.geoffhayward.eu)
 */
public class LoginModule extends AppservPasswordLoginModule {

    @Override
    protected void authenticateUser() throws LoginException {
        
       final UserRealm realm = (UserRealm) _currentRealm;
        
       String[] groups = null;;
        
        try {
            groups = realm.authenticate(_username, String.valueOf(_passwd));
        } catch (Exception ex) {
            Logger.getLogger(LoginModule.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        commitUserAuthentication(groups);
    }
    
}
