package org.geoffhayward.security;

import com.sun.appserv.security.AppservPasswordLoginModule;
import java.util.ArrayList;
import java.util.List;
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
        
        
        List<String> groups = new ArrayList<>();
        
        try {
            groups.addAll(realm.authenticate(_username, String.valueOf(_passwd)));
        } catch (Exception ex) {
            Logger.getLogger(LoginModule.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        commitUserAuthentication(groups.toArray(new String[groups.size()]));
        
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}