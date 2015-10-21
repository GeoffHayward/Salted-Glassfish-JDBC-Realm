package net.eisele.security.glassfishrealm;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import net.eisele.security.util.Password;
import net.eisele.security.util.SecurityStore;
import org.geoffhayward.security.RolesSecurityStore;

/**
 * High Security UserRealm for GlassFish Server. Implementing password salting.
 *
 * @author eiselem
 */
public class UserRealm extends AppservRealm {

    private String jaasCtxName;
    private String dataSource;

    /**
     * Init realm from properties
     *
     * @param props
     * @throws BadRealmException
     * @throws NoSuchRealmException
     */
    @Override
    protected void init(Properties props) throws BadRealmException, NoSuchRealmException {
        _logger.fine("init()");
        jaasCtxName = props.getProperty("jaas-context", "userRealm");
        dataSource = props.getProperty("dataSource", "jdbc/userdb");
    }

    /**
     * {@inheritDoc }
     *
     * @return
     */
    @Override
    public String getJAASContext() {
        return jaasCtxName;
    }

    /**
     * {@inheritDoc }
     *
     * @return
     */
    @Override
    public String getAuthType() {
        return "High Security UserRealm";
    }

    /**
     * Authenticates a user against GlassFish
     *
     * @param name The User ID
     * @param givenPwd The Password to check
     * @return String[] of the groups a user belongs to.
     * @throws Exception
     */
    public String[] authenticate(String name, String givenPwd) throws Exception {
        SecurityStore store = new SecurityStore(dataSource);
        // attempting to read the users-salt
        String salt = store.getSaltForUser(name);

        // Defaulting to a failed login by setting null
        if (salt != null) {
            Password pwd = new Password();
            // get the byte[] from the salt
            byte[] saltBytes = pwd.bytesFrombase64(salt);
            // hash password and salt
            byte[] passwordBytes = pwd.hashWithSalt(givenPwd, saltBytes);
            // Base64 encode to String
            String password = pwd.base64FromBytes(passwordBytes);
            _logger.log(Level.FINE, "PWD Generated {0}", password);
            // validate password with the db
            if (store.validateUser(name, password)) {
                List<String> results = new ArrayList<>();
                Enumeration<String> roles = getGroupNames(name);
                while (roles.hasMoreElements()) {
                    results.add((String) roles.nextElement());
                }
                return results.toArray(new String[results.size()]);
            }
        }
        return null;
    }

    /**
     *
     * @param username
     * @return
     */
    @Override
    public Enumeration getGroupNames(String username) {
        RolesSecurityStore store = new RolesSecurityStore(dataSource);
        return store.getGroupsForUser(username);
    }
}
