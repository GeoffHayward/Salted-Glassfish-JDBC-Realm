package eu.geoffhayward.security;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class RolesSecurityStore {

    private Connection con;
    private final static Logger LOGGER = Logger.getLogger("org.geoffhayward.security");
    private final static String GET_USER_GROUPS = "SELECT groupname FROM groups g WHERE username = ?;";

    /**
     * Public constructor for use with Java EE App-servers or Clients which have
     * access to an InitialContext. In this case a javax.sql.DataSource is
     * looked up with the Context.
     *
     * @param dataSource
     */
    public RolesSecurityStore(String dataSource) {
        Context ctx = null;
        try {
            ctx = new InitialContext();
            DataSource ds = (javax.sql.DataSource) ctx.lookup(dataSource);
            con = ds.getConnection();
        } catch (NamingException | SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting connection!", e);
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException e) {
                    LOGGER.log(Level.SEVERE, "Error closing context!", e);
                }
            }
        }
    }

    

    /**
     * Get's the roles of a given user
     *
     * @param name User name
     * @return
     */
    public Enumeration getGroupsForUser(String name) {
        List<String> roles = new ArrayList<>();
        try {
            PreparedStatement pstm = con.prepareStatement(GET_USER_GROUPS);
            pstm.setString(1, name);
            ResultSet rs = pstm.executeQuery();
            while (rs.next()) {
                roles.add(rs.getString(1));
            }
        } catch (SQLException ex) {
            LOGGER.log(Level.SEVERE, "User not found!", ex);
        }
        return Collections.enumeration(roles);
    }

}
