/*
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.auth;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;
import java.sql.*;
import java.util.*;
import java.util.Date;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventDispatcher;
import org.jivesoftware.util.PropertyEventListener;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.SaslException;
import javax.xml.bind.DatatypeConverter;

/**
 * The JDBC auth provider allows you to authenticate users against any database
 * that you can connect to with JDBC. It can be used along with the
 * {@link HybridAuthProvider hybrid} auth provider, so that you can also have
 * XMPP-only users that won't pollute your external data.<p>
 *
 * To enable this provider, set the following in the system properties:
 * <ul>
 * <li><tt>provider.auth.className = org.jivesoftware.openfire.auth.JDBCAuthProvider</tt></li>
 * </ul>
 *
 * You'll also need to set your JDBC driver, connection string, and SQL statements:
 *
 * <ul>
 * <li><tt>jdbcProvider.driver = com.mysql.jdbc.Driver</tt></li>
 * <li><tt>jdbcProvider.connectionString = jdbc:mysql://localhost/dbname?user=username&amp;password=secret</tt></li>
 * <li><tt>jdbcAuthProvider.passwordSQL = SELECT password FROM user_account WHERE username=?</tt></li>
 * <li><tt>jdbcAuthProvider.passwordType = plain</tt></li>
 * <li><tt>jdbcAuthProvider.allowUpdate = true</tt></li>
 * <li><tt>jdbcAuthProvider.setPasswordSQL = UPDATE user_account SET password=? WHERE username=?</tt></li>
 * <li><tt>jdbcAuthProvider.bcrypt.cost = 12</tt></li>
 * </ul>
 * 
 * <p>jdbcAuthProvider.passwordType can accept a comma separated string of password types.  This can be useful in 
 * situations where legacy (ex/md5) password hashes were stored and then "upgraded" to a stronger hash algorithm.
 * Hashes are executed left to right.</p>
 * <p>Example Setting: "md5,sha1"<br>  
 * Usage: password -&gt;<br>
 * (md5)&nbsp;286755fad04869ca523320acce0dc6a4&nbsp;-&gt;<br>
 * (sha1)&nbsp;0524b1fc84d315b08db890413e65260040b08caa&nbsp;-&gt;</p>
 * 
 * <p>Bcrypt is supported as a passwordType; however, when chaining password types it MUST be the last type given. (bcrypt hashes are different 
 * every time they are generated)</p>
 * <p>Optional bcrypt configuration:</p>
 * <ul>
 * <li><b>jdbcAuthProvider.bcrypt.cost</b>: The BCrypt cost.  Default: BCrypt.GENSALT_DEFAULT_LOG2_ROUNDS  (currently: 10)</li>
 * </ul>
 *
 * In order to use the configured JDBC connection provider do not use a JDBC
 * connection string, set the following property
 *
 * <ul>
 * <li><tt>jdbcAuthProvider.useConnectionProvider = true</tt></li>
 * </ul>
 *
 * The passwordType setting tells Openfire how the password is stored. Setting the value
 * is optional (when not set, it defaults to "plain"). The valid values are:<ul>
 *      <li>{@link PasswordType#plain plain}
 *      <li>{@link PasswordType#md5 md5}
 *      <li>{@link PasswordType#sha1 sha1}
 *      <li>{@link PasswordType#sha256 sha256}
 *      <li>{@link PasswordType#sha512 sha512}
 *      <li>{@link PasswordType#bcrypt bcrypt}
 *      <li>{@link PasswordType#nt nt}
 *  </ul>
 *
 * @author David Snopek
 */
public class JDBCAuthProvider implements AuthProvider, PropertyEventListener {

    private static final Logger Log = LoggerFactory.getLogger(JDBCAuthProvider.class);
    private static final int DEFAULT_BCRYPT_COST = 10; // Current (2015) value provided by Mindrot's BCrypt.GENSALT_DEFAULT_LOG2_ROUNDS value

    private String connectionString;

    private String passwordSQL;
    private String setPasswordSQL;
    private List<PasswordType> passwordTypes;
    private boolean allowUpdate;
    private boolean useConnectionProvider;
    private int bcryptCost;
    private static final String TEST_PASSWORD =
            "SELECT `im_user_name`,im_variable,iterations,salt,stored_key,server_key,modify_time,salt_time FROM im_user_info WHERE `im_user_name`= ? ";
    private static final String UPDATE_PASSWORD =
            "UPDATE im_user_info SET  stored_key=?, server_key=?, salt=?, iterations=?,salt_time=now() WHERE im_user_name=?";

    private static final SecureRandom random = new SecureRandom();

    /**
     * Constructs a new JDBC authentication provider.
     */
    public JDBCAuthProvider() {
        // Convert XML based provider setup to Database based
        JiveGlobals.migrateProperty("jdbcProvider.driver");
        JiveGlobals.migrateProperty("jdbcProvider.connectionString");
        JiveGlobals.migrateProperty("jdbcAuthProvider.passwordSQL");
        JiveGlobals.migrateProperty("jdbcAuthProvider.passwordType");
        JiveGlobals.migrateProperty("jdbcAuthProvider.setPasswordSQL");
        JiveGlobals.migrateProperty("jdbcAuthProvider.allowUpdate");
        JiveGlobals.migrateProperty("jdbcAuthProvider.bcrypt.cost");
        JiveGlobals.migrateProperty("jdbcAuthProvider.useConnectionProvider");
        JiveGlobals.migrateProperty("jdbcAuthProvider.acceptPreHashedPassword");
        
        useConnectionProvider = JiveGlobals.getBooleanProperty("jdbcAuthProvider.useConnectionProvider");
        
        if (!useConnectionProvider) {
            // Load the JDBC driver and connection string.
            String jdbcDriver = JiveGlobals.getProperty("jdbcProvider.driver");
            try {
               Class.forName(jdbcDriver).newInstance();
            }
            catch (Exception e) {
                Log.error("Unable to load JDBC driver: " + jdbcDriver, e);
                return;
            }
            connectionString = JiveGlobals.getProperty("jdbcProvider.connectionString");
        }

        // Load SQL statements.
        passwordSQL = JiveGlobals.getProperty("jdbcAuthProvider.passwordSQL");
        setPasswordSQL = JiveGlobals.getProperty("jdbcAuthProvider.setPasswordSQL");

        allowUpdate = JiveGlobals.getBooleanProperty("jdbcAuthProvider.allowUpdate",false);

        setPasswordTypes(JiveGlobals.getProperty("jdbcAuthProvider.passwordType", "plain"));
        bcryptCost = JiveGlobals.getIntProperty("jdbcAuthProvider.bcrypt.cost", -1);
        PropertyEventDispatcher.addListener(this);
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    private void setPasswordTypes(String passwordTypeProperty){
        Collection<String> passwordTypeStringList = StringUtils.stringToCollection(passwordTypeProperty);
        List<PasswordType> passwordTypeList = new ArrayList<>(passwordTypeStringList.size());
        Iterator<String> it = passwordTypeStringList.iterator();
        while(it.hasNext()){
            try {
                PasswordType type = PasswordType.valueOf(it.next().toLowerCase());
                passwordTypeList.add(type);
                if(type == PasswordType.bcrypt){
                    // Do not support chained hashes beyond bcrypt
                    if(it.hasNext()){
                        Log.warn("The jdbcAuthProvider.passwordType setting in invalid.  Bcrypt must be the final hashType if a series is given.  Ignoring all hash types beyond bcrypt: {}", passwordTypeProperty);
                    }
                    break;
                }
            }
            catch (IllegalArgumentException iae) { }
        }
        if(passwordTypeList.isEmpty()){
            Log.warn("The jdbcAuthProvider.passwordType setting is not set or contains invalid values.  Setting the type to 'plain'");
            passwordTypeList.add(PasswordType.plain);
        }
        passwordTypes = passwordTypeList;
    }

    @Override
    public void authenticate(String username, String password) throws UnauthorizedException {
        if (username == null || password == null) {
            throw new UnauthorizedException();
        }
        username = username.trim().toLowerCase();
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain. Return authentication failed.
                throw new UnauthorizedException();
            }
        }
        String userPassword;
        try {
            userPassword = getPasswordValue(username);
        }
        catch (UserNotFoundException unfe) {
            throw new UnauthorizedException();
        }
        
        if (comparePasswords(password, userPassword)) {
            // Got this far, so the user must be authorized.
            createUser(username);
        } else {
            throw new UnauthorizedException();
        }
    }
    
    // @VisibleForTesting
    protected boolean comparePasswords(String plainText, String hashed) {
        int lastIndex = passwordTypes.size() - 1;
        if (passwordTypes.get(lastIndex) == PasswordType.bcrypt) {
            for (int i = 0; i < lastIndex; i++) {
                plainText = hashPassword(plainText, passwordTypes.get(i));
            }
            return OpenBSDBCrypt.checkPassword(hashed, plainText.toCharArray());
        }

        return hashPassword(plainText).equals(hashed);
    }

    private String hashPassword(String password) {
        for (PasswordType type : passwordTypes) {
            password = hashPassword(password, type);
        }
        return password;
    }

    // @VisibleForTesting
    protected String hashPassword(String password, PasswordType type) {
        switch (type) {
            case md5:
                return StringUtils.hash(password, "MD5");
            case sha1:
                return StringUtils.hash(password, "SHA-1");
            case sha256:
                return StringUtils.hash(password, "SHA-256");
            case sha512:
                return StringUtils.hash(password, "SHA-512");
            case bcrypt:
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                int cost = (bcryptCost < 4 || bcryptCost > 31) ? DEFAULT_BCRYPT_COST : bcryptCost;
                return OpenBSDBCrypt.generate(password.toCharArray(), salt, cost);
            case nt:
                byte[] digestBytes;
                byte[] utf16leBytes = null;
                try {
                  MessageDigest md = MessageDigest.getInstance("MD4");
                  utf16leBytes = password.getBytes("UTF-16LE");
                  digestBytes = md.digest(utf16leBytes);
                  return new String(new String(Hex.encode(digestBytes)));
                }
                catch (Exception e) {
                  return null;
                }
            case plain:
            default:
                return password;
        }
    }

    @Override
    public String getPassword(String username) throws UserNotFoundException,
            UnsupportedOperationException
    {

        if (!supportsPasswordRetrieval()) {
            throw new UnsupportedOperationException();
        }
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain.
                throw new UserNotFoundException();
            }
        }
        return getPasswordValue(username);
    }

    @Override
    public void setPassword(String username, String password)
            throws UserNotFoundException, UnsupportedOperationException
    {
        if (allowUpdate && setPasswordSQL != null) {
            setPasswordValue(username, password);
        } else { 
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public boolean supportsPasswordRetrieval() {
        return (passwordSQL != null && passwordTypes.size() == 1 && passwordTypes.get(0) == PasswordType.plain);
    }

    private Connection getConnection() throws SQLException {
        if (useConnectionProvider)
            return DbConnectionManager.getConnection();
        return DriverManager.getConnection(connectionString);
    }

    /**
     * Returns the value of the password field. It will be in plain text or hashed
     * format, depending on the password type.
     *
     * @param username user to retrieve the password field for
     * @return the password value.
     * @throws UserNotFoundException if the given user could not be loaded.
     */
    private String getPasswordValue(String username) throws UserNotFoundException {
        String password = null;
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain.
                throw new UserNotFoundException();
            }
        }
        try {
            con = getConnection();
            pstmt = con.prepareStatement(passwordSQL);
            pstmt.setString(1, username);

            rs = pstmt.executeQuery();

            // If the query had no results, the username and password
            // did not match a user record. Therefore, throw an exception.
            if (!rs.next()) {
                throw new UserNotFoundException();
            }
            password = rs.getString(1);
        }
        catch (SQLException e) {
            Log.error("Exception in JDBCAuthProvider", e);
            throw new UserNotFoundException();
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        return password;
    }

    private void setPasswordValue(String username, String password) throws UserNotFoundException {
        Connection con = null;
        PreparedStatement pstmt = null;
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain.
                throw new UserNotFoundException();
            }
        }
        try {
            con = getConnection();
            pstmt = con.prepareStatement(setPasswordSQL);
            pstmt.setString(2, username);
            password = hashPassword(password);
            pstmt.setString(1, password);
            pstmt.executeQuery();
        }
        catch (SQLException e) {
            Log.error("Exception in JDBCAuthProvider", e);
            throw new UserNotFoundException();
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
        
    }

    /**
     * Indicates how the password is stored.
     */
    @SuppressWarnings({"UnnecessarySemicolon"})  // Support for QDox Parser
    public enum PasswordType {

        /**
         * The password is stored as plain text.
         */
        plain,

        /**
         * The password is stored as a hex-encoded MD5 hash.
         */
        md5,

        /**
         * The password is stored as a hex-encoded SHA-1 hash.
         */
        sha1,
        
        /**
         * The password is stored as a hex-encoded SHA-256 hash.
         */
        sha256,
              
        /**
          * The password is stored as a hex-encoded SHA-512 hash.
          */
        sha512,
              
        /**
          * The password is stored as a bcrypt hash.
          */
        bcrypt,

        /**
          * The password is stored as an nt hash.
          */
        nt;
   }

    /**
     * Checks to see if the user exists; if not, a new user is created.
     *
     * @param username the username.
     */
    // @VisibleForTesting
    protected void createUser(String username) {
        // See if the user exists in the database. If not, automatically create them.
        UserManager userManager = UserManager.getInstance();
        try {
            userManager.getUser(username);
        }
        catch (UserNotFoundException unfe) {
            try {
                Log.debug("JDBCAuthProvider: Automatically creating new user account for " + username);
                UserManager.getUserProvider().createUser(username, StringUtils.randomString(8),
                        null, null);
            }
            catch (UserAlreadyExistsException uaee) {
                // Ignore.
            }
        }
    }

    @Override
    public boolean isScramSupported() {
        return true;
    }
    private class UserInfo {
        String im_user_name;
        String im_variable;
        int iterations;
        String salt;
        String storedKey;
        String serverKey;
        Date modify_time;
        Date salt_time;
    }

    private UserInfo getUserInfo(String username) throws UnsupportedOperationException, UserNotFoundException {
        UserInfo userInfo =  getUserInfoFromDB(username, false);
        if (userInfo.salt == null ||(userInfo.modify_time!=null && userInfo.salt_time!=null && userInfo.modify_time.after(userInfo.salt_time) )) {
            userInfo = resetSalt(userInfo);
        }
        return  userInfo;
    }

    private UserInfo resetSalt(UserInfo userInfo) throws UserNotFoundException {
        // Determine if the password should be stored as plain text or encrypted.
        boolean usePlainPassword = JiveGlobals.getBooleanProperty("user.usePlainPassword");
        boolean scramOnly = JiveGlobals.getBooleanProperty("user.scramHashedPasswordOnly");
        String encryptedPassword = null;
        String username = userInfo.im_user_name;
        String password = userInfo.im_variable;
        if (username.contains("@")) {
            // Check that the specified domain matches the server's domain
            int index = username.indexOf("@");
            String domain = username.substring(index + 1);
            if (domain.equals(XMPPServer.getInstance().getServerInfo().getXMPPDomain())) {
                username = username.substring(0, index);
            } else {
                // Unknown domain.
                throw new UserNotFoundException();
            }
        }

        // Store the salt and salted password so SCRAM-SHA-1 SASL auth can be used later.
        byte[] saltShaker = new byte[24];
        random.nextBytes(saltShaker);
        String salt = DatatypeConverter.printBase64Binary(saltShaker);


        int iterations = JiveGlobals.getIntProperty("sasl.scram-sha-1.iteration-count",
                ScramUtils.DEFAULT_ITERATION_COUNT);
        byte[] saltedPassword = null, clientKey = null, storedKey = null, serverKey = null;
        try {
            saltedPassword = ScramUtils.createSaltedPassword(saltShaker, password, iterations);
            clientKey = ScramUtils.computeHmac(saltedPassword, "Client Key");
            storedKey = MessageDigest.getInstance("SHA-1").digest(clientKey);
            serverKey = ScramUtils.computeHmac(saltedPassword, "Server Key");
        } catch (SaslException | NoSuchAlgorithmException e) {
            Log.warn("Unable to persist values for SCRAM authentication.");
        }

        if (!scramOnly && !usePlainPassword) {
            try {
                encryptedPassword = AuthFactory.encryptPassword(password);
                // Set password to null so that it's inserted that way.
                password = null;
            }
            catch (UnsupportedOperationException uoe) {
                // Encryption may fail. In that case, ignore the error and
                // the plain password will be stored.
            }
        }
        if (scramOnly) {
            encryptedPassword = null;
            password = null;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = getConnection();
            pstmt = con.prepareStatement(UPDATE_PASSWORD);
            if (storedKey == null) {
                pstmt.setNull(1, Types.VARCHAR);
            }
            else {
                pstmt.setString(1, DatatypeConverter.printBase64Binary(storedKey));
            }
            if (serverKey == null) {
                pstmt.setNull(2, Types.VARCHAR);
            }
            else {
                pstmt.setString(2, DatatypeConverter.printBase64Binary(serverKey));
            }
            pstmt.setString(3, salt);
            pstmt.setInt(4, iterations);
            pstmt.setString(5, username);
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            throw new UserNotFoundException(sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
        return getUserInfoFromDB(username,false);
    }

    private UserInfo getUserInfoFromDB(String username, boolean recurse) throws UnsupportedOperationException, UserNotFoundException {
        if (!isScramSupported()) {
            // Reject the operation since the provider  does not support SCRAM
            throw new UnsupportedOperationException();
        }
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            con = getConnection();
            pstmt = con.prepareStatement(TEST_PASSWORD);
            pstmt.setString(1,username);
            rs = pstmt.executeQuery();
            if (!rs.next()) {
                throw new UserNotFoundException(username);
            }
            UserInfo userInfo = new UserInfo();
            userInfo.im_user_name = rs.getString(1);
            userInfo.im_variable = rs.getString(2);
            userInfo.iterations = rs.getInt(3);
            userInfo.salt = rs.getString(4);
            userInfo.storedKey = rs.getString(5);
            userInfo.serverKey = rs.getString(6);
            userInfo.modify_time = rs.getDate(7);
            userInfo.salt_time = rs.getDate(8);


            // Good to go.
            return userInfo;
        }
        catch (SQLException sqle) {
            Log.error("User SQL failure:", sqle);
            throw new UserNotFoundException(sqle);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
    }

    @Override
    public String getSalt(String username) throws UserNotFoundException {
        return getUserInfo(username).salt;
    }

    @Override
    public int getIterations(String username) throws UserNotFoundException {
        return getUserInfo(username).iterations;
    }

    @Override
    public String getStoredKey(String username) throws UserNotFoundException {
        return getUserInfo(username).storedKey;
    }

    @Override
    public String getServerKey(String username) throws UserNotFoundException {
        return getUserInfo(username).serverKey;
    }

    /**
     * Support a subset of JDBCAuthProvider properties when updated via REST,
     * web GUI, or other sources. Provider strings (and related settings) must
     * be set via XML.
     *
     * @param property the name of the property.
     * @param params event parameters.
     */
    @Override
    public void propertySet(String property, Map<String, Object> params) {
        String value = (String) params.get("value");
        switch (property) {
            case "jdbcAuthProvider.passwordSQL":
                passwordSQL = value;
                Log.debug("jdbcAuthProvider.passwordSQL configured to: {}", passwordSQL);
                break;
            case "jdbcAuthProvider.setPasswordSQL":
                setPasswordSQL = value;
                Log.debug("jdbcAuthProvider.setPasswordSQL configured to: {}", setPasswordSQL);
                break;
            case "jdbcAuthProvider.allowUpdate":
                allowUpdate = Boolean.parseBoolean(value);
                Log.debug("jdbcAuthProvider.allowUpdate configured to: {}", allowUpdate);
                break;
            case "jdbcAuthProvider.passwordType":
                setPasswordTypes(value);
                Log.debug("jdbcAuthProvider.passwordType configured to: {}", Arrays.toString(passwordTypes.toArray()));
                break;
            case "jdbcAuthProvider.bcrypt.cost":
                try {
                    bcryptCost = Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    bcryptCost = -1;
                }
                Log.debug("jdbcAuthProvider.bcrypt.cost configured to: {}", bcryptCost);
                break;
        }
    }

    @Override
    public void propertyDeleted(String property, Map<String, Object> params) {
        propertySet(property, Collections.<String, Object>emptyMap());
    }

    @Override
    public void xmlPropertySet(String property, Map<String, Object> params) {
    }

    @Override
    public void xmlPropertyDeleted(String property, Map<String, Object> params) {
    }                            
}
