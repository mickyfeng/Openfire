package org.jivesoftware.openfire.plugin;

import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

/**
 * Created by micky on 18-7-6.
 */
public class SysMessageDataProvider {
    private static final Logger Log = LoggerFactory.getLogger(SysMessageDataProvider.class);
    private boolean useConnectionProvider;
    private String connectionString;
    private String searchSQL;
    private String updateSendDateSQL ;
    private static final int MAX_AVAILABLE = 10;
    private static final Semaphore available = new Semaphore(MAX_AVAILABLE, true);

    private static volatile SysMessageDataProvider instance;

    public static SysMessageDataProvider getInstance() {
        if (instance == null) {
            synchronized (SysMessageDataProvider.class) {
                if (instance == null) {
                    instance = new SysMessageDataProvider();
                }
            }
        }
        return instance;
    }

    public SysMessageDataProvider(){
        JiveGlobals.migrateProperty("jdbcProvider.driver");
        JiveGlobals.migrateProperty("jdbcProvider.connectionString");
        JiveGlobals.migrateProperty("jdbcSysMessageProvider.searchSQL");
        JiveGlobals.migrateProperty("jdbcSysMessageProvider.updateSendDateSQL");
        useConnectionProvider = JiveGlobals.getBooleanProperty("jdbcUserProvider.useConnectionProvider");

        // Load the JDBC driver and connection string.
        if (!useConnectionProvider) {
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
        searchSQL = JiveGlobals.getProperty("jdbcSysMessageProvider.searchSQL","select sm.id ,ui.im_user_name,sm.content,sm.create_time  " +
                "from im_user_sys_msg sm LEFT JOIN im_user_info ui on sm.to_user_id= ui.user_id  " +
                "where sm.send_time is null and ui.im_user_name =?");
        updateSendDateSQL  = JiveGlobals.getProperty("jdbcSysMessageProvider.updateSendDateSQL","update  im_user_sys_msg set send_time = NOW() where id=?" );

    }

    private Connection getConnection() throws SQLException {
        if (useConnectionProvider) {
            return DbConnectionManager.getConnection();
        } else
        {
            return DriverManager.getConnection(connectionString);
        }
    }

    public List<SysMessageData> getData(String username) throws UserNotFoundException, InterruptedException {
        if(username.contains("@")) {
            if (!XMPPServer.getInstance().isLocal(new JID(username))) {
                throw new UserNotFoundException("Cannot load user of remote server: " + username);
            }
            username = username.substring(0,username.lastIndexOf("@"));
        }
        available.acquire();
        List<SysMessageData> list = new ArrayList();
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            con = getConnection();
            pstmt = con.prepareStatement(searchSQL);
            pstmt.setString(1, username);
            rs = pstmt.executeQuery();

            while (rs.next() ) {
                SysMessageData d = new SysMessageData();
                d.setId(rs.getInt(1));
                d.setToUserName(rs.getString(2));
                d.setContent(rs.getString(3));
                d.setCreateTime(rs.getTime(4));
                list.add(d);
            }
            return list;
        }
        catch (Exception e) {
            throw new UserNotFoundException(e);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
            available.release();
        }
    }

    public void updateSendTime(List<SysMessageData> list) throws UserNotFoundException {
        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = getConnection();
            pstmt = con.prepareStatement(updateSendDateSQL);
            for(SysMessageData d :list){
                pstmt.setInt(1, d.getId());
                pstmt.executeUpdate();
            }
        }
        catch (SQLException sqle) {
            throw new UserNotFoundException(sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }
}

