package org.jivesoftware.openfire.plugin;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.TaskEngine;
import org.jivesoftware.openfire.MessageRouter;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.event.SessionEventDispatcher;
import org.jivesoftware.openfire.event.SessionEventListener;
import org.jivesoftware.openfire.session.Session;
import org.xmpp.packet.JID;

/**
 * MotD (Message of the Day) plugin.
 *
 * @author <a href="mailto:ryan@version2software.com">Ryan Graham</a>
 */
public class MotDPExlugin implements Plugin {
    //private static final String SUBJECT = "plugin.motd.subject";
    //private static final String MESSAGE = "plugin.motd.message";
    private static final String ENABLED = "plugin.motdEx.enabled";

    private JID serverAddress;
    private MessageRouter router;
    private Map<String, SysMessageTimerTask> smttMap;

    private MotDSessionEventListener listener = new MotDSessionEventListener();

    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        serverAddress = new JID(XMPPServer.getInstance().getServerInfo().getXMPPDomain());
        router = XMPPServer.getInstance().getMessageRouter();
        smttMap = new HashMap<>();
        SessionEventDispatcher.addListener(listener);
    }

    public void destroyPlugin() {
        SessionEventDispatcher.removeListener(listener);

        listener = null;
        serverAddress = null;
        router = null;
        for (String key : smttMap.keySet()) {
            SysMessageTimerTask smtt = smttMap.get(key);
            TaskEngine.getInstance().cancelScheduledTask(smtt);
            smttMap.remove(key);
        }
        smttMap = null;
    }

//   public void setSubject(String message) {
//      JiveGlobals.setProperty(SUBJECT, message);
//   }
//
//   public String getSubject() {
//      return JiveGlobals.getProperty(SUBJECT, "System-Share-Message");
//   }
//
//   public void setMessage(String message) {
//      JiveGlobals.setProperty(MESSAGE, message);
//   }
//
//   public String getMessage() {
//      return JiveGlobals.getProperty(MESSAGE, "{\"title\":\"分享状态\",\"datetime\":1530695396243,\"msg\":\"分享状态的内容。。。。。。\",\"home_share_id\":4}");
//   }

    public void setEnabled(boolean enable) {
        JiveGlobals.setProperty(ENABLED, Boolean.toString(enable));
    }

    public boolean isEnabled() {
        return JiveGlobals.getBooleanProperty(ENABLED, false);
    }

    private class MotDSessionEventListener implements SessionEventListener {
        public void sessionCreated(Session session) {
            if (isEnabled()) {
                synchronized (smttMap) {
                    String key = session.getAddress().getNode();
                    if (key == null || "".equals(key) || key.length() < 32) {
                        return;
                    }
                    if (smttMap.containsKey(key)) {
                        return;
                    }
                    SysMessageTimerTask messageTask = new SysMessageTimerTask(router,serverAddress,session.getAddress());
                    TaskEngine.getInstance().schedule(messageTask, 5000,60000 );//3 * 60 * 1000
                    smttMap.put(key, messageTask);
                }
            }
        }

        public void sessionDestroyed(Session session) {
            //ignore
            synchronized (smttMap) {
                String key = session.getAddress().getNode();
                if (smttMap.containsKey(key)) {
                    SysMessageTimerTask s = smttMap.get(key);
                    TaskEngine.getInstance().cancelScheduledTask(s);
                    smttMap.remove(key);
                }
            }
        }

        public void resourceBound(Session session) {
            // Do nothing.
        }

        public void anonymousSessionCreated(Session session) {
            //ignore
        }

        public void anonymousSessionDestroyed(Session session) {
            //ignore
        }
    }
}
