package org.jivesoftware.openfire.plugin;

import org.jivesoftware.openfire.MessageRouter;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;

import java.util.List;
import java.util.TimerTask;

/**
 * Created by micky on 18-7-6.
 */
public class SysMessageTimerTask extends TimerTask {
    private static final Logger Log = LoggerFactory.getLogger(SysMessageTimerTask.class);

    public SysMessageTimerTask( MessageRouter router,JID serverAddress,JID toUser){
        this.router=router;
        this.serverAddress=serverAddress;
        this.to_user = toUser;
        message = new Message();
        message.setTo(to_user);
        message.setFrom(serverAddress);
        message.setSubject(getSubject());
        //message.setBody(messageStr);

    }
    private JID serverAddress;
    private JID to_user;
    private MessageRouter router;
    private Message message;
    @Override
    public void run() {
        try {
            List<SysMessageData> list = SysMessageDataProvider.getInstance().getData(to_user.getNode());
            if (list==null)
                return;
            for(SysMessageData d :list){
                String messageStr =d.getContent();
                message.setBody(messageStr);
                router.route(message);
            }
            SysMessageDataProvider.getInstance().updateSendTime(list);
        } catch (UserNotFoundException e) {
            Log.error(e.getMessage());
            e.printStackTrace();
        } catch (InterruptedException e) {
            Log.error(e.getMessage());
            e.printStackTrace();
        }

    }

    private String getSubject() {
        return "System-Share-Message";
    }


}
