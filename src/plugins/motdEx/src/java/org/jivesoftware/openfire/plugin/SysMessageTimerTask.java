package org.jivesoftware.openfire.plugin;

import org.jivesoftware.openfire.MessageRouter;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;

import java.util.TimerTask;

/**
 * Created by micky on 18-7-6.
 */
public class SysMessageTimerTask extends TimerTask {
    public SysMessageTimerTask( MessageRouter router,JID serverAddress,JID toUser){
        this.router=router;
        this.serverAddress=serverAddress;
        this.to_user = toUser;
        Message message = new Message();
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
        //String messageStr =SysMessageDataProvider.getInstance().getMessageStr(to_user.getNode());
         String messageStr ="{\"title\":\"分享状态\",\"datetime\":1530695396243,\"msg\":\"分享状态的内容。。。。。。\",\"home_share_id\":4}";
        message.setBody(messageStr);
        router.route(message);
    }

    private String getSubject() {
        return "System-Share-Message";
    }


}
