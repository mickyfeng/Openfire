/*
 * Copyright (C) 2004-2008 Jive Software. All rights reserved.
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

package org.jivesoftware.openfire.plugin;

import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import org.jivesoftware.openfire.MessageRouter;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.util.EmailService;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;

import java.io.File;

/**
 * ali Content filter plugin.
 * 
 * @author Terry
 */
public class AliContentFilterPlugin implements Plugin, PacketInterceptor {

    private static final Logger Log = LoggerFactory.getLogger(AliContentFilterPlugin.class);

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY will be notified
     * every time there is a content match, otherwise no notification will be
     * sent. Then default value is false.
     */
    private static final String VIOLATION_NOTIFICATION_ENABLED_PROPERTY = "plugin.aliContentFilter.violation.notification.enabled";

    /**
     * The expected value is a user name. The default value is "admin".
     */
    private static final String VIOLATION_NOTIFICATION_CONTACT_PROPERTY = "plugin.aliContentFilter.violation.notification.contact";

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY, will also
     * receive a copy of the offending packet. The default value is false.
     */
    private static final String VIOLATION_INCLUDE_ORIGNAL_PACKET_ENABLED_PROPERTY = "plugin.aliContentFilter.violation.notification.include.original.enabled";

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY, will receive
     * notification by IM. The default value is true.
     */
    private static final String VIOLATION_NOTIFICATION_BY_IM_ENABLED_PROPERTY = "plugin.aliContentFilter.violation.notification.by.im.enabled";

    /**
     * The expected value is a boolean, if true the user identified by the value
     * of the property #VIOLATION_NOTIFICATION_CONTACT_PROPERTY, will receive
     * notification by email. The default value is false.
     */
    private static final String VIOLATION_NOTIFICATION_BY_EMAIL_ENABLED_PROPERTY = "plugin.aliContentFilter.violation.notification.by.email.enabled";

    /**
     * The expected value is a boolean, if true the sender will be notified when
     * a message is rejected, otherwise the message will be silently
     * rejected,i.e. the sender will not know that the message was rejected and
     * the receiver will not get the message. The default value is false.
     */
    private static final String REJECTION_NOTIFICATION_ENABLED_PROPERTY = "plugin.aliContentFilter.rejection.notification.enabled";

    /**
     * The expected value is a string, containing the desired message for the
     * sender notification.
     */
    private static final String REJECTION_MSG_PROPERTY = "plugin.aliContentFilter.rejection.msg";


    /**
     * The expected value is a boolean, if true Presence packets will be
     * filtered
     */
    private static final String FILTER_STATUS_ENABLED_PROPERTY = "plugin.aliContentFilter.filter.status.enabled";

    private static final String FILTER_ACCESS_KEY_ID_PROPERTY = "plugin.aliContentFilter.filter.access_key_id";
    private static final String FILTER_ACCESS_KEY_SECRET_PROPERTY = "plugin.aliContentFilter.filter.access_key_secret";





    /**
     * the hook into the inteceptor chain
     */
    private InterceptorManager interceptorManager;

    /**
     * used to send violation notifications
     */
    private MessageRouter messageRouter;

    /**
     * delegate that does the real work of this plugin
     */
    private AliContentFilter aliContentFilter;

    /**
     * flags if sender should be notified of rejections
     */
    private boolean rejectionNotificationEnabled;

    /**
     * the rejection msg to send
     */
    private String rejectionMessage;

    /**
     * flags if content matches should result in admin notification
     */
    private boolean violationNotificationEnabled;

    /**
     * the admin user to send violation notifications to
     */
    private String violationContact;

    /**
     * flags if original packet should be included in the message to the
     * violation contact.
     */
    private boolean violationIncludeOriginalPacketEnabled;

    /**
     * flags if violation contact should be notified by IM.
     */
    private boolean violationNotificationByIMEnabled;

    /**
     * flags if violation contact should be notified by email.
     */
    private boolean violationNotificationByEmailEnabled;



    /**
     * flag if Presence packets should be filtered.
     */
    private boolean filterStatusEnabled;

    private  String access_key_id;
    private  String access_key_secret;




    /**
     * violation notification messages will be from this JID
     */
    private JID violationNotificationFrom;

    public AliContentFilterPlugin() {
        aliContentFilter = new AliContentFilter();
        interceptorManager = InterceptorManager.getInstance();
        violationNotificationFrom = new JID(XMPPServer.getInstance()
                .getServerInfo().getXMPPDomain());
        messageRouter = XMPPServer.getInstance().getMessageRouter();
    }

    public void initializePlugin(PluginManager pManager, File pluginDirectory) {
        // configure this plugin
        initFilter();

        try {
            IClientProfile profile = DefaultProfile.getProfile("cn-shanghai", access_key_id, access_key_secret);
            // DefaultProfile.addEndpoint("cn-shanghai", "Green",
            // "cn-shanghai");
            DefaultProfile.addEndpoint("cn-shanghai", "cn-shanghai", "Green", "green.cn-shanghai.aliyuncs.com");
            aliContentFilter.setProfile(profile);
            // register with interceptor manager
            interceptorManager.addInterceptor(this);
        } catch (ClientException e) {
            Log.error(e.getMessage());
            throw new IllegalStateException("This plugin cannot run ,error:"+e.getMessage());
        }

    }

    private void initFilter() {
        // default to false
        violationNotificationEnabled = JiveGlobals.getBooleanProperty(
                VIOLATION_NOTIFICATION_ENABLED_PROPERTY, false);

        // default to "admin"
        violationContact = JiveGlobals.getProperty(
                VIOLATION_NOTIFICATION_CONTACT_PROPERTY, "admin");

        // default to true
        violationNotificationByIMEnabled = JiveGlobals.getBooleanProperty(
                VIOLATION_NOTIFICATION_BY_IM_ENABLED_PROPERTY, true);

        // default to false
        violationNotificationByEmailEnabled = JiveGlobals.getBooleanProperty(
                VIOLATION_NOTIFICATION_BY_EMAIL_ENABLED_PROPERTY, false);

        // default to true
        violationIncludeOriginalPacketEnabled = JiveGlobals.getBooleanProperty(
                VIOLATION_INCLUDE_ORIGNAL_PACKET_ENABLED_PROPERTY, true);

        // default to true
        rejectionNotificationEnabled = JiveGlobals.getBooleanProperty(
                REJECTION_NOTIFICATION_ENABLED_PROPERTY, true);

        // default to english
        rejectionMessage = JiveGlobals.getProperty(REJECTION_MSG_PROPERTY,
                "Message rejected. This is an automated server response");

        // default to false
        filterStatusEnabled = JiveGlobals.getBooleanProperty(
                FILTER_STATUS_ENABLED_PROPERTY, false);

        access_key_id =JiveGlobals.getProperty(
            FILTER_ACCESS_KEY_ID_PROPERTY, "");
         access_key_secret =JiveGlobals.getProperty(
             FILTER_ACCESS_KEY_SECRET_PROPERTY, "");
    }

    /**
     * @see Plugin#destroyPlugin()
     */
    public void destroyPlugin() {
        // unregister with interceptor manager
        interceptorManager.removeInterceptor(this);
    }

    public void interceptPacket(Packet packet, Session session, boolean read,
            boolean processed) throws PacketRejectedException {

        if (isValidTargetPacket(packet, read, processed)) {

            Packet original = packet;

            if (Log.isDebugEnabled()) {
                Log.debug("Content filter: intercepted packet:"
                        + original.toString());
            }

            // make a copy of the original packet only if required,
            // as it's an expensive operation
            if (violationNotificationEnabled
                    && violationIncludeOriginalPacketEnabled ) {
                original = packet.createCopy();
            }

            // filter the packet
            boolean contentMatched = aliContentFilter.filter(packet);

            if (Log.isDebugEnabled()) {
                Log.debug("Content filter: content matched? " + contentMatched);
            }

            // notify admin of violations
            if (contentMatched && violationNotificationEnabled) {
                if (Log.isDebugEnabled()) {
                    Log.debug("Content filter: sending violation notification");
                    Log.debug("Content filter: include original msg ? "
                            + this.violationIncludeOriginalPacketEnabled);
                }
                sendViolationNotification(original);
            }

            // msg will either be rejected silently, rejected with
            // some notification to sender, or allowed and optionally masked.
            // allowing a message without masking can be useful if the admin
            // simply wants to get notified of matches without interrupting
            // the conversation in the  (spy mode!)
            if (contentMatched) {
                    // msg must be rejected
                    if (Log.isDebugEnabled()) {
                        Log.debug("Content filter: rejecting packet");
                    }
                    if (rejectionNotificationEnabled) {
                        PacketRejectedException rejected = new PacketRejectedException(
                            "Packet rejected with disallowed content!");
                        // let the sender know about the rejection, this is
                        // only possible/useful if the content is not masked
                        rejected.setRejectionMessage(rejectionMessage);
                        throw rejected;
                    }
            }
        }
    }

    private boolean isValidTargetPacket(Packet packet, boolean read,
            boolean processed) {
        return filterStatusEnabled
                && !processed
                && read
                // && (packet instanceof Message || (  packet instanceof Presence));
                 && (packet instanceof Message);
    }

    private void sendViolationNotification(Packet originalPacket) {
        String subject = "Content filter notification! ("
                + originalPacket.getFrom().getNode() + ")";

        if (originalPacket instanceof Message) {
            Message originalMsg = (Message) originalPacket;
            String  body = "Disallowed content detected in message from:"
                    + originalMsg.getFrom()
                    + " to:"
                    + originalMsg.getTo()
                    + ", message was  rejected."
                    + (violationIncludeOriginalPacketEnabled ? "\nOriginal subject:"
                            + (originalMsg.getSubject() != null ? originalMsg
                                    .getSubject() : "")
                            + "\nOriginal content:"
                            + (originalMsg.getBody() != null ? originalMsg
                                    .getBody() : "")
                            : "");
            if (violationNotificationByIMEnabled) {

                if (Log.isDebugEnabled()) {
                    Log.debug("Content filter: sending IM notification");
                }
                sendViolationNotificationIM(subject, body);
            }

            if (violationNotificationByEmailEnabled) {

                if (Log.isDebugEnabled()) {
                    Log.debug("Content filter: sending email notification");
                }
                sendViolationNotificationEmail(subject, body);
            }
        }


    }

    private void sendViolationNotificationIM(String subject, String body) {
        Message message = createServerMessage(subject, body);
        // TODO consider spining off a separate thread here,
        // in high volume situations, it will result in
        // in faster response and notification is not required
        // to be real time.
        messageRouter.route(message);
    }

    private Message createServerMessage(String subject, String body) {
        Message msg = new Message();
        msg.setSubject(subject);
        msg.setTo(violationContact + "@"
                + violationNotificationFrom.getDomain());
        msg.setFrom(violationNotificationFrom);
        msg.setBody(body);
        return msg;
    }

    private void sendViolationNotificationEmail(String subject, String body) {
        try {
            User user = UserManager.getInstance().getUser(violationContact);
            
            //this is automatically put on a another thread for execution.
            EmailService.getInstance().sendMessage(user.getName(), user.getEmail(), "Openfire",
                "no_reply@" + violationNotificationFrom.getDomain(), subject, body, null);

        }
        catch (Throwable e) {
            // catch throwable in case email setup is invalid
            Log.error("Content Filter: Failed to send email, please review Openfire setup", e);
        }
    }
}
