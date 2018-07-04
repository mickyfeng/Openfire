
<%--
  -
  - Copyright (C) 2004-2008 Jive Software. All rights reserved.
  -
  - Licensed under the Apache License, Version 2.0 (the "License");
  - you may not use this file except in compliance with the License.
  - You may obtain a copy of the License at
  -
  -     http://www.apache.org/licenses/LICENSE-2.0
  -
  - Unless required by applicable law or agreed to in writing, software
  - distributed under the License is distributed on an "AS IS" BASIS,
  - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  - See the License for the specific language governing permissions and
  - limitations under the License.
--%>

<%@ page import="org.jivesoftware.util.ParamUtils,
                 org.jivesoftware.openfire.SessionManager,
                 java.util.HashMap"
    errorPage="error.jsp"
%>
<%@ page import="java.util.Map" %>

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%  // Get parameters
    //String username = ParamUtils.getParameter(request,"username");
    boolean send = ParamUtils.getBooleanParameter(request,"send");
    boolean success = ParamUtils.getBooleanParameter(request,"success");
    //boolean sendToAll = ParamUtils.getBooleanParameter(request,"sendToAll");
   // boolean tabs = ParamUtils.getBooleanParameter(request,"tabs",true);
    //String jid = ParamUtils.getParameter(request,"jid");
    //String[] jids = ParamUtils.getParameters(request,"jid");
    String message = ParamUtils.getParameter(request,"message");
%>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<% webManager.init(pageContext); %>

<%
    // Handle a cancel
    if (request.getParameter("cancel") != null) {
        response.sendRedirect("session-summary.jsp");
        return;
    }
    // Get the session manager
    SessionManager sessionManager = webManager.getSessionManager();

    // Handle the request to send a message:
    Map<String,String> errors = new HashMap<>();

    if (send) {
        // Validate the message and jid
        if (message == null) {
            errors.put("message","message");
        }
        if (errors.size() == 0) {
            sessionManager.sendServerMessage_sys(message);
            response.sendRedirect("system-message.jsp?success=true");
            return;
        }
    }
%>


<html>
<head>
<title><fmt:message key="system.message.title"/></title>
<meta name="pageID" content="system-message"/>
<meta name="helpPage" content="send_an_administrative_message_to_users.html"/>
</head>
<body>

<%  if (success) { %>

    <div class="jive-success">
    <table cellpadding="0" cellspacing="0" border="0">
    <tbody>
        <tr><td class="jive-icon"><img src="images/success-16x16.gif" width="16" height="16" border="0" alt=""></td>
        <td class="jive-icon-label">
        <fmt:message key="system.message.send" />
        </td></tr>
    </tbody>
    </table>
    </div><br>

<%  } %>


<form action="system-message.jsp" method="post" name="f">
<input type="hidden" name="send" value="true">

    <!-- BEGIN send message block -->
    <!--<div class="jive-contentBoxHeader">
        <fmt:message key="system.message.send_admin_msg" />
    </div>-->
    <div class="jive-contentBox" style="-moz-border-radius: 3px;">
        <table cellpadding="3" cellspacing="1" border="0" width="600">

        <tr><td colspan=3 class="text" style="padding-bottom: 10px;">

            <p><fmt:message key="system.message.info" /></p>

        </td></tr>
        <tr>
            <td class="jive-label">
                <fmt:message key="system.message.to" />:
            </td>
            <td>
                <fmt:message key="system.message.all_online_user" />
            </td>
        </tr>
        <tr valign="top">
            <td class="jive-label">
                <fmt:message key="system.message.message" />:
            </td>
            <td>
                <%  if (errors.get("message") != null) { %>

                    <span class="jive-error-text">
                    <fmt:message key="system.message.valid_message" />
                    </span>
                    <br>

                <%  } %>
                <textarea name="message" cols="55" rows="5" wrap="virtual"></textarea>
            </td>
        </tr>
        </table>
    </div>
    <!-- END send message block -->

<input type="submit" value="<fmt:message key="system.message.send_message" />">
<input type="submit" name="cancel" value="<fmt:message key="global.cancel" />">

</form>

<script language="JavaScript" type="text/javascript">
document.f.message.focus();
</script>


</body>
</html>
