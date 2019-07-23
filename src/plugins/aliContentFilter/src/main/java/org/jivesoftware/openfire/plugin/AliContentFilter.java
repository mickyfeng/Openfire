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

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.exceptions.ServerException;
import com.aliyuncs.green.model.v20180509.ImageSyncScanRequest;
import com.aliyuncs.green.model.v20180509.TextScanRequest;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpResponse;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.profile.IClientProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;

import java.nio.charset.Charset;
import java.util.*;

/**
 * Filters message content using ali interface
 *
 * @author Terry
 */
public class AliContentFilter {
    private static final Logger logger = LoggerFactory.getLogger(AliContentFilter.class);
    private static final String ossHttp="https://neverlost-msg.oss-cn-shenzhen.aliyuncs.com/";

    private void logInof(String log){
        if (logger.isDebugEnabled()){
            logger.debug(log);
        }

    }

    public void setProfile(IClientProfile profile) {
        this.profile = profile;
    }

    private IClientProfile profile;
    private String message="Content.alleged.violation";

    /**
     * Filters packet content.
     *
     * @param p the packet to filter, its content may be altered if there
     *            are content matches and a content mask is set
     * @return true if the msg content matched up, false otherwise
     */
    public boolean filter(Packet p) {
        if (p instanceof Message){
            return process((Message) p);
        }
        return false;
    }

    private boolean process(Message msg) {
        if (Message.Type.chat.equals (msg.getType())){
            String body = msg.getBody();
            if ((body != null) && (body.length() > 0)) {
                try{
                    JSONObject b = JSON.parseObject(body);
                    int type = b.getIntValue("type");
                    String content= b.getString("content");
                    try {
                        if (type == 1) {
                            checkStr(content);
                        } else if (type == 2) {
                            checkImg(content);
                        }
                    }catch (AliyunGreenException e){
                        return true;
                    }
                } catch (Exception e) {
                    try {
                        checkStr(body);
                    }catch (AliyunGreenException e2){
                        return true;
                    }
                    return false;
                }
            }
        }
        return false;
    }

    private   IAcsClient getClient()  {
         return new DefaultAcsClient(profile);
    }

    private  void checkImg(String imgUrl) throws AliyunGreenException {
        if (imgUrl == null)
            return;
        if (!(imgUrl.indexOf("https://")==0 ||imgUrl.indexOf("http://")==0) ){
            imgUrl=ossHttp+imgUrl;
        }
        IAcsClient client = getClient();

        ImageSyncScanRequest imageSyncScanRequest = new ImageSyncScanRequest();
        // 指定api返回格式
        imageSyncScanRequest.setAcceptFormat(FormatType.JSON);
        // 指定请求方法
        imageSyncScanRequest.setMethod(MethodType.POST);
        imageSyncScanRequest.setEncoding("utf-8");
        // 支持http和https
        imageSyncScanRequest.setProtocol(ProtocolType.HTTP);

        JSONObject httpBody = new JSONObject();
        /**
         * 设置要检测的场景, 计费是按照该处传递的场景进行 一次请求中可以同时检测多张图片，每张图片可以同时检测多个风险场景，计费按照场景计算
         * 例如：检测2张图片，场景传递porn,terrorism，计费会按照2张图片鉴黄，2张图片暴恐检测计算 porn:
         * porn表示色情场景检测
         */
        httpBody.put("scenes", Arrays.asList("porn", "terrorism"));

        /**
         * 设置待检测图片， 一张图片一个task， 多张图片同时检测时，处理的时间由最后一个处理完的图片决定。
         * 通常情况下批量检测的平均rt比单张检测的要长, 一次批量提交的图片数越多，rt被拉长的概率越高 这里以单张图片检测作为示例,
         * 如果是批量图片检测，请自行构建多个task
         */
        List<JSONObject> tasks = new ArrayList<JSONObject>();

            JSONObject task = new JSONObject();
            task.put("dataId", UUID.randomUUID().toString());
            // 设置图片链接
            task.put("url", imgUrl);
            task.put("time", new Date());
            tasks.add(task);
        httpBody.put("tasks", tasks);

        imageSyncScanRequest.setHttpContent(org.apache.commons.codec.binary.StringUtils.getBytesUtf8(httpBody.toJSONString()), "UTF-8", FormatType.JSON);

        /**
         * 请设置超时时间, 服务端全链路处理超时时间为10秒，请做相应设置 如果您设置的ReadTimeout
         * 小于服务端处理的时间，程序中会获得一个read timeout 异常
         */
        imageSyncScanRequest.setConnectTimeout(3000);
        imageSyncScanRequest.setReadTimeout(10000);
        HttpResponse httpResponse = null;
        try {
            httpResponse = client.doAction(imageSyncScanRequest);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 服务端接收到请求，并完成处理返回的结果
        if (httpResponse != null && httpResponse.isSuccess()) {
            JSONObject scrResponse = JSON.parseObject(org.apache.commons.codec.binary.StringUtils.newStringUtf8(httpResponse.getHttpContent()));
            logInof(JSON.toJSONString(scrResponse, true));
            int requestCode = scrResponse.getIntValue("code");
            // 每一张图片的检测结果
            JSONArray taskResults = scrResponse.getJSONArray("data");
            if (200 == requestCode) {
                for (Object taskResult : taskResults) {
                    // 单张图片的处理结果
                    int taskCode = ((JSONObject) taskResult).getIntValue("code");
                    // 图片要检测的场景的处理结果, 如果是多个场景，则会有每个场景的结果
                    JSONArray sceneResults = ((JSONObject) taskResult).getJSONArray("results");
                    if (200 == taskCode) {
                        for (Object sceneResult : sceneResults) {
                            String scene = ((JSONObject) sceneResult).getString("scene");
                            String label = ((JSONObject) sceneResult).getString("label");
                            String suggestion = ((JSONObject) sceneResult).getString("suggestion");
                            doResult(scene, label, suggestion);
                            // 根据scene和suggetion做相关处理
                            // do something
                            logInof("scene = [" + scene + "]");
                            logInof("suggestion = [" + suggestion + "]");
                        }
                    } else {
                        // 单张图片处理失败, 原因是具体的情况详细分析
                        // logInof("task process fail. task response:" +
                        // JSON.toJSONString(taskResult));
                        throw new AliyunGreenException(JSON.toJSONString(taskResult));
                    }
                }
            } else {
                /**
                 * 表明请求整体处理失败，原因视具体的情况详细分析
                 */
                logInof("the whole image scan request failed. response:" + JSON.toJSONString(scrResponse));
            }
        }

    }

    private  void doResult(String scene, String label, String suggestion) throws AliyunGreenException {
        if (!"normal".equalsIgnoreCase(label)) {
            throw new AliyunGreenException(message);
        }

    }

    private  void doResultStr(String scene, String label, String suggestion, int level) throws AliyunGreenException {
        // normal：正常文本
        // spam：含垃圾信息
        // ad：广告
        // politics：涉政
        // terrorism：暴恐
        // abuse：辱骂
        // porn：色情
        // flood：灌水
        // contraband：违禁
        // meaningless：无意义
        // customized：自定义（比如命中自定义关键词）
        if (level == 1) {
            if (!"normal".equalsIgnoreCase(label)) {
                throw new AliyunGreenException(message);
            }
        } else if (level == 2) {
            if (!"normal".equalsIgnoreCase(label) && !"meaningless".equalsIgnoreCase(label) && !"flood".equalsIgnoreCase(label)) {
                throw new AliyunGreenException(message);
            }
        } else {
            if ("politics".equalsIgnoreCase(label) || "terrorism".equalsIgnoreCase(label) || "abuse".equalsIgnoreCase(label) || "porn".equalsIgnoreCase(label)
                || "contraband".equalsIgnoreCase(label) || "customized".equalsIgnoreCase(label)) {
                throw new AliyunGreenException(message);
            }
        }
    }

    public  void checkStr(String text) throws AliyunGreenException {
        checkStr(text, 3);
    }

    public  void checkStr(String text, int level) throws AliyunGreenException {
        if (text == null)
            return;
        if (text.length() >= 10000) {
            throw new AliyunGreenException("文本太长！");
        }
        IAcsClient client = getClient();
        TextScanRequest textScanRequest = new TextScanRequest();
        textScanRequest.setAcceptFormat(FormatType.JSON); // 指定api返回格式
        textScanRequest.setHttpContentType(FormatType.JSON);
        textScanRequest.setMethod(MethodType.POST); // 指定请求方法
        textScanRequest.setEncoding("UTF-8");
        textScanRequest.setRegionId("cn-shanghai");
        List<Map<String, Object>> tasks = new ArrayList<Map<String, Object>>();

        Map<String, Object> task1 = new LinkedHashMap<String, Object>();
        task1.put("dataId", UUID.randomUUID().toString());
        /**
         * 待检测的文本，长度不超过10000个字符
         */
        task1.put("content", text);
        tasks.add(task1);
        JSONObject data = new JSONObject();

        /**
         * 检测场景，文本垃圾检测传递：antispam
         **/
        data.put("scenes", Arrays.asList("antispam"));
        data.put("tasks", tasks);
        logInof(JSON.toJSONString(data, true));
        textScanRequest.setHttpContent(data.toJSONString().getBytes(Charset.forName("UTF-8")), "UTF-8", FormatType.JSON);
        // 请务必设置超时时间
        textScanRequest.setConnectTimeout(3000);
        textScanRequest.setReadTimeout(6000);
        try {
            HttpResponse httpResponse = client.doAction(textScanRequest);
            if (httpResponse.isSuccess()) {
                JSONObject scrResponse = JSON.parseObject(new String(httpResponse.getHttpContent(), Charset.forName("UTF-8")));
                logInof(JSON.toJSONString(scrResponse, true));
                if (200 == scrResponse.getInteger("code")) {
                    JSONArray taskResults = scrResponse.getJSONArray("data");
                    for (Object taskResult : taskResults) {
                        if (200 == ((JSONObject) taskResult).getInteger("code")) {
                            JSONArray sceneResults = ((JSONObject) taskResult).getJSONArray("results");
                            for (Object sceneResult : sceneResults) {
                                String scene = ((JSONObject) sceneResult).getString("scene");
                                String label = ((JSONObject) sceneResult).getString("label");
                                String suggestion = ((JSONObject) sceneResult).getString("suggestion");
                                // 根据scene和suggetion做相关处理
                                // suggestion == pass 未命中垃圾 suggestion == block
                                // 命中了垃圾，可以通过label字段查看命中的垃圾分类
                                logInof("args = [" + scene + "]");
                                logInof("args = [" + suggestion + "]");
                                doResultStr(scene, label, suggestion, level);
                            }
                        } else {
                            logInof("task process fail:" + ((JSONObject) taskResult).getInteger("code"));
                        }
                    }
                } else {
                    logInof("detect not success. code:" + scrResponse.getInteger("code"));
                }
            } else {
                logInof("response not success. status:" + httpResponse.getStatus());
            }
        } catch (ServerException e) {
            e.printStackTrace();
        } catch (ClientException e) {
            e.printStackTrace();
        }
    }
    

}
