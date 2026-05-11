package com.security.burp.ai;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.security.burp.config.PluginConfig;
import okhttp3.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * 通用AI客户端 - 支持多种AI模型
 * 
 * 支持的AI提供商：
 * - 阿里千问 (Qianwen)
 * - DeepSeek
 * - 智谱AI (GLM)
 * - 字节豆包 (Doubao)
 * - OpenAI
 * - 月之暗面 (Moonshot/Kimi)
 * - 百川智能 (Baichuan)
 * - 零一万物 (Yi)
 * - 自定义API端点
 */
public class QianwenAIClient {
    
    private PluginConfig config;
    private OkHttpClient httpClient;
    private Gson gson;
    
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    
    public QianwenAIClient(PluginConfig config) {
        this.config = config;
        this.gson = new Gson();
        
        // 配置HTTP客户端 - 增加超时时间
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)  // 连接超时：60秒
                .readTimeout(120, TimeUnit.SECONDS)    // 读取超时：120秒（AI分析需要时间）
                .writeTimeout(60, TimeUnit.SECONDS)    // 写入超时：60秒
                .build();
    }
    
    /**
     * 分析请求
     */
    public String analyze(String prompt) throws IOException {
        String baseUrl = config.getApiBaseUrl() == null ? "" : config.getApiBaseUrl().trim();
        if (baseUrl.isEmpty()) {
            throw new IOException("Base URL 为空，请在配置页填写 AI API Base URL");
        }

        IOException lastException = null;
        String[] candidateUrls = buildCandidateChatCompletionUrls(baseUrl);

        for (String url : candidateUrls) {
            try {
                String result = analyzeOnce(url, prompt);
                System.out.println("[调试] 成功使用API端点: " + url);
                return result;
            } catch (IOException e) {
                lastException = e;
                System.out.println("[调试] API端点失败: " + url + "，原因: " + e.getMessage());
            }
        }

        if (lastException != null) {
            throw lastException;
        }
        throw new IOException("无法访问任何API端点，请检查 Base URL 是否正确: " + baseUrl);
    }

    private String analyzeOnce(String url, String prompt) throws IOException {
        System.out.println("[调试] 尝试API端点: " + url);
        
        // 构建请求体 - 支持多种格式
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", config.getModel());
        requestBody.addProperty("temperature", config.getTemperature());
        requestBody.addProperty("max_tokens", config.getMaxTokens());
        
        // 添加消息
        JsonArray messages = new JsonArray();
        
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", "你是一个专业的Web安全专家，擅长分析各种安全漏洞。");
        messages.add(systemMessage);
        
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", prompt);
        messages.add(userMessage);
        
        requestBody.add("messages", messages);
        
        // 为某些API网关添加额外字段
        requestBody.addProperty("stream", false);
        
        System.out.println("[调试] 请求体: " + gson.toJson(requestBody));
        
        // 构建HTTP请求 - 为小鹰token等特殊API网关添加更多头部
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("User-Agent", "Anon-Scanner/1.0")
                .post(RequestBody.create(gson.toJson(requestBody), JSON));
        
        // 添加Authorization头部
        String apiKey = config.getApiKey().trim();
        if (!apiKey.isEmpty()) {
            // 尝试不同的认证方式
            if (apiKey.startsWith("Bearer ")) {
                requestBuilder.addHeader("Authorization", apiKey);
            } else if (apiKey.startsWith("sk-")) {
                requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
            } else {
                // 可能是其他格式的API Key，尝试多种方式
                requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
                requestBuilder.addHeader("X-API-Key", apiKey);
                requestBuilder.addHeader("Api-Key", apiKey);
            }
        }
        
        Request request = requestBuilder.build();
        
        System.out.println("[调试] 请求URL: " + url);
        System.out.println("[调试] 请求头: " + request.headers().toString());
        System.out.println("[调试] 请求体: " + gson.toJson(requestBody));
        
        // 发送请求
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = "";
                if (response.body() != null) {
                    errorBody = response.body().string();
                }
                throw new IOException("API请求失败: " + response.code() + " - " + response.message() + 
                    (errorBody.isEmpty() ? "" : "\n响应内容: " + errorBody));
            }
            
            String responseBody = response.body().string();
            return parseResponse(responseBody);
        }
    }

    private String[] buildCandidateChatCompletionUrls(String baseUrl) {
        String normalized = baseUrl == null ? "" : baseUrl.trim();
        normalized = stripTrailingSlash(normalized);

        if (normalized.isEmpty()) {
            return new String[0];
        }

        // 用户已经填了完整端点
        if (containsChatCompletionPath(normalized)) {
            return new String[]{normalized};
        }

        // 常见情况：用户填的是 API Base（例如 https://host/v1 或 https://api.openai.com/v1）
        java.util.LinkedHashSet<String> urls = new java.util.LinkedHashSet<>();

        // 如果 baseUrl 已经以 /v1 或 /api/v1 或 /openai/v1 结尾，直接追加 chat/completions
        String lower = normalized.toLowerCase();
        if (lower.endsWith("/v1") || lower.endsWith("/api/v1") || lower.endsWith("/openai/v1")) {
            urls.add(normalized + "/chat/completions");
        }

        // 如果用户只填了域名/端口（或其它根路径），尝试补齐常见前缀
        urls.add(normalized + "/v1/chat/completions");
        urls.add(normalized + "/openai/v1/chat/completions");
        urls.add(normalized + "/api/v1/chat/completions");
        urls.add(normalized + "/chat/completions");

        return urls.toArray(new String[0]);
    }

    private boolean containsChatCompletionPath(String url) {
        String u = url == null ? "" : url.toLowerCase();
        return u.contains("/chat/completions");
    }

    private String stripTrailingSlash(String url) {
        if (url == null) {
            return "";
        }
        String u = url.trim();
        while (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }
        return u;
    }
    
    /**
     * 解析API响应
     */
    private String parseResponse(String responseBody) throws IOException {
        // 先打印原始响应用于调试
        System.out.println("[调试] API原始响应: " + responseBody.substring(0, Math.min(500, responseBody.length())) + 
            (responseBody.length() > 500 ? "..." : ""));
        
        // 检查响应是否为空
        if (responseBody == null || responseBody.trim().isEmpty()) {
            throw new IOException("API返回空响应");
        }
        
        // 检查是否返回了HTML页面（通常是错误的URL或需要登录）
        String trimmedResponse = responseBody.trim().toLowerCase();
        if (trimmedResponse.startsWith("<!doctype html") || 
            trimmedResponse.startsWith("<html") || 
            trimmedResponse.contains("<title>")) {
            
            // 尝试从HTML中提取有用信息
            String title = "";
            if (responseBody.contains("<title>")) {
                int start = responseBody.indexOf("<title>") + 7;
                int end = responseBody.indexOf("</title>");
                if (end > start) {
                    title = responseBody.substring(start, end);
                }
            }
            
            throw new IOException("API返回HTML页面而不是JSON响应（疑似命中了网关前端/登录页）\n" +
                "返回标题: " + (title.isEmpty() ? "(无)" : title) + "\n" +
                "请把 Base URL 配置为 OpenAI 兼容接口地址，例如：\n" +
                "- https://<host>/v1\n" +
                "- https://<host>/openai/v1\n" +
                "- https://<host>/api/v1\n" +
                "或直接填完整端点：\n" +
                "- https://<host>/v1/chat/completions\n" +
                "- https://<host>/openai/v1/chat/completions\n" +
                "- https://<host>/api/v1/chat/completions");
        }
        
        // 尝试解析JSON响应
        JsonObject jsonResponse;
        try {
            jsonResponse = gson.fromJson(responseBody, JsonObject.class);
        } catch (Exception e) {
            // 如果不是标准JSON格式，可能是纯文本响应
            if (responseBody.startsWith("{") && responseBody.endsWith("}")) {
                throw new IOException("JSON解析失败: " + e.getMessage() + "\n原始响应: " + responseBody);
            } else {
                // 可能是纯文本响应，直接返回
                return responseBody.trim();
            }
        }
        
        // 检查是否有错误
        if (jsonResponse.has("error")) {
            JsonObject error = jsonResponse.getAsJsonObject("error");
            String errorMessage = error.has("message") ? error.get("message").getAsString() : "未知错误";
            throw new IOException("API返回错误: " + errorMessage);
        }
        
        // 尝试解析标准OpenAI格式
        if (jsonResponse.has("choices") && jsonResponse.getAsJsonArray("choices").size() > 0) {
            JsonObject choice = jsonResponse.getAsJsonArray("choices").get(0).getAsJsonObject();
            if (choice.has("message")) {
                JsonObject message = choice.getAsJsonObject("message");
                return message.get("content").getAsString();
            } else if (choice.has("text")) {
                // 兼容旧版completions格式
                return choice.get("text").getAsString();
            }
        }
        
        // 尝试解析其他可能的格式
        if (jsonResponse.has("response")) {
            return jsonResponse.get("response").getAsString();
        }
        
        if (jsonResponse.has("content")) {
            return jsonResponse.get("content").getAsString();
        }
        
        if (jsonResponse.has("text")) {
            return jsonResponse.get("text").getAsString();
        }
        
        // 如果都不匹配，返回整个响应
        throw new IOException("无法解析API响应格式，请检查API兼容性\n原始响应: " + responseBody);
    }
    
    /**
     * 测试连接
     */
    public boolean testConnection() {
        return testConnection(null);
    }
    
    /**
     * 测试连接（带错误信息）
     */
    public boolean testConnection(StringBuilder errorMessage) {
        try {
            System.out.println("[调试] 开始测试连接...");
            System.out.println("[调试] Base URL: " + config.getApiBaseUrl());
            System.out.println("[调试] Model: " + config.getModel());
            System.out.println("[调试] API Key长度: " + config.getApiKey().length());
            
            String testPrompt = "请回复：连接成功";
            String response = analyze(testPrompt);
            boolean success = response != null && !response.isEmpty();
            
            if (success) {
                System.out.println("[调试] 测试成功，响应: " + response);
            } else {
                System.out.println("[调试] 测试失败，响应为空");
                if (errorMessage != null) {
                    errorMessage.append("API响应为空");
                }
            }
            
            return success;
        } catch (Exception e) {
            System.out.println("[调试] 测试失败，异常: " + e.getMessage());
            e.printStackTrace();
            
            if (errorMessage != null) {
                errorMessage.append(e.getMessage());
            }
            return false;
        }
    }
}
