package com.security.burp.dnslog;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import okhttp3.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * DNSLog客户端 - 用于无回显漏洞验证
 * 支持 DNSLog.cn 和 Ceye.io
 */
public class DnsLogClient {
    
    private OkHttpClient httpClient;
    private Gson gson;
    private String domain;
    private String token;
    private DnsLogProvider provider;
    
    public enum DnsLogProvider {
        DNSLOG_CN,
        CEYE_IO,
        CUSTOM
    }
    
    public DnsLogClient(DnsLogProvider provider) {
        this.provider = provider;
        this.gson = new Gson();
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .build();
    }
    
    /**
     * 初始化DNSLog（获取域名）
     */
    public boolean init() {
        try {
            switch (provider) {
                case DNSLOG_CN:
                    return initDnsLogCn();
                case CEYE_IO:
                    return initCeye();
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 初始化 DNSLog.cn
     */
    private boolean initDnsLogCn() throws IOException {
        Request request = new Request.Builder()
                .url("http://www.dnslog.cn/getdomain.php")
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                this.domain = response.body().string().trim();
                return domain != null && !domain.isEmpty();
            }
        }
        return false;
    }
    
    /**
     * 初始化 Ceye.io
     */
    private boolean initCeye() {
        // Ceye需要用户提供token和domain
        // 这里只是占位，实际使用时需要配置
        return token != null && domain != null;
    }
    
    /**
     * 设置Ceye配置
     */
    public void setCeyeConfig(String domain, String token) {
        this.domain = domain;
        this.token = token;
    }
    
    /**
     * 获取DNSLog域名
     */
    public String getDomain() {
        return domain;
    }
    
    /**
     * 生成随机子域名
     */
    public String generateSubdomain(String prefix) {
        String random = String.valueOf(System.currentTimeMillis());
        return prefix + random + "." + domain;
    }
    
    /**
     * 检查DNS记录
     */
    public List<String> checkRecords() {
        try {
            switch (provider) {
                case DNSLOG_CN:
                    return checkDnsLogCnRecords();
                case CEYE_IO:
                    return checkCeyeRecords();
                default:
                    return new ArrayList<>();
            }
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
    
    /**
     * 检查 DNSLog.cn 记录
     */
    private List<String> checkDnsLogCnRecords() throws IOException {
        List<String> records = new ArrayList<>();
        
        Request request = new Request.Builder()
                .url("http://www.dnslog.cn/getrecords.php")
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                String body = response.body().string();
                
                // 解析JSON数组
                if (body != null && !body.trim().isEmpty() && !body.equals("[]")) {
                    // 简单解析，提取域名记录
                    String[] lines = body.split("\n");
                    for (String line : lines) {
                        if (line.contains(domain)) {
                            records.add(line);
                        }
                    }
                }
            }
        }
        
        return records;
    }
    
    /**
     * 检查 Ceye.io 记录
     */
    private List<String> checkCeyeRecords() throws IOException {
        List<String> records = new ArrayList<>();
        
        if (token == null || domain == null) {
            return records;
        }
        
        String url = "http://api.ceye.io/v1/records?token=" + token + "&type=dns";
        
        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                String body = response.body().string();
                JsonObject json = gson.fromJson(body, JsonObject.class);
                
                if (json.has("data")) {
                    // 解析DNS记录
                    records.add(json.get("data").toString());
                }
            }
        }
        
        return records;
    }
    
    /**
     * 检查特定子域名是否有记录
     */
    public boolean hasRecord(String subdomain) {
        List<String> records = checkRecords();
        for (String record : records) {
            if (record.contains(subdomain)) {
                return true;
            }
        }
        return false;
    }
}
