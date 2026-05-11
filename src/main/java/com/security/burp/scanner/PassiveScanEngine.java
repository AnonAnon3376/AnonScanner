package com.security.burp.scanner;

import burp.*;
import com.security.burp.config.PluginConfig;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * 被动扫描引擎 - 自动监控HTTP流量
 */
public class PassiveScanEngine implements IScannerCheck {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PluginConfig config;
    private AISecurityScanner scanner;
    private ScanTaskManager taskManager;
    
    // 统计信息
    private int totalRequests = 0;
    private int scannedRequests = 0;
    private int filteredRequests = 0;
    
    public PassiveScanEngine(IBurpExtenderCallbacks callbacks, PluginConfig config, 
                            AISecurityScanner scanner, ScanTaskManager taskManager) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.config = config;
        this.scanner = scanner;
        this.taskManager = taskManager;
        
        stdout.println("[被动扫描引擎] 初始化完成");
        stdout.println("[被动扫描引擎] 监控方法: POST, PUT, DELETE, PATCH");
        stdout.println("[被动扫描引擎] 过滤静态资源: .css, .js, .png, .jpg 等");
    }
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        totalRequests++;
        
        // 检查是否启用被动扫描
        if (!config.isPassiveScanEnabled()) {
            return null;
        }
        
        // 智能过滤
        if (!shouldScan(baseRequestResponse)) {
            filteredRequests++;
            return null;
        }
        
        // 添加到扫描队列
        try {
            String taskId = taskManager.addTask(baseRequestResponse, ScanTask.ScanMode.PASSIVE);
            if (taskId != null) {
                scannedRequests++;
                
                IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
                String url = requestInfo.getUrl().toString();
                stdout.println("[被动扫描] 检测到请求: " + requestInfo.getMethod() + " " + url);
                stdout.println("[被动扫描] 添加任务: " + taskId);
                
                // 异步执行扫描
                new Thread(() -> {
                    try {
                        ScanTask task = taskManager.getTask(taskId);
                        if (task != null) {
                            task.setStatus(ScanTask.TaskStatus.RUNNING);
                        }
                        
                        String result = scanner.scan(baseRequestResponse);
                        
                        if (task != null) {
                            task.setResult(result);
                            task.setStatus(ScanTask.TaskStatus.COMPLETED);
                            stdout.println("[被动扫描] 任务完成: " + taskId);
                        }
                    } catch (Exception e) {
                        stdout.println("[-] 被动扫描失败: " + e.getMessage());
                        ScanTask task = taskManager.getTask(taskId);
                        if (task != null) {
                            task.setStatus(ScanTask.TaskStatus.FAILED);
                            task.setError(e.getMessage());
                        }
                    }
                }).start();
            } else {
                stdout.println("[被动扫描] 任务被拒绝（可能达到扫描限制）");
            }
        } catch (Exception e) {
            stdout.println("[-] 被动扫描异常: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
        }
        
        return null; // 不创建Burp的Issue，使用自己的结果面板
    }
    
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, 
                                         IScannerInsertionPoint insertionPoint) {
        // 不实现主动扫描
        return null;
    }
    
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
    
    /**
     * 智能过滤 - 决定是否扫描该请求
     */
    private boolean shouldScan(IHttpRequestResponse requestResponse) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            
            // 1. 只扫描特定方法（POST/PUT/DELETE/PATCH）
            String method = requestInfo.getMethod();
            if (!method.equals("POST") && !method.equals("PUT") && 
                !method.equals("DELETE") && !method.equals("PATCH")) {
                return false;
            }
            
            // 2. 排除静态资源
            String url = requestInfo.getUrl().toString().toLowerCase();
            String[] staticExtensions = {
                ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", 
                ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map"
            };
            
            for (String ext : staticExtensions) {
                if (url.endsWith(ext)) {
                    return false;
                }
            }
            
            // 排除静态资源路径
            String[] staticPaths = {
                "/static/", "/css/", "/js/", "/images/", "/img/", 
                "/fonts/", "/assets/", "/public/"
            };
            
            for (String path : staticPaths) {
                if (url.contains(path)) {
                    return false;
                }
            }
            
            // 3. 检查是否有请求体（POST/PUT/DELETE通常有body）
            byte[] request = requestResponse.getRequest();
            int bodyOffset = requestInfo.getBodyOffset();
            if (bodyOffset >= request.length) {
                // 没有请求体，可能不值得扫描
                return false;
            }
            
            // 4. 检查Content-Type（优先扫描JSON/XML）
            List<String> headers = requestInfo.getHeaders();
            boolean hasInterestingContentType = false;
            for (String header : headers) {
                String lowerHeader = header.toLowerCase();
                if (lowerHeader.startsWith("content-type:")) {
                    if (lowerHeader.contains("json") || 
                        lowerHeader.contains("xml") || 
                        lowerHeader.contains("form") ||
                        lowerHeader.contains("multipart")) {
                        hasInterestingContentType = true;
                        break;
                    }
                }
            }
            
            // 如果有参数或有趣的Content-Type，就扫描
            if (!requestInfo.getParameters().isEmpty() || hasInterestingContentType) {
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            stdout.println("[-] 过滤检查异常: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取统计信息
     */
    public String getStatistics() {
        return String.format("总请求: %d, 已扫描: %d, 已过滤: %d", 
                           totalRequests, scannedRequests, filteredRequests);
    }
}
