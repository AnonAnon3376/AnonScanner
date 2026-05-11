package com.security.burp.scanner.detectors;

import burp.IParameter;
import com.security.burp.scanner.ScanContext;
import com.security.burp.scanner.VulnerabilityDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 模板注入(SSTI)检测器
 * 检测：Freemarker、Velocity、Thymeleaf、Jinja2
 */
public class SSTIDetector implements VulnerabilityDetector {
    
    // Freemarker特征
    private static final Pattern FREEMARKER_PATTERN = Pattern.compile(
        "<#|<@|\\$\\{|\\[#|freemarker",
        Pattern.CASE_INSENSITIVE
    );
    
    // Velocity特征
    private static final Pattern VELOCITY_PATTERN = Pattern.compile(
        "#set|#if|#foreach|#include|#parse|\\$!|velocity",
        Pattern.CASE_INSENSITIVE
    );
    
    // Thymeleaf特征
    private static final Pattern THYMELEAF_PATTERN = Pattern.compile(
        "th:|\\$\\{|__\\$\\{|thymeleaf",
        Pattern.CASE_INSENSITIVE
    );
    
    // Jinja2特征
    private static final Pattern JINJA2_PATTERN = Pattern.compile(
        "\\{\\{|\\{%|\\{#|jinja",
        Pattern.CASE_INSENSITIVE
    );
    
    // 通用模板表达式
    private static final Pattern TEMPLATE_EXPR = Pattern.compile(
        "\\$\\{.*\\}|\\{\\{.*\\}\\}|\\{%.*%\\}|<#.*>",
        Pattern.CASE_INSENSITIVE
    );
    
    // 危险方法调用
    private static final String[] DANGEROUS_METHODS = {
        "getClass()", "forName(", "newInstance(", "getRuntime()",
        "exec(", "ProcessBuilder", "__import__", "eval(", "compile("
    };
    
    @Override
    public String getName() {
        return "模板注入(SSTI)检测";
    }
    
    @Override
    public List<String> detect(ScanContext context) {
        List<String> findings = new ArrayList<>();
        
        String body = context.getBody();
        String url = context.getUrl();
        
        // 检测Freemarker
        if (FREEMARKER_PATTERN.matcher(body).find() || FREEMARKER_PATTERN.matcher(url).find()) {
            findings.add("发现Freemarker模板特征 (<#assign> / ${...})");
        }
        
        // 检测Velocity
        if (VELOCITY_PATTERN.matcher(body).find() || VELOCITY_PATTERN.matcher(url).find()) {
            findings.add("发现Velocity模板特征 (#set / #if / $!)");
        }
        
        // 检测Thymeleaf
        if (THYMELEAF_PATTERN.matcher(body).find() || THYMELEAF_PATTERN.matcher(url).find()) {
            findings.add("发现Thymeleaf模板特征 (th:属性 / ${...})");
        }
        
        // 检测Jinja2
        if (JINJA2_PATTERN.matcher(body).find() || JINJA2_PATTERN.matcher(url).find()) {
            findings.add("发现Jinja2模板特征 ({{...}} / {%...%})");
        }
        
        // 检测通用模板表达式
        if (TEMPLATE_EXPR.matcher(body).find() || TEMPLATE_EXPR.matcher(url).find()) {
            findings.add("发现模板表达式语法");
        }
        
        // 检测危险方法调用
        for (String method : DANGEROUS_METHODS) {
            if (body.contains(method) || url.contains(method)) {
                findings.add("发现危险方法调用: " + method);
            }
        }
        
        // 检查参数
        for (IParameter param : context.getParameters()) {
            String name = param.getName();
            String value = param.getValue();
            
            if (value == null || value.isEmpty()) {
                continue;
            }
            
            // 检查参数值中的模板语法
            if (TEMPLATE_EXPR.matcher(value).find()) {
                findings.add("参数 " + name + " 包含模板表达式");
            }
            
            // 检查常见的SSTI测试Payload
            if (value.contains("7*7") || value.contains("{{7*7}}") || 
                value.contains("${7*7}") || value.contains("<#assign")) {
                findings.add("参数 " + name + " 包含SSTI测试Payload");
            }
            
            // 检查Python特定的SSTI
            if (value.contains("__class__") || value.contains("__mro__") || 
                value.contains("__subclasses__") || value.contains("__globals__")) {
                findings.add("参数 " + name + " 包含Python SSTI特征");
            }
            
            // 检查Java特定的SSTI
            if (value.contains(".getClass()") || value.contains("Class.forName") ||
                value.contains("Runtime.getRuntime()")) {
                findings.add("参数 " + name + " 包含Java SSTI特征");
            }
        }
        
        // 检查响应头中的模板引擎标识
        for (String header : context.getHeaders()) {
            String lowerHeader = header.toLowerCase();
            if (lowerHeader.contains("x-powered-by") || lowerHeader.contains("server")) {
                if (lowerHeader.contains("freemarker") || lowerHeader.contains("velocity") ||
                    lowerHeader.contains("thymeleaf") || lowerHeader.contains("jinja")) {
                    findings.add("响应头中发现模板引擎标识");
                    break;
                }
            }
        }
        
        return findings;
    }
}
