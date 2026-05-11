package com.security.burp.scanner.detectors;

import burp.IParameter;
import com.security.burp.scanner.ScanContext;
import com.security.burp.scanner.VulnerabilityDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 命令执行漏洞检测器
 * 检测：Log4j2、Spring4Shell、Struts2、Weblogic、Shiro
 */
public class CommandExecutionDetector implements VulnerabilityDetector {
    
    // Log4j2 JNDI注入特征
    private static final Pattern LOG4J2_PATTERN = Pattern.compile(
        "\\$\\{jndi:|\\$\\{.*:.*://|\\$\\{.*lower.*\\}|\\$\\{.*upper.*\\}|\\$\\{.*env:.*\\}",
        Pattern.CASE_INSENSITIVE
    );
    
    // Spring4Shell特征
    private static final Pattern SPRING4SHELL_PATTERN = Pattern.compile(
        "class\\.module|class\\.classLoader|tomcatValveState",
        Pattern.CASE_INSENSITIVE
    );
    
    // Struts2 OGNL注入特征
    private static final Pattern STRUTS2_PATTERN = Pattern.compile(
        "%\\{|#\\{|@java\\.|#context|#_memberAccess|#application|#session",
        Pattern.CASE_INSENSITIVE
    );
    
    // Weblogic T3特征
    private static final Pattern WEBLOGIC_PATTERN = Pattern.compile(
        "t3://|t3s://|iiop://|weblogic\\.jndi|weblogic\\.rmi",
        Pattern.CASE_INSENSITIVE
    );
    
    // Shiro特征
    private static final Pattern SHIRO_PATTERN = Pattern.compile(
        "rememberMe=|shiro|JSESSIONID",
        Pattern.CASE_INSENSITIVE
    );
    
    // 命令执行关键字
    private static final String[] CMD_KEYWORDS = {
        "Runtime.getRuntime", "ProcessBuilder", "exec(", "cmd.exe", "/bin/sh",
        "bash", "powershell", "eval(", "system(", "shell_exec"
    };
    
    @Override
    public String getName() {
        return "命令执行漏洞检测";
    }
    
    @Override
    public List<String> detect(ScanContext context) {
        List<String> findings = new ArrayList<>();
        
        String body = context.getBody();
        String url = context.getUrl();
        List<String> headers = context.getHeaders();
        
        // 检测Log4j2 RCE
        if (LOG4J2_PATTERN.matcher(body).find() || LOG4J2_PATTERN.matcher(url).find()) {
            findings.add("发现Log4j2 JNDI注入特征 (${jndi:...})");
        }
        
        // 检查Header中的Log4j2
        for (String header : headers) {
            if (LOG4J2_PATTERN.matcher(header).find()) {
                findings.add("Header中发现Log4j2注入特征: " + header.split(":")[0]);
                break;
            }
        }
        
        // 检测Spring4Shell
        for (IParameter param : context.getParameters()) {
            String name = param.getName();
            String value = param.getValue();
            
            if (SPRING4SHELL_PATTERN.matcher(name).find() || 
                SPRING4SHELL_PATTERN.matcher(value).find()) {
                findings.add("发现Spring4Shell特征 (class.module.classLoader参数)");
                break;
            }
        }
        
        // 检测Struts2 OGNL注入
        if (STRUTS2_PATTERN.matcher(body).find() || STRUTS2_PATTERN.matcher(url).find()) {
            findings.add("发现Struts2 OGNL注入特征 (%{...} 或 #{...})");
        }
        
        // 检测Weblogic T3
        if (WEBLOGIC_PATTERN.matcher(body).find() || WEBLOGIC_PATTERN.matcher(url).find()) {
            findings.add("发现Weblogic T3协议特征");
        }
        
        // 检测Shiro反序列化
        for (String header : headers) {
            if (header.toLowerCase().contains("cookie") && 
                SHIRO_PATTERN.matcher(header).find()) {
                findings.add("发现Shiro Cookie (rememberMe)，可能存在反序列化漏洞");
                break;
            }
        }
        
        // 检测命令执行关键字
        for (String keyword : CMD_KEYWORDS) {
            if (body.contains(keyword) || url.contains(keyword)) {
                findings.add("发现命令执行关键字: " + keyword);
            }
        }
        
        // 检查参数值中的命令注入特征
        for (IParameter param : context.getParameters()) {
            String value = param.getValue();
            if (value != null) {
                // 检查管道符、重定向等
                if (value.matches(".*[|;&`$()\\[\\]{}].*")) {
                    findings.add("参数 " + param.getName() + " 包含命令注入特殊字符");
                }
            }
        }
        
        return findings;
    }
}
