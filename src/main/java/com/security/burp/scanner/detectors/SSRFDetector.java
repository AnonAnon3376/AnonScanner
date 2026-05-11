package com.security.burp.scanner.detectors;

import burp.IParameter;
import com.security.burp.scanner.ScanContext;
import com.security.burp.scanner.VulnerabilityDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SSRF漏洞检测器
 */
public class SSRFDetector implements VulnerabilityDetector {
    
    // URL参数特征
    private static final Pattern URL_PARAM = Pattern.compile(
        "url=|uri=|path=|redirect=|jump=|target=|to=|link=|goto=|callback=|return=|page=|site=|html=",
        Pattern.CASE_INSENSITIVE
    );
    
    // URL协议
    private static final Pattern URL_PROTOCOL = Pattern.compile(
        "https?://|ftp://|file://|gopher://|dict://|ldap://|tftp://|sftp://",
        Pattern.CASE_INSENSITIVE
    );
    
    // 内网地址
    private static final Pattern INTERNAL_IP = Pattern.compile(
        "127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2[0-9]|3[0-1])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+",
        Pattern.CASE_INSENSITIVE
    );
    
    // 云服务元数据地址
    private static final String[] METADATA_URLS = {
        "169.254.169.254",  // AWS/Azure/GCP
        "metadata.google.internal",
        "169.254.170.2",    // AWS ECS
        "100.100.100.200"   // 阿里云
    };
    
    // 文件包含特征
    private static final Pattern FILE_INCLUSION = Pattern.compile(
        "file=|include=|require=|page=|template=|load=",
        Pattern.CASE_INSENSITIVE
    );
    
    @Override
    public String getName() {
        return "SSRF漏洞检测";
    }
    
    @Override
    public List<String> detect(ScanContext context) {
        List<String> findings = new ArrayList<>();
        
        String body = context.getBody();
        String url = context.getUrl();
        
        // 检查URL参数
        if (URL_PARAM.matcher(url).find() || URL_PARAM.matcher(body).find()) {
            findings.add("发现URL相关参数 (url/uri/redirect等)");
        }
        
        // 检查URL协议
        if (URL_PROTOCOL.matcher(body).find()) {
            findings.add("请求体中包含URL协议 (http/ftp/file等)");
        }
        
        // 检查内网地址
        if (INTERNAL_IP.matcher(body).find() || INTERNAL_IP.matcher(url).find()) {
            findings.add("发现内网地址 (127.0.0.1/10.x.x.x/192.168.x.x)");
        }
        
        // 检查云服务元数据地址
        for (String metadata : METADATA_URLS) {
            if (body.contains(metadata) || url.contains(metadata)) {
                findings.add("发现云服务元数据地址: " + metadata);
            }
        }
        
        // 检查文件包含
        if (FILE_INCLUSION.matcher(url).find() || FILE_INCLUSION.matcher(body).find()) {
            findings.add("发现文件包含相关参数");
        }
        
        // 检查参数
        for (IParameter param : context.getParameters()) {
            String name = param.getName().toLowerCase();
            String value = param.getValue();
            
            if (value == null || value.isEmpty()) {
                continue;
            }
            
            // 检查参数名
            if (name.contains("url") || name.contains("uri") || name.contains("redirect") ||
                name.contains("callback") || name.contains("link") || name.contains("target")) {
                findings.add("参数 " + param.getName() + " 可能用于URL跳转/回调");
                
                // 检查参数值
                if (URL_PROTOCOL.matcher(value).find()) {
                    findings.add("参数 " + param.getName() + " 包含完整URL");
                }
                
                if (INTERNAL_IP.matcher(value).find()) {
                    findings.add("参数 " + param.getName() + " 包含内网地址");
                }
            }
            
            // 检查文件路径
            if (name.contains("file") || name.contains("path") || name.contains("include")) {
                findings.add("参数 " + param.getName() + " 可能用于文件操作");
                
                if (value.startsWith("/") || value.contains("..") || value.contains("file://")) {
                    findings.add("参数 " + param.getName() + " 包含文件路径特征");
                }
            }
            
            // 检查IP地址
            if (value.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
                findings.add("参数 " + param.getName() + " 包含IP地址: " + value);
            }
            
            // 检查域名
            if (value.matches(".*\\.[a-z]{2,}.*")) {
                findings.add("参数 " + param.getName() + " 包含域名");
            }
        }
        
        return findings;
    }
}
