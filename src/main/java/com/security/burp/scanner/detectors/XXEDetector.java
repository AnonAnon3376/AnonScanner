package com.security.burp.scanner.detectors;

import com.security.burp.scanner.ScanContext;
import com.security.burp.scanner.VulnerabilityDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * XXE漏洞检测器
 * 检测：标准XXE、Blind XXE、SVG XXE、Office文档XXE
 */
public class XXEDetector implements VulnerabilityDetector {
    
    // XML声明
    private static final Pattern XML_DECLARATION = Pattern.compile(
        "<\\?xml|xmlns",
        Pattern.CASE_INSENSITIVE
    );
    
    // DOCTYPE声明
    private static final Pattern DOCTYPE = Pattern.compile(
        "<!DOCTYPE|<!ENTITY",
        Pattern.CASE_INSENSITIVE
    );
    
    // SYSTEM/PUBLIC关键字
    private static final Pattern SYSTEM_PUBLIC = Pattern.compile(
        "SYSTEM|PUBLIC",
        Pattern.CASE_INSENSITIVE
    );
    
    // 外部实体引用
    private static final Pattern EXTERNAL_ENTITY = Pattern.compile(
        "&[a-zA-Z0-9_]+;",
        Pattern.CASE_INSENSITIVE
    );
    
    // SVG文件特征
    private static final Pattern SVG_PATTERN = Pattern.compile(
        "<svg|<image|xlink:href",
        Pattern.CASE_INSENSITIVE
    );
    
    // Office文档特征
    private static final Pattern OFFICE_PATTERN = Pattern.compile(
        "application/vnd\\.openxmlformats|application/vnd\\.ms-|\\.(docx|xlsx|pptx)",
        Pattern.CASE_INSENSITIVE
    );
    
    @Override
    public String getName() {
        return "XXE漏洞检测";
    }
    
    @Override
    public List<String> detect(ScanContext context) {
        List<String> findings = new ArrayList<>();
        
        String body = context.getBody();
        String url = context.getUrl();
        List<String> headers = context.getHeaders();
        
        // 检查Content-Type
        boolean isXML = false;
        boolean isSVG = false;
        boolean isOffice = false;
        
        for (String header : headers) {
            String lowerHeader = header.toLowerCase();
            if (lowerHeader.contains("content-type")) {
                if (lowerHeader.contains("xml") || lowerHeader.contains("text/xml") || 
                    lowerHeader.contains("application/xml")) {
                    isXML = true;
                    findings.add("Content-Type为XML格式");
                }
                if (lowerHeader.contains("svg") || lowerHeader.contains("image/svg+xml")) {
                    isSVG = true;
                    findings.add("Content-Type为SVG格式");
                }
                if (OFFICE_PATTERN.matcher(lowerHeader).find()) {
                    isOffice = true;
                    findings.add("Content-Type为Office文档格式");
                }
            }
        }
        
        // 检查XML声明
        if (XML_DECLARATION.matcher(body).find()) {
            findings.add("发现XML声明 (<?xml)");
            isXML = true;
        }
        
        // 如果是XML内容，进行深入检查
        if (isXML || body.contains("<") && body.contains(">")) {
            
            // 检查DOCTYPE声明
            if (DOCTYPE.matcher(body).find()) {
                findings.add("发现DOCTYPE/ENTITY声明，可能存在XXE漏洞");
                
                // 检查SYSTEM/PUBLIC
                if (SYSTEM_PUBLIC.matcher(body).find()) {
                    findings.add("发现SYSTEM/PUBLIC关键字，可能引用外部实体");
                }
            }
            
            // 检查外部实体引用
            if (EXTERNAL_ENTITY.matcher(body).find()) {
                findings.add("发现实体引用 (&xxx;)");
            }
            
            // 检查常见的XXE Payload特征
            if (body.contains("file://") || body.contains("http://") || 
                body.contains("ftp://") || body.contains("php://")) {
                findings.add("发现外部资源引用 (file:// / http:// 等)");
            }
            
            // 检查参数实体
            if (body.contains("%") && body.contains(";")) {
                findings.add("发现参数实体特征，可能用于Blind XXE");
            }
        }
        
        // 检查SVG XXE
        if (isSVG || SVG_PATTERN.matcher(body).find()) {
            findings.add("发现SVG内容");
            if (DOCTYPE.matcher(body).find()) {
                findings.add("SVG中包含DOCTYPE，可能存在SVG XXE漏洞");
            }
        }
        
        // 检查Office文档XXE
        if (isOffice) {
            findings.add("上传Office文档，可能存在XXE漏洞 (需解压检查XML文件)");
        }
        
        // 检查URL中的XXE特征
        if (url.contains("xml") || url.contains("dtd")) {
            findings.add("URL中包含xml/dtd关键字");
        }
        
        return findings;
    }
}
