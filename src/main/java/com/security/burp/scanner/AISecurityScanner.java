package com.security.burp.scanner;

import burp.*;
import com.security.burp.config.PluginConfig;
import com.security.burp.ai.QianwenAIClient;
import com.security.burp.scanner.detectors.*;

import java.util.ArrayList;
import java.util.List;

/**
 * AI安全扫描器
 * 
 * 负责协调各个漏洞检测器，并使用AI进行智能分析
 */
public class AISecurityScanner {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PluginConfig config;
    private QianwenAIClient aiClient;
    
    // 漏洞检测器列表
    private List<VulnerabilityDetector> detectors;
    
    public AISecurityScanner(IBurpExtenderCallbacks callbacks, PluginConfig config) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.config = config;
        this.aiClient = new QianwenAIClient(config);
        
        // 初始化所有漏洞检测器
        initDetectors();
    }
    
    /**
     * 初始化漏洞检测器
     */
    private void initDetectors() {
        detectors = new ArrayList<>();
        
        // 反序列化漏洞检测器
        detectors.add(new DeserializationDetector());
        
        // 命令执行漏洞检测器
        detectors.add(new CommandExecutionDetector());
        
        // SQL注入检测器
        detectors.add(new SQLInjectionDetector());
        
        // XXE漏洞检测器
        detectors.add(new XXEDetector());
        
        // 模板注入检测器
        detectors.add(new SSTIDetector());
        
        // SSRF检测器
        detectors.add(new SSRFDetector());
        
        // 文件漏洞检测器
        detectors.add(new FileVulnerabilityDetector());
    }
    
    /**
     * 扫描HTTP请求
     */
    public String scan(IHttpRequestResponse message) throws Exception {
        // 解析请求
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        byte[] request = message.getRequest();
        
        // 提取请求信息
        String url = requestInfo.getUrl().toString();
        String method = requestInfo.getMethod();
        List<IParameter> parameters = requestInfo.getParameters();
        String body = extractBody(request, requestInfo.getBodyOffset());
        List<String> headers = requestInfo.getHeaders();
        
        // 构建扫描上下文
        ScanContext context = new ScanContext();
        context.setUrl(url);
        context.setMethod(method);
        context.setParameters(parameters);
        context.setBody(body);
        context.setHeaders(headers);
        context.setRequest(request);
        context.setRequestInfo(requestInfo);
        
        // 第一阶段：使用规则检测器快速识别可疑点
        StringBuilder suspiciousFindings = new StringBuilder();
        suspiciousFindings.append("【可疑特征检测】\n\n");
        
        for (VulnerabilityDetector detector : detectors) {
            List<String> findings = detector.detect(context);
            if (!findings.isEmpty()) {
                suspiciousFindings.append(detector.getName()).append(":\n");
                for (String finding : findings) {
                    suspiciousFindings.append("  • ").append(finding).append("\n");
                }
                suspiciousFindings.append("\n");
            }
        }
        
        // 第二阶段：使用AI进行深度分析
        String aiAnalysis = performAIAnalysis(context, suspiciousFindings.toString());
        
        return aiAnalysis;
    }
    
    /**
     * 使用AI进行深度分析
     */
    private String performAIAnalysis(ScanContext context, String suspiciousFindings) throws Exception {
        // 构建AI分析提示词
        String prompt = buildAnalysisPrompt(context, suspiciousFindings);
        
        // 调用AI API
        String aiResponse = aiClient.analyze(prompt);
        
        return aiResponse;
    }
    
    /**
     * 构建AI分析提示词
     */
    private String buildAnalysisPrompt(ScanContext context, String suspiciousFindings) {
        StringBuilder prompt = new StringBuilder();
        
        prompt.append("你是一个专业的Web安全专家，请分析以下HTTP请求中可能存在的安全漏洞。\n\n");
        
        prompt.append("【请求信息】\n");
        prompt.append("URL: ").append(context.getUrl()).append("\n");
        prompt.append("Method: ").append(context.getMethod()).append("\n");
        prompt.append("Parameters: ").append(context.getParameters().size()).append("个\n\n");
        
        // 添加参数详情
        if (!context.getParameters().isEmpty()) {
            prompt.append("【参数列表】\n");
            for (IParameter param : context.getParameters()) {
                prompt.append("  • ").append(param.getName())
                      .append(" = ").append(param.getValue())
                      .append(" (").append(getParameterType(param.getType())).append(")\n");
            }
            prompt.append("\n");
        }
        
        // 添加请求体
        if (context.getBody() != null && !context.getBody().isEmpty()) {
            prompt.append("【请求体】\n");
            prompt.append(context.getBody()).append("\n\n");
        }
        
        // 添加可疑特征
        prompt.append(suspiciousFindings);
        
        prompt.append("【分析要求】\n");
        prompt.append("请重点分析以下漏洞类型：\n\n");
        
        prompt.append("1. 反序列化漏洞\n");
        prompt.append("   - FastJson (检查@type字段、特殊类名)\n");
        prompt.append("   - Jackson (检查enableDefaultTyping配置)\n");
        prompt.append("   - XStream (检查XML反序列化)\n");
        prompt.append("   - SnakeYAML (检查YAML解析)\n");
        prompt.append("   - Hessian (检查二进制序列化)\n");
        prompt.append("   - Java原生序列化 (检查ObjectInputStream)\n\n");
        
        prompt.append("2. 命令执行漏洞\n");
        prompt.append("   - Log4j2 RCE (检查${jndi:ldap/rmi}模式)\n");
        prompt.append("   - Spring4Shell (检查class.module.classLoader参数)\n");
        prompt.append("   - Struts2 (检查OGNL表达式)\n");
        prompt.append("   - Weblogic T3 (检查T3协议反序列化)\n");
        prompt.append("   - Shiro (检查rememberMe cookie)\n\n");
        
        prompt.append("3. SQL注入\n");
        prompt.append("   - 检查参数中的SQL关键字\n");
        prompt.append("   - 检查单引号、双引号、注释符\n");
        prompt.append("   - 检查UNION、OR、AND等注入点\n");
        prompt.append("   - 检查时间盲注特征\n");
        prompt.append("   - 检查NoSQL注入 ($where, $regex等)\n\n");
        
        prompt.append("4. XXE漏洞\n");
        prompt.append("   - 检查XML实体定义\n");
        prompt.append("   - 检查DOCTYPE声明\n");
        prompt.append("   - 检查SYSTEM/PUBLIC关键字\n");
        prompt.append("   - 检查SVG文件上传\n");
        prompt.append("   - 检查Office文档解析\n\n");
        
        prompt.append("5. 模板注入 (SSTI)\n");
        prompt.append("   - Freemarker (检查<#assign>等标签)\n");
        prompt.append("   - Velocity (检查#set等指令)\n");
        prompt.append("   - Thymeleaf (检查th:属性)\n");
        prompt.append("   - Jinja2 (检查{{}}模板语法)\n\n");
        
        prompt.append("6. SSRF漏洞\n");
        prompt.append("   - 检查URL参数\n");
        prompt.append("   - 检查回调地址\n");
        prompt.append("   - 检查文件包含\n");
        prompt.append("   - 检查内网地址访问\n\n");
        
        prompt.append("7. 文件漏洞\n");
        prompt.append("   - 文件上传 (检查文件类型、扩展名绕过)\n");
        prompt.append("   - 任意文件读取 (检查路径参数)\n");
        prompt.append("   - 目录遍历 (检查../等路径穿越)\n\n");
        
        prompt.append("【输出格式】\n");
        prompt.append("请按以下格式输出分析结果：\n\n");
        prompt.append("## 漏洞分析结果\n\n");
        prompt.append("### 发现的漏洞\n");
        prompt.append("[列出所有发现的漏洞，包括漏洞类型、位置、风险等级]\n\n");
        prompt.append("### 漏洞详情\n");
        prompt.append("[对每个漏洞进行详细分析]\n\n");
        prompt.append("### 攻击Payload\n");
        prompt.append("[提供具体的测试Payload，用代码块标注]\n\n");
        prompt.append("### 风险评估\n");
        prompt.append("[评估漏洞的危害等级：严重/高危/中危/低危]\n\n");
        prompt.append("### 修复建议\n");
        prompt.append("[提供具体的修复方案]\n\n");
        prompt.append("如果未发现明显漏洞，请说明原因并给出安全建议。\n");
        
        return prompt.toString();
    }
    
    /**
     * 提取请求体
     */
    private String extractBody(byte[] request, int bodyOffset) {
        if (bodyOffset >= request.length) {
            return "";
        }
        byte[] bodyBytes = new byte[request.length - bodyOffset];
        System.arraycopy(request, bodyOffset, bodyBytes, 0, bodyBytes.length);
        return new String(bodyBytes);
    }
    
    /**
     * 获取参数类型名称
     */
    private String getParameterType(byte type) {
        switch (type) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_XML:
                return "XML";
            case IParameter.PARAM_XML_ATTR:
                return "XML Attribute";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Multipart";
            case IParameter.PARAM_JSON:
                return "JSON";
            default:
                return "Unknown";
        }
    }
}
