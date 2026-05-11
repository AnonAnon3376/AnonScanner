package com.security.burp.scanner.detectors;

import burp.IParameter;
import com.security.burp.scanner.ScanContext;
import com.security.burp.scanner.VulnerabilityDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 反序列化漏洞检测器
 * 检测：FastJson、Jackson、XStream、SnakeYAML、Hessian、Java原生序列化
 */
public class DeserializationDetector implements VulnerabilityDetector {
    
    // FastJson特征
    private static final Pattern FASTJSON_PATTERN = Pattern.compile(
        "@type|autoType|com\\.alibaba\\.fastjson|JSONObject\\.parse",
        Pattern.CASE_INSENSITIVE
    );
    
    // Jackson特征
    private static final Pattern JACKSON_PATTERN = Pattern.compile(
        "@class|@c|enableDefaultTyping|ObjectMapper|JsonTypeInfo",
        Pattern.CASE_INSENSITIVE
    );
    
    // XStream特征
    private static final Pattern XSTREAM_PATTERN = Pattern.compile(
        "<\\?xml|<object|<list|<map|XStream|fromXML",
        Pattern.CASE_INSENSITIVE
    );
    
    // SnakeYAML特征
    private static final Pattern YAML_PATTERN = Pattern.compile(
        "!!java|!!javax|!!com\\.|!!org\\.|tag:yaml",
        Pattern.CASE_INSENSITIVE
    );
    
    // Hessian特征
    private static final Pattern HESSIAN_PATTERN = Pattern.compile(
        "application/x-hessian|Hessian2Input|HessianInput",
        Pattern.CASE_INSENSITIVE
    );
    
    // Java序列化特征
    private static final Pattern JAVA_SER_PATTERN = Pattern.compile(
        "\\xac\\xed\\x00\\x05|rO0AB|application/x-java-serialized-object|ObjectInputStream",
        Pattern.CASE_INSENSITIVE
    );
    
    // 危险类名
    private static final String[] DANGEROUS_CLASSES = {
        "Runtime", "ProcessBuilder", "URLClassLoader", "ScriptEngineManager",
        "JdbcRowSetImpl", "TemplatesImpl", "JndiDataSourceFactory",
        "WrapperConnectionPoolDataSource", "C3P0", "Druid", "Tomcat"
    };
    
    @Override
    public String getName() {
        return "反序列化漏洞检测";
    }
    
    @Override
    public List<String> detect(ScanContext context) {
        List<String> findings = new ArrayList<>();
        
        String body = context.getBody();
        String url = context.getUrl();
        
        // 检测FastJson
        if (FASTJSON_PATTERN.matcher(body).find() || FASTJSON_PATTERN.matcher(url).find()) {
            findings.add("发现FastJson特征 (@type字段)");
            
            // 检查是否包含危险类
            for (String dangerousClass : DANGEROUS_CLASSES) {
                if (body.contains(dangerousClass)) {
                    findings.add("发现危险类名: " + dangerousClass);
                }
            }
        }
        
        // 检测Jackson
        if (JACKSON_PATTERN.matcher(body).find()) {
            findings.add("发现Jackson特征 (@class/@c字段)");
        }
        
        // 检测XStream
        if (XSTREAM_PATTERN.matcher(body).find()) {
            findings.add("发现XStream特征 (XML序列化)");
        }
        
        // 检测SnakeYAML
        if (YAML_PATTERN.matcher(body).find()) {
            findings.add("发现SnakeYAML特征 (!!java标签)");
        }
        
        // 检测Hessian
        for (String header : context.getHeaders()) {
            if (HESSIAN_PATTERN.matcher(header).find()) {
                findings.add("发现Hessian特征 (Content-Type: application/x-hessian)");
                break;
            }
        }
        
        // 检测Java原生序列化
        if (JAVA_SER_PATTERN.matcher(body).find()) {
            findings.add("发现Java序列化特征 (魔术字节: 0xACED0005)");
        }
        
        // 检查参数中的序列化数据
        for (IParameter param : context.getParameters()) {
            String value = param.getValue();
            if (value != null && value.length() > 50) {
                // 检查Base64编码的序列化数据
                if (value.matches("^[A-Za-z0-9+/=]+$") && value.startsWith("rO0")) {
                    findings.add("参数 " + param.getName() + " 可能包含Base64编码的Java序列化数据");
                }
            }
        }
        
        return findings;
    }
}
