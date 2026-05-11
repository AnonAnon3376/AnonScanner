package com.security.burp.scanner.detectors;

import burp.IParameter;
import com.security.burp.scanner.ScanContext;
import com.security.burp.scanner.VulnerabilityDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SQL注入检测器
 * 检测：MySQL、PostgreSQL、Oracle、MSSQL、MongoDB
 */
public class SQLInjectionDetector implements VulnerabilityDetector {
    
    // SQL关键字
    private static final Pattern SQL_KEYWORDS = Pattern.compile(
        "\\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|WHERE|FROM|JOIN|EXEC|EXECUTE)\\b",
        Pattern.CASE_INSENSITIVE
    );
    
    // SQL注入特征
    private static final Pattern SQL_INJECTION = Pattern.compile(
        "'|--|#|/\\*|\\*/|;|\\bOR\\b|\\bAND\\b|\\bUNION\\b|\\bSELECT\\b|0x[0-9a-f]+|CHAR\\(|CONCAT\\(",
        Pattern.CASE_INSENSITIVE
    );
    
    // 时间盲注特征
    private static final Pattern TIME_BASED = Pattern.compile(
        "SLEEP\\(|BENCHMARK\\(|WAITFOR\\s+DELAY|pg_sleep\\(|DBMS_LOCK\\.SLEEP",
        Pattern.CASE_INSENSITIVE
    );
    
    // 布尔盲注特征
    private static final Pattern BOOLEAN_BASED = Pattern.compile(
        "\\bOR\\s+1=1|\\bAND\\s+1=1|\\bOR\\s+'1'='1|\\bAND\\s+'1'='1",
        Pattern.CASE_INSENSITIVE
    );
    
    // NoSQL注入特征 (MongoDB)
    private static final Pattern NOSQL_INJECTION = Pattern.compile(
        "\\$where|\\$regex|\\$ne|\\$gt|\\$lt|\\$in|\\$nin|\\$or|\\$and",
        Pattern.CASE_INSENSITIVE
    );
    
    // 数据库特定函数
    private static final String[] DB_FUNCTIONS = {
        // MySQL
        "VERSION()", "DATABASE()", "USER()", "LOAD_FILE(", "INTO OUTFILE",
        // PostgreSQL
        "pg_database", "pg_user", "current_database()", "current_user",
        // Oracle
        "SYS.DATABASE_NAME", "USER_TABLES", "ALL_TABLES", "DBMS_",
        // MSSQL
        "@@VERSION", "DB_NAME()", "SYSTEM_USER", "xp_cmdshell"
    };
    
    @Override
    public String getName() {
        return "SQL注入检测";
    }
    
    @Override
    public List<String> detect(ScanContext context) {
        List<String> findings = new ArrayList<>();
        
        String body = context.getBody();
        String url = context.getUrl();
        
        // 检查URL和Body中的SQL关键字
        if (SQL_KEYWORDS.matcher(url).find()) {
            findings.add("URL中发现SQL关键字");
        }
        
        if (SQL_KEYWORDS.matcher(body).find()) {
            findings.add("请求体中发现SQL关键字");
        }
        
        // 检查SQL注入特征
        if (SQL_INJECTION.matcher(url).find()) {
            findings.add("URL中发现SQL注入特征 (引号、注释符等)");
        }
        
        if (SQL_INJECTION.matcher(body).find()) {
            findings.add("请求体中发现SQL注入特征");
        }
        
        // 检查时间盲注
        if (TIME_BASED.matcher(url).find() || TIME_BASED.matcher(body).find()) {
            findings.add("发现时间盲注特征 (SLEEP/BENCHMARK等)");
        }
        
        // 检查布尔盲注
        if (BOOLEAN_BASED.matcher(url).find() || BOOLEAN_BASED.matcher(body).find()) {
            findings.add("发现布尔盲注特征 (OR 1=1 / AND 1=1)");
        }
        
        // 检查NoSQL注入
        if (NOSQL_INJECTION.matcher(body).find()) {
            findings.add("发现MongoDB NoSQL注入特征 ($where/$regex等)");
        }
        
        // 检查数据库特定函数
        for (String func : DB_FUNCTIONS) {
            if (body.contains(func) || url.contains(func)) {
                findings.add("发现数据库特定函数: " + func);
            }
        }
        
        // 检查参数
        for (IParameter param : context.getParameters()) {
            String name = param.getName();
            String value = param.getValue();
            
            if (value == null || value.isEmpty()) {
                continue;
            }
            
            // 检查参数值中的SQL注入特征
            if (SQL_INJECTION.matcher(value).find()) {
                findings.add("参数 " + name + " 包含SQL注入特征");
            }
            
            // 检查数字型注入
            if (value.matches("^\\d+$")) {
                findings.add("参数 " + name + " 为纯数字，可能存在数字型注入");
            }
            
            // 检查引号闭合
            if (value.contains("'") || value.contains("\"")) {
                findings.add("参数 " + name + " 包含引号，可能用于闭合SQL语句");
            }
            
            // 检查UNION注入
            if (value.toUpperCase().contains("UNION") && 
                value.toUpperCase().contains("SELECT")) {
                findings.add("参数 " + name + " 包含UNION SELECT，疑似联合查询注入");
            }
        }
        
        return findings;
    }
}
