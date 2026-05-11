package com.security.burp.config;

/**
 * 插件配置类
 */
public class PluginConfig {
    
    // AI提供商预设
    public enum AIProvider {
        QIANWEN("阿里千问", "https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen-plus"),
        DEEPSEEK("DeepSeek", "https://api.deepseek.com/v1", "deepseek-chat"),
        GLM("智谱AI", "https://open.bigmodel.cn/api/paas/v4", "glm-4"),
        DOUBAO("字节豆包", "https://ark.cn-beijing.volces.com/api/v3", "doubao-pro-32k"),
        OPENAI("OpenAI", "https://api.openai.com/v1", "gpt-4o-mini"),
        MOONSHOT("月之暗面", "https://api.moonshot.cn/v1", "moonshot-v1-8k"),
        BAICHUAN("百川智能", "https://api.baichuan-ai.com/v1", "Baichuan2-Turbo"),
        YI("零一万物", "https://api.lingyiwanwu.com/v1", "yi-large"),
        CUSTOM("自定义", "", "");
        
        private final String displayName;
        private final String defaultBaseUrl;
        private final String defaultModel;
        
        AIProvider(String displayName, String defaultBaseUrl, String defaultModel) {
            this.displayName = displayName;
            this.defaultBaseUrl = defaultBaseUrl;
            this.defaultModel = defaultModel;
        }
        
        public String getDisplayName() {
            return displayName;
        }
        
        public String getDefaultBaseUrl() {
            return defaultBaseUrl;
        }
        
        public String getDefaultModel() {
            return defaultModel;
        }
        
        @Override
        public String toString() {
            return displayName;
        }
    }
    
    // API配置
    private AIProvider provider = AIProvider.QIANWEN;
    private String apiBaseUrl = "https://dashscope.aliyuncs.com/compatible-mode/v1";
    private String apiKey = "";
    private String model = "qwen-plus";
    private int maxTokens = 4000;
    private double temperature = 0.7;
    
    // 扫描选项
    private boolean deepAnalysis = true;
    private boolean generatePayload = true;
    private boolean riskAssessment = true;
    
    // 验证选项（新增）
    private boolean autoVerify = false;
    private String dnsLogProvider = "DNSLOG_CN"; // DNSLOG_CN, CEYE_IO, CUSTOM
    private String ceyeDomain = "";
    private String ceyeToken = "";
    private int verifyTimeout = 5; // 秒
    
    // 被动扫描选项（新增）
    private boolean passiveScanEnabled = true; // 默认启用
    
    // 成本控制（新增）
    private int maxDailyScans = 100;
    private int maxHourlyScans = 20;
    private int maxConcurrentScans = 3;
    
    // Getters and Setters
    
    public AIProvider getProvider() {
        return provider;
    }
    
    public void setProvider(AIProvider provider) {
        this.provider = provider;
    }
    
    public String getApiBaseUrl() {
        return apiBaseUrl;
    }
    
    public void setApiBaseUrl(String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
    }
    
    public String getApiKey() {
        return apiKey;
    }
    
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    public String getModel() {
        return model;
    }
    
    public void setModel(String model) {
        this.model = model;
    }
    
    public int getMaxTokens() {
        return maxTokens;
    }
    
    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }
    
    public double getTemperature() {
        return temperature;
    }
    
    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }
    
    public boolean isDeepAnalysis() {
        return deepAnalysis;
    }
    
    public void setDeepAnalysis(boolean deepAnalysis) {
        this.deepAnalysis = deepAnalysis;
    }
    
    public boolean isGeneratePayload() {
        return generatePayload;
    }
    
    public void setGeneratePayload(boolean generatePayload) {
        this.generatePayload = generatePayload;
    }
    
    public boolean isRiskAssessment() {
        return riskAssessment;
    }
    
    public void setRiskAssessment(boolean riskAssessment) {
        this.riskAssessment = riskAssessment;
    }
    
    public boolean isAutoVerify() {
        return autoVerify;
    }
    
    public void setAutoVerify(boolean autoVerify) {
        this.autoVerify = autoVerify;
    }
    
    public String getDnsLogProvider() {
        return dnsLogProvider;
    }
    
    public void setDnsLogProvider(String dnsLogProvider) {
        this.dnsLogProvider = dnsLogProvider;
    }
    
    public String getCeyeDomain() {
        return ceyeDomain;
    }
    
    public void setCeyeDomain(String ceyeDomain) {
        this.ceyeDomain = ceyeDomain;
    }
    
    public String getCeyeToken() {
        return ceyeToken;
    }
    
    public void setCeyeToken(String ceyeToken) {
        this.ceyeToken = ceyeToken;
    }
    
    public int getVerifyTimeout() {
        return verifyTimeout;
    }
    
    public void setVerifyTimeout(int verifyTimeout) {
        this.verifyTimeout = verifyTimeout;
    }
    
    public boolean isPassiveScanEnabled() {
        return passiveScanEnabled;
    }
    
    public void setPassiveScanEnabled(boolean passiveScanEnabled) {
        this.passiveScanEnabled = passiveScanEnabled;
    }
    
    public int getMaxDailyScans() {
        return maxDailyScans;
    }
    
    public void setMaxDailyScans(int maxDailyScans) {
        this.maxDailyScans = maxDailyScans;
    }
    
    public int getMaxHourlyScans() {
        return maxHourlyScans;
    }
    
    public void setMaxHourlyScans(int maxHourlyScans) {
        this.maxHourlyScans = maxHourlyScans;
    }
    
    public int getMaxConcurrentScans() {
        return maxConcurrentScans;
    }
    
    public void setMaxConcurrentScans(int maxConcurrentScans) {
        this.maxConcurrentScans = maxConcurrentScans;
    }
    
    /**
     * 检查配置是否完整
     */
    public boolean isConfigured() {
        return apiKey != null && !apiKey.trim().isEmpty();
    }
}
