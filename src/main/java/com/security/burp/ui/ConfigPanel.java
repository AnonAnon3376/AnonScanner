package com.security.burp.ui;

import com.security.burp.config.PluginConfig;
import com.security.burp.ai.QianwenAIClient;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;

/**
 * 配置面板
 */
public class ConfigPanel extends JPanel {
    
    private PluginConfig config;
    private PrintWriter stdout;
    
    private JComboBox<PluginConfig.AIProvider> providerComboBox;
    private JTextField apiBaseUrlField;
    private JPasswordField apiKeyField;
    private JTextField modelField;
    private JSpinner maxTokensSpinner;
    private JSpinner temperatureSpinner;
    
    private JCheckBox deepAnalysisCheckBox;
    private JCheckBox generatePayloadCheckBox;
    private JCheckBox riskAssessmentCheckBox;
    
    // 验证选项（新增）
    private JCheckBox autoVerifyCheckBox;
    private JComboBox<String> dnsLogProviderComboBox;
    private JTextField ceyeDomainField;
    private JTextField ceyeTokenField;
    private JSpinner verifyTimeoutSpinner;
    
    // 被动扫描选项（新增）
    private JCheckBox passiveScanCheckBox;
    
    // 成本控制（新增）
    private JSpinner maxDailyScansSpinner;
    private JSpinner maxHourlyScansSpinner;
    private JSpinner maxConcurrentScansSpinner;
    
    private JButton testButton;
    private JButton saveButton;
    private JLabel statusLabel;
    
    public ConfigPanel(PluginConfig config, PrintWriter stdout) {
        this.config = config;
        this.stdout = stdout;
        
        initUI();
    }
    
    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        // 主面板
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        // API配置区域
        mainPanel.add(createApiConfigPanel());
        mainPanel.add(Box.createVerticalStrut(20));
        
        // 扫描选项区域
        mainPanel.add(createScanOptionsPanel());
        mainPanel.add(Box.createVerticalStrut(20));
        
        // 验证选项区域（新增）
        mainPanel.add(createVerifyOptionsPanel());
        mainPanel.add(Box.createVerticalStrut(20));
        
        // 被动扫描选项区域（新增）
        mainPanel.add(createPassiveScanPanel());
        mainPanel.add(Box.createVerticalStrut(20));
        
        // 成本控制区域（新增）
        mainPanel.add(createCostControlPanel());
        mainPanel.add(Box.createVerticalStrut(20));
        
        // 按钮区域
        mainPanel.add(createButtonPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        
        // 状态标签
        statusLabel = new JLabel(" ");
        statusLabel.setFont(new Font("Microsoft YaHei", Font.BOLD, 14));
        mainPanel.add(statusLabel);
        
        // 添加滚动条支持
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        add(scrollPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建API配置面板
     */
    private JPanel createApiConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), 
            "AI模型配置",
            0, 0,
            new Font("Microsoft YaHei", Font.BOLD, 14)
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // AI提供商选择
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("AI提供商:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        providerComboBox = new JComboBox<>(PluginConfig.AIProvider.values());
        providerComboBox.setSelectedItem(config.getProvider());
        providerComboBox.addActionListener(e -> onProviderChanged());
        panel.add(providerComboBox, gbc);
        
        // Base URL
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Base URL:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        apiBaseUrlField = new JTextField(config.getApiBaseUrl(), 40);
        panel.add(apiBaseUrlField, gbc);
        
        // API Key
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("API Key:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(config.getApiKey(), 40);
        panel.add(apiKeyField, gbc);
        
        // Model
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Model:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        modelField = new JTextField(config.getModel(), 40);
        panel.add(modelField, gbc);
        
        // Max Tokens
        gbc.gridx = 0; gbc.gridy = 4; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        panel.add(new JLabel("Max Tokens:"), gbc);
        
        gbc.gridx = 1;
        maxTokensSpinner = new JSpinner(new SpinnerNumberModel(config.getMaxTokens(), 1000, 10000, 500));
        panel.add(maxTokensSpinner, gbc);
        
        // Temperature
        gbc.gridx = 0; gbc.gridy = 5;
        panel.add(new JLabel("Temperature:"), gbc);
        
        gbc.gridx = 1;
        temperatureSpinner = new JSpinner(new SpinnerNumberModel(config.getTemperature(), 0.0, 1.0, 0.1));
        panel.add(temperatureSpinner, gbc);
        
        // 说明文字
        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 2;
        JLabel helpLabel = new JLabel("<html><font color='gray'>" +
            "提示：选择AI提供商后会自动填充默认配置，也可以选择「自定义」手动填写任意兼容OpenAI格式的API" +
            "</font></html>");
        panel.add(helpLabel, gbc);
        
        return panel;
    }
    
    /**
     * AI提供商改变时的处理
     */
    private void onProviderChanged() {
        PluginConfig.AIProvider provider = (PluginConfig.AIProvider) providerComboBox.getSelectedItem();
        if (provider != null && provider != PluginConfig.AIProvider.CUSTOM) {
            // 自动填充默认配置
            apiBaseUrlField.setText(provider.getDefaultBaseUrl());
            modelField.setText(provider.getDefaultModel());
            
            // 如果是自定义，启用所有字段编辑
            boolean isCustom = (provider == PluginConfig.AIProvider.CUSTOM);
            apiBaseUrlField.setEnabled(true);
            modelField.setEnabled(true);
        }
    }
    
    /**
     * 创建扫描选项面板
     */
    private JPanel createScanOptionsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "扫描选项",
            0, 0,
            new Font("Microsoft YaHei", Font.BOLD, 14)
        ));
        
        deepAnalysisCheckBox = new JCheckBox("深度分析（更详细的漏洞分析，耗时更长）", config.isDeepAnalysis());
        generatePayloadCheckBox = new JCheckBox("生成Payload（自动生成针对性的攻击载荷）", config.isGeneratePayload());
        riskAssessmentCheckBox = new JCheckBox("风险评估（评估漏洞的危害等级）", config.isRiskAssessment());
        
        panel.add(deepAnalysisCheckBox);
        panel.add(generatePayloadCheckBox);
        panel.add(riskAssessmentCheckBox);
        
        return panel;
    }
    
    /**
     * 创建验证选项面板（新增）
     */
    private JPanel createVerifyOptionsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "自动验证选项（混合模式）",
            0, 0,
            new Font("Microsoft YaHei", Font.BOLD, 14)
        ));
        
        // 启用自动验证
        autoVerifyCheckBox = new JCheckBox("启用自动验证（AI分析后自动发送测试请求）", config.isAutoVerify());
        autoVerifyCheckBox.addActionListener(e -> updateVerifyOptionsState());
        panel.add(autoVerifyCheckBox);
        
        panel.add(Box.createVerticalStrut(10));
        
        // 反连平台选择
        JPanel providerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        providerPanel.add(new JLabel("反连平台:"));
        String[] providers = {"DNSLOG_CN（推荐，免费）", "CEYE_IO（需注册）", "自定义"};
        dnsLogProviderComboBox = new JComboBox<>(providers);
        dnsLogProviderComboBox.setSelectedIndex(0);
        dnsLogProviderComboBox.addActionListener(e -> updateCeyeFieldsState());
        providerPanel.add(dnsLogProviderComboBox);
        panel.add(providerPanel);
        
        // Ceye配置
        JPanel ceyePanel = new JPanel(new GridLayout(2, 2, 5, 5));
        ceyePanel.add(new JLabel("  Ceye域名:"));
        ceyeDomainField = new JTextField(config.getCeyeDomain(), 20);
        ceyePanel.add(ceyeDomainField);
        ceyePanel.add(new JLabel("  Ceye Token:"));
        ceyeTokenField = new JTextField(config.getCeyeToken(), 20);
        ceyePanel.add(ceyeTokenField);
        panel.add(ceyePanel);
        
        panel.add(Box.createVerticalStrut(10));
        
        // 验证超时
        JPanel timeoutPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        timeoutPanel.add(new JLabel("验证超时:"));
        verifyTimeoutSpinner = new JSpinner(new SpinnerNumberModel(config.getVerifyTimeout(), 1, 30, 1));
        timeoutPanel.add(verifyTimeoutSpinner);
        timeoutPanel.add(new JLabel("秒"));
        panel.add(timeoutPanel);
        
        // 初始化状态
        updateVerifyOptionsState();
        updateCeyeFieldsState();
        
        return panel;
    }
    
    /**
     * 更新验证选项状态
     */
    private void updateVerifyOptionsState() {
        boolean enabled = autoVerifyCheckBox.isSelected();
        dnsLogProviderComboBox.setEnabled(enabled);
        ceyeDomainField.setEnabled(enabled);
        ceyeTokenField.setEnabled(enabled);
        verifyTimeoutSpinner.setEnabled(enabled);
    }
    
    /**
     * 更新Ceye字段状态
     */
    private void updateCeyeFieldsState() {
        boolean isCeye = dnsLogProviderComboBox.getSelectedIndex() == 1;
        ceyeDomainField.setEnabled(isCeye && autoVerifyCheckBox.isSelected());
        ceyeTokenField.setEnabled(isCeye && autoVerifyCheckBox.isSelected());
    }
    
    /**
     * 创建被动扫描面板（新增）
     */
    private JPanel createPassiveScanPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "被动扫描选项",
            0, 0,
            new Font("Microsoft YaHei", Font.BOLD, 14)
        ));
        
        passiveScanCheckBox = new JCheckBox("启用被动扫描（自动监控HTTP流量并分析）", config.isPassiveScanEnabled());
        panel.add(passiveScanCheckBox);
        
        return panel;
    }
    
    /**
     * 创建成本控制面板（新增）
     */
    private JPanel createCostControlPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "成本控制",
            0, 0,
            new Font("Microsoft YaHei", Font.BOLD, 14)
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // 每日最大扫描数
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("每日最大扫描数:"), gbc);
        
        gbc.gridx = 1;
        maxDailyScansSpinner = new JSpinner(new SpinnerNumberModel(config.getMaxDailyScans(), 10, 1000, 10));
        panel.add(maxDailyScansSpinner, gbc);
        
        gbc.gridx = 2;
        panel.add(new JLabel("次/天"), gbc);
        
        // 每小时最大扫描数
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new JLabel("每小时最大扫描数:"), gbc);
        
        gbc.gridx = 1;
        maxHourlyScansSpinner = new JSpinner(new SpinnerNumberModel(config.getMaxHourlyScans(), 5, 100, 5));
        panel.add(maxHourlyScansSpinner, gbc);
        
        gbc.gridx = 2;
        panel.add(new JLabel("次/小时"), gbc);
        
        // 并发扫描数
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(new JLabel("最大并发扫描数:"), gbc);
        
        gbc.gridx = 1;
        maxConcurrentScansSpinner = new JSpinner(new SpinnerNumberModel(config.getMaxConcurrentScans(), 1, 10, 1));
        panel.add(maxConcurrentScansSpinner, gbc);
        
        gbc.gridx = 2;
        panel.add(new JLabel("个"), gbc);
        
        return panel;
    }
    
    /**
     * 创建按钮面板
     */
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        testButton = new JButton("测试连接");
        testButton.addActionListener(e -> testConnection());
        
        saveButton = new JButton("保存配置");
        saveButton.addActionListener(e -> saveConfig());
        
        panel.add(testButton);
        panel.add(saveButton);
        
        return panel;
    }
    
    /**
     * 测试连接
     */
    private void testConnection() {
        // 先保存配置
        updateConfig();
        
        if (!config.isConfigured()) {
            showStatus("请先填写API Key！", Color.RED);
            return;
        }
        
        testButton.setEnabled(false);
        testButton.setText("测试中...");
        statusLabel.setText("正在测试连接...");
        statusLabel.setForeground(Color.BLUE);
        
        new Thread(() -> {
            try {
                QianwenAIClient client = new QianwenAIClient(config);
                StringBuilder errorMessage = new StringBuilder();
                boolean success = client.testConnection(errorMessage);
                
                SwingUtilities.invokeLater(() -> {
                    if (success) {
                        showStatus("✅ 连接成功！", Color.GREEN);
                        stdout.println("[+] API连接测试成功");
                    } else {
                        String error = errorMessage.length() > 0 ? errorMessage.toString() : "连接失败";
                        showStatus("❌ 连接失败：" + error, Color.RED);
                        stdout.println("[-] API连接测试失败: " + error);
                        
                        // 显示详细的调试信息
                        stdout.println("[调试信息] 配置详情:");
                        stdout.println("  AI提供商: " + config.getProvider());
                        stdout.println("  Base URL: " + config.getApiBaseUrl());
                        stdout.println("  Model: " + config.getModel());
                        stdout.println("  API Key: " + (config.getApiKey().length() > 10 ? 
                            config.getApiKey().substring(0, 10) + "..." : "太短"));
                        
                        // 显示最终请求URL
                        String baseUrl = config.getApiBaseUrl().trim();
                        String finalUrl;
                        if (baseUrl.contains("/chat/completions") || baseUrl.contains("/completions")) {
                            finalUrl = baseUrl;
                        } else {
                            if (!baseUrl.endsWith("/")) {
                                baseUrl += "/";
                            }
                            finalUrl = baseUrl + "chat/completions";
                        }
                        stdout.println("  最终请求URL: " + finalUrl);
                    }
                    testButton.setEnabled(true);
                    testButton.setText("测试连接");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    showStatus("❌ 连接失败：" + ex.getMessage(), Color.RED);
                    stdout.println("[-] API连接测试失败: " + ex.getMessage());
                    ex.printStackTrace(new java.io.PrintWriter(System.err));
                    testButton.setEnabled(true);
                    testButton.setText("测试连接");
                });
            }
        }).start();
    }
    
    /**
     * 保存配置
     */
    private void saveConfig() {
        updateConfig();
        showStatus("✅ 配置已保存", Color.GREEN);
        stdout.println("[+] 配置已保存");
    }
    
    /**
     * 更新配置对象
     */
    private void updateConfig() {
        config.setProvider((PluginConfig.AIProvider) providerComboBox.getSelectedItem());
        config.setApiBaseUrl(apiBaseUrlField.getText().trim());
        config.setApiKey(new String(apiKeyField.getPassword()).trim());
        config.setModel(modelField.getText().trim());
        config.setMaxTokens((Integer) maxTokensSpinner.getValue());
        config.setTemperature((Double) temperatureSpinner.getValue());
        
        config.setDeepAnalysis(deepAnalysisCheckBox.isSelected());
        config.setGeneratePayload(generatePayloadCheckBox.isSelected());
        config.setRiskAssessment(riskAssessmentCheckBox.isSelected());
        
        // 验证选项（新增）
        config.setAutoVerify(autoVerifyCheckBox.isSelected());
        String provider = "DNSLOG_CN";
        if (dnsLogProviderComboBox.getSelectedIndex() == 1) {
            provider = "CEYE_IO";
        } else if (dnsLogProviderComboBox.getSelectedIndex() == 2) {
            provider = "CUSTOM";
        }
        config.setDnsLogProvider(provider);
        config.setCeyeDomain(ceyeDomainField.getText().trim());
        config.setCeyeToken(ceyeTokenField.getText().trim());
        config.setVerifyTimeout((Integer) verifyTimeoutSpinner.getValue());
        
        // 被动扫描选项（新增）
        config.setPassiveScanEnabled(passiveScanCheckBox.isSelected());
        
        // 成本控制（新增）
        config.setMaxDailyScans((Integer) maxDailyScansSpinner.getValue());
        config.setMaxHourlyScans((Integer) maxHourlyScansSpinner.getValue());
        config.setMaxConcurrentScans((Integer) maxConcurrentScansSpinner.getValue());
    }
    
    /**
     * 显示状态信息
     */
    private void showStatus(String message, Color color) {
        statusLabel.setText(message);
        statusLabel.setForeground(color);
    }
}
