package com.security.burp;

import burp.*;
import com.security.burp.ui.ConfigPanel;
import com.security.burp.ui.ResultPanel;
import com.security.burp.ui.TaskManagerPanel;
import com.security.burp.scanner.AISecurityScanner;
import com.security.burp.scanner.ScanTask;
import com.security.burp.scanner.ScanTaskManager;
import com.security.burp.scanner.PassiveScanEngine;
import com.security.burp.config.PluginConfig;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Burp AI Security Scanner - 主扩展类
 * 
 * 功能：
 * 1. AI驱动的漏洞检测
 * 2. 支持阿里千问API
 * 3. 专注高危漏洞：反序列化、命令执行、SQL注入、XXE、模板注入、SSRF、文件漏洞
 * 
 * @author Security Team
 * @version 1.0.0
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private JPanel mainPanel;
    private ConfigPanel configPanel;
    private ResultPanel resultPanel;
    private TaskManagerPanel taskManagerPanel;
    private AISecurityScanner scanner;
    private PluginConfig config;
    private ScanTaskManager taskManager;
    private PassiveScanEngine passiveScanEngine;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // 设置扩展名称
        callbacks.setExtensionName("Anon Scanner");
        
        // 初始化配置
        config = new PluginConfig();
        
        // 初始化任务管理器
        taskManager = new ScanTaskManager(stdout);
        taskManager.setMaxDailyScans(config.getMaxDailyScans());
        taskManager.setMaxHourlyScans(config.getMaxHourlyScans());
        taskManager.setMaxConcurrentScans(config.getMaxConcurrentScans());
        
        // 初始化扫描器
        scanner = new AISecurityScanner(callbacks, config);
        
        // 初始化被动扫描引擎
        passiveScanEngine = new PassiveScanEngine(callbacks, config, scanner, taskManager);
        
        // 始终注册被动扫描（在引擎内部检查配置）
        callbacks.registerScannerCheck(passiveScanEngine);
        stdout.println("[+] 被动扫描引擎已注册（状态: " + 
            (config.isPassiveScanEnabled() ? "启用" : "禁用") + "）");
        
        // 初始化UI
        initUI();
        
        // 注册右键菜单
        callbacks.registerContextMenuFactory(this);
        
        // 添加标签页
        callbacks.addSuiteTab(this);
        
        stdout.println("========================================");
        stdout.println("Anon Scanner v1.0.0 已加载");
        stdout.println("========================================");
        stdout.println("支持的漏洞类型：");
        stdout.println("  ✓ 反序列化漏洞 (FastJson/Jackson/XStream/SnakeYAML/Hessian)");
        stdout.println("  ✓ 命令执行漏洞 (Log4j2/Spring4Shell/Struts2/Weblogic/Shiro)");
        stdout.println("  ✓ SQL注入 (MySQL/PostgreSQL/Oracle/MSSQL/MongoDB)");
        stdout.println("  ✓ XXE漏洞 (标准XXE/Blind XXE/SVG/Office文档)");
        stdout.println("  ✓ 模板注入 (Freemarker/Velocity/Thymeleaf/Jinja2)");
        stdout.println("  ✓ SSRF漏洞");
        stdout.println("  ✓ 文件上传漏洞");
        stdout.println("  ✓ 任意文件读取");
        stdout.println("  ✓ 目录遍历");
        stdout.println("========================================");
        stdout.println("使用方法：");
        stdout.println("  1. 在配置标签页填入阿里千问API Key");
        stdout.println("  2. 右键点击HTTP请求");
        stdout.println("  3. 选择 'Send to AI Security Scanner'");
        stdout.println("  4. 在结果标签页查看AI分析结果");
        stdout.println("========================================");
    }
    
    /**
     * 初始化UI界面
     */
    private void initUI() {
        mainPanel = new JPanel(new BorderLayout());
        
        // 创建选项卡面板
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // 配置面板
        configPanel = new ConfigPanel(config, stdout);
        tabbedPane.addTab("配置", configPanel);
        
        // 任务管理面板
        taskManagerPanel = new TaskManagerPanel(stdout, taskManager);
        taskManagerPanel.setHelpers(helpers);
        tabbedPane.addTab("任务管理", taskManagerPanel);
        
        // 结果面板
        resultPanel = new ResultPanel(stdout);
        resultPanel.setHelpers(helpers);  // 传递helpers
        tabbedPane.addTab("扫描结果", resultPanel);
        
        // 移除了使用说明标签页
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建帮助面板
     */
    private JPanel createHelpPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        JTextArea helpText = new JTextArea();
        helpText.setEditable(false);
        helpText.setFont(new Font("Microsoft YaHei", Font.PLAIN, 14));
        helpText.setMargin(new Insets(10, 10, 10, 10));
        
        StringBuilder help = new StringBuilder();
        help.append("═══════════════════════════════════════════════════════\n");
        help.append("          Anon Scanner 使用说明\n");
        help.append("═══════════════════════════════════════════════════════\n\n");
        
        help.append("【功能介绍】\n");
        help.append("本插件使用AI技术自动检测Web应用中的高危安全漏洞。\n\n");
        
        help.append("【支持的漏洞类型】\n\n");
        help.append("1. 反序列化漏洞\n");
        help.append("   • FastJson (1.2.24-1.2.80全版本)\n");
        help.append("   • Jackson\n");
        help.append("   • XStream\n");
        help.append("   • SnakeYAML\n");
        help.append("   • Hessian\n");
        help.append("   • Java原生反序列化\n\n");
        
        help.append("2. 命令执行漏洞\n");
        help.append("   • Log4j2 RCE (CVE-2021-44228)\n");
        help.append("   • Spring4Shell (CVE-2022-22965)\n");
        help.append("   • Struts2系列漏洞\n");
        help.append("   • Weblogic T3/IIOP反序列化\n");
        help.append("   • Shiro反序列化\n\n");
        
        help.append("3. SQL注入\n");
        help.append("   • MySQL/MariaDB注入\n");
        help.append("   • PostgreSQL注入\n");
        help.append("   • Oracle注入\n");
        help.append("   • MSSQL注入\n");
        help.append("   • MongoDB NoSQL注入\n\n");
        
        help.append("4. XXE漏洞\n");
        help.append("   • 标准XXE\n");
        help.append("   • Blind XXE\n");
        help.append("   • XXE via SVG\n");
        help.append("   • XXE via XLSX/DOCX\n\n");
        
        help.append("5. 模板注入\n");
        help.append("   • Freemarker SSTI\n");
        help.append("   • Velocity SSTI\n");
        help.append("   • Thymeleaf SSTI\n");
        help.append("   • Jinja2 SSTI\n\n");
        
        help.append("6. 其他高危漏洞\n");
        help.append("   • SSRF (服务端请求伪造)\n");
        help.append("   • 文件上传漏洞\n");
        help.append("   • 任意文件读取\n");
        help.append("   • 目录遍历\n\n");
        
        help.append("【使用步骤】\n\n");
        help.append("步骤1：配置API\n");
        help.append("  1. 点击「配置」标签页\n");
        help.append("  2. 填入阿里千问API Key\n");
        help.append("  3. 点击「测试连接」验证配置\n");
        help.append("  4. 点击「保存配置」\n\n");
        
        help.append("步骤2：扫描请求\n");
        help.append("  1. 在Burp的任意位置找到HTTP请求\n");
        help.append("  2. 右键点击请求\n");
        help.append("  3. 选择「Send to Anon Scanner」\n");
        help.append("  4. 等待AI分析（通常5-15秒）\n\n");
        
        help.append("步骤3：查看结果\n");
        help.append("  1. 点击「扫描结果」标签页\n");
        help.append("  2. 查看AI识别的漏洞\n");
        help.append("  3. 复制建议的Payload进行验证\n");
        help.append("  4. 根据修复建议加固应用\n\n");
        
        help.append("【配置说明】\n\n");
        help.append("AI提供商：\n");
        help.append("  • 阿里千问 - qwen-plus / qwen-max / qwen-turbo\n");
        help.append("  • DeepSeek - deepseek-chat / deepseek-coder\n");
        help.append("  • 智谱AI - glm-4 / glm-4-flash / glm-3-turbo\n");
        help.append("  • 字节豆包 - doubao-pro-32k / doubao-lite-32k\n");
        help.append("  • OpenAI - gpt-4o / gpt-4o-mini / gpt-3.5-turbo\n");
        help.append("  • 月之暗面 - moonshot-v1-8k / moonshot-v1-32k\n");
        help.append("  • 百川智能 - Baichuan2-Turbo / Baichuan2-53B\n");
        help.append("  • 零一万物 - yi-large / yi-medium / yi-spark\n");
        help.append("  • 自定义 - 任意兼容OpenAI格式的API\n\n");
        
        help.append("API配置：\n");
        help.append("  • AI提供商: 从下拉列表选择或选择自定义\n");
        help.append("  • Base URL: 选择提供商后自动填充\n");
        help.append("  • API Key: 从对应平台获取\n");
        help.append("  • Model: 选择提供商后自动填充推荐模型\n");
        help.append("  • Max Tokens: 4000 (默认)\n");
        help.append("  • Temperature: 0.7 (默认)\n\n");
        
        help.append("扫描选项：\n");
        help.append("  • 深度分析：更详细的漏洞分析（耗时更长）\n");
        help.append("  • 生成Payload：自动生成针对性的攻击载荷\n");
        help.append("  • 风险评估：评估漏洞的危害等级\n\n");
        
        help.append("【注意事项】\n\n");
        help.append("⚠ 仅在授权测试中使用本插件\n");
        help.append("⚠ AI分析结果需要人工验证\n");
        help.append("⚠ 建议在测试环境中先验证Payload\n");
        help.append("⚠ 保护好API Key，避免泄露\n");
        help.append("⚠ 注意API调用成本（阿里千问约¥0.004/千tokens）\n\n");
        
        help.append("【常见问题】\n\n");
        help.append("Q: 支持哪些AI模型？\n");
        help.append("A: 支持阿里千问、DeepSeek、智谱AI、字节豆包、OpenAI、\n");
        help.append("   月之暗面、百川智能、零一万物，以及任意兼容OpenAI格式的API\n\n");
        
        help.append("Q: 测试连接失败？\n");
        help.append("A: 检查API Key是否正确，网络是否能访问对应的API服务\n\n");
        
        help.append("Q: 扫描没有结果？\n");
        help.append("A: 可能请求不包含可疑参数，或AI未识别到漏洞\n\n");
        
        help.append("Q: 如何使用自定义API？\n");
        help.append("A: 选择「自定义」提供商，手动填写Base URL、API Key和Model名称\n\n");
        
        help.append("═══════════════════════════════════════════════════════\n");
        help.append("                    版本: 1.0.0\n");
        help.append("                    作者: Security Team\n");
        help.append("═══════════════════════════════════════════════════════\n");
        
        helpText.setText(help.toString());
        
        JScrollPane scrollPane = new JScrollPane(helpText);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    @Override
    public String getTabCaption() {
        return "Anon Scanner";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        // 只在请求上下文中显示菜单
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE) {
            
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            
            // 单个请求扫描
            JMenuItem singleScanItem = new JMenuItem("Send to Anon Scanner");
            singleScanItem.addActionListener(e -> {
                if (messages != null && messages.length > 0) {
                    scanRequest(messages[0]);
                }
            });
            menuItems.add(singleScanItem);
            
            // 批量扫描（如果选择了多个请求）
            if (messages != null && messages.length > 1) {
                JMenuItem batchScanItem = new JMenuItem("Batch Scan (" + messages.length + " requests)");
                batchScanItem.addActionListener(e -> {
                    batchScanRequests(messages);
                });
                menuItems.add(batchScanItem);
            }
        }
        
        return menuItems;
    }
    
    /**
     * 扫描HTTP请求
     */
    private void scanRequest(IHttpRequestResponse message) {
        // 检查配置
        if (!config.isConfigured()) {
            JOptionPane.showMessageDialog(mainPanel,
                "请先在「配置」标签页中配置阿里千问API Key！",
                "配置错误",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // 在新线程中执行扫描
        new Thread(() -> {
            try {
                stdout.println("\n[*] 开始AI安全扫描...");
                
                // 显示进度
                SwingUtilities.invokeLater(() -> {
                    resultPanel.addScanStart(message);
                });
                
                // 执行扫描
                String result = scanner.scan(message);
                
                // 显示结果
                SwingUtilities.invokeLater(() -> {
                    resultPanel.addScanResult(message, result);
                });
                
                stdout.println("[+] AI安全扫描完成");
                
            } catch (Exception e) {
                stderr.println("[-] 扫描失败: " + e.getMessage());
                e.printStackTrace(stderr);
                
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel,
                        "扫描失败: " + e.getMessage(),
                        "错误",
                        JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }
    
    /**
     * 批量扫描HTTP请求
     */
    private void batchScanRequests(IHttpRequestResponse[] messages) {
        // 检查配置
        if (!config.isConfigured()) {
            JOptionPane.showMessageDialog(mainPanel,
                "请先在「配置」标签页中配置AI API Key！",
                "配置错误",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // 确认批量扫描
        int confirm = JOptionPane.showConfirmDialog(mainPanel,
            "确定要批量扫描 " + messages.length + " 个请求吗？\n" +
            "这可能会消耗较多API额度。",
            "批量扫描确认",
            JOptionPane.YES_NO_OPTION);
        
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }
        
        stdout.println("\n[*] 开始批量扫描: " + messages.length + " 个请求");
        
        // 在新线程中执行批量扫描
        new Thread(() -> {
            int successCount = 0;
            int failCount = 0;
            
            for (int i = 0; i < messages.length; i++) {
                final int index = i;
                final IHttpRequestResponse message = messages[i];
                
                try {
                    stdout.println("[*] 扫描进度: " + (i + 1) + "/" + messages.length);
                    
                    // 添加到任务队列
                    String taskId = taskManager.addTask(message, ScanTask.ScanMode.BATCH);
                    
                    if (taskId != null) {
                        // 执行扫描
                        String result = scanner.scan(message);
                        
                        // 更新任务状态
                        ScanTask task = taskManager.getTask(taskId);
                        if (task != null) {
                            task.setResult(result);
                            task.setStatus(ScanTask.TaskStatus.COMPLETED);
                        }
                        
                        // 显示结果
                        SwingUtilities.invokeLater(() -> {
                            resultPanel.addScanResult(message, result);
                        });
                        
                        successCount++;
                        
                        // 间隔1秒，避免API限流
                        if (i < messages.length - 1) {
                            Thread.sleep(1000);
                        }
                    } else {
                        failCount++;
                        stdout.println("[-] 任务被拒绝（可能达到扫描限制）");
                    }
                    
                } catch (Exception e) {
                    failCount++;
                    stdout.println("[-] 扫描失败: " + e.getMessage());
                }
            }
            
            final int finalSuccess = successCount;
            final int finalFail = failCount;
            
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "批量扫描完成！\n" +
                    "成功: " + finalSuccess + " 个\n" +
                    "失败: " + finalFail + " 个",
                    "批量扫描完成",
                    JOptionPane.INFORMATION_MESSAGE);
            });
            
            stdout.println("[+] 批量扫描完成: 成功 " + finalSuccess + ", 失败 " + finalFail);
            
        }).start();
    }
}
