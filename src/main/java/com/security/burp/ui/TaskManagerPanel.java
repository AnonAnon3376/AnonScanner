package com.security.burp.ui;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IExtensionHelpers;
import com.security.burp.scanner.ScanTask;
import com.security.burp.scanner.ScanTaskManager;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.List;

/**
 * 任务管理面板 - 类似Burp的表格展示
 */
public class TaskManagerPanel extends JPanel {
    
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    private ScanTaskManager taskManager;
    private DefaultTableModel tableModel;
    private JTable taskTable;
    private JTextArea detailArea;
    private SimpleDateFormat dateFormat;
    private Timer refreshTimer;
    
    public TaskManagerPanel(PrintWriter stdout, ScanTaskManager taskManager) {
        this.stdout = stdout;
        this.taskManager = taskManager;
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        initUI();
        startAutoRefresh();
    }
    
    /**
     * 设置helpers（由BurpExtender调用）
     */
    public void setHelpers(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }
    
    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);
        
        // 上半部分：任务列表
        splitPane.setTopComponent(createTaskListPanel());
        
        // 下半部分：详细信息
        splitPane.setBottomComponent(createDetailPanel());
        
        add(splitPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建任务列表面板
     */
    private JPanel createTaskListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("扫描任务列表"));
        
        // 表格列
        String[] columns = {"#", "时间", "URL", "方法", "状态", "风险", "模式", "耗时(秒)"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 7) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        
        taskTable = new JTable(tableModel);
        taskTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        taskTable.setAutoCreateRowSorter(true);
        taskTable.setRowHeight(25);
        
        // 设置列宽
        taskTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        taskTable.getColumnModel().getColumn(1).setPreferredWidth(140);  // 时间
        taskTable.getColumnModel().getColumn(2).setPreferredWidth(350);  // URL
        taskTable.getColumnModel().getColumn(3).setPreferredWidth(60);   // 方法
        taskTable.getColumnModel().getColumn(4).setPreferredWidth(80);   // 状态
        taskTable.getColumnModel().getColumn(5).setPreferredWidth(80);   // 风险
        taskTable.getColumnModel().getColumn(6).setPreferredWidth(80);   // 模式
        taskTable.getColumnModel().getColumn(7).setPreferredWidth(80);   // 耗时
        
        // 自定义渲染器 - 高亮显示有漏洞的行
        taskTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (!isSelected) {
                    String risk = (String) table.getValueAt(row, 5); // 风险列
                    String status = (String) table.getValueAt(row, 4); // 状态列
                    
                    // 根据风险等级设置背景色
                    if ("高危".equals(risk)) {
                        c.setBackground(new Color(255, 200, 200)); // 浅红色
                        c.setForeground(Color.BLACK);
                    } else if ("中危".equals(risk)) {
                        c.setBackground(new Color(255, 235, 200)); // 浅橙色
                        c.setForeground(Color.BLACK);
                    } else if ("低危".equals(risk)) {
                        c.setBackground(new Color(255, 255, 200)); // 浅黄色
                        c.setForeground(Color.BLACK);
                    } else if ("扫描中".equals(status)) {
                        c.setBackground(new Color(200, 220, 255)); // 浅蓝色
                        c.setForeground(Color.BLACK);
                    } else if ("失败".equals(status)) {
                        c.setBackground(new Color(220, 220, 220)); // 灰色
                        c.setForeground(Color.DARK_GRAY);
                    } else {
                        c.setBackground(Color.WHITE);
                        c.setForeground(Color.BLACK);
                    }
                } else {
                    c.setBackground(table.getSelectionBackground());
                    c.setForeground(table.getSelectionForeground());
                }
                
                // 风险列加粗
                if (column == 5) {
                    setFont(getFont().deriveFont(Font.BOLD));
                } else {
                    setFont(getFont().deriveFont(Font.PLAIN));
                }
                
                return c;
            }
        });
        
        // 选择监听
        taskTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = taskTable.getSelectedRow();
                if (selectedRow >= 0) {
                    showTaskDetail(selectedRow);
                }
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(taskTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 工具栏
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton refreshButton = new JButton("刷新");
        refreshButton.addActionListener(e -> refreshTaskList());
        toolBar.add(refreshButton);
        
        JButton clearButton = new JButton("清空已完成");
        clearButton.addActionListener(e -> clearCompletedTasks());
        toolBar.add(clearButton);
        
        JButton clearAllButton = new JButton("清空全部");
        clearAllButton.addActionListener(e -> clearAllTasks());
        toolBar.add(clearAllButton);
        
        // 统计信息
        JLabel statsLabel = new JLabel();
        statsLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        toolBar.add(Box.createHorizontalStrut(20));
        toolBar.add(statsLabel);
        
        panel.add(toolBar, BorderLayout.SOUTH);
        
        // 定时更新统计信息
        Timer statsTimer = new Timer(1000, e -> {
            if (taskManager != null) {
                int total = taskManager.getTotalScans();
                int today = taskManager.getTodayScans();
                int hour = taskManager.getHourlyScans();
                int running = taskManager.getRunningScans();
                
                statsLabel.setText(String.format(
                    "总计: %d | 今日: %d | 本小时: %d | 运行中: %d",
                    total, today, hour, running
                ));
            }
        });
        statsTimer.start();
        
        return panel;
    }
    
    /**
     * 创建详细信息面板
     */
    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("任务详情"));
        
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font("Microsoft YaHei", Font.PLAIN, 13));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        
        JScrollPane scrollPane = new JScrollPane(detailArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 工具栏
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton copyButton = new JButton("复制详情");
        copyButton.addActionListener(e -> copyDetail());
        toolBar.add(copyButton);
        
        panel.add(toolBar, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 刷新任务列表
     */
    public void refreshTaskList() {
        if (taskManager == null || helpers == null) {
            return;
        }
        
        // 保存当前选中行
        int selectedRow = taskTable.getSelectedRow();
        String selectedTaskId = null;
        if (selectedRow >= 0) {
            selectedTaskId = (String) tableModel.getValueAt(selectedRow, 0);
        }
        
        // 清空表格
        tableModel.setRowCount(0);
        
        // 获取所有任务
        List<ScanTask> tasks = taskManager.getAllTasks();
        
        int index = 1;
        for (ScanTask task : tasks) {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(task.getMessage());
                String url = requestInfo.getUrl().toString();
                String method = requestInfo.getMethod();
                String time = dateFormat.format(task.getStartTime());
                String status = getStatusText(task.getStatus());
                String risk = extractRiskLevel(task.getResult());
                String mode = getModeText(task.getMode());
                
                long duration = 0;
                if (task.getEndTime() != null) {
                    duration = (task.getEndTime().getTime() - task.getStartTime().getTime()) / 1000;
                } else if (task.getStatus() == ScanTask.TaskStatus.RUNNING) {
                    duration = (System.currentTimeMillis() - task.getStartTime().getTime()) / 1000;
                }
                
                tableModel.addRow(new Object[]{
                    index++,
                    time,
                    url,
                    method,
                    status,
                    risk,
                    mode,
                    duration
                });
                
            } catch (Exception e) {
                stdout.println("[-] 刷新任务失败: " + e.getMessage());
            }
        }
        
        // 恢复选中行
        if (selectedTaskId != null) {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                if (selectedTaskId.equals(tableModel.getValueAt(i, 0))) {
                    taskTable.setRowSelectionInterval(i, i);
                    break;
                }
            }
        }
    }
    
    /**
     * 显示任务详情
     */
    private void showTaskDetail(int row) {
        if (taskManager == null || helpers == null) {
            return;
        }
        
        try {
            List<ScanTask> tasks = taskManager.getAllTasks();
            if (row >= 0 && row < tasks.size()) {
                ScanTask task = tasks.get(row);
                
                StringBuilder detail = new StringBuilder();
                detail.append("═══════════════════════════════════════════════════════\n");
                detail.append("任务详情\n");
                detail.append("═══════════════════════════════════════════════════════\n\n");
                
                IRequestInfo requestInfo = helpers.analyzeRequest(task.getMessage());
                detail.append("【请求信息】\n");
                detail.append("URL: ").append(requestInfo.getUrl()).append("\n");
                detail.append("方法: ").append(requestInfo.getMethod()).append("\n");
                detail.append("开始时间: ").append(dateFormat.format(task.getStartTime())).append("\n");
                if (task.getEndTime() != null) {
                    detail.append("结束时间: ").append(dateFormat.format(task.getEndTime())).append("\n");
                    long duration = (task.getEndTime().getTime() - task.getStartTime().getTime()) / 1000;
                    detail.append("耗时: ").append(duration).append(" 秒\n");
                }
                detail.append("状态: ").append(getStatusText(task.getStatus())).append("\n");
                detail.append("模式: ").append(getModeText(task.getMode())).append("\n\n");
                
                if (task.getResult() != null && !task.getResult().isEmpty()) {
                    detail.append("【AI分析结果】\n");
                    detail.append(task.getResult()).append("\n");
                } else if (task.getStatus() == ScanTask.TaskStatus.RUNNING) {
                    detail.append("【AI分析结果】\n");
                    detail.append("正在扫描中，请稍候...\n");
                } else if (task.getStatus() == ScanTask.TaskStatus.FAILED) {
                    detail.append("【AI分析结果】\n");
                    detail.append("扫描失败\n");
                }
                
                detailArea.setText(detail.toString());
                detailArea.setCaretPosition(0);
            }
        } catch (Exception e) {
            stdout.println("[-] 显示任务详情失败: " + e.getMessage());
        }
    }
    
    /**
     * 从结果中提取风险等级
     */
    private String extractRiskLevel(String result) {
        if (result == null || result.isEmpty()) {
            return "-";
        }
        
        String lowerResult = result.toLowerCase();
        
        // 检查是否包含高危关键词
        if (lowerResult.contains("高危") || lowerResult.contains("严重") || 
            lowerResult.contains("critical") || lowerResult.contains("high")) {
            return "高危";
        }
        
        // 检查是否包含中危关键词
        if (lowerResult.contains("中危") || lowerResult.contains("medium")) {
            return "中危";
        }
        
        // 检查是否包含低危关键词
        if (lowerResult.contains("低危") || lowerResult.contains("low")) {
            return "低危";
        }
        
        // 检查是否发现漏洞
        if (lowerResult.contains("漏洞") || lowerResult.contains("vulnerability") ||
            lowerResult.contains("存在") || lowerResult.contains("发现")) {
            return "中危"; // 默认中危
        }
        
        // 检查是否安全
        if (lowerResult.contains("未发现") || lowerResult.contains("安全") || 
            lowerResult.contains("no vulnerability") || lowerResult.contains("safe")) {
            return "安全";
        }
        
        return "-";
    }
    
    /**
     * 获取状态文本
     */
    private String getStatusText(ScanTask.TaskStatus status) {
        switch (status) {
            case PENDING: return "等待中";
            case RUNNING: return "扫描中";
            case COMPLETED: return "已完成";
            case FAILED: return "失败";
            default: return "未知";
        }
    }
    
    /**
     * 获取模式文本
     */
    private String getModeText(ScanTask.ScanMode mode) {
        switch (mode) {
            case MANUAL: return "手动";
            case PASSIVE: return "被动";
            case BATCH: return "批量";
            default: return "未知";
        }
    }
    
    /**
     * 清空已完成的任务
     */
    private void clearCompletedTasks() {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "确定要清空所有已完成的任务吗？",
            "确认",
            JOptionPane.YES_NO_OPTION
        );
        
        if (confirm == JOptionPane.YES_OPTION) {
            if (taskManager != null) {
                taskManager.clearCompletedTasks();
                refreshTaskList();
                detailArea.setText("");
                stdout.println("[*] 已清空已完成的任务");
            }
        }
    }
    
    /**
     * 清空所有任务
     */
    private void clearAllTasks() {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "确定要清空所有任务吗？（包括正在运行的任务）",
            "确认",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        
        if (confirm == JOptionPane.YES_OPTION) {
            if (taskManager != null) {
                taskManager.clearAllTasks();
                refreshTaskList();
                detailArea.setText("");
                stdout.println("[*] 已清空所有任务");
            }
        }
    }
    
    /**
     * 复制详情
     */
    private void copyDetail() {
        String text = detailArea.getText();
        if (text != null && !text.isEmpty()) {
            java.awt.datatransfer.StringSelection selection = 
                new java.awt.datatransfer.StringSelection(text);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            JOptionPane.showMessageDialog(this, "已复制到剪贴板！", "提示", 
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 启动自动刷新
     */
    private void startAutoRefresh() {
        refreshTimer = new Timer(2000, e -> refreshTaskList());
        refreshTimer.start();
    }
    
    /**
     * 停止自动刷新
     */
    public void stopAutoRefresh() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
    }
}
