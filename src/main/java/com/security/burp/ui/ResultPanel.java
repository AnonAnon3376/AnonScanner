package com.security.burp.ui;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IExtensionHelpers;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;

/**
 * 结果展示面板
 */
public class ResultPanel extends JPanel {
    
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    private DefaultTableModel tableModel;
    private JTable resultTable;
    private JTextArea detailArea;
    private SimpleDateFormat dateFormat;
    private List<String> scanResults;
    
    public ResultPanel(PrintWriter stdout) {
        this.stdout = stdout;
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.scanResults = new ArrayList<>();
        
        initUI();
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
        splitPane.setResizeWeight(0.4);
        
        // 上半部分：结果列表
        splitPane.setTopComponent(createResultListPanel());
        
        // 下半部分：详细信息
        splitPane.setBottomComponent(createDetailPanel());
        
        add(splitPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建结果列表面板
     */
    private JPanel createResultListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("扫描历史"));
        
        // 表格
        String[] columns = {"时间", "URL", "方法", "状态"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        resultTable = new JTable(tableModel);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultTable.getSelectedRow();
                if (selectedRow >= 0) {
                    showDetail(selectedRow);
                }
            }
        });
        
        // 设置列宽
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(400);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        
        JScrollPane scrollPane = new JScrollPane(resultTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 工具栏
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearButton = new JButton("清空历史");
        clearButton.addActionListener(e -> clearResults());
        toolBar.add(clearButton);
        
        panel.add(toolBar, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建详细信息面板
     */
    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("AI分析结果"));
        
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        
        // 修复字体显示问题 - 使用支持中文的字体
        try {
            // 尝试使用系统中文字体
            Font font = new Font("Microsoft YaHei", Font.PLAIN, 13);
            if (font.getFamily().equals("Microsoft YaHei")) {
                detailArea.setFont(font);
            } else {
                // 如果微软雅黑不可用，尝试其他中文字体
                font = new Font("SimSun", Font.PLAIN, 13);
                if (font.getFamily().equals("SimSun")) {
                    detailArea.setFont(font);
                } else {
                    // 使用默认对话框字体
                    detailArea.setFont(new Font("Dialog", Font.PLAIN, 13));
                }
            }
        } catch (Exception e) {
            // 如果设置字体失败，使用默认字体
            detailArea.setFont(new Font("Dialog", Font.PLAIN, 13));
        }
        
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        
        JScrollPane scrollPane = new JScrollPane(detailArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // 工具栏
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton copyButton = new JButton("复制结果");
        copyButton.addActionListener(e -> copyToClipboard());
        toolBar.add(copyButton);
        
        JButton exportButton = new JButton("导出报告");
        exportButton.addActionListener(e -> exportReport());
        toolBar.add(exportButton);
        
        panel.add(toolBar, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 添加扫描开始记录
     */
    public void addScanStart(IHttpRequestResponse message) {
        try {
            if (helpers == null) {
                stdout.println("[-] Helpers未初始化");
                return;
            }
            
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            String url = requestInfo.getUrl().toString();
            String method = requestInfo.getMethod();
            String time = dateFormat.format(new Date());
            
            tableModel.addRow(new Object[]{time, url, method, "扫描中..."});
            
            // 自动选中最新的一行
            int lastRow = tableModel.getRowCount() - 1;
            resultTable.setRowSelectionInterval(lastRow, lastRow);
            resultTable.scrollRectToVisible(resultTable.getCellRect(lastRow, 0, true));
            
        } catch (Exception e) {
            stdout.println("[-] 添加扫描记录失败: " + e.getMessage());
        }
    }
    
    /**
     * 添加扫描结果
     */
    public void addScanResult(IHttpRequestResponse message, String result) {
        try {
            int lastRow = tableModel.getRowCount() - 1;
            if (lastRow >= 0) {
                tableModel.setValueAt("完成", lastRow, 3);
            }
            
            // 保存结果
            scanResults.add(result);
            
            // 显示结果
            detailArea.setText(result);
            detailArea.setCaretPosition(0);
            
        } catch (Exception e) {
            stdout.println("[-] 添加扫描结果失败: " + e.getMessage());
        }
    }
    
    /**
     * 显示详细信息
     */
    private void showDetail(int row) {
        try {
            if (row >= 0 && row < scanResults.size()) {
                detailArea.setText(scanResults.get(row));
                detailArea.setCaretPosition(0);
            }
        } catch (Exception e) {
            stdout.println("[-] 显示详情失败: " + e.getMessage());
        }
    }
    
    /**
     * 清空结果
     */
    private void clearResults() {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "确定要清空所有扫描历史吗？",
            "确认",
            JOptionPane.YES_NO_OPTION
        );
        
        if (confirm == JOptionPane.YES_OPTION) {
            tableModel.setRowCount(0);
            scanResults.clear();
            detailArea.setText("");
            stdout.println("[*] 已清空扫描历史");
        }
    }
    
    /**
     * 复制到剪贴板
     */
    private void copyToClipboard() {
        String text = detailArea.getText();
        if (text != null && !text.isEmpty()) {
            StringSelection selection = new StringSelection(text);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            JOptionPane.showMessageDialog(this, "已复制到剪贴板！", "提示", JOptionPane.INFORMATION_MESSAGE);
            stdout.println("[+] 结果已复制到剪贴板");
        }
    }
    
    /**
     * 导出报告
     */
    private void exportReport() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出报告");
        fileChooser.setSelectedFile(new java.io.File("AI_Security_Report_" + 
            new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".txt"));
        
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                java.nio.file.Files.write(file.toPath(), detailArea.getText().getBytes("UTF-8"));
                JOptionPane.showMessageDialog(this, "报告已导出到：\n" + file.getAbsolutePath(), 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                stdout.println("[+] 报告已导出: " + file.getAbsolutePath());
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "导出失败：" + e.getMessage(), 
                    "错误", JOptionPane.ERROR_MESSAGE);
                stdout.println("[-] 导出报告失败: " + e.getMessage());
            }
        }
    }
}
