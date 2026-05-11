package com.security.burp.scanner;

import burp.IHttpRequestResponse;
import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.*;

/**
 * 扫描任务管理器
 */
public class ScanTaskManager {
    
    private PrintWriter stdout;
    private Map<String, ScanTask> tasks;
    private Queue<ScanTask> taskQueue;
    private ExecutorService executorService;
    private boolean running;
    
    // 统计信息
    private int totalScans;
    private int todayScans;
    private int hourlyScans;
    private Date lastResetDate;
    private Date lastHourlyReset;
    
    // 限制配置
    private int maxDailyScans = 100;
    private int maxHourlyScans = 20;
    private int maxConcurrentScans = 3;
    
    public ScanTaskManager(PrintWriter stdout) {
        this.stdout = stdout;
        this.tasks = new ConcurrentHashMap<>();
        this.taskQueue = new ConcurrentLinkedQueue<>();
        this.executorService = Executors.newFixedThreadPool(maxConcurrentScans);
        this.running = true;
        this.lastResetDate = new Date();
        this.lastHourlyReset = new Date();
        
        // 启动任务处理线程
        startTaskProcessor();
    }
    
    /**
     * 添加扫描任务
     */
    public String addTask(IHttpRequestResponse message, ScanTask.ScanMode scanMode) {
        // 检查限制
        if (!checkLimits()) {
            stdout.println("[-] 已达到扫描限制，任务被拒绝");
            return null;
        }
        
        String taskId = generateTaskId();
        ScanTask task = new ScanTask(taskId, message, scanMode);
        
        tasks.put(taskId, task);
        taskQueue.offer(task);
        
        stdout.println("[+] 添加扫描任务: " + taskId + " (" + scanMode.getDisplayName() + ")");
        
        return taskId;
    }
    
    /**
     * 批量添加任务
     */
    public List<String> addBatchTasks(List<IHttpRequestResponse> messages, ScanTask.ScanMode scanMode) {
        List<String> taskIds = new ArrayList<>();
        
        for (IHttpRequestResponse message : messages) {
            String taskId = addTask(message, scanMode);
            if (taskId != null) {
                taskIds.add(taskId);
            }
        }
        
        stdout.println("[+] 批量添加任务: " + taskIds.size() + " 个");
        
        return taskIds;
    }
    
    /**
     * 获取任务
     */
    public ScanTask getTask(String taskId) {
        return tasks.get(taskId);
    }
    
    /**
     * 获取所有任务
     */
    public List<ScanTask> getAllTasks() {
        return new ArrayList<>(tasks.values());
    }
    
    /**
     * 获取待处理任务数
     */
    public int getPendingTaskCount() {
        return taskQueue.size();
    }
    
    /**
     * 获取运行中任务数
     */
    public int getRunningTaskCount() {
        return (int) tasks.values().stream()
                .filter(t -> t.getStatus() == ScanTask.TaskStatus.RUNNING)
                .count();
    }
    
    /**
     * 取消任务
     */
    public boolean cancelTask(String taskId) {
        ScanTask task = tasks.get(taskId);
        if (task != null && task.getStatus() == ScanTask.TaskStatus.PENDING) {
            task.setStatus(ScanTask.TaskStatus.CANCELLED);
            taskQueue.remove(task);
            stdout.println("[*] 任务已取消: " + taskId);
            return true;
        }
        return false;
    }
    
    /**
     * 清空所有任务
     */
    public void clearAllTasks() {
        tasks.clear();
        taskQueue.clear();
        stdout.println("[*] 已清空所有任务");
    }
    
    /**
     * 清空已完成的任务
     */
    public void clearCompletedTasks() {
        List<String> toRemove = new ArrayList<>();
        for (Map.Entry<String, ScanTask> entry : tasks.entrySet()) {
            if (entry.getValue().getStatus() == ScanTask.TaskStatus.COMPLETED ||
                entry.getValue().getStatus() == ScanTask.TaskStatus.FAILED ||
                entry.getValue().getStatus() == ScanTask.TaskStatus.CANCELLED) {
                toRemove.add(entry.getKey());
            }
        }
        
        for (String taskId : toRemove) {
            tasks.remove(taskId);
        }
        
        stdout.println("[*] 已清空 " + toRemove.size() + " 个已完成的任务");
    }
    
    /**
     * 获取总扫描数
     */
    public int getTotalScans() {
        return totalScans;
    }
    
    /**
     * 获取今日扫描数
     */
    public int getTodayScans() {
        return todayScans;
    }
    
    /**
     * 获取本小时扫描数
     */
    public int getHourlyScans() {
        return hourlyScans;
    }
    
    /**
     * 获取运行中的扫描数
     */
    public int getRunningScans() {
        return getRunningTaskCount();
    }
    
    /**
     * 检查扫描限制
     */
    private boolean checkLimits() {
        // 重置每日计数
        Calendar cal = Calendar.getInstance();
        cal.setTime(lastResetDate);
        Calendar now = Calendar.getInstance();
        
        if (cal.get(Calendar.DAY_OF_YEAR) != now.get(Calendar.DAY_OF_YEAR)) {
            todayScans = 0;
            lastResetDate = new Date();
        }
        
        // 重置每小时计数
        long hoursDiff = (new Date().getTime() - lastHourlyReset.getTime()) / (60 * 60 * 1000);
        if (hoursDiff >= 1) {
            hourlyScans = 0;
            lastHourlyReset = new Date();
        }
        
        // 检查限制
        if (todayScans >= maxDailyScans) {
            stdout.println("[-] 已达到每日扫描限制: " + maxDailyScans);
            return false;
        }
        
        if (hourlyScans >= maxHourlyScans) {
            stdout.println("[-] 已达到每小时扫描限制: " + maxHourlyScans);
            return false;
        }
        
        return true;
    }
    
    /**
     * 启动任务处理线程
     */
    private void startTaskProcessor() {
        Thread processor = new Thread(() -> {
            while (running) {
                try {
                    ScanTask task = taskQueue.poll();
                    if (task != null) {
                        // 提交任务到线程池
                        executorService.submit(() -> processTask(task));
                    } else {
                        Thread.sleep(1000); // 队列为空时等待
                    }
                } catch (Exception e) {
                    stdout.println("[-] 任务处理异常: " + e.getMessage());
                }
            }
        });
        processor.setDaemon(true);
        processor.start();
    }
    
    /**
     * 处理任务（占位方法，实际由Scanner调用）
     */
    private void processTask(ScanTask task) {
        task.setStatus(ScanTask.TaskStatus.RUNNING);
        totalScans++;
        todayScans++;
        hourlyScans++;
        
        // 实际扫描逻辑由AISecurityScanner处理
        // 这里只是更新状态
    }
    
    /**
     * 生成任务ID
     */
    private String generateTaskId() {
        return "TASK-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
    }
    
    /**
     * 获取统计信息
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalScans", totalScans);
        stats.put("todayScans", todayScans);
        stats.put("hourlyScans", hourlyScans);
        stats.put("pendingTasks", getPendingTaskCount());
        stats.put("runningTasks", getRunningTaskCount());
        stats.put("maxDailyScans", maxDailyScans);
        stats.put("maxHourlyScans", maxHourlyScans);
        stats.put("remainingDaily", maxDailyScans - todayScans);
        stats.put("remainingHourly", maxHourlyScans - hourlyScans);
        return stats;
    }
    
    /**
     * 设置限制
     */
    public void setMaxDailyScans(int max) {
        this.maxDailyScans = max;
    }
    
    public void setMaxHourlyScans(int max) {
        this.maxHourlyScans = max;
    }
    
    public void setMaxConcurrentScans(int max) {
        this.maxConcurrentScans = max;
        // 重新创建线程池
        executorService.shutdown();
        executorService = Executors.newFixedThreadPool(max);
    }
    
    /**
     * 关闭管理器
     */
    public void shutdown() {
        running = false;
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
}
