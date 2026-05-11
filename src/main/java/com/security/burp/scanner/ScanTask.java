package com.security.burp.scanner;

import burp.IHttpRequestResponse;
import java.util.Date;

/**
 * 扫描任务
 */
public class ScanTask {
    
    public enum TaskStatus {
        PENDING("待扫描"),
        RUNNING("扫描中"),
        COMPLETED("已完成"),
        FAILED("失败"),
        CANCELLED("已取消");
        
        private String displayName;
        
        TaskStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum ScanMode {
        MANUAL("手动扫描"),
        PASSIVE("被动扫描"),
        BATCH("批量扫描"),
        ACTIVE("主动扫描"),
        SCHEDULED("定时扫描");
        
        private String displayName;
        
        ScanMode(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    private String taskId;
    private IHttpRequestResponse message;
    private String url;
    private String method;
    private ScanMode scanMode;
    private TaskStatus status;
    private Date createTime;
    private Date startTime;
    private Date endTime;
    private String result;
    private String error;
    private boolean verified;
    private String verifyResult;
    
    public ScanTask(String taskId, IHttpRequestResponse message, ScanMode scanMode) {
        this.taskId = taskId;
        this.message = message;
        this.scanMode = scanMode;
        this.status = TaskStatus.PENDING;
        this.createTime = new Date();
    }
    
    // Getters and Setters
    
    public String getTaskId() {
        return taskId;
    }
    
    public IHttpRequestResponse getMessage() {
        return message;
    }
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url;
    }
    
    public String getMethod() {
        return method;
    }
    
    public void setMethod(String method) {
        this.method = method;
    }
    
    public ScanMode getScanMode() {
        return scanMode;
    }
    
    public ScanMode getMode() {
        return scanMode;
    }
    
    public TaskStatus getStatus() {
        return status;
    }
    
    public void setStatus(TaskStatus status) {
        this.status = status;
        if (status == TaskStatus.RUNNING && startTime == null) {
            startTime = new Date();
        } else if ((status == TaskStatus.COMPLETED || status == TaskStatus.FAILED) && endTime == null) {
            endTime = new Date();
        }
    }
    
    public Date getCreateTime() {
        return createTime;
    }
    
    public Date getStartTime() {
        return startTime;
    }
    
    public Date getEndTime() {
        return endTime;
    }
    
    public String getResult() {
        return result;
    }
    
    public void setResult(String result) {
        this.result = result;
    }
    
    public String getError() {
        return error;
    }
    
    public void setError(String error) {
        this.error = error;
    }
    
    public boolean isVerified() {
        return verified;
    }
    
    public void setVerified(boolean verified) {
        this.verified = verified;
    }
    
    public String getVerifyResult() {
        return verifyResult;
    }
    
    public void setVerifyResult(String verifyResult) {
        this.verifyResult = verifyResult;
    }
    
    public long getDuration() {
        if (startTime != null && endTime != null) {
            return endTime.getTime() - startTime.getTime();
        }
        return 0;
    }
}
