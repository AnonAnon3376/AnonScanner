package com.security.burp.scanner;

import burp.IParameter;
import burp.IRequestInfo;

import java.util.List;

/**
 * 扫描上下文
 * 包含扫描所需的所有信息
 */
public class ScanContext {
    
    private String url;
    private String method;
    private List<IParameter> parameters;
    private String body;
    private List<String> headers;
    private byte[] request;
    private IRequestInfo requestInfo;
    
    // Getters and Setters
    
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
    
    public List<IParameter> getParameters() {
        return parameters;
    }
    
    public void setParameters(List<IParameter> parameters) {
        this.parameters = parameters;
    }
    
    public String getBody() {
        return body;
    }
    
    public void setBody(String body) {
        this.body = body;
    }
    
    public List<String> getHeaders() {
        return headers;
    }
    
    public void setHeaders(List<String> headers) {
        this.headers = headers;
    }
    
    public byte[] getRequest() {
        return request;
    }
    
    public void setRequest(byte[] request) {
        this.request = request;
    }
    
    public IRequestInfo getRequestInfo() {
        return requestInfo;
    }
    
    public void setRequestInfo(IRequestInfo requestInfo) {
        this.requestInfo = requestInfo;
    }
}
