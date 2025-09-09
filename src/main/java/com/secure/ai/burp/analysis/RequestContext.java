package com.secure.ai.burp.analysis;

import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;

public class RequestContext {
    private String method;
    private String path;
    private String url;
    private String host;
    private String userAgent;
    private String referer;
    private String contentType;
    private boolean hasBody;
    private String bodyContent;
    private int bodyLength;
    
    // Headers and parameters
    private Map<String, String> headers = new ConcurrentHashMap<>();
    private Set<String> parameters = ConcurrentHashMap.newKeySet();
    private Map<String, String> parameterValues = new ConcurrentHashMap<>();
    private Set<String> cookies = ConcurrentHashMap.newKeySet();
    private Map<String, String> cookieValues = new ConcurrentHashMap<>();
    
    // Authentication context
    private boolean hasAuthHeaders;
    private boolean hasAuthParameters;
    private Set<String> authMethods = ConcurrentHashMap.newKeySet();
    
    // Request characteristics
    private boolean isAjaxRequest;
    private boolean isJsonRequest;
    private boolean isXmlRequest;
    private boolean isFileUpload;
    
    // Security context
    private boolean hasCSRFToken;
    private boolean hasSensitiveData;
    private boolean hasAuthData;
    private boolean susceptibleToXXE;
    
    // Parameter analysis
    private Set<String> idParameters = ConcurrentHashMap.newKeySet();
    private Set<String> suspiciousParameters = ConcurrentHashMap.newKeySet();
    private Set<String> sessionMethods = ConcurrentHashMap.newKeySet();
    
    // Additional metadata
    private Map<String, Object> additionalData = new ConcurrentHashMap<>();
    
    // Constructors
    public RequestContext() {}
    
    // Getters and Setters
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
    
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    
    public String getReferer() { return referer; }
    public void setReferer(String referer) { this.referer = referer; }
    
    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }
    
    public boolean hasBody() { return hasBody; }
    public void setHasBody(boolean hasBody) { this.hasBody = hasBody; }
    
    public String getBodyContent() { return bodyContent; }
    public void setBodyContent(String bodyContent) { this.bodyContent = bodyContent; }
    
    public int getBodyLength() { return bodyLength; }
    public void setBodyLength(int bodyLength) { this.bodyLength = bodyLength; }
    
    public Map<String, String> getHeaders() { return headers; }
    public void setHeaders(Map<String, String> headers) { this.headers = headers; }
    
    public Set<String> getParameters() { return parameters; }
    public void setParameters(Set<String> parameters) { this.parameters = parameters; }
    
    public Map<String, String> getParameterValues() { return parameterValues; }
    public void setParameterValues(Map<String, String> parameterValues) { this.parameterValues = parameterValues; }
    
    public Set<String> getCookies() { return cookies; }
    public void setCookies(Set<String> cookies) { this.cookies = cookies; }
    
    public Map<String, String> getCookieValues() { return cookieValues; }
    public void setCookieValues(Map<String, String> cookieValues) { this.cookieValues = cookieValues; }
    
    public boolean hasAuthHeaders() { return hasAuthHeaders; }
    public void setHasAuthHeaders(boolean hasAuthHeaders) { this.hasAuthHeaders = hasAuthHeaders; }
    
    public boolean hasAuthParameters() { return hasAuthParameters; }
    public void setHasAuthParameters(boolean hasAuthParameters) { this.hasAuthParameters = hasAuthParameters; }
    
    public Set<String> getAuthMethods() { return authMethods; }
    public void setAuthMethods(Set<String> authMethods) { this.authMethods = authMethods; }
    
    public boolean isAjaxRequest() { return isAjaxRequest; }
    public void setIsAjaxRequest(boolean isAjaxRequest) { this.isAjaxRequest = isAjaxRequest; }
    
    public boolean isJsonRequest() { return isJsonRequest; }
    public void setIsJsonRequest(boolean isJsonRequest) { this.isJsonRequest = isJsonRequest; }
    
    public boolean isXmlRequest() { return isXmlRequest; }
    public void setIsXmlRequest(boolean isXmlRequest) { this.isXmlRequest = isXmlRequest; }
    
    public boolean isFileUpload() { return isFileUpload; }
    public void setIsFileUpload(boolean isFileUpload) { this.isFileUpload = isFileUpload; }
    
    public boolean hasCSRFToken() { return hasCSRFToken; }
    public void setHasCSRFToken(boolean hasCSRFToken) { this.hasCSRFToken = hasCSRFToken; }
    
    public boolean hasSensitiveData() { return hasSensitiveData; }
    public void setHasSensitiveData(boolean hasSensitiveData) { this.hasSensitiveData = hasSensitiveData; }
    
    public boolean hasAuthData() { return hasAuthData; }
    public void setHasAuthData(boolean hasAuthData) { this.hasAuthData = hasAuthData; }
    
    public boolean isSusceptibleToXXE() { return susceptibleToXXE; }
    public void setSusceptibleToXXE(boolean susceptibleToXXE) { this.susceptibleToXXE = susceptibleToXXE; }
    
    public Set<String> getIdParameters() { return idParameters; }
    public void setIdParameters(Set<String> idParameters) { this.idParameters = idParameters; }
    
    public Set<String> getSuspiciousParameters() { return suspiciousParameters; }
    public void setSuspiciousParameters(Set<String> suspiciousParameters) { this.suspiciousParameters = suspiciousParameters; }
    
    public Set<String> getSessionMethods() { return sessionMethods; }
    public void setSessionMethods(Set<String> sessionMethods) { this.sessionMethods = sessionMethods; }
    
    public Map<String, Object> getAdditionalData() { return additionalData; }
    public void setAdditionalData(Map<String, Object> additionalData) { this.additionalData = additionalData; }
    
    // Helper methods
    public boolean hasParameter(String parameter) {
        return parameters.contains(parameter);
    }
    
    public String getParameterValue(String parameter) {
        return parameterValues.get(parameter);
    }
    
    public boolean hasCookie(String cookieName) {
        return cookies.contains(cookieName);
    }
    
    public String getCookieValue(String cookieName) {
        return cookieValues.get(cookieName);
    }
    
    public boolean hasHeader(String headerName) {
        return headers.containsKey(headerName.toLowerCase());
    }
    
    public String getHeaderValue(String headerName) {
        return headers.get(headerName.toLowerCase());
    }
    
    public boolean hasAuthentication() {
        return hasAuthHeaders || hasAuthParameters || !authMethods.isEmpty();
    }
    
    public boolean hasSuspiciousContent() {
        return !suspiciousParameters.isEmpty() || hasSensitiveData;
    }
    
    public boolean isHighRiskRequest() {
        return hasSuspiciousContent() || isFileUpload || susceptibleToXXE;
    }
    
    public void addAdditionalData(String key, Object value) {
        additionalData.put(key, value);
    }
    
    public Object getAdditionalData(String key) {
        return additionalData.get(key);
    }
    
    @Override
    public String toString() {
        return String.format("RequestContext{method='%s', path='%s', hasBody=%s, parametersCount=%d, cookiesCount=%d, hasAuth=%s}", 
                           method, path, hasBody, parameters.size(), cookies.size(), hasAuthentication());
    }
}