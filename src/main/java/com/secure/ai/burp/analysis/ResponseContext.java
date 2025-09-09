package com.secure.ai.burp.analysis;

import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;

public class ResponseContext {
    private int statusCode;
    private String serverType;
    private String contentType;
    private String redirectLocation;
    private boolean hasBody;
    private String bodyContent;
    private int bodyLength;
    
    // Headers
    private Map<String, String> headers = new ConcurrentHashMap<>();
    private Map<String, String> securityHeaders = new ConcurrentHashMap<>();
    
    // Technology detection
    private Set<String> detectedTechnologies = ConcurrentHashMap.newKeySet();
    private Set<String> frameworks = ConcurrentHashMap.newKeySet();
    private Set<String> detectedDatabases = ConcurrentHashMap.newKeySet();
    private String applicationLanguage;
    
    // Security characteristics
    private boolean hasXSSProtection;
    private boolean hasCSRFProtection;
    private boolean hasSQLiProtection;
    private boolean hasContentTypeProtection;
    private boolean hasClickjackingProtection;
    private boolean hasCSP;
    private boolean hasHSTS;
    private boolean hasHttpOnlyCookies;
    private boolean hasSecureCookies;
    private boolean hasSameSiteCookies;
    
    // Session management
    private Set<String> sessionMethods = ConcurrentHashMap.newKeySet();
    
    // Error and sensitive information
    private Set<String> errorTypes = ConcurrentHashMap.newKeySet();
    private boolean hasSensitiveInfo;
    private Set<String> sensitiveInfoTypes = ConcurrentHashMap.newKeySet();
    
    // Additional metadata
    private Map<String, Object> additionalData = new ConcurrentHashMap<>();
    
    // Constructors
    public ResponseContext() {}
    
    // Getters and Setters
    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
    
    public String getServerType() { return serverType; }
    public void setServerType(String serverType) { this.serverType = serverType; }
    
    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }
    
    public String getRedirectLocation() { return redirectLocation; }
    public void setRedirectLocation(String redirectLocation) { this.redirectLocation = redirectLocation; }
    
    public boolean hasBody() { return hasBody; }
    public void setHasBody(boolean hasBody) { this.hasBody = hasBody; }
    
    public String getBodyContent() { return bodyContent; }
    public void setBodyContent(String bodyContent) { this.bodyContent = bodyContent; }
    
    public int getBodyLength() { return bodyLength; }
    public void setBodyLength(int bodyLength) { this.bodyLength = bodyLength; }
    
    public Map<String, String> getHeaders() { return headers; }
    public void setHeaders(Map<String, String> headers) { this.headers = headers; }
    
    public Map<String, String> getSecurityHeaders() { return securityHeaders; }
    public void setSecurityHeaders(Map<String, String> securityHeaders) { this.securityHeaders = securityHeaders; }
    
    public Set<String> getDetectedTechnologies() { return detectedTechnologies; }
    public void setDetectedTechnologies(Set<String> detectedTechnologies) { this.detectedTechnologies = detectedTechnologies; }
    
    public Set<String> getFrameworks() { return frameworks; }
    public void setFrameworks(Set<String> frameworks) { this.frameworks = frameworks; }
    
    public Set<String> getDetectedDatabases() { return detectedDatabases; }
    public void setDetectedDatabases(Set<String> detectedDatabases) { this.detectedDatabases = detectedDatabases; }
    
    public String getApplicationLanguage() { return applicationLanguage; }
    public void setApplicationLanguage(String applicationLanguage) { this.applicationLanguage = applicationLanguage; }
    
    public boolean hasXSSProtection() { return hasXSSProtection; }
    public void setHasXSSProtection(boolean hasXSSProtection) { this.hasXSSProtection = hasXSSProtection; }
    
    public boolean hasCSRFProtection() { return hasCSRFProtection; }
    public void setHasCSRFProtection(boolean hasCSRFProtection) { this.hasCSRFProtection = hasCSRFProtection; }
    
    public boolean hasSQLiProtection() { return hasSQLiProtection; }
    public void setHasSQLiProtection(boolean hasSQLiProtection) { this.hasSQLiProtection = hasSQLiProtection; }
    
    public boolean hasContentTypeProtection() { return hasContentTypeProtection; }
    public void setHasContentTypeProtection(boolean hasContentTypeProtection) { this.hasContentTypeProtection = hasContentTypeProtection; }
    
    public boolean hasClickjackingProtection() { return hasClickjackingProtection; }
    public void setHasClickjackingProtection(boolean hasClickjackingProtection) { this.hasClickjackingProtection = hasClickjackingProtection; }
    
    public boolean hasCSP() { return hasCSP; }
    public void setHasCSP(boolean hasCSP) { this.hasCSP = hasCSP; }
    
    public boolean hasHSTS() { return hasHSTS; }
    public void setHasHSTS(boolean hasHSTS) { this.hasHSTS = hasHSTS; }
    
    public boolean hasHttpOnlyCookies() { return hasHttpOnlyCookies; }
    public void setHasHttpOnlyCookies(boolean hasHttpOnlyCookies) { this.hasHttpOnlyCookies = hasHttpOnlyCookies; }
    
    public boolean hasSecureCookies() { return hasSecureCookies; }
    public void setHasSecureCookies(boolean hasSecureCookies) { this.hasSecureCookies = hasSecureCookies; }
    
    public boolean hasSameSiteCookies() { return hasSameSiteCookies; }
    public void setHasSameSiteCookies(boolean hasSameSiteCookies) { this.hasSameSiteCookies = hasSameSiteCookies; }
    
    public Set<String> getSessionMethods() { return sessionMethods; }
    public void setSessionMethods(Set<String> sessionMethods) { this.sessionMethods = sessionMethods; }
    
    public Set<String> getErrorTypes() { return errorTypes; }
    public void setErrorTypes(Set<String> errorTypes) { this.errorTypes = errorTypes; }
    
    public boolean hasSensitiveInfo() { return hasSensitiveInfo; }
    public void setHasSensitiveInfo(boolean hasSensitiveInfo) { this.hasSensitiveInfo = hasSensitiveInfo; }
    
    public Set<String> getSensitiveInfoTypes() { return sensitiveInfoTypes; }
    public void setSensitiveInfoTypes(Set<String> sensitiveInfoTypes) { this.sensitiveInfoTypes = sensitiveInfoTypes; }
    
    public Map<String, Object> getAdditionalData() { return additionalData; }
    public void setAdditionalData(Map<String, Object> additionalData) { this.additionalData = additionalData; }
    
    // Helper methods
    public boolean isSuccessful() {
        return statusCode >= 200 && statusCode < 300;
    }
    
    public boolean isRedirect() {
        return statusCode >= 300 && statusCode < 400;
    }
    
    public boolean isClientError() {
        return statusCode >= 400 && statusCode < 500;
    }
    
    public boolean isServerError() {
        return statusCode >= 500;
    }
    
    public boolean isError() {
        return statusCode >= 400;
    }
    
    public boolean hasTechnology(String technology) {
        return detectedTechnologies.contains(technology.toLowerCase());
    }
    
    public boolean hasFramework(String framework) {
        return frameworks.contains(framework.toLowerCase());
    }
    
    public boolean hasDatabase(String database) {
        return detectedDatabases.contains(database.toLowerCase());
    }
    
    public boolean hasSecurityHeader(String headerName) {
        return securityHeaders.containsKey(headerName.toLowerCase());
    }
    
    public String getSecurityHeaderValue(String headerName) {
        return securityHeaders.get(headerName.toLowerCase());
    }
    
    public boolean hasHeader(String headerName) {
        return headers.containsKey(headerName.toLowerCase());
    }
    
    public String getHeaderValue(String headerName) {
        return headers.get(headerName.toLowerCase());
    }
    
    public boolean hasErrorType(String errorType) {
        return errorTypes.contains(errorType);
    }
    
    public boolean hasSensitiveInfoType(String infoType) {
        return sensitiveInfoTypes.contains(infoType);
    }
    
    public boolean hasGoodSecurity() {
        return hasXSSProtection && hasContentTypeProtection && hasClickjackingProtection && 
               hasCSP && hasHSTS && hasHttpOnlyCookies && hasSecureCookies;
    }
    
    public boolean hasWeakSecurity() {
        return !hasXSSProtection || !hasContentTypeProtection || !hasClickjackingProtection ||
               !hasCSP || !hasHttpOnlyCookies || !hasSecureCookies;
    }
    
    public int getSecurityScore() {
        int score = 0;
        
        if (hasXSSProtection) score += 10;
        if (hasContentTypeProtection) score += 10;
        if (hasClickjackingProtection) score += 10;
        if (hasCSP) score += 15;
        if (hasHSTS) score += 15;
        if (hasHttpOnlyCookies) score += 10;
        if (hasSecureCookies) score += 10;
        if (hasSameSiteCookies) score += 10;
        if (hasCSRFProtection) score += 10;
        
        return score;
    }
    
    public boolean isHighRiskResponse() {
        return isServerError() || hasSensitiveInfo || !errorTypes.isEmpty();
    }
    
    public void addAdditionalData(String key, Object value) {
        additionalData.put(key, value);
    }
    
    public Object getAdditionalData(String key) {
        return additionalData.get(key);
    }
    
    public void addTechnology(String technology) {
        detectedTechnologies.add(technology.toLowerCase());
    }
    
    public void addFramework(String framework) {
        frameworks.add(framework.toLowerCase());
    }
    
    public void addDatabase(String database) {
        detectedDatabases.add(database.toLowerCase());
    }
    
    public void addErrorType(String errorType) {
        errorTypes.add(errorType);
    }
    
    public void addSensitiveInfoType(String infoType) {
        sensitiveInfoTypes.add(infoType);
        hasSensitiveInfo = true;
    }
    
    public void addSessionMethod(String method) {
        sessionMethods.add(method);
    }
    
    @Override
    public String toString() {
        return String.format("ResponseContext{status=%d, server='%s', contentType='%s', technologies=%s, securityScore=%d}", 
                           statusCode, serverType, contentType, detectedTechnologies, getSecurityScore());
    }
}