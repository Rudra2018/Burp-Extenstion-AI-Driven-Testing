package com.secure.ai.burp.payloads;

import com.secure.ai.burp.core.ApplicationContext;
import com.secure.ai.burp.analysis.RequestContext;
import burp.api.montoya.http.HttpRequestToBeSent;

import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;

public class PayloadContext {
    private final HttpRequestToBeSent originalRequest;
    private final ApplicationContext applicationContext;
    private final RequestContext requestContext;
    
    // Request characteristics
    private boolean hasAuthenticationContext;
    private boolean hasFileParameters;
    private boolean hasUploadFunctionality;
    private boolean hasUrlParameters;
    private boolean hasHttpParameters;
    private boolean hasIdParameters;
    private boolean hasJsonContent;
    private boolean hasXmlContent;
    private boolean hasSerializedData;
    private boolean hasNoSQLIndicators;
    private boolean hasReflectedParameters;
    private boolean hasFormInputs;
    private boolean hasSearchParameters;
    private boolean hasDatabaseInteraction;
    private boolean hasPathParameters;
    private boolean hasStateChangingOperations;
    
    // Parameter analysis
    private final Set<String> reflectedParameters = ConcurrentHashMap.newKeySet();
    private final Set<String> hiddenParameters = ConcurrentHashMap.newKeySet();
    private final Set<String> numericParameters = ConcurrentHashMap.newKeySet();
    private final Set<String> filePathParameters = ConcurrentHashMap.newKeySet();
    private final Set<String> urlParameters = ConcurrentHashMap.newKeySet();
    private final Set<String> emailParameters = ConcurrentHashMap.newKeySet();
    
    // Context metadata
    private final Map<String, Object> contextMetadata = new ConcurrentHashMap<>();
    
    // Vulnerability context
    private final Map<String, Double> vulnerabilityLikelihoods = new ConcurrentHashMap<>();
    private final Set<String> suspiciousPatterns = ConcurrentHashMap.newKeySet();
    
    public PayloadContext(HttpRequestToBeSent request, ApplicationContext appContext, RequestContext reqContext) {
        this.originalRequest = request;
        this.applicationContext = appContext;
        this.requestContext = reqContext;
        
        initializeContext();
    }
    
    private void initializeContext() {
        // Analyze authentication context
        hasAuthenticationContext = requestContext.hasAuthentication() || 
                                 !applicationContext.getAuthenticationMethods().isEmpty();
        
        // Analyze parameters
        analyzeParameters();
        
        // Analyze content types
        analyzeContentTypes();
        
        // Analyze technology context
        analyzeTechnologyContext();
        
        // Calculate vulnerability likelihoods
        calculateVulnerabilityLikelihoods();
        
        // Detect suspicious patterns
        detectSuspiciousPatterns();
    }
    
    private void analyzeParameters() {
        Set<String> parameters = requestContext.getParameters();
        Map<String, String> paramValues = requestContext.getParameterValues();
        
        hasIdParameters = false;
        hasFileParameters = false;
        hasUrlParameters = false;
        hasPathParameters = false;
        hasSearchParameters = false;
        
        for (String param : parameters) {
            String value = paramValues.get(param);
            String lowerParam = param.toLowerCase();
            String lowerValue = value != null ? value.toLowerCase() : "";
            
            // Categorize parameters
            if (lowerParam.contains("id") || lowerParam.contains("uid") || 
                lowerParam.contains("key") || lowerParam.contains("index")) {
                hasIdParameters = true;
                if (isNumeric(value)) {
                    numericParameters.add(param);
                }
            }
            
            if (lowerParam.contains("file") || lowerParam.contains("path") || 
                lowerParam.contains("dir") || lowerParam.contains("folder")) {
                hasFileParameters = true;
                filePathParameters.add(param);
            }
            
            if (lowerParam.contains("url") || lowerParam.contains("link") || 
                lowerParam.contains("redirect") || lowerParam.contains("callback")) {
                hasUrlParameters = true;
                urlParameters.add(param);
            }
            
            if (lowerParam.contains("search") || lowerParam.contains("query") || 
                lowerParam.contains("term") || lowerParam.contains("keyword")) {
                hasSearchParameters = true;
            }
            
            if (lowerParam.contains("email") || lowerParam.contains("mail")) {
                emailParameters.add(param);
            }
            
            // Check for reflected parameters (simplified check)
            if (value != null && value.length() > 2) {
                // This would need actual response analysis in a real implementation
                reflectedParameters.add(param);
                hasReflectedParameters = true;
            }
            
            // Check for hidden/sensitive parameters
            if (lowerParam.contains("hidden") || lowerParam.contains("secret") || 
                lowerParam.contains("token") || lowerParam.contains("csrf")) {
                hiddenParameters.add(param);
            }
        }
        
        hasHttpParameters = !parameters.isEmpty();
        hasFormInputs = requestContext.hasBody() && requestContext.getContentType() != null &&
                       requestContext.getContentType().contains("form-urlencoded");
    }
    
    private void analyzeContentTypes() {
        String contentType = requestContext.getContentType();
        
        hasJsonContent = requestContext.isJsonRequest();
        hasXmlContent = requestContext.isXmlRequest();
        hasUploadFunctionality = requestContext.isFileUpload();
        
        // Check for serialized data patterns
        String body = requestContext.getBodyContent();
        if (body != null) {
            hasSerializedData = body.contains("serialVersionUID") || 
                              body.contains("java.io.Serializable") ||
                              body.contains("__class__") || // Python pickle
                              body.contains("O:") || // PHP serialize
                              body.startsWith("rO0"); // Java base64 serialized
        }
        
        // Detect NoSQL patterns
        hasNoSQLIndicators = hasJsonContent && body != null && 
                           (body.contains("$where") || body.contains("$regex") || 
                            body.contains("$ne") || body.contains("$gt"));
    }
    
    private void analyzeTechnologyContext() {
        // Check for database interaction indicators
        hasDatabaseInteraction = !applicationContext.getDatabases().isEmpty() ||
                               hasSearchParameters || hasIdParameters;
        
        // Check for state-changing operations
        String method = requestContext.getMethod();
        hasStateChangingOperations = "POST".equals(method) || "PUT".equals(method) || 
                                   "DELETE".equals(method) || "PATCH".equals(method);
    }
    
    private void calculateVulnerabilityLikelihoods() {
        // XSS likelihood
        double xssLikelihood = 0.0;
        if (hasReflectedParameters) xssLikelihood += 0.4;
        if (hasFormInputs) xssLikelihood += 0.3;
        if (!applicationContext.hasXSSProtection()) xssLikelihood += 0.3;
        vulnerabilityLikelihoods.put("xss", Math.min(xssLikelihood, 1.0));
        
        // SQL Injection likelihood
        double sqliLikelihood = 0.0;
        if (hasDatabaseInteraction) sqliLikelihood += 0.3;
        if (hasSearchParameters) sqliLikelihood += 0.3;
        if (hasIdParameters) sqliLikelihood += 0.2;
        if (!applicationContext.hasSQLiProtection()) sqliLikelihood += 0.2;
        vulnerabilityLikelihoods.put("sqli", Math.min(sqliLikelihood, 1.0));
        
        // SSRF likelihood
        double ssrfLikelihood = 0.0;
        if (hasUrlParameters) ssrfLikelihood += 0.5;
        if (hasHttpParameters) ssrfLikelihood += 0.2;
        if (applicationContext.hasTechnology("php")) ssrfLikelihood += 0.3;
        vulnerabilityLikelihoods.put("ssrf", Math.min(ssrfLikelihood, 1.0));
        
        // LFI likelihood
        double lfiLikelihood = 0.0;
        if (hasFileParameters) lfiLikelihood += 0.6;
        if (hasPathParameters) lfiLikelihood += 0.3;
        if (applicationContext.hasTechnology("php")) lfiLikelihood += 0.1;
        vulnerabilityLikelihoods.put("lfi", Math.min(lfiLikelihood, 1.0));
        
        // IDOR likelihood
        double idorLikelihood = 0.0;
        if (hasIdParameters) idorLikelihood += 0.5;
        if (hasAuthenticationContext) idorLikelihood += 0.3;
        if (!applicationContext.hasCSRFProtection()) idorLikelihood += 0.2;
        vulnerabilityLikelihoods.put("idor", Math.min(idorLikelihood, 1.0));
        
        // CSRF likelihood
        double csrfLikelihood = 0.0;
        if (hasStateChangingOperations) csrfLikelihood += 0.4;
        if (hasAuthenticationContext) csrfLikelihood += 0.3;
        if (!applicationContext.hasCSRFProtection()) csrfLikelihood += 0.3;
        vulnerabilityLikelihoods.put("csrf", Math.min(csrfLikelihood, 1.0));
        
        // XXE likelihood
        double xxeLikelihood = 0.0;
        if (hasXmlContent) xxeLikelihood += 0.6;
        if (applicationContext.hasTechnology("java")) xxeLikelihood += 0.2;
        if (requestContext.isSusceptibleToXXE()) xxeLikelihood += 0.2;
        vulnerabilityLikelihoods.put("xxe", Math.min(xxeLikelihood, 1.0));
        
        // Deserialization likelihood
        double deserLikelihood = 0.0;
        if (hasSerializedData) deserLikelihood += 0.7;
        if (applicationContext.hasTechnology("java")) deserLikelihood += 0.2;
        if (applicationContext.hasTechnology("python")) deserLikelihood += 0.1;
        vulnerabilityLikelihoods.put("deserialization", Math.min(deserLikelihood, 1.0));
        
        // NoSQL Injection likelihood
        double nosqlLikelihood = 0.0;
        if (hasNoSQLIndicators) nosqlLikelihood += 0.5;
        if (applicationContext.hasDatabase("mongodb")) nosqlLikelihood += 0.3;
        if (hasJsonContent) nosqlLikelihood += 0.2;
        vulnerabilityLikelihoods.put("nosql", Math.min(nosqlLikelihood, 1.0));
    }
    
    private void detectSuspiciousPatterns() {
        Set<String> requestSuspiciousPatterns = requestContext.getSuspiciousParameters();
        suspiciousPatterns.addAll(requestSuspiciousPatterns);
        
        // Add application-specific suspicious patterns
        if (applicationContext.getOverallRiskScore() > 7.0) {
            suspiciousPatterns.add("high_risk_application");
        }
        
        if (applicationContext.getVulnerabilityHistory().size() > 5) {
            suspiciousPatterns.add("vulnerability_history");
        }
    }
    
    private boolean isNumeric(String value) {
        if (value == null || value.isEmpty()) return false;
        try {
            Double.parseDouble(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    // Getters
    public HttpRequestToBeSent getOriginalRequest() { return originalRequest; }
    public ApplicationContext getApplicationContext() { return applicationContext; }
    public RequestContext getRequestContext() { return requestContext; }
    
    public boolean hasAuthenticationContext() { return hasAuthenticationContext; }
    public boolean hasFileParameters() { return hasFileParameters; }
    public boolean hasUploadFunctionality() { return hasUploadFunctionality; }
    public boolean hasUrlParameters() { return hasUrlParameters; }
    public boolean hasHttpParameters() { return hasHttpParameters; }
    public boolean hasIdParameters() { return hasIdParameters; }
    public boolean hasJsonContent() { return hasJsonContent; }
    public boolean hasXmlContent() { return hasXmlContent; }
    public boolean hasSerializedData() { return hasSerializedData; }
    public boolean hasNoSQLIndicators() { return hasNoSQLIndicators; }
    public boolean hasReflectedParameters() { return hasReflectedParameters; }
    public boolean hasFormInputs() { return hasFormInputs; }
    public boolean hasSearchParameters() { return hasSearchParameters; }
    public boolean hasDatabaseInteraction() { return hasDatabaseInteraction; }
    public boolean hasPathParameters() { return hasPathParameters; }
    public boolean hasStateChangingOperations() { return hasStateChangingOperations; }
    
    public Set<String> getReflectedParameters() { return new HashSet<>(reflectedParameters); }
    public Set<String> getHiddenParameters() { return new HashSet<>(hiddenParameters); }
    public Set<String> getNumericParameters() { return new HashSet<>(numericParameters); }
    public Set<String> getFilePathParameters() { return new HashSet<>(filePathParameters); }
    public Set<String> getUrlParameters() { return new HashSet<>(urlParameters); }
    public Set<String> getEmailParameters() { return new HashSet<>(emailParameters); }
    public Set<String> getSuspiciousPatterns() { return new HashSet<>(suspiciousPatterns); }
    
    public double getVulnerabilityLikelihood(String vulnerabilityType) {
        return vulnerabilityLikelihoods.getOrDefault(vulnerabilityType, 0.0);
    }
    
    public Map<String, Double> getAllVulnerabilityLikelihoods() {
        return new ConcurrentHashMap<>(vulnerabilityLikelihoods);
    }
    
    public void addContextMetadata(String key, Object value) {
        contextMetadata.put(key, value);
    }
    
    public Object getContextMetadata(String key) {
        return contextMetadata.get(key);
    }
    
    public Map<String, Object> getAllContextMetadata() {
        return new ConcurrentHashMap<>(contextMetadata);
    }
    
    public boolean isHighRiskContext() {
        return vulnerabilityLikelihoods.values().stream()
                                     .mapToDouble(Double::doubleValue)
                                     .average()
                                     .orElse(0.0) > 0.6;
    }
    
    public boolean isLowRiskContext() {
        return vulnerabilityLikelihoods.values().stream()
                                     .mapToDouble(Double::doubleValue)
                                     .average()
                                     .orElse(0.0) < 0.3;
    }
    
    @Override
    public String toString() {
        return String.format("PayloadContext{auth=%s, params=%d, vulnLikelihoods=%s}", 
                           hasAuthenticationContext, 
                           requestContext.getParameters().size(),
                           vulnerabilityLikelihoods);
    }
}