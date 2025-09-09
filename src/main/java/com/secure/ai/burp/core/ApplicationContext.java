package com.secure.ai.burp.core;

import com.secure.ai.burp.analysis.RequestContext;
import com.secure.ai.burp.analysis.ResponseContext;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.time.LocalDateTime;

public class ApplicationContext {
    private final String host;
    private final LocalDateTime discoveryTime;
    private final AtomicLong requestCount;
    private final Map<String, Object> contextData;
    
    // Technology stack detection
    private final Set<String> detectedTechnologies;
    private final Set<String> frameworks;
    private final Set<String> databases;
    private String serverType;
    private String applicationLanguage;
    
    // Security characteristics
    private final Set<String> authenticationMethods;
    private final Set<String> sessionManagement;
    private final Map<String, String> securityHeaders;
    private boolean hasCSRFProtection;
    private boolean hasXSSProtection;
    private boolean hasSQLiProtection;
    
    // Application structure
    private final Set<String> endpoints;
    private final Set<String> parameters;
    private final Map<String, Set<String>> endpointParameters;
    private final Set<String> cookies;
    
    // Vulnerability history
    private final Map<String, Integer> vulnerabilityHistory;
    private final Map<String, Double> riskScores;
    
    public ApplicationContext(String host) {
        this.host = host;
        this.discoveryTime = LocalDateTime.now();
        this.requestCount = new AtomicLong(0);
        this.contextData = new ConcurrentHashMap<>();
        
        this.detectedTechnologies = ConcurrentHashMap.newKeySet();
        this.frameworks = ConcurrentHashMap.newKeySet();
        this.databases = ConcurrentHashMap.newKeySet();
        this.authenticationMethods = ConcurrentHashMap.newKeySet();
        this.sessionManagement = ConcurrentHashMap.newKeySet();
        this.securityHeaders = new ConcurrentHashMap<>();
        this.endpoints = ConcurrentHashMap.newKeySet();
        this.parameters = ConcurrentHashMap.newKeySet();
        this.endpointParameters = new ConcurrentHashMap<>();
        this.cookies = ConcurrentHashMap.newKeySet();
        this.vulnerabilityHistory = new ConcurrentHashMap<>();
        this.riskScores = new ConcurrentHashMap<>();
    }
    
    public void updateFromRequest(RequestContext requestContext) {
        requestCount.incrementAndGet();
        
        // Update endpoints and parameters
        endpoints.add(requestContext.getPath());
        parameters.addAll(requestContext.getParameters());
        
        // Update endpoint-specific parameters
        endpointParameters.computeIfAbsent(requestContext.getPath(), k -> ConcurrentHashMap.newKeySet())
                         .addAll(requestContext.getParameters());
        
        // Update cookies
        cookies.addAll(requestContext.getCookies());
        
        // Update authentication detection
        if (requestContext.hasAuthHeaders()) {
            authenticationMethods.addAll(requestContext.getAuthMethods());
        }
        
        // Store additional context data
        contextData.putAll(requestContext.getAdditionalData());
    }
    
    public void updateFromResponse(ResponseContext responseContext) {
        // Detect technologies from response headers
        detectedTechnologies.addAll(responseContext.getDetectedTechnologies());
        frameworks.addAll(responseContext.getFrameworks());
        
        // Update server information
        if (responseContext.getServerType() != null) {
            this.serverType = responseContext.getServerType();
        }
        
        if (responseContext.getApplicationLanguage() != null) {
            this.applicationLanguage = responseContext.getApplicationLanguage();
        }
        
        // Update security headers
        securityHeaders.putAll(responseContext.getSecurityHeaders());
        
        // Update protection mechanisms
        this.hasCSRFProtection = responseContext.hasCSRFProtection();
        this.hasXSSProtection = responseContext.hasXSSProtection();
        this.hasSQLiProtection = responseContext.hasSQLiProtection();
        
        // Update session management
        sessionManagement.addAll(responseContext.getSessionMethods());
        
        // Update databases if detected
        databases.addAll(responseContext.getDetectedDatabases());
        
        // Store additional context data
        contextData.putAll(responseContext.getAdditionalData());
    }
    
    public void recordVulnerability(String vulnerabilityType, double riskScore) {
        vulnerabilityHistory.merge(vulnerabilityType, 1, Integer::sum);
        riskScores.put(vulnerabilityType, Math.max(riskScores.getOrDefault(vulnerabilityType, 0.0), riskScore));
    }
    
    public double getOverallRiskScore() {
        return riskScores.values().stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
    }
    
    public boolean isHighRiskApplication() {
        return getOverallRiskScore() > 7.0 || 
               vulnerabilityHistory.values().stream().mapToInt(Integer::intValue).sum() > 10;
    }
    
    public boolean hasFramework(String framework) {
        return frameworks.contains(framework.toLowerCase());
    }
    
    public boolean hasTechnology(String technology) {
        return detectedTechnologies.contains(technology.toLowerCase());
    }
    
    public boolean hasDatabase(String database) {
        return databases.contains(database.toLowerCase());
    }
    
    public Set<String> getParametersForEndpoint(String endpoint) {
        return new HashSet<>(endpointParameters.getOrDefault(endpoint, new HashSet<>()));
    }
    
    public boolean isParameterKnown(String parameter) {
        return parameters.contains(parameter);
    }
    
    public boolean isEndpointKnown(String endpoint) {
        return endpoints.contains(endpoint);
    }
    
    // Getters
    public String getHost() { return host; }
    public LocalDateTime getDiscoveryTime() { return discoveryTime; }
    public long getRequestCount() { return requestCount.get(); }
    public Set<String> getDetectedTechnologies() { return new HashSet<>(detectedTechnologies); }
    public Set<String> getFrameworks() { return new HashSet<>(frameworks); }
    public Set<String> getDatabases() { return new HashSet<>(databases); }
    public String getServerType() { return serverType; }
    public String getApplicationLanguage() { return applicationLanguage; }
    public Set<String> getAuthenticationMethods() { return new HashSet<>(authenticationMethods); }
    public Set<String> getSessionManagement() { return new HashSet<>(sessionManagement); }
    public Map<String, String> getSecurityHeaders() { return new ConcurrentHashMap<>(securityHeaders); }
    public boolean hasCSRFProtection() { return hasCSRFProtection; }
    public boolean hasXSSProtection() { return hasXSSProtection; }
    public boolean hasSQLiProtection() { return hasSQLiProtection; }
    public Set<String> getEndpoints() { return new HashSet<>(endpoints); }
    public Set<String> getParameters() { return new HashSet<>(parameters); }
    public Set<String> getCookies() { return new HashSet<>(cookies); }
    public Map<String, Integer> getVulnerabilityHistory() { return new ConcurrentHashMap<>(vulnerabilityHistory); }
    public Map<String, Double> getRiskScores() { return new ConcurrentHashMap<>(riskScores); }
    public Object getContextData(String key) { return contextData.get(key); }
    public Map<String, Object> getAllContextData() { return new ConcurrentHashMap<>(contextData); }
}