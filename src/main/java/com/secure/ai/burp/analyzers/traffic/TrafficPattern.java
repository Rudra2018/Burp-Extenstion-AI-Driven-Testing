package com.secure.ai.burp.analyzers.traffic;

import burp.api.montoya.http.*;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

class TrafficPattern {
    private final String host;
    private final LocalDateTime firstSeen;
    private final AtomicLong totalRequests;
    private final AtomicLong totalResponses;
    
    // Traffic timing patterns
    private final Map<String, AtomicLong> methodCounts;
    private final Map<String, AtomicLong> pathCounts;
    private final Map<Integer, AtomicLong> statusCounts;
    private final Map<String, AtomicLong> contentTypeCounts;
    
    // Request patterns
    private final Set<String> uniquePaths;
    private final Set<String> uniqueParameters;
    private final Map<String, Long> averageRequestSizes;
    private final Map<String, Long> averageResponseSizes;
    
    // Timing patterns
    private final List<LocalDateTime> requestTimestamps;
    private final Map<String, List<Long>> responseTimings;
    
    // Error patterns
    private final Map<Integer, List<String>> errorResponses;
    private final Set<String> suspiciousPatterns;
    
    public TrafficPattern(String host) {
        this.host = host;
        this.firstSeen = LocalDateTime.now();
        this.totalRequests = new AtomicLong(0);
        this.totalResponses = new AtomicLong(0);
        
        this.methodCounts = new ConcurrentHashMap<>();
        this.pathCounts = new ConcurrentHashMap<>();
        this.statusCounts = new ConcurrentHashMap<>();
        this.contentTypeCounts = new ConcurrentHashMap<>();
        
        this.uniquePaths = ConcurrentHashMap.newKeySet();
        this.uniqueParameters = ConcurrentHashMap.newKeySet();
        this.averageRequestSizes = new ConcurrentHashMap<>();
        this.averageResponseSizes = new ConcurrentHashMap<>();
        
        this.requestTimestamps = Collections.synchronizedList(new ArrayList<>());
        this.responseTimings = new ConcurrentHashMap<>();
        
        this.errorResponses = new ConcurrentHashMap<>();
        this.suspiciousPatterns = ConcurrentHashMap.newKeySet();
    }
    
    public void addRequest(HttpRequestToBeSent request) {
        totalRequests.incrementAndGet();
        requestTimestamps.add(LocalDateTime.now());
        
        // Track HTTP methods
        String method = request.method();
        methodCounts.computeIfAbsent(method, k -> new AtomicLong(0)).incrementAndGet();
        
        // Track paths
        String path = request.path();
        pathCounts.computeIfAbsent(path, k -> new AtomicLong(0)).incrementAndGet();
        uniquePaths.add(path);
        
        // Track request sizes
        long requestSize = request.hasBody() ? request.body().length() : 0;
        updateAverageSize(averageRequestSizes, path, requestSize);
        
        // Extract and track parameters
        extractParameters(request);
        
        // Detect suspicious patterns
        detectSuspiciousRequest(request);
    }
    
    public void addResponse(HttpResponseReceived response) {
        totalResponses.incrementAndGet();
        
        int statusCode = response.statusCode();
        statusCounts.computeIfAbsent(statusCode, k -> new AtomicLong(0)).incrementAndGet();
        
        // Track content types
        String contentType = getContentType(response);
        if (contentType != null) {
            contentTypeCounts.computeIfAbsent(contentType, k -> new AtomicLong(0)).incrementAndGet();
        }
        
        // Track response sizes
        String path = response.initiatingRequest().path();
        long responseSize = response.body().length();
        updateAverageSize(averageResponseSizes, path, responseSize);
        
        // Track error responses
        if (statusCode >= 400) {
            errorResponses.computeIfAbsent(statusCode, k -> new ArrayList<>())
                          .add(response.bodyToString().substring(0, Math.min(500, response.bodyToString().length())));
        }
        
        // Detect suspicious patterns in responses
        detectSuspiciousResponse(response);
    }
    
    private void extractParameters(HttpRequestToBeSent request) {
        // Extract URL parameters
        String url = request.url();
        if (url.contains("?")) {
            String queryString = url.substring(url.indexOf("?") + 1);
            String[] params = queryString.split("&");
            
            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length > 0) {
                    uniqueParameters.add(keyValue[0]);
                }
            }
        }
        
        // Extract POST parameters
        if (request.hasBody() && request.contentType() != null && 
            request.contentType().toLowerCase().contains("form-urlencoded")) {
            String body = request.bodyToString();
            String[] params = body.split("&");
            
            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length > 0) {
                    uniqueParameters.add(keyValue[0]);
                }
            }
        }
    }
    
    private void detectSuspiciousRequest(HttpRequestToBeSent request) {
        String url = request.url().toLowerCase();
        String body = request.hasBody() ? request.bodyToString().toLowerCase() : "";
        
        // Check for common attack patterns
        if (containsXSSPatterns(url + " " + body)) {
            suspiciousPatterns.add("xss_attempt");
        }
        
        if (containsSQLiPatterns(url + " " + body)) {
            suspiciousPatterns.add("sqli_attempt");
        }
        
        if (containsSSRFPatterns(url + " " + body)) {
            suspiciousPatterns.add("ssrf_attempt");
        }
        
        if (containsPathTraversalPatterns(url + " " + body)) {
            suspiciousPatterns.add("path_traversal_attempt");
        }
        
        // Check for unusually long parameters (potential buffer overflow)
        if (url.length() > 2000 || body.length() > 10000) {
            suspiciousPatterns.add("oversized_request");
        }
    }
    
    private void detectSuspiciousResponse(HttpResponseReceived response) {
        String body = response.bodyToString().toLowerCase();
        int statusCode = response.statusCode();
        
        // Check for error messages that might reveal information
        if (statusCode >= 500) {
            if (body.contains("sql") || body.contains("database") || body.contains("mysql")) {
                suspiciousPatterns.add("sql_error_disclosure");
            }
            if (body.contains("exception") || body.contains("stack trace")) {
                suspiciousPatterns.add("exception_disclosure");
            }
        }
        
        // Check for potential sensitive information
        if (body.contains("password") || body.contains("secret") || body.contains("token")) {
            suspiciousPatterns.add("sensitive_info_response");
        }
        
        // Check for directory listings
        if (body.contains("index of") || body.contains("parent directory")) {
            suspiciousPatterns.add("directory_listing");
        }
    }
    
    private boolean containsXSSPatterns(String input) {
        return input.contains("<script") || 
               input.contains("javascript:") || 
               input.contains("onerror") || 
               input.contains("onload") ||
               input.contains("alert(") ||
               input.contains("document.cookie");
    }
    
    private boolean containsSQLiPatterns(String input) {
        return input.contains("union select") || 
               input.contains("' or ") || 
               input.contains("\" or ") ||
               input.contains("drop table") ||
               input.contains("insert into") ||
               input.contains("delete from") ||
               input.contains("--") ||
               input.contains("/*");
    }
    
    private boolean containsSSRFPatterns(String input) {
        return input.contains("localhost") || 
               input.contains("127.0.0.1") || 
               input.contains("169.254") ||
               input.contains("192.168") ||
               input.contains("10.") ||
               input.contains("file://") ||
               input.contains("gopher://");
    }
    
    private boolean containsPathTraversalPatterns(String input) {
        return input.contains("../") || 
               input.contains("..\\") || 
               input.contains("%2e%2e") ||
               input.contains("etc/passwd") ||
               input.contains("windows/system32");
    }
    
    private String getContentType(HttpResponseReceived response) {
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("content-type")) {
                String contentType = header.value().toLowerCase();
                // Return simplified content type
                if (contentType.contains("json")) return "json";
                if (contentType.contains("xml")) return "xml";
                if (contentType.contains("html")) return "html";
                if (contentType.contains("text")) return "text";
                if (contentType.contains("image")) return "image";
                return contentType.split(";")[0].trim();
            }
        }
        return null;
    }
    
    private void updateAverageSize(Map<String, Long> averageSizes, String key, long newSize) {
        averageSizes.compute(key, (k, currentAvg) -> {
            if (currentAvg == null) {
                return newSize;
            } else {
                // Simple running average (could be improved)
                return (currentAvg + newSize) / 2;
            }
        });
    }
    
    public boolean isHighTrafficEndpoint(String path) {
        AtomicLong count = pathCounts.get(path);
        if (count == null) return false;
        
        long totalPathRequests = pathCounts.values().stream()
                                          .mapToLong(AtomicLong::get)
                                          .sum();
        
        // Consider high traffic if this path represents more than 20% of requests
        return count.get() > (totalPathRequests * 0.2);
    }
    
    public boolean hasErrorPattern() {
        return !errorResponses.isEmpty();
    }
    
    public boolean hasSuspiciousActivity() {
        return !suspiciousPatterns.isEmpty();
    }
    
    public double getErrorRate() {
        long totalErrorResponses = statusCounts.entrySet().stream()
                                              .filter(entry -> entry.getKey() >= 400)
                                              .mapToLong(entry -> entry.getValue().get())
                                              .sum();
        
        long total = totalResponses.get();
        return total > 0 ? (double) totalErrorResponses / total : 0.0;
    }
    
    public double getRequestRate() {
        if (requestTimestamps.size() < 2) return 0.0;
        
        LocalDateTime first = requestTimestamps.get(0);
        LocalDateTime last = requestTimestamps.get(requestTimestamps.size() - 1);
        
        long minutesBetween = java.time.Duration.between(first, last).toMinutes();
        if (minutesBetween == 0) minutesBetween = 1; // Avoid division by zero
        
        return (double) requestTimestamps.size() / minutesBetween;
    }
    
    // Getters
    public String getHost() { return host; }
    public LocalDateTime getFirstSeen() { return firstSeen; }
    public long getTotalRequests() { return totalRequests.get(); }
    public long getTotalResponses() { return totalResponses.get(); }
    public Map<String, AtomicLong> getMethodCounts() { return new ConcurrentHashMap<>(methodCounts); }
    public Map<String, AtomicLong> getPathCounts() { return new ConcurrentHashMap<>(pathCounts); }
    public Map<Integer, AtomicLong> getStatusCounts() { return new ConcurrentHashMap<>(statusCounts); }
    public Map<String, AtomicLong> getContentTypeCounts() { return new ConcurrentHashMap<>(contentTypeCounts); }
    public Set<String> getUniquePaths() { return Set.copyOf(uniquePaths); }
    public Set<String> getUniqueParameters() { return Set.copyOf(uniqueParameters); }
    public Map<String, Long> getAverageRequestSizes() { return new ConcurrentHashMap<>(averageRequestSizes); }
    public Map<String, Long> getAverageResponseSizes() { return new ConcurrentHashMap<>(averageResponseSizes); }
    public Map<Integer, List<String>> getErrorResponses() { return new ConcurrentHashMap<>(errorResponses); }
    public Set<String> getSuspiciousPatterns() { return Set.copyOf(suspiciousPatterns); }
}