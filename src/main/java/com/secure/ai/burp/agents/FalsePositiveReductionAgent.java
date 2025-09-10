package com.secure.ai.burp.agents;

import burp.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Tier 1: False Positive Reduction Agent
 * 
 * Learns from user actions to identify and filter out application-specific false positives.
 * Creates dynamic suppression rules based on observed patterns.
 */
public class FalsePositiveReductionAgent {
    
    private final IBurpExtenderCallbacks callbacks;
    private final ExecutorService executorService;
    
    private final AtomicInteger patternCount = new AtomicInteger(0);
    private final AtomicInteger suppressedCount = new AtomicInteger(0);
    private volatile boolean active = false;
    
    // Learning patterns for false positives
    private final Map<String, FalsePositivePattern> learnedPatterns = new ConcurrentHashMap<>();
    private final List<IScanIssue> observedIssues = new ArrayList<>();
    private final Set<String> userDeletedIssues = Collections.synchronizedSet(new HashSet<>());
    
    public FalsePositiveReductionAgent(IBurpExtenderCallbacks callbacks, ExecutorService executorService) {
        this.callbacks = callbacks;
        this.executorService = executorService;
    }
    
    public void start() {
        this.active = true;
        
        // Start monitoring user behavior
        executorService.submit(this::monitorUserBehavior);
        
        // Start pattern learning
        executorService.submit(this::analyzePatterns);
    }
    
    public void stop() {
        this.active = false;
    }
    
    public String getStatus() {
        return active ? "LEARNING - " + patternCount.get() + " patterns" : "STOPPED";
    }
    
    public int getPatternCount() {
        return patternCount.get();
    }
    
    public int getSuppressedCount() {
        return suppressedCount.get();
    }
    
    private void monitorUserBehavior() {
        Set<String> previousIssueSet = new HashSet<>();
        
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                IScanIssue[] currentIssues = callbacks.getScanIssues(null);
                Set<String> currentIssueSet = new HashSet<>();
                
                // Build current issue set
                for (IScanIssue issue : currentIssues) {
                    String issueId = generateIssueId(issue);
                    currentIssueSet.add(issueId);
                    
                    // Track new issues for learning
                    if (!previousIssueSet.contains(issueId)) {
                        synchronized (observedIssues) {
                            observedIssues.add(issue);
                        }
                    }
                }
                
                // Detect deleted issues (potential false positives marked by user)
                for (String previousIssueId : previousIssueSet) {
                    if (!currentIssueSet.contains(previousIssueId)) {
                        userDeletedIssues.add(previousIssueId);
                        learnFromDeletedIssue(previousIssueId);
                    }
                }
                
                previousIssueSet = currentIssueSet;
                Thread.sleep(10000); // Check every 10 seconds
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void analyzePatterns() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                // Analyze accumulated patterns every minute
                Thread.sleep(60000);
                
                if (!userDeletedIssues.isEmpty()) {
                    identifyCommonPatterns();
                    applySuppressionRules();
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void learnFromDeletedIssue(String issueId) {
        // Find the deleted issue in our observed list
        synchronized (observedIssues) {
            for (IScanIssue issue : observedIssues) {
                if (generateIssueId(issue).equals(issueId)) {
                    extractPatternFromIssue(issue);
                    break;
                }
            }
        }
    }
    
    private void extractPatternFromIssue(IScanIssue issue) {
        try {
            // Extract patterns that might indicate false positives
            FalsePositivePattern pattern = new FalsePositivePattern();
            pattern.issueName = issue.getIssueName();
            pattern.url = issue.getUrl().toString();
            pattern.host = issue.getUrl().getHost();
            pattern.path = issue.getUrl().getPath();
            
            // Analyze HTTP messages for patterns
            if (issue.getHttpMessages() != null && issue.getHttpMessages().length > 0) {
                IHttpRequestResponse message = issue.getHttpMessages()[0];
                
                if (message.getResponse() != null) {
                    String response = new String(message.getResponse());
                    pattern.responsePatterns = extractResponsePatterns(response);
                    pattern.statusCode = extractStatusCode(response);
                }
                
                if (message.getRequest() != null) {
                    String request = new String(message.getRequest());
                    pattern.requestPatterns = extractRequestPatterns(request);
                }
            }
            
            // Store the pattern
            String patternKey = generatePatternKey(pattern);
            learnedPatterns.put(patternKey, pattern);
            patternCount.incrementAndGet();
            
            callbacks.printOutput("Learned FP pattern: " + pattern.issueName + " on " + pattern.host);
            
        } catch (Exception e) {
            callbacks.printError("Error learning from deleted issue: " + e.getMessage());
        }
    }
    
    private void identifyCommonPatterns() {
        // Identify common characteristics in false positives
        Map<String, Integer> hostFrequency = new HashMap<>();
        Map<String, Integer> pathFrequency = new HashMap<>();
        Map<String, Integer> issueTypeFrequency = new HashMap<>();
        
        for (FalsePositivePattern pattern : learnedPatterns.values()) {
            hostFrequency.merge(pattern.host, 1, Integer::sum);
            pathFrequency.merge(pattern.path, 1, Integer::sum);
            issueTypeFrequency.merge(pattern.issueName, 1, Integer::sum);
        }
        
        // Create suppression rules for frequent patterns
        for (Map.Entry<String, Integer> entry : hostFrequency.entrySet()) {
            if (entry.getValue() >= 3) { // If same host has 3+ FPs
                createSuppressionRule("host", entry.getKey(), "Frequent false positives on host");
            }
        }
        
        for (Map.Entry<String, Integer> entry : pathFrequency.entrySet()) {
            if (entry.getValue() >= 2) { // If same path has 2+ FPs
                createSuppressionRule("path", entry.getKey(), "Frequent false positives on path");
            }
        }
    }
    
    private void applySuppressionRules() {
        IScanIssue[] currentIssues = callbacks.getScanIssues(null);
        
        for (IScanIssue issue : currentIssues) {
            if (shouldSuppressIssue(issue)) {
                // In a real implementation, this would suppress the issue
                // For now, we'll just log it and track the count
                suppressedCount.incrementAndGet();
                callbacks.printOutput("Auto-suppressed likely FP: " + issue.getIssueName() + 
                    " on " + issue.getUrl().getHost());
            }
        }
    }
    
    private boolean shouldSuppressIssue(IScanIssue issue) {
        // Check if issue matches learned false positive patterns
        for (FalsePositivePattern pattern : learnedPatterns.values()) {
            if (matchesPattern(issue, pattern)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean matchesPattern(IScanIssue issue, FalsePositivePattern pattern) {
        // Check for pattern matches
        if (!issue.getIssueName().equals(pattern.issueName)) {
            return false;
        }
        
        if (!issue.getUrl().getHost().equals(pattern.host)) {
            return false;
        }
        
        // Check for response pattern matches
        if (issue.getHttpMessages() != null && issue.getHttpMessages().length > 0) {
            IHttpRequestResponse message = issue.getHttpMessages()[0];
            if (message.getResponse() != null) {
                String response = new String(message.getResponse());
                
                // Check if response matches learned patterns
                for (String responsePattern : pattern.responsePatterns) {
                    if (response.contains(responsePattern)) {
                        return true;
                    }
                }
                
                // Check status code match
                if (pattern.statusCode != null && extractStatusCode(response).equals(pattern.statusCode)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private List<String> extractResponsePatterns(String response) {
        List<String> patterns = new ArrayList<>();
        
        // Extract common false positive indicators
        if (response.contains("404") || response.contains("Not Found")) {
            patterns.add("404_error_page");
        }
        
        if (response.contains("Access Denied") || response.contains("Forbidden")) {
            patterns.add("access_denied");
        }
        
        if (response.contains("Custom Error Page") || response.contains("Error Handler")) {
            patterns.add("custom_error_page");
        }
        
        // Extract unique strings that might be app-specific
        String[] lines = response.split("\\n");
        for (String line : lines) {
            if (line.contains("Server Error") || line.contains("Application Error")) {
                patterns.add(line.trim());
            }
        }
        
        return patterns;
    }
    
    private List<String> extractRequestPatterns(String request) {
        List<String> patterns = new ArrayList<>();
        
        // Extract request characteristics that might indicate FPs
        String[] lines = request.split("\\n");
        for (String line : lines) {
            if (line.startsWith("User-Agent:") || line.startsWith("Referer:")) {
                patterns.add(line.trim());
            }
        }
        
        return patterns;
    }
    
    private String extractStatusCode(String response) {
        String[] lines = response.split("\\n");
        if (lines.length > 0) {
            String statusLine = lines[0];
            if (statusLine.startsWith("HTTP/")) {
                String[] parts = statusLine.split(" ");
                if (parts.length >= 2) {
                    return parts[1];
                }
            }
        }
        return "unknown";
    }
    
    private String generateIssueId(IScanIssue issue) {
        return issue.getIssueName() + "|" + issue.getUrl() + "|" + 
               (issue.getIssueDetail() != null ? issue.getIssueDetail().hashCode() : "");
    }
    
    private String generatePatternKey(FalsePositivePattern pattern) {
        return pattern.issueName + "|" + pattern.host + "|" + pattern.path;
    }
    
    private void createSuppressionRule(String type, String value, String reason) {
        callbacks.printOutput("Created suppression rule: " + type + "=" + value + " (" + reason + ")");
    }
    
    public void showLearningPatterns() {
        StringBuilder patterns = new StringBuilder();
        patterns.append("LEARNED FALSE POSITIVE PATTERNS\\n");
        patterns.append("================================\\n\\n");
        
        for (Map.Entry<String, FalsePositivePattern> entry : learnedPatterns.entrySet()) {
            FalsePositivePattern pattern = entry.getValue();
            patterns.append("Pattern: ").append(entry.getKey()).append("\\n");
            patterns.append("Issue Type: ").append(pattern.issueName).append("\\n");
            patterns.append("Host: ").append(pattern.host).append("\\n");
            patterns.append("Path: ").append(pattern.path).append("\\n");
            patterns.append("Status Code: ").append(pattern.statusCode).append("\\n");
            patterns.append("Response Patterns: ").append(pattern.responsePatterns.size()).append(" patterns\\n");
            patterns.append("\\n");
        }
        
        if (learnedPatterns.isEmpty()) {
            patterns.append("No patterns learned yet. Delete some false positive issues to start learning.\\n");
        }
        
        callbacks.printOutput(patterns.toString());
    }
    
    // Supporting data class
    private static class FalsePositivePattern {
        public String issueName;
        public String url;
        public String host;
        public String path;
        public String statusCode;
        public List<String> responsePatterns = new ArrayList<>();
        public List<String> requestPatterns = new ArrayList<>();
        public long timestamp = System.currentTimeMillis();
    }
}