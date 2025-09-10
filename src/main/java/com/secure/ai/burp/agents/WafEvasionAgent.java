package com.secure.ai.burp.agents;

import burp.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Tier 3: WAF Evasion Agent
 * 
 * Learns WAF patterns and generates evasion techniques.
 * Iteratively adapts payloads to bypass Web Application Firewalls.
 */
public class WafEvasionAgent {
    
    private final IBurpExtenderCallbacks callbacks;
    private final ExecutorService executorService;
    
    private final AtomicInteger evasionAttempts = new AtomicInteger(0);
    private final AtomicInteger successfulEvasions = new AtomicInteger(0);
    private volatile boolean active = false;
    
    // WAF detection and evasion
    private final Map<String, WafSignature> detectedWafs = new ConcurrentHashMap<>();
    private final List<EvasionTechnique> evasionTechniques;
    private final Map<String, List<String>> successfulEvasions_cache = new ConcurrentHashMap<>();
    
    public WafEvasionAgent(IBurpExtenderCallbacks callbacks, ExecutorService executorService) {
        this.callbacks = callbacks;
        this.executorService = executorService;
        this.evasionTechniques = initializeEvasionTechniques();
    }
    
    public void start() {
        this.active = true;
        
        // Start WAF detection
        executorService.submit(this::detectWafPresence);
        
        // Start learning from blocked requests
        executorService.submit(this::learnFromBlockedRequests);
    }
    
    public void stop() {
        this.active = false;
    }
    
    public String getStatus() {
        return active ? "ACTIVE - " + successfulEvasions.get() + " evasions found" : "STOPPED";
    }
    
    public int getEvasionAttempts() {
        return evasionAttempts.get();
    }
    
    public int getSuccessfulEvasions() {
        return successfulEvasions.get();
    }
    
    private List<EvasionTechnique> initializeEvasionTechniques() {
        List<EvasionTechnique> techniques = new ArrayList<>();
        
        // SQL Injection evasion techniques
        techniques.add(new EvasionTechnique("SQL_CASE_VARIATION", this::applyCaseVariation));
        techniques.add(new EvasionTechnique("SQL_COMMENT_INSERTION", this::applyCommentInsertion));
        techniques.add(new EvasionTechnique("SQL_ENCODING", this::applyUrlEncoding));
        techniques.add(new EvasionTechnique("SQL_WHITESPACE", this::applyWhitespaceVariation));
        techniques.add(new EvasionTechnique("SQL_FUNCTION_CONCATENATION", this::applyFunctionConcatenation));
        
        // XSS evasion techniques
        techniques.add(new EvasionTechnique("XSS_TAG_VARIATION", this::applyTagVariation));
        techniques.add(new EvasionTechnique("XSS_ENCODING", this::applyXssEncoding));
        techniques.add(new EvasionTechnique("XSS_EVENT_HANDLER", this::applyEventHandlerVariation));
        techniques.add(new EvasionTechnique("XSS_PROTOCOL_MANIPULATION", this::applyProtocolManipulation));
        
        // Command Injection evasion
        techniques.add(new EvasionTechnique("CMD_SEPARATOR_VARIATION", this::applySeparatorVariation));
        techniques.add(new EvasionTechnique("CMD_ENCODING", this::applyCommandEncoding));
        techniques.add(new EvasionTechnique("CMD_CONCATENATION", this::applyCommandConcatenation));
        
        // Generic evasion techniques
        techniques.add(new EvasionTechnique("DOUBLE_ENCODING", this::applyDoubleEncoding));
        techniques.add(new EvasionTechnique("UNICODE_EVASION", this::applyUnicodeEvasion));
        techniques.add(new EvasionTechnique("NULL_BYTE_INJECTION", this::applyNullByteInjection));
        
        return techniques;
    }
    
    private void detectWafPresence() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                IHttpRequestResponse[] history = callbacks.getProxyHistory();
                
                for (IHttpRequestResponse item : history) {
                    if (item.getResponse() != null) {
                        analyzeResponseForWafSignatures(item);
                    }
                }
                
                Thread.sleep(60000); // Check every minute
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void analyzeResponseForWafSignatures(IHttpRequestResponse item) {
        try {
            byte[] response = item.getResponse();
            String responseString = new String(response);
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
            
            String host = callbacks.getHelpers().analyzeRequest(item).getUrl().getHost();
            int statusCode = responseInfo.getStatusCode();
            
            // Check for WAF signatures
            WafSignature wafSignature = identifyWafFromResponse(responseString, responseInfo.getHeaders(), statusCode);
            if (wafSignature != null) {
                detectedWafs.put(host, wafSignature);
                callbacks.printOutput("WAF detected on " + host + ": " + wafSignature.name);
            }
            
        } catch (Exception e) {
            // Continue processing
        }
    }
    
    private WafSignature identifyWafFromResponse(String response, List<String> headers, int statusCode) {
        String lowerResponse = response.toLowerCase();
        
        // Cloudflare
        if (lowerResponse.contains("cloudflare") || 
            headers.stream().anyMatch(h -> h.toLowerCase().contains("cf-ray"))) {
            return new WafSignature("Cloudflare", "cloudflare", Arrays.asList("cf-ray", "cloudflare"));
        }
        
        // AWS WAF
        if (lowerResponse.contains("aws") && statusCode == 403) {
            return new WafSignature("AWS WAF", "aws", Arrays.asList("aws", "x-amzn-requestid"));
        }
        
        // ModSecurity
        if (lowerResponse.contains("mod_security") || lowerResponse.contains("modsecurity")) {
            return new WafSignature("ModSecurity", "modsecurity", Arrays.asList("mod_security"));
        }
        
        // Akamai
        if (headers.stream().anyMatch(h -> h.toLowerCase().contains("akamai"))) {
            return new WafSignature("Akamai", "akamai", Arrays.asList("akamai"));
        }
        
        // F5 BIG-IP
        if (lowerResponse.contains("big-ip") || lowerResponse.contains("f5")) {
            return new WafSignature("F5 BIG-IP", "f5", Arrays.asList("big-ip", "f5"));
        }
        
        // Generic WAF detection based on common blocking responses
        if (statusCode == 403 && (lowerResponse.contains("blocked") || 
                                  lowerResponse.contains("forbidden") ||
                                  lowerResponse.contains("not allowed"))) {
            return new WafSignature("Generic WAF", "generic", Arrays.asList("blocked", "forbidden"));
        }
        
        return null;
    }
    
    private void learnFromBlockedRequests() {
        Set<String> processedRequests = new HashSet<>();
        
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                IHttpRequestResponse[] history = callbacks.getProxyHistory();
                
                for (IHttpRequestResponse item : history) {
                    String requestId = generateRequestId(item);
                    if (!processedRequests.contains(requestId) && isBlockedRequest(item)) {
                        processedRequests.add(requestId);
                        learnEvasionFromBlockedRequest(item);
                    }
                }
                
                Thread.sleep(30000); // Check every 30 seconds
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private boolean isBlockedRequest(IHttpRequestResponse item) {
        if (item.getResponse() == null) return false;
        
        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(item.getResponse());
        int statusCode = responseInfo.getStatusCode();
        String response = new String(item.getResponse()).toLowerCase();
        
        return statusCode == 403 || statusCode == 406 || statusCode == 501 ||
               response.contains("blocked") || response.contains("filtered") ||
               response.contains("not allowed") || response.contains("suspicious");
    }
    
    private void learnEvasionFromBlockedRequest(IHttpRequestResponse item) {
        executorService.submit(() -> {
            try {
                String host = callbacks.getHelpers().analyzeRequest(item).getUrl().getHost();
                WafSignature waf = detectedWafs.get(host);
                
                // Try different evasion techniques
                for (EvasionTechnique technique : evasionTechniques) {
                    if (!active) break;
                    
                    String originalPayload = extractPayloadFromRequest(item);
                    if (originalPayload != null) {
                        testEvasionTechnique(item, technique, originalPayload);
                        evasionAttempts.incrementAndGet();
                    }
                    
                    // Rate limiting
                    Thread.sleep(2000);
                }
                
            } catch (Exception e) {
                callbacks.printError("Evasion learning error: " + e.getMessage());
            }
        });
    }
    
    private String extractPayloadFromRequest(IHttpRequestResponse item) {
        try {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(item);
            
            // Look for potentially malicious payloads in parameters
            for (IParameter param : requestInfo.getParameters()) {
                String value = param.getValue();
                if (containsSuspiciousContent(value)) {
                    return value;
                }
            }
            
            // Check request body for payloads
            if (item.getRequest().length > requestInfo.getBodyOffset()) {
                String body = new String(item.getRequest(), requestInfo.getBodyOffset(), 
                                       item.getRequest().length - requestInfo.getBodyOffset());
                if (containsSuspiciousContent(body)) {
                    return body;
                }
            }
            
        } catch (Exception e) {
            // Return null if extraction fails
        }
        
        return null;
    }
    
    private boolean containsSuspiciousContent(String content) {
        String lower = content.toLowerCase();
        return lower.contains("select") || lower.contains("union") || lower.contains("script") ||
               lower.contains("alert") || lower.contains("exec") || lower.contains("system") ||
               lower.contains("..") || lower.contains("=");
    }
    
    private void testEvasionTechnique(IHttpRequestResponse originalRequest, EvasionTechnique technique, String payload) {
        try {
            String evadedPayload = technique.applyTechnique.apply(payload);
            if (evadedPayload.equals(payload)) return; // No transformation applied
            
            // Create modified request with evaded payload
            byte[] modifiedRequest = createModifiedRequest(originalRequest, payload, evadedPayload);
            
            // Send the modified request
            IHttpService service = originalRequest.getHttpService();
            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(service, modifiedRequest);
            
            if (testResponse.getResponse() != null) {
                boolean wasBlocked = isBlockedRequest(testResponse);
                
                if (!wasBlocked) {
                    // Evasion successful!
                    recordSuccessfulEvasion(technique, payload, evadedPayload, originalRequest);
                    successfulEvasions.incrementAndGet();
                    
                    callbacks.printOutput("WAF EVASION SUCCESS: " + technique.name + 
                                         " bypassed blocking for payload: " + payload.substring(0, Math.min(50, payload.length())));
                }
            }
            
        } catch (Exception e) {
            // Continue with next technique
        }
    }
    
    private byte[] createModifiedRequest(IHttpRequestResponse originalRequest, String originalPayload, String evadedPayload) {
        String request = new String(originalRequest.getRequest());
        String modifiedRequest = request.replace(originalPayload, evadedPayload);
        return modifiedRequest.getBytes();
    }
    
    private void recordSuccessfulEvasion(EvasionTechnique technique, String originalPayload, String evadedPayload, IHttpRequestResponse request) {
        try {
            String host = callbacks.getHelpers().analyzeRequest(request).getUrl().getHost();
            String key = host + "_" + technique.name;
            
            successfulEvasions_cache.computeIfAbsent(key, k -> new ArrayList<>()).add(evadedPayload);
            
        } catch (Exception e) {
            // Continue
        }
    }
    
    private String generateRequestId(IHttpRequestResponse item) {
        try {
            IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(item);
            return reqInfo.getUrl().toString() + "_" + Arrays.hashCode(item.getRequest());
        } catch (Exception e) {
            return String.valueOf(System.identityHashCode(item));
        }
    }
    
    // Evasion Technique Implementations
    
    private String applyCaseVariation(String payload) {
        // Randomly vary case of alphabetic characters
        StringBuilder result = new StringBuilder();
        Random random = new Random();
        
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        
        return result.toString();
    }
    
    private String applyCommentInsertion(String payload) {
        // Insert SQL comments to break up keywords
        return payload.replaceAll("(?i)(select|union|where|from)", "$1/*comment*/");
    }
    
    private String applyUrlEncoding(String payload) {
        // Apply URL encoding to special characters
        return payload.replace(" ", "%20")
                     .replace("'", "%27")
                     .replace("\"", "%22")
                     .replace("<", "%3C")
                     .replace(">", "%3E");
    }
    
    private String applyWhitespaceVariation(String payload) {
        // Replace spaces with alternative whitespace characters
        return payload.replace(" ", "\t")
                     .replace("  ", "\n")
                     .replace("\t", "\r\n");
    }
    
    private String applyFunctionConcatenation(String payload) {
        // Use SQL functions to concatenate strings
        if (payload.contains("'")) {
            return payload.replace("'", "char(39)");
        }
        return payload;
    }
    
    private String applyTagVariation(String payload) {
        // Vary HTML tags and attributes
        return payload.replace("<script", "<ScRiPt")
                     .replace("javascript:", "java\tscript:")
                     .replace("alert", "al\\u0065rt");
    }
    
    private String applyXssEncoding(String payload) {
        // Apply various encoding techniques for XSS
        return payload.replace("<", "\\x3c")
                     .replace(">", "\\x3e")
                     .replace("'", "\\x27")
                     .replace("\"", "\\x22");
    }
    
    private String applyEventHandlerVariation(String payload) {
        // Vary event handlers
        return payload.replace("onload", "onLoad")
                     .replace("onerror", "onError")
                     .replace("onclick", "onClick");
    }
    
    private String applyProtocolManipulation(String payload) {
        // Manipulate protocol specifications
        return payload.replace("javascript:", "JAVASCRIPT:")
                     .replace("data:", "DATA:");
    }
    
    private String applySeparatorVariation(String payload) {
        // Vary command separators
        return payload.replace(";", "&&")
                     .replace("&", "||")
                     .replace("|", "\n");
    }
    
    private String applyCommandEncoding(String payload) {
        // Apply encoding to command injection payloads
        return payload.replace(" ", "${IFS}")
                     .replace("/", "\\x2f");
    }
    
    private String applyCommandConcatenation(String payload) {
        // Use concatenation techniques
        return payload.replace("cat", "c''at")
                     .replace("ls", "l''s");
    }
    
    private String applyDoubleEncoding(String payload) {
        // Apply double URL encoding
        String encoded = applyUrlEncoding(payload);
        return applyUrlEncoding(encoded);
    }
    
    private String applyUnicodeEvasion(String payload) {
        // Use Unicode alternatives
        return payload.replace("<", "\\u003c")
                     .replace(">", "\\u003e")
                     .replace("'", "\\u0027");
    }
    
    private String applyNullByteInjection(String payload) {
        // Inject null bytes
        return payload.replace("=", "=%00");
    }
    
    public List<String> generateWafEvasionPayloads(String originalPayload, String targetHost) {
        List<String> evasionPayloads = new ArrayList<>();
        
        // Check if we have successful evasions for this host
        WafSignature waf = detectedWafs.get(targetHost);
        if (waf != null) {
            // Apply techniques that have worked for this WAF type
            for (EvasionTechnique technique : evasionTechniques) {
                String key = targetHost + "_" + technique.name;
                if (successfulEvasions_cache.containsKey(key)) {
                    String evadedPayload = technique.applyTechnique.apply(originalPayload);
                    evasionPayloads.add(evadedPayload);
                }
            }
        }
        
        // If no specific successful techniques, try all
        if (evasionPayloads.isEmpty()) {
            for (EvasionTechnique technique : evasionTechniques) {
                String evadedPayload = technique.applyTechnique.apply(originalPayload);
                if (!evadedPayload.equals(originalPayload)) {
                    evasionPayloads.add(evadedPayload);
                }
            }
        }
        
        return evasionPayloads;
    }
    
    public void showWafAnalysis() {
        StringBuilder report = new StringBuilder();
        report.append("WAF DETECTION & EVASION ANALYSIS\n");
        report.append("=================================\n\n");
        
        // Show detected WAFs
        report.append("DETECTED WAFs:\n");
        for (Map.Entry<String, WafSignature> entry : detectedWafs.entrySet()) {
            WafSignature waf = entry.getValue();
            report.append("  - ").append(entry.getKey()).append(": ").append(waf.name).append("\n");
        }
        
        if (detectedWafs.isEmpty()) {
            report.append("  No WAFs detected yet.\n");
        }
        report.append("\n");
        
        // Show evasion statistics
        report.append("EVASION STATISTICS:\n");
        report.append("  Total evasion attempts: ").append(evasionAttempts.get()).append("\n");
        report.append("  Successful evasions: ").append(successfulEvasions.get()).append("\n");
        
        if (evasionAttempts.get() > 0) {
            double successRate = (double) successfulEvasions.get() / evasionAttempts.get() * 100;
            report.append("  Success rate: ").append(String.format("%.1f%%", successRate)).append("\n");
        }
        report.append("\n");
        
        // Show successful techniques
        report.append("SUCCESSFUL EVASION TECHNIQUES:\n");
        for (Map.Entry<String, List<String>> entry : successfulEvasions_cache.entrySet()) {
            report.append("  - ").append(entry.getKey()).append(": ")
                  .append(entry.getValue().size()).append(" successful payloads\n");
        }
        
        if (successfulEvasions_cache.isEmpty()) {
            report.append("  No successful evasions recorded yet.\n");
        }
        
        callbacks.printOutput(report.toString());
    }
    
    // Supporting data classes
    
    private static class WafSignature {
        public String name;
        public String type;
        public List<String> signatures;
        
        public WafSignature(String name, String type, List<String> signatures) {
            this.name = name;
            this.type = type;
            this.signatures = signatures;
        }
    }
    
    private static class EvasionTechnique {
        public String name;
        public java.util.function.Function<String, String> applyTechnique;
        
        public EvasionTechnique(String name, java.util.function.Function<String, String> applyTechnique) {
            this.name = name;
            this.applyTechnique = applyTechnique;
        }
    }
}