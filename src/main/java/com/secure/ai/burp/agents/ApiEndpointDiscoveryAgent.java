package com.secure.ai.burp.agents;

import burp.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;

/**
 * Tier 2: API & Endpoint Discovery Agent
 * 
 * Finds undocumented or hidden API endpoints through static analysis and directory brute-forcing.
 * Uses intelligent discovery patterns based on observed application structure.
 */
public class ApiEndpointDiscoveryAgent {
    
    private final IBurpExtenderCallbacks callbacks;
    private final ExecutorService executorService;
    
    private final AtomicInteger discoveredEndpoints = new AtomicInteger(0);
    private final AtomicInteger testedPaths = new AtomicInteger(0);
    private volatile boolean active = false;
    
    // Discovered endpoints and their metadata
    private final Set<String> discoveredPaths = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, EndpointInfo> endpointDetails = new ConcurrentHashMap<>();
    private final Set<String> observedHosts = Collections.synchronizedSet(new HashSet<>());
    
    // Pattern-based discovery templates
    private final List<String> apiPathPatterns;
    private final List<String> commonEndpoints;
    private final Map<String, List<String>> frameworkSpecificPaths;
    
    public ApiEndpointDiscoveryAgent(IBurpExtenderCallbacks callbacks, ExecutorService executorService) {
        this.callbacks = callbacks;
        this.executorService = executorService;
        
        initializeDiscoveryPatterns();
        this.apiPathPatterns = buildApiPathPatterns();
        this.commonEndpoints = buildCommonEndpoints();
        this.frameworkSpecificPaths = buildFrameworkPaths();
    }
    
    public void start() {
        this.active = true;
        
        // Start passive endpoint discovery from traffic
        executorService.submit(this::analyzeTrafficForEndpoints);
        
        // Start active endpoint discovery
        executorService.submit(this::performActiveDiscovery);
        
        // Start JavaScript/HTML analysis
        executorService.submit(this::analyzeClientSideCode);
    }
    
    public void stop() {
        this.active = false;
    }
    
    public String getStatus() {
        return active ? "DISCOVERING - " + discoveredEndpoints.get() + " endpoints found" : "STOPPED";
    }
    
    public int getDiscoveredCount() {
        return discoveredEndpoints.get();
    }
    
    public int getTestedCount() {
        return testedPaths.get();
    }
    
    private void initializeDiscoveryPatterns() {
        // Initialize patterns for endpoint discovery
    }
    
    private List<String> buildApiPathPatterns() {
        return Arrays.asList(
            "/api/v{version}/{resource}",
            "/api/{resource}",
            "/rest/{resource}",
            "/services/{resource}",
            "/graphql",
            "/graphql/schema",
            "/{resource}/api",
            "/admin/{resource}",
            "/internal/{resource}",
            "/private/{resource}",
            "/dev/{resource}",
            "/test/{resource}",
            "/debug/{resource}",
            "/status",
            "/health",
            "/metrics",
            "/actuator/{endpoint}",
            "/swagger.json",
            "/swagger-ui",
            "/openapi.json",
            "/.well-known/{resource}"
        );
    }
    
    private List<String> buildCommonEndpoints() {
        return Arrays.asList(
            "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
            "/wp-admin/", "/admin/", "/administrator/", "/manager/",
            "/console/", "/dashboard/", "/panel/", "/control/",
            "/api/", "/api/v1/", "/api/v2/", "/rest/", "/graphql/",
            "/swagger/", "/swagger-ui/", "/docs/", "/documentation/",
            "/config/", "/configuration/", "/settings/", "/preferences/",
            "/backup/", "/backups/", "/tmp/", "/temp/", "/cache/",
            "/logs/", "/log/", "/error/", "/errors/", "/debug/",
            "/test/", "/tests/", "/testing/", "/dev/", "/development/",
            "/staging/", "/prod/", "/production/", "/internal/", "/private/"
        );
    }
    
    private Map<String, List<String>> buildFrameworkPaths() {
        Map<String, List<String>> paths = new HashMap<>();
        
        // Spring Boot
        paths.put("spring", Arrays.asList(
            "/actuator/health", "/actuator/info", "/actuator/env",
            "/actuator/beans", "/actuator/configprops", "/actuator/dump",
            "/h2-console/", "/error", "/trace"
        ));
        
        // Django
        paths.put("django", Arrays.asList(
            "/admin/", "/static/", "/media/", "/__debug__/",
            "/api-auth/", "/docs/", "/redoc/"
        ));
        
        // Laravel
        paths.put("laravel", Arrays.asList(
            "/telescope/", "/horizon/", "/nova/", "/vapor-ui/",
            "/_ignition/health-check", "/log-viewer/"
        ));
        
        // Express.js
        paths.put("express", Arrays.asList(
            "/api/", "/auth/", "/users/", "/admin/",
            "/health", "/status", "/metrics"
        ));
        
        return paths;
    }
    
    private void analyzeTrafficForEndpoints() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                // Get current proxy history
                IHttpRequestResponse[] history = callbacks.getProxyHistory();
                
                for (IHttpRequestResponse item : history) {
                    if (item.getRequest() != null) {
                        analyzeRequestForEndpoints(item);
                    }
                    
                    if (item.getResponse() != null) {
                        analyzeResponseForEndpoints(item);
                    }
                }
                
                Thread.sleep(30000); // Analyze every 30 seconds
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void analyzeRequestForEndpoints(IHttpRequestResponse item) {
        try {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(item);
            URL url = requestInfo.getUrl();
            String host = url.getHost();
            String path = url.getPath();
            
            observedHosts.add(host);
            
            // Extract API patterns from observed traffic
            if (isApiEndpoint(path)) {
                recordDiscoveredEndpoint(url.toString(), "TRAFFIC_ANALYSIS", item);
            }
            
            // Extract potential endpoints from request parameters
            extractEndpointsFromParameters(item);
            
        } catch (Exception e) {
            // Continue processing other items
        }
    }
    
    private void analyzeResponseForEndpoints(IHttpRequestResponse item) {
        try {
            byte[] response = item.getResponse();
            if (response == null) return;
            
            String responseString = new String(response);
            
            // Look for endpoint references in response body
            extractEndpointsFromResponse(responseString, item);
            
            // Analyze response headers for additional endpoints
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
            for (String header : responseInfo.getHeaders()) {
                if (header.toLowerCase().contains("location") || 
                    header.toLowerCase().contains("link")) {
                    extractEndpointsFromHeader(header, item);
                }
            }
            
        } catch (Exception e) {
            // Continue processing
        }
    }
    
    private void performActiveDiscovery() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                // Wait for some traffic to be observed
                Thread.sleep(60000);
                
                for (String host : new HashSet<>(observedHosts)) {
                    performDiscoveryOnHost(host);
                }
                
                Thread.sleep(300000); // Perform active discovery every 5 minutes
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void performDiscoveryOnHost(String host) {
        // Test common endpoints
        for (String endpoint : commonEndpoints) {
            if (!active) break;
            
            String testUrl = "https://" + host + endpoint;
            testEndpoint(testUrl, "COMMON_ENDPOINT");
            testedPaths.incrementAndGet();
            
            try {
                Thread.sleep(1000); // Rate limiting
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        
        // Test framework-specific endpoints based on detected technology
        String detectedFramework = detectFramework(host);
        if (detectedFramework != null && frameworkSpecificPaths.containsKey(detectedFramework)) {
            for (String endpoint : frameworkSpecificPaths.get(detectedFramework)) {
                if (!active) break;
                
                String testUrl = "https://" + host + endpoint;
                testEndpoint(testUrl, "FRAMEWORK_SPECIFIC");
                testedPaths.incrementAndGet();
                
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }
    
    private void testEndpoint(String url, String discoveryMethod) {
        try {
            URL testUrl = new URL(url);
            byte[] request = callbacks.getHelpers().buildHttpRequest(testUrl);
            
            IHttpService service = callbacks.getHelpers().buildHttpService(
                testUrl.getHost(), testUrl.getPort(), 
                testUrl.getProtocol().equals("https"));
            
            IHttpRequestResponse response = callbacks.makeHttpRequest(service, request);
            
            if (response.getResponse() != null) {
                IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response.getResponse());
                int statusCode = responseInfo.getStatusCode();
                
                // Consider endpoints interesting if they don't return 404
                if (statusCode != 404 && statusCode != 403) {
                    recordDiscoveredEndpoint(url, discoveryMethod, response);
                }
            }
            
        } catch (Exception e) {
            // Continue with next endpoint
        }
    }
    
    private void analyzeClientSideCode() {
        while (active && !Thread.currentThread().isInterrupted()) {
            try {
                // Get responses containing JavaScript or HTML
                IHttpRequestResponse[] history = callbacks.getProxyHistory();
                
                for (IHttpRequestResponse item : history) {
                    if (item.getResponse() != null) {
                        analyzeClientSideCodeInResponse(item);
                    }
                }
                
                Thread.sleep(120000); // Analyze every 2 minutes
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void analyzeClientSideCodeInResponse(IHttpRequestResponse item) {
        try {
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(item.getResponse());
            String mimeType = responseInfo.getInferredMimeType();
            
            if (mimeType.contains("HTML") || mimeType.contains("script") || 
                mimeType.contains("JSON")) {
                
                String response = new String(item.getResponse());
                extractEndpointsFromClientCode(response, item);
            }
            
        } catch (Exception e) {
            // Continue processing
        }
    }
    
    private void extractEndpointsFromClientCode(String content, IHttpRequestResponse baseItem) {
        // Pattern for URL-like strings in JavaScript/HTML
        Pattern urlPattern = Pattern.compile(
            "(['\"`])((https?://[^'`\"\\s]+)|(/[^'`\"\\s]*))\\1", 
            Pattern.CASE_INSENSITIVE);
        
        Matcher matcher = urlPattern.matcher(content);
        while (matcher.find()) {
            String potentialEndpoint = matcher.group(2);
            
            if (potentialEndpoint.startsWith("/")) {
                try {
                    URL baseUrl = callbacks.getHelpers().analyzeRequest(baseItem).getUrl();
                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                   (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                   potentialEndpoint;
                    
                    if (isInterestingEndpoint(potentialEndpoint)) {
                        recordDiscoveredEndpoint(fullUrl, "CLIENT_CODE_ANALYSIS", baseItem);
                    }
                } catch (Exception e) {
                    // Continue with next match
                }
            }
        }
        
        // Look for API endpoints in fetch/xhr calls
        Pattern apiCallPattern = Pattern.compile(
            "(fetch|xhr|ajax|get|post)\\s*\\([^)]*['\"`]([^'`\"]+)['\"`]", 
            Pattern.CASE_INSENSITIVE);
        
        Matcher apiMatcher = apiCallPattern.matcher(content);
        while (apiMatcher.find()) {
            String endpoint = apiMatcher.group(2);
            if (isApiEndpoint(endpoint)) {
                try {
                    URL baseUrl = callbacks.getHelpers().analyzeRequest(baseItem).getUrl();
                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                   (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                   endpoint;
                    recordDiscoveredEndpoint(fullUrl, "API_CALL_ANALYSIS", baseItem);
                } catch (Exception e) {
                    // Continue
                }
            }
        }
    }
    
    private void extractEndpointsFromParameters(IHttpRequestResponse item) {
        try {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(item);
            
            for (IParameter param : requestInfo.getParameters()) {
                String value = param.getValue();
                
                // Check if parameter value looks like an endpoint
                if (value.startsWith("/") && value.length() > 1) {
                    URL baseUrl = requestInfo.getUrl();
                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                   (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                   value;
                    
                    if (isInterestingEndpoint(value)) {
                        recordDiscoveredEndpoint(fullUrl, "PARAMETER_ANALYSIS", item);
                    }
                }
            }
        } catch (Exception e) {
            // Continue processing
        }
    }
    
    private void extractEndpointsFromResponse(String response, IHttpRequestResponse item) {
        // Look for href and src attributes
        Pattern linkPattern = Pattern.compile(
            "(href|src|action)\\s*=\\s*['\"`]([^'`\"]+)['\"`]", 
            Pattern.CASE_INSENSITIVE);
        
        Matcher matcher = linkPattern.matcher(response);
        while (matcher.find()) {
            String endpoint = matcher.group(2);
            
            if (endpoint.startsWith("/") && isInterestingEndpoint(endpoint)) {
                try {
                    URL baseUrl = callbacks.getHelpers().analyzeRequest(item).getUrl();
                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                   (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                   endpoint;
                    recordDiscoveredEndpoint(fullUrl, "RESPONSE_ANALYSIS", item);
                } catch (Exception e) {
                    // Continue
                }
            }
        }
    }
    
    private void extractEndpointsFromHeader(String header, IHttpRequestResponse item) {
        Pattern urlPattern = Pattern.compile("https?://[^\\s]+|/[^\\s]+");
        Matcher matcher = urlPattern.matcher(header);
        
        while (matcher.find()) {
            String endpoint = matcher.group();
            
            if (endpoint.startsWith("/")) {
                try {
                    URL baseUrl = callbacks.getHelpers().analyzeRequest(item).getUrl();
                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                   (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                   endpoint;
                    recordDiscoveredEndpoint(fullUrl, "HEADER_ANALYSIS", item);
                } catch (Exception e) {
                    // Continue
                }
            } else if (endpoint.startsWith("http")) {
                recordDiscoveredEndpoint(endpoint, "HEADER_ANALYSIS", item);
            }
        }
    }
    
    private boolean isApiEndpoint(String path) {
        String lowerPath = path.toLowerCase();
        return lowerPath.contains("/api/") || 
               lowerPath.contains("/rest/") || 
               lowerPath.contains("/graphql") ||
               lowerPath.contains("/services/") ||
               lowerPath.endsWith(".json") ||
               lowerPath.endsWith(".xml");
    }
    
    private boolean isInterestingEndpoint(String path) {
        String lowerPath = path.toLowerCase();
        
        // Skip common static resources
        if (lowerPath.endsWith(".css") || lowerPath.endsWith(".js") || 
            lowerPath.endsWith(".png") || lowerPath.endsWith(".jpg") ||
            lowerPath.endsWith(".gif") || lowerPath.endsWith(".ico")) {
            return false;
        }
        
        // Interesting paths
        return lowerPath.contains("admin") || 
               lowerPath.contains("api") || 
               lowerPath.contains("config") || 
               lowerPath.contains("debug") || 
               lowerPath.contains("test") || 
               lowerPath.contains("internal") || 
               lowerPath.contains("private") ||
               lowerPath.contains("management") ||
               lowerPath.contains("status") ||
               lowerPath.contains("health");
    }
    
    private String detectFramework(String host) {
        // Simple framework detection based on observed patterns
        // In a real implementation, this would be more sophisticated
        return "spring"; // Placeholder
    }
    
    private void recordDiscoveredEndpoint(String url, String discoveryMethod, IHttpRequestResponse evidence) {
        if (!discoveredPaths.contains(url)) {
            discoveredPaths.add(url);
            discoveredEndpoints.incrementAndGet();
            
            EndpointInfo info = new EndpointInfo();
            info.url = url;
            info.discoveryMethod = discoveryMethod;
            info.timestamp = System.currentTimeMillis();
            info.evidence = evidence;
            
            endpointDetails.put(url, info);
            
            callbacks.printOutput("Discovered endpoint: " + url + " (via " + discoveryMethod + ")");
        }
    }
    
    public void showDiscoveredEndpoints() {
        StringBuilder report = new StringBuilder();
        report.append("DISCOVERED API ENDPOINTS\n");
        report.append("========================\n\n");
        
        Map<String, List<String>> groupedByMethod = new HashMap<>();
        
        for (EndpointInfo info : endpointDetails.values()) {
            groupedByMethod.computeIfAbsent(info.discoveryMethod, k -> new ArrayList<>()).add(info.url);
        }
        
        for (Map.Entry<String, List<String>> entry : groupedByMethod.entrySet()) {
            report.append(entry.getKey()).append(":\n");
            for (String url : entry.getValue()) {
                report.append("  - ").append(url).append("\n");
            }
            report.append("\n");
        }
        
        if (discoveredPaths.isEmpty()) {
            report.append("No endpoints discovered yet. Monitor traffic or perform active discovery.\n");
        } else {
            report.append("Total discovered: ").append(discoveredEndpoints.get()).append(" endpoints\n");
            report.append("Total paths tested: ").append(testedPaths.get()).append("\n");
        }
        
        callbacks.printOutput(report.toString());
    }
    
    // Supporting data class
    private static class EndpointInfo {
        public String url;
        public String discoveryMethod;
        public long timestamp;
        public IHttpRequestResponse evidence;
    }
}