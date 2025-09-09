package com.secure.ai.burp.analysis;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.*;
import com.secure.ai.burp.core.ApplicationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.time.LocalDateTime;
import java.time.Duration;

public class TrafficAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(TrafficAnalyzer.class);
    
    private final MontoyaApi api;
    private final Map<String, TrafficPattern> trafficPatterns;
    private final Map<String, AtomicLong> requestCounts;
    private final Map<String, LocalDateTime> lastAnalysis;
    
    // Pattern matching for various technologies and frameworks
    private static final Pattern PHP_PATTERN = Pattern.compile(".*\\.php|.*PHPSESSID.*|.*PHP/\\d.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern ASP_PATTERN = Pattern.compile(".*\\.aspx?|.*ASP\\.NET.*|.*ASPSESSIONID.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern JSP_PATTERN = Pattern.compile(".*\\.jsp|.*JSESSIONID.*|.*Tomcat.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern NODE_PATTERN = Pattern.compile(".*Express.*|.*Node\\.js.*|.*connect\\.sid.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern PYTHON_PATTERN = Pattern.compile(".*Django.*|.*Flask.*|.*Werkzeug.*|.*sessionid.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern RUBY_PATTERN = Pattern.compile(".*Rails.*|.*Ruby.*|.*_session_id.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern JAVA_PATTERN = Pattern.compile(".*Spring.*|.*Struts.*|.*Hibernate.*", Pattern.CASE_INSENSITIVE);
    
    // Database patterns
    private static final Pattern MYSQL_PATTERN = Pattern.compile(".*mysql.*|.*MariaDB.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern POSTGRES_PATTERN = Pattern.compile(".*postgres.*|.*PostgreSQL.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern ORACLE_PATTERN = Pattern.compile(".*oracle.*|.*ORA-\\d+.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern MSSQL_PATTERN = Pattern.compile(".*SQL Server.*|.*MSSQL.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern MONGODB_PATTERN = Pattern.compile(".*mongodb.*|.*mongo.*", Pattern.CASE_INSENSITIVE);
    
    // Security header patterns
    private static final Pattern CSRF_PATTERN = Pattern.compile(".*csrf.*|.*_token.*|.*authenticity_token.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern XSS_PROTECTION_PATTERN = Pattern.compile(".*X-XSS-Protection.*", Pattern.CASE_INSENSITIVE);
    
    public TrafficAnalyzer(MontoyaApi api) {
        this.api = api;
        this.trafficPatterns = new ConcurrentHashMap<>();
        this.requestCounts = new ConcurrentHashMap<>();
        this.lastAnalysis = new ConcurrentHashMap<>();
    }
    
    public void initialize() {
        logger.info("Traffic Analyzer initialized");
    }
    
    public void analyzeRequest(HttpRequestToBeSent request, ApplicationContext context) {
        try {
            String host = request.httpService().host();
            String path = request.path();
            
            // Update request count
            requestCounts.computeIfAbsent(host, k -> new AtomicLong(0)).incrementAndGet();
            
            // Extract request patterns
            TrafficPattern pattern = getOrCreatePattern(host);
            pattern.addRequest(request);
            
            // Analyze request for technologies and vulnerabilities
            analyzeRequestTechnologies(request, context);
            analyzeRequestSecurity(request, context);
            analyzeRequestParameters(request, context);
            
            lastAnalysis.put(host, LocalDateTime.now());
            
        } catch (Exception e) {
            logger.warn("Error analyzing request for host: {}", request.httpService().host(), e);
        }
    }
    
    public void analyzeResponse(HttpResponseReceived response, ApplicationContext context) {
        try {
            String host = response.initiatingRequest().httpService().host();
            
            // Extract response patterns
            TrafficPattern pattern = getOrCreatePattern(host);
            pattern.addResponse(response);
            
            // Analyze response for technologies and security indicators
            analyzeResponseTechnologies(response, context);
            analyzeResponseSecurity(response, context);
            analyzeResponseErrors(response, context);
            
        } catch (Exception e) {
            logger.warn("Error analyzing response for host: {}", 
                       response.initiatingRequest().httpService().host(), e);
        }
    }
    
    private TrafficPattern getOrCreatePattern(String host) {
        return trafficPatterns.computeIfAbsent(host, k -> new TrafficPattern(k));
    }
    
    private void analyzeRequestTechnologies(HttpRequestToBeSent request, ApplicationContext context) {
        String path = request.path();
        String headers = request.headers().toString();
        String body = request.hasBody() ? request.bodyToString() : "";
        
        // Detect technologies from path extensions and patterns
        if (PHP_PATTERN.matcher(path + headers).find()) {
            context.getDetectedTechnologies().add("php");
        }
        if (ASP_PATTERN.matcher(path + headers).find()) {
            context.getDetectedTechnologies().add("asp.net");
        }
        if (JSP_PATTERN.matcher(path + headers).find()) {
            context.getDetectedTechnologies().add("java");
            context.getFrameworks().add("jsp");
        }
        if (NODE_PATTERN.matcher(headers).find()) {
            context.getDetectedTechnologies().add("node.js");
        }
        if (PYTHON_PATTERN.matcher(headers).find()) {
            context.getDetectedTechnologies().add("python");
        }
        if (RUBY_PATTERN.matcher(headers).find()) {
            context.getDetectedTechnologies().add("ruby");
        }
        
        // Detect frameworks from headers and content
        if (JAVA_PATTERN.matcher(headers + body).find()) {
            context.getFrameworks().add("java");
        }
    }
    
    private void analyzeResponseTechnologies(HttpResponseReceived response, ApplicationContext context) {
        String headers = response.headers().toString();
        String body = response.bodyToString();
        
        // Extract server information
        for (HttpHeader header : response.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value().toLowerCase();
            
            if (name.equals("server")) {
                detectServerTechnology(value, context);
            } else if (name.equals("x-powered-by")) {
                detectPoweredByTechnology(value, context);
            } else if (name.startsWith("x-") || name.contains("framework")) {
                detectFrameworkHeaders(name, value, context);
            }
        }
        
        // Detect databases from error messages and patterns
        if (MYSQL_PATTERN.matcher(body).find()) {
            context.getDatabases().add("mysql");
        }
        if (POSTGRES_PATTERN.matcher(body).find()) {
            context.getDatabases().add("postgresql");
        }
        if (ORACLE_PATTERN.matcher(body).find()) {
            context.getDatabases().add("oracle");
        }
        if (MSSQL_PATTERN.matcher(body).find()) {
            context.getDatabases().add("mssql");
        }
        if (MONGODB_PATTERN.matcher(body).find()) {
            context.getDatabases().add("mongodb");
        }
    }
    
    private void detectServerTechnology(String serverHeader, ApplicationContext context) {
        String server = serverHeader.toLowerCase();
        
        if (server.contains("apache")) {
            context.getDetectedTechnologies().add("apache");
        }
        if (server.contains("nginx")) {
            context.getDetectedTechnologies().add("nginx");
        }
        if (server.contains("iis")) {
            context.getDetectedTechnologies().add("iis");
        }
        if (server.contains("tomcat")) {
            context.getDetectedTechnologies().add("tomcat");
            context.getFrameworks().add("java");
        }
        if (server.contains("jetty")) {
            context.getDetectedTechnologies().add("jetty");
            context.getFrameworks().add("java");
        }
    }
    
    private void detectPoweredByTechnology(String poweredBy, ApplicationContext context) {
        String powered = poweredBy.toLowerCase();
        
        if (powered.contains("php")) {
            context.getDetectedTechnologies().add("php");
        }
        if (powered.contains("asp.net")) {
            context.getDetectedTechnologies().add("asp.net");
        }
        if (powered.contains("express")) {
            context.getDetectedTechnologies().add("node.js");
            context.getFrameworks().add("express");
        }
    }
    
    private void detectFrameworkHeaders(String headerName, String headerValue, ApplicationContext context) {
        String name = headerName.toLowerCase();
        String value = headerValue.toLowerCase();
        
        if (name.contains("django") || value.contains("django")) {
            context.getFrameworks().add("django");
            context.getDetectedTechnologies().add("python");
        }
        if (name.contains("rails") || value.contains("rails")) {
            context.getFrameworks().add("rails");
            context.getDetectedTechnologies().add("ruby");
        }
        if (name.contains("spring") || value.contains("spring")) {
            context.getFrameworks().add("spring");
            context.getDetectedTechnologies().add("java");
        }
        if (name.contains("laravel") || value.contains("laravel")) {
            context.getFrameworks().add("laravel");
            context.getDetectedTechnologies().add("php");
        }
    }
    
    private void analyzeRequestSecurity(HttpRequestToBeSent request, ApplicationContext context) {
        String headers = request.headers().toString();
        String body = request.hasBody() ? request.bodyToString() : "";
        
        // Check for CSRF tokens
        if (CSRF_PATTERN.matcher(headers + body).find()) {
            // TODO: context.setHasCSRFProtection(true);
        }
        
        // Analyze authentication methods
        for (HttpHeader header : request.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value();
            
            if (name.equals("authorization")) {
                if (value.toLowerCase().startsWith("bearer")) {
                    context.getAuthenticationMethods().add("bearer_token");
                } else if (value.toLowerCase().startsWith("basic")) {
                    context.getAuthenticationMethods().add("basic_auth");
                } else {
                    context.getAuthenticationMethods().add("custom_auth");
                }
            } else if (name.equals("cookie")) {
                // Analyze session cookies
                analyzeSessionCookies(value, context);
            }
        }
    }
    
    private void analyzeResponseSecurity(HttpResponseReceived response, ApplicationContext context) {
        Map<String, String> securityHeaders = new ConcurrentHashMap<>();
        
        for (HttpHeader header : response.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value();
            
            // Collect security headers
            if (isSecurityHeader(name)) {
                securityHeaders.put(name, value);
            }
            
            // Check for specific protections
            if (name.equals("x-xss-protection")) {
                // TODO: context.setHasXSSProtection(true);
            }
            if (name.equals("x-content-type-options")) {
                securityHeaders.put(name, value);
            }
            if (name.equals("x-frame-options")) {
                securityHeaders.put(name, value);
            }
            if (name.equals("content-security-policy")) {
                securityHeaders.put(name, value);
            }
        }
        
        // TODO: context.updateSecurityHeaders(securityHeaders);
    }
    
    private void analyzeRequestParameters(HttpRequestToBeSent request, ApplicationContext context) {
        // Extract parameters from URL
        String url = request.url();
        if (url.contains("?")) {
            String queryString = url.substring(url.indexOf("?") + 1);
            String[] params = queryString.split("&");
            
            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length > 0) {
                    context.getParameters().add(keyValue[0]);
                }
            }
        }
        
        // Extract parameters from POST body
        if (request.hasBody() && request.contentType().toLowerCase().contains("form-urlencoded")) {
            String body = request.bodyToString();
            String[] params = body.split("&");
            
            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length > 0) {
                    context.getParameters().add(keyValue[0]);
                }
            }
        }
    }
    
    private void analyzeSessionCookies(String cookieHeader, ApplicationContext context) {
        String[] cookies = cookieHeader.split(";");
        
        for (String cookie : cookies) {
            String[] nameValue = cookie.trim().split("=", 2);
            if (nameValue.length > 0) {
                String cookieName = nameValue[0].toLowerCase();
                
                // Identify session management types
                if (cookieName.contains("session")) {
                    context.getSessionManagement().add("cookie_session");
                }
                if (cookieName.contains("jwt") || cookieName.contains("token")) {
                    context.getSessionManagement().add("jwt_token");
                }
                if (cookieName.startsWith("_") && cookieName.contains("session")) {
                    context.getSessionManagement().add("framework_session");
                }
                
                context.getCookies().add(cookieName);
            }
        }
    }
    
    private void analyzeResponseErrors(HttpResponseReceived response, ApplicationContext context) {
        String body = response.bodyToString();
        int statusCode = response.statusCode();
        
        // Look for database error patterns
        if (statusCode >= 500) {
            if (body.contains("SQL") || body.contains("ORA-") || body.contains("MySQL")) {
                context.recordVulnerability("sql_error_disclosure", 6.0);
            }
            if (body.contains("Exception") || body.contains("Stack trace")) {
                context.recordVulnerability("stack_trace_disclosure", 5.0);
            }
        }
        
        // Check for directory listing
        if (statusCode == 200 && body.contains("Index of /")) {
            context.recordVulnerability("directory_listing", 4.0);
        }
        
        // Check for sensitive information disclosure
        if (body.toLowerCase().contains("password") || 
            body.toLowerCase().contains("secret") ||
            body.toLowerCase().contains("private")) {
            context.recordVulnerability("sensitive_info_disclosure", 7.0);
        }
    }
    
    private boolean isSecurityHeader(String headerName) {
        String name = headerName.toLowerCase();
        return name.startsWith("x-") || 
               name.equals("content-security-policy") ||
               name.equals("strict-transport-security") ||
               name.equals("access-control-allow-origin") ||
               name.equals("referrer-policy");
    }
    
    public TrafficPattern getTrafficPattern(String host) {
        return trafficPatterns.get(host);
    }
    
    public Map<String, TrafficPattern> getAllTrafficPatterns() {
        return new ConcurrentHashMap<>(trafficPatterns);
    }
    
    public long getRequestCount(String host) {
        AtomicLong count = requestCounts.get(host);
        return count != null ? count.get() : 0;
    }
    
    public boolean hasRecentActivity(String host, Duration within) {
        LocalDateTime lastActivity = lastAnalysis.get(host);
        if (lastActivity == null) return false;
        
        return Duration.between(lastActivity, LocalDateTime.now()).compareTo(within) <= 0;
    }
}