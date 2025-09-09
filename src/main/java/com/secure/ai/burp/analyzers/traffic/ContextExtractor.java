package com.secure.ai.burp.analyzers.traffic;

import burp.api.montoya.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

class ContextExtractor {
    private static final Logger logger = LoggerFactory.getLogger(ContextExtractor.class);
    
    // Patterns for extracting various contexts
    private static final Pattern PARAM_PATTERN = Pattern.compile("[?&]([^=&]+)=([^&]*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTH_PATTERN = Pattern.compile("(token|session|auth|login|password|secret)", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSRF_PATTERN = Pattern.compile("(csrf|_token|authenticity_token|__RequestVerificationToken)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ID_PATTERN = Pattern.compile("(id|uid|user_?id|account_?id|session_?id)", Pattern.CASE_INSENSITIVE);
    
    // Content type patterns
    private static final Pattern JSON_PATTERN = Pattern.compile("application/json", Pattern.CASE_INSENSITIVE);
    private static final Pattern XML_PATTERN = Pattern.compile("(application|text)/(xml|soap)", Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_PATTERN = Pattern.compile("application/x-www-form-urlencoded", Pattern.CASE_INSENSITIVE);
    private static final Pattern MULTIPART_PATTERN = Pattern.compile("multipart/form-data", Pattern.CASE_INSENSITIVE);
    
    // Technology detection patterns
    private static final Pattern TECHNOLOGY_PATTERNS = Pattern.compile(
        "(php|asp\\.?net|jsp|node\\.?js|python|ruby|java|go|rust|c#|\\.net)", 
        Pattern.CASE_INSENSITIVE
    );
    
    public ContextExtractor() {
        logger.info("Context Extractor initialized");
    }
    
    public RequestContext extractContext(HttpRequestToBeSent request) {
        RequestContext context = new RequestContext();
        
        try {
            // Basic request information
            context.setMethod(request.method());
            context.setPath(request.path());
            context.setUrl(request.url());
            context.setHasBody(request.hasBody());
            
            // Extract headers context
            extractRequestHeaders(request, context);
            
            // Extract parameters
            extractRequestParameters(request, context);
            
            // Extract cookies
            extractRequestCookies(request, context);
            
            // Extract content type and body context
            extractRequestBody(request, context);
            
            // Analyze authentication context
            analyzeAuthentication(request, context);
            
            // Extract additional metadata
            extractRequestMetadata(request, context);
            
        } catch (Exception e) {
            logger.warn("Error extracting request context", e);
        }
        
        return context;
    }
    
    public ResponseContext extractContext(HttpResponseReceived response) {
        ResponseContext context = new ResponseContext();
        
        try {
            // Basic response information
            context.setStatusCode(response.statusCode());
            context.setHasBody(response.body().length() > 0);
            context.setBodyLength(response.body().length());
            
            // Extract headers context
            extractResponseHeaders(response, context);
            
            // Extract content analysis
            extractResponseContent(response, context);
            
            // Detect technologies from response
            detectResponseTechnologies(response, context);
            
            // Analyze security headers
            analyzeSecurityHeaders(response, context);
            
            // Extract error information
            extractErrorContext(response, context);
            
            // Extract additional metadata
            extractResponseMetadata(response, context);
            
        } catch (Exception e) {
            logger.warn("Error extracting response context", e);
        }
        
        return context;
    }
    
    private void extractRequestHeaders(HttpRequestToBeSent request, RequestContext context) {
        Map<String, String> headers = new ConcurrentHashMap<>();
        
        for (HttpHeader header : request.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value();
            headers.put(name, value);
            
            // Analyze specific headers
            switch (name) {
                case "user-agent":
                    context.setUserAgent(value);
                    break;
                case "referer":
                    context.setReferer(value);
                    break;
                case "host":
                    context.setHost(value);
                    break;
                case "content-type":
                    context.setContentType(value);
                    break;
                case "authorization":
                    context.setHasAuthHeaders(true);
                    analyzeAuthorizationHeader(value, context);
                    break;
                case "x-requested-with":
                    if (value.equalsIgnoreCase("XMLHttpRequest")) {
                        context.setIsAjaxRequest(true);
                    }
                    break;
            }
        }
        
        context.setHeaders(headers);
    }
    
    private void extractRequestParameters(HttpRequestToBeSent request, RequestContext context) {
        Set<String> parameters = new HashSet<>();
        Map<String, String> parameterValues = new ConcurrentHashMap<>();
        
        // Extract URL parameters
        String url = request.url();
        if (url.contains("?")) {
            String queryString = url.substring(url.indexOf("?") + 1);
            Matcher matcher = PARAM_PATTERN.matcher("?" + queryString);
            
            while (matcher.find()) {
                String paramName = urlDecode(matcher.group(1));
                String paramValue = urlDecode(matcher.group(2));
                
                parameters.add(paramName);
                parameterValues.put(paramName, paramValue);
                
                // Analyze parameter types
                analyzeParameterType(paramName, paramValue, context);
            }
        }
        
        // Extract POST parameters
        if (request.hasBody() && context.getContentType() != null) {
            if (FORM_PATTERN.matcher(context.getContentType()).find()) {
                String body = request.bodyToString();
                Matcher matcher = PARAM_PATTERN.matcher("?" + body);
                
                while (matcher.find()) {
                    String paramName = urlDecode(matcher.group(1));
                    String paramValue = urlDecode(matcher.group(2));
                    
                    parameters.add(paramName);
                    parameterValues.put(paramName, paramValue);
                    
                    analyzeParameterType(paramName, paramValue, context);
                }
            } else if (JSON_PATTERN.matcher(context.getContentType()).find()) {
                // For JSON, we'd need a JSON parser, but for now just mark as JSON request
                context.setIsJsonRequest(true);
            }
        }
        
        context.setParameters(parameters);
        context.setParameterValues(parameterValues);
    }
    
    private void extractRequestCookies(HttpRequestToBeSent request, RequestContext context) {
        Set<String> cookies = new HashSet<>();
        Map<String, String> cookieValues = new ConcurrentHashMap<>();
        
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase("cookie")) {
                String[] cookiePairs = header.value().split(";");
                
                for (String cookiePair : cookiePairs) {
                    String[] nameValue = cookiePair.trim().split("=", 2);
                    if (nameValue.length >= 1) {
                        String cookieName = nameValue[0].trim();
                        String cookieValue = nameValue.length > 1 ? nameValue[1].trim() : "";
                        
                        cookies.add(cookieName);
                        cookieValues.put(cookieName, cookieValue);
                        
                        // Analyze cookie types
                        analyzeCookieType(cookieName, cookieValue, context);
                    }
                }
                break;
            }
        }
        
        context.setCookies(cookies);
        context.setCookieValues(cookieValues);
    }
    
    private void extractRequestBody(HttpRequestToBeSent request, RequestContext context) {
        if (!request.hasBody()) return;
        
        String body = request.bodyToString();
        context.setBodyContent(body);
        context.setBodyLength(body.length());
        
        // Analyze body content type
        String contentType = context.getContentType();
        if (contentType != null) {
            if (JSON_PATTERN.matcher(contentType).find()) {
                context.setIsJsonRequest(true);
                analyzeJsonContent(body, context);
            } else if (XML_PATTERN.matcher(contentType).find()) {
                context.setIsXmlRequest(true);
                analyzeXmlContent(body, context);
            } else if (MULTIPART_PATTERN.matcher(contentType).find()) {
                context.setIsFileUpload(true);
            }
        }
    }
    
    private void extractResponseHeaders(HttpResponseReceived response, ResponseContext context) {
        Map<String, String> headers = new ConcurrentHashMap<>();
        
        for (HttpHeader header : response.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value();
            headers.put(name, value);
            
            // Analyze specific response headers
            switch (name) {
                case "server":
                    context.setServerType(value);
                    detectServerTechnology(value, context);
                    break;
                case "x-powered-by":
                    detectPoweredByTechnology(value, context);
                    break;
                case "content-type":
                    context.setContentType(value);
                    break;
                case "set-cookie":
                    analyzeSetCookieHeader(value, context);
                    break;
                case "location":
                    context.setRedirectLocation(value);
                    break;
            }
        }
        
        context.setHeaders(headers);
    }
    
    private void extractResponseContent(HttpResponseReceived response, ResponseContext context) {
        String body = response.bodyToString();
        context.setBodyContent(body);
        context.setBodyLength(body.length());
        
        // Analyze content for technologies
        analyzeContentForTechnologies(body, context);
        
        // Check for error patterns
        analyzeErrorPatterns(body, response.statusCode(), context);
        
        // Look for sensitive information
        analyzeSensitiveInformation(body, context);
    }
    
    private void analyzeAuthentication(HttpRequestToBeSent request, RequestContext context) {
        Set<String> authMethods = new HashSet<>();
        
        // Check Authorization header
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase("authorization")) {
                String value = header.value().toLowerCase();
                
                if (value.startsWith("bearer")) {
                    authMethods.add("bearer_token");
                } else if (value.startsWith("basic")) {
                    authMethods.add("basic_auth");
                } else if (value.startsWith("digest")) {
                    authMethods.add("digest_auth");
                } else {
                    authMethods.add("custom_auth");
                }
                break;
            }
        }
        
        // Check for session cookies
        for (String cookie : context.getCookies()) {
            if (cookie.toLowerCase().contains("session") || 
                cookie.toLowerCase().contains("auth") ||
                cookie.toLowerCase().contains("token")) {
                authMethods.add("session_cookie");
                break;
            }
        }
        
        // Check for authentication parameters
        for (String param : context.getParameters()) {
            if (AUTH_PATTERN.matcher(param).find()) {
                authMethods.add("auth_parameter");
                break;
            }
        }
        
        context.setAuthMethods(authMethods);
    }
    
    private void analyzeParameterType(String name, String value, RequestContext context) {
        // Check for CSRF tokens
        if (CSRF_PATTERN.matcher(name).find()) {
            context.setHasCSRFToken(true);
        }
        
        // Check for ID parameters
        if (ID_PATTERN.matcher(name).find()) {
            context.getIdParameters().add(name);
        }
        
        // Check for authentication parameters
        if (AUTH_PATTERN.matcher(name).find()) {
            context.setHasAuthParameters(true);
        }
        
        // Analyze value patterns for potential vulnerabilities
        if (value != null && !value.isEmpty()) {
            analyzeParameterValue(name, value, context);
        }
    }
    
    private void analyzeParameterValue(String name, String value, RequestContext context) {
        String lowerValue = value.toLowerCase();
        
        // Check for potential XSS payloads
        if (lowerValue.contains("<script") || lowerValue.contains("javascript:") || 
            lowerValue.contains("onerror") || lowerValue.contains("alert(")) {
            context.getSuspiciousParameters().add(name + "=xss_pattern");
        }
        
        // Check for potential SQL injection
        if (lowerValue.contains("union select") || lowerValue.contains("' or ") || 
            lowerValue.contains("\" or ") || lowerValue.contains("--")) {
            context.getSuspiciousParameters().add(name + "=sqli_pattern");
        }
        
        // Check for potential SSRF
        if (lowerValue.contains("localhost") || lowerValue.contains("127.0.0.1") || 
            lowerValue.contains("file://") || lowerValue.contains("169.254")) {
            context.getSuspiciousParameters().add(name + "=ssrf_pattern");
        }
        
        // Check for path traversal
        if (lowerValue.contains("../") || lowerValue.contains("..\\") || 
            lowerValue.contains("etc/passwd")) {
            context.getSuspiciousParameters().add(name + "=path_traversal");
        }
    }
    
    private void analyzeCookieType(String name, String value, RequestContext context) {
        String lowerName = name.toLowerCase();
        
        if (lowerName.contains("session")) {
            context.getSessionMethods().add("session_cookie");
        }
        if (lowerName.contains("jwt") || lowerName.contains("token")) {
            context.getSessionMethods().add("jwt_token");
        }
        if (lowerName.contains("auth")) {
            context.getSessionMethods().add("auth_cookie");
        }
    }
    
    private void analyzeJsonContent(String json, RequestContext context) {
        // Simple JSON analysis - in a real implementation, you'd use a JSON parser
        if (json.contains("\"password\"") || json.contains("\"secret\"")) {
            context.setHasSensitiveData(true);
        }
        if (json.contains("\"token\"") || json.contains("\"auth\"")) {
            context.setHasAuthData(true);
        }
    }
    
    private void analyzeXmlContent(String xml, RequestContext context) {
        if (xml.contains("password") || xml.contains("secret")) {
            context.setHasSensitiveData(true);
        }
        if (xml.contains("<!ENTITY") || xml.contains("<!DOCTYPE")) {
            context.setSusceptibleToXXE(true);
        }
    }
    
    private void analyzeAuthorizationHeader(String authValue, RequestContext context) {
        if (authValue.toLowerCase().startsWith("bearer")) {
            String token = authValue.substring(7).trim();
            if (token.contains(".")) {
                context.getAuthMethods().add("jwt_token");
            } else {
                context.getAuthMethods().add("bearer_token");
            }
        }
    }
    
    private void detectServerTechnology(String server, ResponseContext context) {
        String lowerServer = server.toLowerCase();
        
        if (lowerServer.contains("apache")) {
            context.getDetectedTechnologies().add("apache");
        }
        if (lowerServer.contains("nginx")) {
            context.getDetectedTechnologies().add("nginx");
        }
        if (lowerServer.contains("iis")) {
            context.getDetectedTechnologies().add("iis");
        }
        if (lowerServer.contains("tomcat")) {
            context.getDetectedTechnologies().add("tomcat");
            context.getFrameworks().add("java");
        }
    }
    
    private void detectPoweredByTechnology(String poweredBy, ResponseContext context) {
        String lowerPowered = poweredBy.toLowerCase();
        
        if (lowerPowered.contains("php")) {
            context.getDetectedTechnologies().add("php");
        }
        if (lowerPowered.contains("asp.net")) {
            context.getDetectedTechnologies().add("asp.net");
        }
        if (lowerPowered.contains("express")) {
            context.getDetectedTechnologies().add("node.js");
            context.getFrameworks().add("express");
        }
    }
    
    private void detectResponseTechnologies(HttpResponseReceived response, ResponseContext context) {
        // Detect from response body
        String body = response.bodyToString().toLowerCase();
        
        Matcher techMatcher = TECHNOLOGY_PATTERNS.matcher(body);
        while (techMatcher.find()) {
            String tech = techMatcher.group(1).toLowerCase();
            context.getDetectedTechnologies().add(tech);
        }
        
        // Detect frameworks from HTML comments, meta tags, etc.
        detectFrameworksFromContent(body, context);
    }
    
    private void detectFrameworksFromContent(String content, ResponseContext context) {
        if (content.contains("django")) {
            context.getFrameworks().add("django");
            context.getDetectedTechnologies().add("python");
        }
        if (content.contains("rails") || content.contains("ruby")) {
            context.getFrameworks().add("rails");
            context.getDetectedTechnologies().add("ruby");
        }
        if (content.contains("laravel")) {
            context.getFrameworks().add("laravel");
            context.getDetectedTechnologies().add("php");
        }
        if (content.contains("spring")) {
            context.getFrameworks().add("spring");
            context.getDetectedTechnologies().add("java");
        }
    }
    
    private void analyzeContentForTechnologies(String content, ResponseContext context) {
        String lowerContent = content.toLowerCase();
        
        // Database detection from error messages
        if (lowerContent.contains("mysql") || lowerContent.contains("mariadb")) {
            context.getDetectedDatabases().add("mysql");
        }
        if (lowerContent.contains("postgresql") || lowerContent.contains("postgres")) {
            context.getDetectedDatabases().add("postgresql");
        }
        if (lowerContent.contains("oracle") || lowerContent.contains("ora-")) {
            context.getDetectedDatabases().add("oracle");
        }
        if (lowerContent.contains("sql server") || lowerContent.contains("mssql")) {
            context.getDetectedDatabases().add("mssql");
        }
        if (lowerContent.contains("mongodb") || lowerContent.contains("mongo")) {
            context.getDetectedDatabases().add("mongodb");
        }
    }
    
    private void analyzeSecurityHeaders(HttpResponseReceived response, ResponseContext context) {
        Map<String, String> securityHeaders = new ConcurrentHashMap<>();
        
        for (HttpHeader header : response.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value();
            
            if (isSecurityHeader(name)) {
                securityHeaders.put(name, value);
                
                // Analyze specific security headers
                switch (name) {
                    case "x-xss-protection":
                        context.setHasXSSProtection(true);
                        break;
                    case "x-content-type-options":
                        if (value.equalsIgnoreCase("nosniff")) {
                            context.setHasContentTypeProtection(true);
                        }
                        break;
                    case "x-frame-options":
                        context.setHasClickjackingProtection(true);
                        break;
                    case "content-security-policy":
                        context.setHasCSP(true);
                        break;
                    case "strict-transport-security":
                        context.setHasHSTS(true);
                        break;
                }
            }
        }
        
        context.setSecurityHeaders(securityHeaders);
    }
    
    private void analyzeSetCookieHeader(String setCookieValue, ResponseContext context) {
        String lowerValue = setCookieValue.toLowerCase();
        
        if (lowerValue.contains("httponly")) {
            context.setHasHttpOnlyCookies(true);
        }
        if (lowerValue.contains("secure")) {
            context.setHasSecureCookies(true);
        }
        if (lowerValue.contains("samesite")) {
            context.setHasSameSiteCookies(true);
        }
    }
    
    private void analyzeErrorPatterns(String content, int statusCode, ResponseContext context) {
        if (statusCode >= 400) {
            String lowerContent = content.toLowerCase();
            
            if (lowerContent.contains("sql") || lowerContent.contains("database")) {
                context.getErrorTypes().add("sql_error");
            }
            if (lowerContent.contains("exception") || lowerContent.contains("stack trace")) {
                context.getErrorTypes().add("exception");
            }
            if (lowerContent.contains("not found") || statusCode == 404) {
                context.getErrorTypes().add("not_found");
            }
            if (lowerContent.contains("forbidden") || statusCode == 403) {
                context.getErrorTypes().add("forbidden");
            }
            if (statusCode >= 500) {
                context.getErrorTypes().add("server_error");
            }
        }
    }
    
    private void analyzeSensitiveInformation(String content, ResponseContext context) {
        String lowerContent = content.toLowerCase();
        
        if (lowerContent.contains("password") || lowerContent.contains("secret")) {
            context.setHasSensitiveInfo(true);
            context.getSensitiveInfoTypes().add("credentials");
        }
        if (lowerContent.contains("api key") || lowerContent.contains("token")) {
            context.setHasSensitiveInfo(true);
            context.getSensitiveInfoTypes().add("api_keys");
        }
        if (lowerContent.contains("private") || lowerContent.contains("confidential")) {
            context.setHasSensitiveInfo(true);
            context.getSensitiveInfoTypes().add("private_info");
        }
    }
    
    private void extractRequestMetadata(HttpRequestToBeSent request, RequestContext context) {
        Map<String, Object> metadata = new ConcurrentHashMap<>();
        
        metadata.put("timestamp", System.currentTimeMillis());
        metadata.put("url_length", request.url().length());
        metadata.put("header_count", request.headers().size());
        metadata.put("is_https", request.url().startsWith("https"));
        metadata.put("has_query_params", request.url().contains("?"));
        
        context.setAdditionalData(metadata);
    }
    
    private void extractResponseMetadata(HttpResponseReceived response, ResponseContext context) {
        Map<String, Object> metadata = new ConcurrentHashMap<>();
        
        metadata.put("timestamp", System.currentTimeMillis());
        metadata.put("header_count", response.headers().size());
        metadata.put("content_length", response.body().length());
        metadata.put("is_redirect", response.statusCode() >= 300 && response.statusCode() < 400);
        metadata.put("is_error", response.statusCode() >= 400);
        
        context.setAdditionalData(metadata);
    }
    
    private boolean isSecurityHeader(String headerName) {
        String name = headerName.toLowerCase();
        return name.startsWith("x-") || 
               name.equals("content-security-policy") ||
               name.equals("strict-transport-security") ||
               name.equals("referrer-policy") ||
               name.equals("permissions-policy");
    }
    
    private String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value; // Return original if decoding fails
        }
    }
}