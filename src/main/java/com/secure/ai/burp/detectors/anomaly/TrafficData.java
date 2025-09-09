package com.secure.ai.burp.detectors.anomaly;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Traffic data structure for anomaly detection
 */
class TrafficData {
    private final String sessionId;
    private final LocalDateTime timestamp;
    private final String sourceIP;
    private final String method;
    private final String endpoint;
    private final int statusCode;
    private final long responseSize;
    private final long responseTime;
    private final int parameterCount;
    private final int headerCount;
    private final String userAgent;
    private final String userId;
    private final String payload;
    private final double payloadEntropy;
    private final long contentLength;
    private final Map<String, String> headers;
    private final Map<String, String> parameters;
    
    public TrafficData(String sessionId, LocalDateTime timestamp, String sourceIP,
                      String method, String endpoint, int statusCode, long responseSize,
                      long responseTime, int parameterCount, int headerCount,
                      String userAgent, String userId, String payload, double payloadEntropy,
                      long contentLength, Map<String, String> headers, Map<String, String> parameters) {
        this.sessionId = sessionId;
        this.timestamp = timestamp;
        this.sourceIP = sourceIP;
        this.method = method;
        this.endpoint = endpoint;
        this.statusCode = statusCode;
        this.responseSize = responseSize;
        this.responseTime = responseTime;
        this.parameterCount = parameterCount;
        this.headerCount = headerCount;
        this.userAgent = userAgent;
        this.userId = userId;
        this.payload = payload;
        this.payloadEntropy = payloadEntropy;
        this.contentLength = contentLength;
        this.headers = headers;
        this.parameters = parameters;
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getSourceIP() { return sourceIP; }
    public String getMethod() { return method; }
    public String getEndpoint() { return endpoint; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSize() { return responseSize; }
    public long getResponseTime() { return responseTime; }
    public int getParameterCount() { return parameterCount; }
    public int getHeaderCount() { return headerCount; }
    public String getUserAgent() { return userAgent; }
    public String getUserId() { return userId; }
    public String getPayload() { return payload; }
    public double getPayloadEntropy() { return payloadEntropy; }
    public long getContentLength() { return contentLength; }
    public Map<String, String> getHeaders() { return headers; }
    public Map<String, String> getParameters() { return parameters; }
}