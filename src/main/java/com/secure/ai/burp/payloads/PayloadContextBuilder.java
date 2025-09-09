package com.secure.ai.burp.payloads;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Context information for intelligent payload generation
 */
public class PayloadContext {
    private final String method;
    private final String path;
    private final String contentType;
    private final Map<String, String> parameters;
    private final Map<String, String> headers;
    private final Set<String> technologies;
    private final String applicationType;
    private final List<String> endpoints;
    private final String bodyContent;
    private final double bodyEntropy;
    private final int bodyLength;
    
    private PayloadContext(Builder builder) {
        this.method = builder.method;
        this.path = builder.path;
        this.contentType = builder.contentType;
        this.parameters = builder.parameters;
        this.headers = builder.headers;
        this.technologies = builder.technologies;
        this.applicationType = builder.applicationType;
        this.endpoints = builder.endpoints;
        this.bodyContent = builder.bodyContent;
        this.bodyEntropy = builder.bodyEntropy;
        this.bodyLength = builder.bodyLength;
    }
    
    // Getters
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getContentType() { return contentType; }
    public Map<String, String> getParameters() { return parameters; }
    public Map<String, String> getHeaders() { return headers; }
    public Set<String> getTechnologies() { return technologies; }
    public String getApplicationType() { return applicationType; }
    public List<String> getEndpoints() { return endpoints; }
    public String getBodyContent() { return bodyContent; }
    public double getBodyEntropy() { return bodyEntropy; }
    public int getBodyLength() { return bodyLength; }
    
    public static class Builder {
        private String method;
        private String path;
        private String contentType;
        private Map<String, String> parameters;
        private Map<String, String> headers;
        private Set<String> technologies;
        private String applicationType;
        private List<String> endpoints;
        private String bodyContent;
        private double bodyEntropy;
        private int bodyLength;
        
        public Builder withMethod(String method) {
            this.method = method;
            return this;
        }
        
        public Builder withPath(String path) {
            this.path = path;
            return this;
        }
        
        public Builder withContentType(String contentType) {
            this.contentType = contentType;
            return this;
        }
        
        public Builder withParameters(Map<String, String> parameters) {
            this.parameters = parameters;
            return this;
        }
        
        public Builder withHeaders(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }
        
        public Builder withTechnologies(Set<String> technologies) {
            this.technologies = technologies;
            return this;
        }
        
        public Builder withApplicationType(String applicationType) {
            this.applicationType = applicationType;
            return this;
        }
        
        public Builder withEndpoints(List<String> endpoints) {
            this.endpoints = endpoints;
            return this;
        }
        
        public Builder withBodyContent(String bodyContent) {
            this.bodyContent = bodyContent;
            return this;
        }
        
        public Builder withBodyEntropy(double bodyEntropy) {
            this.bodyEntropy = bodyEntropy;
            return this;
        }
        
        public Builder withBodyLength(int bodyLength) {
            this.bodyLength = bodyLength;
            return this;
        }
        
        public PayloadContext build() {
            return new PayloadContext(this);
        }
    }
}

/**
 * Builder class for PayloadContext
 */
class PayloadContextBuilder {
    private final PayloadContext.Builder builder = new PayloadContext.Builder();
    
    public PayloadContextBuilder withMethod(String method) {
        builder.withMethod(method);
        return this;
    }
    
    public PayloadContextBuilder withPath(String path) {
        builder.withPath(path);
        return this;
    }
    
    public PayloadContextBuilder withContentType(String contentType) {
        builder.withContentType(contentType);
        return this;
    }
    
    public PayloadContextBuilder withParameters(Map<String, String> parameters) {
        builder.withParameters(parameters);
        return this;
    }
    
    public PayloadContextBuilder withHeaders(Map<String, String> headers) {
        builder.withHeaders(headers);
        return this;
    }
    
    public PayloadContextBuilder withTechnologies(Set<String> technologies) {
        builder.withTechnologies(technologies);
        return this;
    }
    
    public PayloadContextBuilder withApplicationType(String applicationType) {
        builder.withApplicationType(applicationType);
        return this;
    }
    
    public PayloadContextBuilder withEndpoints(List<String> endpoints) {
        builder.withEndpoints(endpoints);
        return this;
    }
    
    public PayloadContextBuilder withBodyContent(String bodyContent) {
        builder.withBodyContent(bodyContent);
        return this;
    }
    
    public PayloadContextBuilder withBodyEntropy(double bodyEntropy) {
        builder.withBodyEntropy(bodyEntropy);
        return this;
    }
    
    public PayloadContextBuilder withBodyLength(int bodyLength) {
        builder.withBodyLength(bodyLength);
        return this;
    }
    
    public PayloadContext build() {
        return builder.build();
    }
}