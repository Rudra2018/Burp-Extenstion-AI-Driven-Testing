package com.secure.ai.burp.generators.payload;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.models.data.ApplicationContext;
import com.secure.ai.burp.analyzers.traffic.ContextExtractor;
import com.secure.ai.burp.analyzers.traffic.RequestContext;

class PayloadContextAnalyzer {
    private final ContextExtractor contextExtractor;
    
    public PayloadContextAnalyzer() {
        this.contextExtractor = new ContextExtractor();
    }
    
    public PayloadContext analyzeContext(HttpRequestToBeSent request, ApplicationContext appContext) {
        // Extract request context
        RequestContext requestContext = contextExtractor.extractContext(request);
        
        // Create and return payload context
        return new PayloadContext(request, appContext, requestContext);
    }
}