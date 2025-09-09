package com.secure.ai.burp.payloads;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.core.ApplicationContext;
import com.secure.ai.burp.analysis.ContextExtractor;
import com.secure.ai.burp.analysis.RequestContext;

public class PayloadContextAnalyzer {
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