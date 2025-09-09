package com.secure.ai.burp.extension;

import burp.api.montoya.MontoyaApi;
import com.secure.ai.burp.engine.AISecurityEngine;

class AIExtensionUI {
    private final MontoyaApi api;
    private final AISecurityEngine securityEngine;
    
    public AIExtensionUI(MontoyaApi api, AISecurityEngine securityEngine) {
        this.api = api;
        this.securityEngine = securityEngine;
        // Initialize UI components
    }
    
    public void cleanup() {
        // Cleanup UI resources
    }
}