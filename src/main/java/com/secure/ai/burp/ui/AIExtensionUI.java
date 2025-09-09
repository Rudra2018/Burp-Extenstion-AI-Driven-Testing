package com.secure.ai.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.secure.ai.burp.core.AISecurityEngine;

public class AIExtensionUI {
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