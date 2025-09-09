package com.secure.ai.burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import com.secure.ai.burp.engine.AISecurityEngine;
import com.secure.ai.burp.extension.AIExtensionUI;
import com.secure.ai.burp.testing.poc.AISecurityTestingPOC;
import com.secure.ai.burp.learners.adaptive.AdvancedLearningEngine;
import com.secure.ai.burp.integrations.nuclei.NucleiIntegration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AIExtensionMain implements BurpExtension, ExtensionUnloadingHandler {
    private static final Logger logger = LoggerFactory.getLogger(AIExtensionMain.class);
    
    private AISecurityEngine securityEngine;
    private AIExtensionUI extensionUI;
    private AISecurityTestingPOC pocDemo;
    private AdvancedLearningEngine learningEngine;
    private NucleiIntegration nucleiIntegration;
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        
        // Set extension name and register unloading handler
        api.extension().setName("AI-Driven Security Testing Pro");
        api.extension().registerUnloadingHandler(this);
        
        try {
            logger.info("Initializing AI-Driven Security Testing Extension...");
            
            // Initialize the main AI Security Engine
            securityEngine = new AISecurityEngine(api);
            
            // Initialize Advanced Learning Engine
            learningEngine = new AdvancedLearningEngine(securityEngine.getModelManager());
            
            // Initialize Nuclei Integration
            nucleiIntegration = new NucleiIntegration(api, learningEngine);
            
            // Initialize POC Demonstration
            pocDemo = new AISecurityTestingPOC(api);
            
            // Initialize UI components
            extensionUI = new AIExtensionUI(api, securityEngine);
            
            // Log successful initialization
            api.logging().logToOutput("═══════════════════════════════════════════════════════");
            api.logging().logToOutput("    AI-Driven Security Testing Pro - INITIALIZED");
            api.logging().logToOutput("═══════════════════════════════════════════════════════");
            api.logging().logToOutput("✓ ML Model Manager: Active");
            api.logging().logToOutput("✓ Traffic Analyzer: Monitoring");
            api.logging().logToOutput("✓ Context Extractor: Learning");
            api.logging().logToOutput("✓ Payload Generator: Ready");
            api.logging().logToOutput("✓ Vulnerability Scanner: Armed");
            api.logging().logToOutput("✓ Advanced Learning Engine: Enabled");
            api.logging().logToOutput("✓ Nuclei Integration: " + (nucleiIntegration.isNucleiAvailable() ? "Active" : "Fallback"));
            api.logging().logToOutput("✓ Anomaly Detection: Real-time");
            api.logging().logToOutput("✓ Security Reporter: Listening");
            api.logging().logToOutput("");
            api.logging().logToOutput("🔒 Context-aware vulnerability testing active");
            api.logging().logToOutput("🤖 AI-powered payload generation enabled");
            api.logging().logToOutput("📊 Real-time traffic analysis running");
            api.logging().logToOutput("🧠 Adaptive learning engine operational");
            api.logging().logToOutput("🚀 Nuclei integration for gap analysis");
            api.logging().logToOutput("🚨 Real-time anomaly detection active");
            api.logging().logToOutput("═══════════════════════════════════════════════════════");
            api.logging().logToOutput("");
            api.logging().logToOutput("🎯 Run comprehensive POC: Extension menu → 'Run AI Security POC'");
            api.logging().logToOutput("═══════════════════════════════════════════════════════");
            
            logger.info("AI-Driven Security Testing Extension initialized successfully");
            
        } catch (Exception e) {
            String errorMsg = "Failed to initialize AI Security Extension: " + e.getMessage();
            logger.error(errorMsg, e);
            api.logging().logToError(errorMsg);
            
            // Try to show error in UI if possible
            if (api.userInterface() != null) {
                api.userInterface().applyThemeToComponent(
                    new javax.swing.JLabel("❌ " + errorMsg)
                );
            }
            
            throw new RuntimeException(errorMsg, e);
        }
    }

    @Override
    public void extensionUnloaded() {
        try {
            logger.info("Unloading AI-Driven Security Testing Extension...");
            
            if (securityEngine != null) {
                securityEngine.shutdown();
            }
            
            if (extensionUI != null) {
                extensionUI.cleanup();
            }
            
            api.logging().logToOutput("AI-Driven Security Testing Extension unloaded successfully");
            logger.info("Extension unloaded successfully");
            
        } catch (Exception e) {
            logger.error("Error during extension unloading", e);
            api.logging().logToError("Error during extension unloading: " + e.getMessage());
        }
    }
    
    // Provide access to the security engine for other components
    public AISecurityEngine getSecurityEngine() {
        return securityEngine;
    }
    
    // Provide access to the API for other components
    public MontoyaApi getApi() {
        return api;
    }
}
