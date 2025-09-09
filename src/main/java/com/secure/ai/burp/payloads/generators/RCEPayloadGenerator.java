package com.secure.ai.burp.payloads.generators;

import burp.api.montoya.http.HttpRequestToBeSent;
import com.secure.ai.burp.ml.ModelManager;
import com.secure.ai.burp.payloads.GeneratedPayload;
import com.secure.ai.burp.payloads.PayloadContext;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class RCEPayloadGenerator implements PayloadGeneratorStrategy {
    private final ModelManager modelManager;
    private final AtomicInteger generatedCount = new AtomicInteger(0);
    
    public RCEPayloadGenerator(ModelManager modelManager) { this.modelManager = modelManager; }
    
    @Override
    public List<GeneratedPayload> generatePayloads(HttpRequestToBeSent request, PayloadContext context) {
        List<GeneratedPayload> payloads = new ArrayList<>();
        String[] rcePayloads = {";id", "&&id", "|id", "`id`", "$(id)"};
        for (String payload : rcePayloads) {
            payloads.add(new GeneratedPayload.Builder(payload, "rce", context).build());
        }
        generatedCount.addAndGet(payloads.size());
        return payloads;
    }
    
    @Override public GeneratedPayload customizePayload(String basePayload, PayloadContext context) { return new GeneratedPayload.Builder(basePayload, "rce", context).build(); }
    @Override public String getVulnerabilityType() { return "rce"; }
    @Override public int getGeneratedCount() { return generatedCount.get(); }
    @Override public void updateLearning(GeneratedPayload payload, boolean wasSuccessful, double actualEffectiveness) {}
    @Override public double getContextualPriority(PayloadContext context) { return 0.9; }
    @Override public boolean isApplicable(PayloadContext context) { return true; }
}