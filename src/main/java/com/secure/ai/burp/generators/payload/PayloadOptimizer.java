package com.secure.ai.burp.generators.payload;

import com.secure.ai.burp.models.ml.ModelManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

class PayloadOptimizer {
    private static final Logger logger = LoggerFactory.getLogger(PayloadOptimizer.class);
    
    private final ModelManager modelManager;
    
    public PayloadOptimizer(ModelManager modelManager) {
        this.modelManager = modelManager;
    }
    
    public List<GeneratedPayload> optimizePayloads(List<GeneratedPayload> payloads, PayloadContext context) {
        // Remove low-priority payloads
        List<GeneratedPayload> optimized = payloads.stream()
                .filter(p -> p.getFinalScore() >= 0.3)
                .collect(Collectors.toList());
        
        // Limit payload count based on context
        int maxPayloads = getMaxPayloadsForContext(context);
        if (optimized.size() > maxPayloads) {
            optimized = optimized.stream()
                    .sorted((p1, p2) -> Double.compare(p2.getFinalScore(), p1.getFinalScore()))
                    .limit(maxPayloads)
                    .collect(Collectors.toList());
        }
        
        return optimized;
    }
    
    private int getMaxPayloadsForContext(PayloadContext context) {
        if (context.isHighRiskContext()) return 50;
        if (context.isLowRiskContext()) return 10;
        return 25;
    }
    
    public void updateLearning(GeneratedPayload payload, boolean wasSuccessful, double actualEffectiveness) {
        // Update optimization learning
        logger.debug("Updating optimizer learning for payload: {}", payload.getVulnerabilityType());
    }
}