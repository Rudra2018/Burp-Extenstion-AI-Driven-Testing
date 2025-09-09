package com.secure.ai.burp.generators.payload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Payload evolution engine that learns from feedback and evolves successful payloads
 */
class PayloadEvolutionEngine {
    private static final Logger logger = LoggerFactory.getLogger(PayloadEvolutionEngine.class);
    
    private final Map<String, PayloadGenes> payloadGenome = new ConcurrentHashMap<>();
    private final Map<String, Double> fitnessScores = new ConcurrentHashMap<>();
    private final List<PayloadFeedback> feedbackHistory = Collections.synchronizedList(new ArrayList<>());
    
    // Evolution parameters
    private static final double MUTATION_RATE = 0.1;
    private static final double CROSSOVER_RATE = 0.7;
    private static final int POPULATION_SIZE = 50;
    private static final int MAX_GENERATIONS = 10;
    
    /**
     * Evolve a payload based on context and learned feedback
     */
    public String evolvePayload(String basePayload, PayloadContext context) {
        try {
            // Create initial population if needed
            String payloadKey = generatePayloadKey(basePayload, context);
            PayloadGenes genes = payloadGenome.computeIfAbsent(payloadKey, 
                k -> extractPayloadGenes(basePayload));
            
            // Generate population variations
            List<PayloadCandidate> population = generatePopulation(genes, context);
            
            // Evolve through generations
            for (int generation = 0; generation < MAX_GENERATIONS; generation++) {
                population = evolveGeneration(population, context);
            }
            
            // Return the best candidate
            return population.stream()
                .max(Comparator.comparingDouble(PayloadCandidate::getFitnessScore))
                .map(PayloadCandidate::getPayload)
                .orElse(basePayload);
                
        } catch (Exception e) {
            logger.debug("Payload evolution failed", e);
            return basePayload;
        }
    }
    
    /**
     * Provide feedback on payload effectiveness
     */
    public void provideFeedback(PayloadFeedback feedback) {
        feedbackHistory.add(feedback);
        
        // Update fitness scores
        String payloadKey = generatePayloadKey(feedback.getPayload().getPayload(), null);
        double currentScore = fitnessScores.getOrDefault(payloadKey, 0.0);
        double newScore = feedback.wasEffective() ? 1.0 : 0.0;
        
        // Weighted average with existing score
        double updatedScore = (currentScore * 0.7) + (newScore * 0.3);
        fitnessScores.put(payloadKey, updatedScore);
        
        // Keep feedback history manageable
        if (feedbackHistory.size() > 10000) {
            feedbackHistory.subList(0, feedbackHistory.size() - 5000).clear();
        }
        
        logger.debug("Updated payload fitness: {} -> {}", payloadKey.substring(0, Math.min(20, payloadKey.length())), updatedScore);
    }
    
    private List<PayloadCandidate> generatePopulation(PayloadGenes genes, PayloadContext context) {
        List<PayloadCandidate> population = new ArrayList<>();
        
        // Add the original as baseline
        String original = reconstructPayload(genes);
        population.add(new PayloadCandidate(original, calculateFitness(original, context)));
        
        // Generate variations
        for (int i = 1; i < POPULATION_SIZE; i++) {
            PayloadGenes mutated = mutateGenes(genes, context);
            String candidate = reconstructPayload(mutated);
            double fitness = calculateFitness(candidate, context);
            population.add(new PayloadCandidate(candidate, fitness));
        }
        
        return population;
    }
    
    private List<PayloadCandidate> evolveGeneration(List<PayloadCandidate> population, PayloadContext context) {
        List<PayloadCandidate> newGeneration = new ArrayList<>();
        
        // Sort by fitness
        population.sort(Comparator.comparingDouble(PayloadCandidate::getFitnessScore).reversed());
        
        // Keep top performers (elitism)
        int eliteCount = Math.max(1, POPULATION_SIZE / 10);
        newGeneration.addAll(population.subList(0, eliteCount));
        
        // Generate offspring through crossover and mutation
        while (newGeneration.size() < POPULATION_SIZE) {
            PayloadCandidate parent1 = selectParent(population);
            PayloadCandidate parent2 = selectParent(population);
            
            if (ThreadLocalRandom.current().nextDouble() < CROSSOVER_RATE) {
                PayloadCandidate offspring = crossover(parent1, parent2, context);
                newGeneration.add(offspring);
            } else {
                // Direct reproduction with mutation
                PayloadGenes genes = extractPayloadGenes(parent1.getPayload());
                PayloadGenes mutated = mutateGenes(genes, context);
                String mutatedPayload = reconstructPayload(mutated);
                newGeneration.add(new PayloadCandidate(mutatedPayload, calculateFitness(mutatedPayload, context)));
            }
        }
        
        return newGeneration;
    }
    
    private PayloadCandidate selectParent(List<PayloadCandidate> population) {
        // Tournament selection
        int tournamentSize = 3;
        PayloadCandidate best = null;
        
        for (int i = 0; i < tournamentSize; i++) {
            PayloadCandidate candidate = population.get(ThreadLocalRandom.current().nextInt(population.size()));
            if (best == null || candidate.getFitnessScore() > best.getFitnessScore()) {
                best = candidate;
            }
        }
        
        return best;
    }
    
    private PayloadCandidate crossover(PayloadCandidate parent1, PayloadCandidate parent2, PayloadContext context) {
        PayloadGenes genes1 = extractPayloadGenes(parent1.getPayload());
        PayloadGenes genes2 = extractPayloadGenes(parent2.getPayload());
        
        // Single-point crossover
        PayloadGenes offspring = new PayloadGenes();
        
        // Mix core components
        offspring.corePayload = ThreadLocalRandom.current().nextBoolean() ? 
            genes1.corePayload : genes2.corePayload;
        
        // Mix prefixes and suffixes
        offspring.prefix = ThreadLocalRandom.current().nextBoolean() ? 
            genes1.prefix : genes2.prefix;
        offspring.suffix = ThreadLocalRandom.current().nextBoolean() ? 
            genes1.suffix : genes2.suffix;
        
        // Mix encoding techniques
        offspring.encodingTechniques = new ArrayList<>(genes1.encodingTechniques);
        if (ThreadLocalRandom.current().nextBoolean()) {
            offspring.encodingTechniques.addAll(genes2.encodingTechniques);
        }
        
        // Mix evasion techniques
        offspring.evasionTechniques = new ArrayList<>(genes1.evasionTechniques);
        if (ThreadLocalRandom.current().nextBoolean()) {
            offspring.evasionTechniques.addAll(genes2.evasionTechniques);
        }
        
        String offspringPayload = reconstructPayload(offspring);
        return new PayloadCandidate(offspringPayload, calculateFitness(offspringPayload, context));
    }
    
    private PayloadGenes mutateGenes(PayloadGenes original, PayloadContext context) {
        PayloadGenes mutated = new PayloadGenes();
        
        // Copy from original
        mutated.corePayload = original.corePayload;
        mutated.prefix = original.prefix;
        mutated.suffix = original.suffix;
        mutated.encodingTechniques = new ArrayList<>(original.encodingTechniques);
        mutated.evasionTechniques = new ArrayList<>(original.evasionTechniques);
        
        ThreadLocalRandom random = ThreadLocalRandom.current();
        
        // Mutate core payload
        if (random.nextDouble() < MUTATION_RATE) {
            mutated.corePayload = mutateString(mutated.corePayload);
        }
        
        // Mutate prefix
        if (random.nextDouble() < MUTATION_RATE) {
            mutated.prefix = generateRandomPrefix(context);
        }
        
        // Mutate suffix
        if (random.nextDouble() < MUTATION_RATE) {
            mutated.suffix = generateRandomSuffix(context);
        }
        
        // Add/remove encoding techniques
        if (random.nextDouble() < MUTATION_RATE) {
            if (random.nextBoolean() && !mutated.encodingTechniques.isEmpty()) {
                mutated.encodingTechniques.remove(random.nextInt(mutated.encodingTechniques.size()));
            } else {
                mutated.encodingTechniques.add(getRandomEncodingTechnique());
            }
        }
        
        // Add/remove evasion techniques
        if (random.nextDouble() < MUTATION_RATE) {
            if (random.nextBoolean() && !mutated.evasionTechniques.isEmpty()) {
                mutated.evasionTechniques.remove(random.nextInt(mutated.evasionTechniques.size()));
            } else {
                mutated.evasionTechniques.add(getRandomEvasionTechnique());
            }
        }
        
        return mutated;
    }
    
    private PayloadGenes extractPayloadGenes(String payload) {
        PayloadGenes genes = new PayloadGenes();
        
        // Simple heuristics to extract components
        genes.corePayload = extractCorePayload(payload);
        genes.prefix = extractPrefix(payload);
        genes.suffix = extractSuffix(payload);
        genes.encodingTechniques = detectEncodingTechniques(payload);
        genes.evasionTechniques = detectEvasionTechniques(payload);
        
        return genes;
    }
    
    private String reconstructPayload(PayloadGenes genes) {
        StringBuilder payload = new StringBuilder();
        
        if (genes.prefix != null && !genes.prefix.isEmpty()) {
            payload.append(genes.prefix);
        }
        
        String core = genes.corePayload;
        
        // Apply encoding techniques
        for (String encoding : genes.encodingTechniques) {
            core = applyEncoding(core, encoding);
        }
        
        // Apply evasion techniques
        for (String evasion : genes.evasionTechniques) {
            core = applyEvasion(core, evasion);
        }
        
        payload.append(core);
        
        if (genes.suffix != null && !genes.suffix.isEmpty()) {
            payload.append(genes.suffix);
        }
        
        return payload.toString();
    }
    
    private double calculateFitness(String payload, PayloadContext context) {
        double fitness = 0.5; // Base fitness
        
        // Check historical effectiveness
        String payloadKey = generatePayloadKey(payload, context);
        Double historicalScore = fitnessScores.get(payloadKey);
        if (historicalScore != null) {
            fitness = (fitness + historicalScore) / 2.0;
        }
        
        // Context-based scoring
        if (context != null) {
            // Technology-specific bonuses
            for (String tech : context.getTechnologies()) {
                if (payload.toLowerCase().contains(tech.toLowerCase())) {
                    fitness += 0.1;
                }
            }
            
            // Content-type specific bonuses
            if (context.getContentType() != null) {
                if (context.getContentType().contains("json") && payload.contains("{")) {
                    fitness += 0.1;
                } else if (context.getContentType().contains("xml") && payload.contains("<")) {
                    fitness += 0.1;
                }
            }
        }
        
        // Complexity penalty (avoid overly complex payloads)
        if (payload.length() > 200) {
            fitness -= 0.1;
        }
        
        // Diversity bonus (encourage unique payloads)
        if (payload.matches(".*[!@#$%^&*()_+={}\\[\\]:;\"'<>?,./].*")) {
            fitness += 0.05;
        }
        
        return Math.max(0.0, Math.min(1.0, fitness));
    }
    
    // Helper methods for mutation and reconstruction
    
    private String mutateString(String input) {
        if (input == null || input.isEmpty()) return input;
        
        ThreadLocalRandom random = ThreadLocalRandom.current();
        StringBuilder mutated = new StringBuilder(input);
        
        // Random character substitution
        if (random.nextDouble() < 0.3) {
            int pos = random.nextInt(mutated.length());
            char[] alternatives = {'\'', '"', '<', '>', '&', ';', '(', ')', '=', ' '};
            mutated.setCharAt(pos, alternatives[random.nextInt(alternatives.length)]);
        }
        
        // Random insertion
        if (random.nextDouble() < 0.2) {
            int pos = random.nextInt(mutated.length() + 1);
            char[] insertions = {'/', '\\', '%', '#', '|'};
            mutated.insert(pos, insertions[random.nextInt(insertions.length)]);
        }
        
        // Random deletion
        if (random.nextDouble() < 0.1 && mutated.length() > 1) {
            int pos = random.nextInt(mutated.length());
            mutated.deleteCharAt(pos);
        }
        
        return mutated.toString();
    }
    
    private String extractCorePayload(String payload) {
        // Remove common prefixes and suffixes to get core
        String core = payload;
        
        // Remove comments
        core = core.replaceAll("--.*$", "").replaceAll("/\\*.*?\\*/", "");
        
        // Remove common SQL injection prefixes/suffixes
        if (core.startsWith("' ")) core = core.substring(2);
        if (core.startsWith("\" ")) core = core.substring(2);
        if (core.endsWith(" --")) core = core.substring(0, core.length() - 3);
        
        return core.trim();
    }
    
    private String extractPrefix(String payload) {
        if (payload.startsWith("'") || payload.startsWith("\"")) {
            return payload.substring(0, 1);
        }
        return "";
    }
    
    private String extractSuffix(String payload) {
        if (payload.endsWith("--") || payload.endsWith("/*")) {
            return payload.substring(payload.length() - 2);
        }
        if (payload.endsWith("-->")) {
            return "-->";
        }
        return "";
    }
    
    private List<String> detectEncodingTechniques(String payload) {
        List<String> techniques = new ArrayList<>();
        
        if (payload.contains("%")) techniques.add("url_encoding");
        if (payload.contains("&lt;") || payload.contains("&gt;")) techniques.add("html_encoding");
        if (payload.matches(".*\\\\u[0-9a-fA-F]{4}.*")) techniques.add("unicode_encoding");
        
        return techniques;
    }
    
    private List<String> detectEvasionTechniques(String payload) {
        List<String> techniques = new ArrayList<>();
        
        if (payload.contains("/**/")) techniques.add("comment_insertion");
        if (payload.matches(".*[A-Z][a-z].*")) techniques.add("mixed_case");
        if (payload.contains("  ")) techniques.add("space_variation");
        
        return techniques;
    }
    
    private String generateRandomPrefix(PayloadContext context) {
        String[] prefixes = {"'", "\"", ")", "'))", "\"))", "')", "\")"};
        return prefixes[ThreadLocalRandom.current().nextInt(prefixes.length)];
    }
    
    private String generateRandomSuffix(PayloadContext context) {
        String[] suffixes = {"--", "/*", "*/", "--+", "-- -", "#"};
        return suffixes[ThreadLocalRandom.current().nextInt(suffixes.length)];
    }
    
    private String getRandomEncodingTechnique() {
        String[] techniques = {"url_encoding", "html_encoding", "unicode_encoding", "base64_encoding"};
        return techniques[ThreadLocalRandom.current().nextInt(techniques.length)];
    }
    
    private String getRandomEvasionTechnique() {
        String[] techniques = {"comment_insertion", "mixed_case", "space_variation", "character_replacement"};
        return techniques[ThreadLocalRandom.current().nextInt(techniques.length)];
    }
    
    private String applyEncoding(String input, String technique) {
        switch (technique) {
            case "url_encoding":
                return input.replace(" ", "%20").replace("'", "%27").replace("\"", "%22");
            case "html_encoding":
                return input.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
            case "unicode_encoding":
                return input.replace("'", "\\u0027").replace("\"", "\\u0022");
            default:
                return input;
        }
    }
    
    private String applyEvasion(String input, String technique) {
        switch (technique) {
            case "comment_insertion":
                return input.replace(" ", "/**/");
            case "mixed_case":
                return mixCase(input);
            case "space_variation":
                return input.replace(" ", "  ");
            case "character_replacement":
                return input.replace("OR", "||");
            default:
                return input;
        }
    }
    
    private String mixCase(String input) {
        StringBuilder mixed = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (i % 2 == 0) {
                mixed.append(Character.toLowerCase(c));
            } else {
                mixed.append(Character.toUpperCase(c));
            }
        }
        return mixed.toString();
    }
    
    private String generatePayloadKey(String payload, PayloadContext context) {
        return payload.toLowerCase().replaceAll("\\s+", " ").trim();
    }
    
    // Supporting classes
    
    private static class PayloadGenes {
        String corePayload = "";
        String prefix = "";
        String suffix = "";
        List<String> encodingTechniques = new ArrayList<>();
        List<String> evasionTechniques = new ArrayList<>();
    }
    
    private static class PayloadCandidate {
        private final String payload;
        private final double fitnessScore;
        
        PayloadCandidate(String payload, double fitnessScore) {
            this.payload = payload;
            this.fitnessScore = fitnessScore;
        }
        
        String getPayload() { return payload; }
        double getFitnessScore() { return fitnessScore; }
    }
}

/**
 * Feedback data for payload effectiveness
 */
class PayloadFeedback {
    private final IntelligentPayloadGenerator.IntelligentPayload payload;
    private final boolean effective;
    private final String responseContent;
    private final double responseTime;
    private final long timestamp;
    
    public PayloadFeedback(IntelligentPayloadGenerator.IntelligentPayload payload, boolean effective, 
                          String responseContent, double responseTime, long timestamp) {
        this.payload = payload;
        this.effective = effective;
        this.responseContent = responseContent;
        this.responseTime = responseTime;
        this.timestamp = timestamp;
    }
    
    public IntelligentPayloadGenerator.IntelligentPayload getPayload() { return payload; }
    public boolean wasEffective() { return effective; }
    public String getResponseContent() { return responseContent; }
    public double getResponseTime() { return responseTime; }
    public long getTimestamp() { return timestamp; }
}