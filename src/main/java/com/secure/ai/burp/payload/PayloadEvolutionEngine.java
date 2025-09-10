package com.secure.ai.burp.payload;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.secure.ai.burp.payload.PayloadGeneratorAgent.TechStackInfo;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * PayloadEvolutionEngine - Genetic Algorithm-Based Payload Evolution
 * 
 * Uses genetic algorithms to evolve and optimize payloads based on:
 * - Success rates from previous attempts
 * - Target technology stack characteristics
 * - Bypass techniques effectiveness
 * - Encoding and obfuscation strategies
 */
public class PayloadEvolutionEngine {
    
    private static final int POPULATION_SIZE = 20;
    private static final int MAX_GENERATIONS = 10;
    private static final double MUTATION_RATE = 0.1;
    private static final double CROSSOVER_RATE = 0.7;
    private static final int ELITE_COUNT = 4;
    
    private final Map<String, PayloadDNA> payloadGenome;
    private final Map<String, Double> payloadFitness;
    private final Random random;
    
    public PayloadEvolutionEngine() {
        this.payloadGenome = new HashMap<>();
        this.payloadFitness = new HashMap<>();
        this.random = ThreadLocalRandom.current();
        
        initializePayloadGenome();
    }
    
    /**
     * Evolve payloads using genetic algorithms
     */
    public void evolvePayloads(ObjectNode payloadsResult, TechStackInfo techStack) {
        JsonNode payloadCategories = payloadsResult.get("payloads");
        
        if (payloadCategories != null && payloadCategories.isObject()) {
            // Evolve each category of payloads
            payloadCategories.fields().forEachRemaining(entry -> {
                String category = entry.getKey();
                JsonNode categoryPayloads = entry.getValue();
                
                if (categoryPayloads.isArray()) {
                    evolvePayloadCategory(category, (ArrayNode) categoryPayloads, techStack);
                }
            });
        }
        
        // Add evolved metadata
        payloadsResult.put("evolution_applied", true);
        payloadsResult.put("evolution_generations", MAX_GENERATIONS);
        payloadsResult.put("population_size", POPULATION_SIZE);
        payloadsResult.put("mutation_rate", MUTATION_RATE);
    }
    
    private void evolvePayloadCategory(String category, ArrayNode payloads, TechStackInfo techStack) {
        if (payloads.size() == 0) return;
        
        List<PayloadIndividual> population = createInitialPopulation(payloads, category);
        
        for (int generation = 0; generation < MAX_GENERATIONS; generation++) {
            // Evaluate fitness
            evaluateFitness(population, techStack, category);
            
            // Create next generation
            population = createNextGeneration(population);
            
            // Apply tech stack specific mutations
            applyTechStackMutations(population, techStack);
        }
        
        // Replace original payloads with evolved ones
        replaceWithEvolvedPayloads(payloads, population);
        
        // Add evolution statistics
        addEvolutionStats(payloads, population);
    }
    
    private List<PayloadIndividual> createInitialPopulation(ArrayNode originalPayloads, String category) {
        List<PayloadIndividual> population = new ArrayList<>();
        
        // Add original payloads as initial population
        for (int i = 0; i < originalPayloads.size() && population.size() < POPULATION_SIZE; i++) {
            JsonNode payloadNode = originalPayloads.get(i);
            if (payloadNode.has("payload")) {
                String payload = payloadNode.get("payload").asText();
                population.add(new PayloadIndividual(payload, category));
            }
        }
        
        // Generate additional individuals through mutation
        while (population.size() < POPULATION_SIZE) {
            PayloadIndividual parent = population.get(random.nextInt(population.size()));
            PayloadIndividual mutated = mutate(parent);
            population.add(mutated);
        }
        
        return population;
    }
    
    private void evaluateFitness(List<PayloadIndividual> population, TechStackInfo techStack, String category) {
        for (PayloadIndividual individual : population) {
            double fitness = calculateFitness(individual, techStack, category);
            individual.setFitness(fitness);
        }
        
        // Sort by fitness (descending)
        population.sort((a, b) -> Double.compare(b.getFitness(), a.getFitness()));
    }
    
    private double calculateFitness(PayloadIndividual individual, TechStackInfo techStack, String category) {
        double fitness = 0.0;
        String payload = individual.getPayload();
        
        // Base fitness based on payload complexity and type
        fitness += calculateComplexityScore(payload);
        fitness += calculateTypeSpecificScore(payload, category);
        fitness += calculateTechStackCompatibility(payload, techStack);
        fitness += calculateEncodingDiversity(payload);
        fitness += calculateBypassPotential(payload, techStack);
        
        // Historical success rate (if available)
        if (payloadFitness.containsKey(payload)) {
            fitness += payloadFitness.get(payload) * 2.0;
        }
        
        // Penalize overly long payloads
        if (payload.length() > 500) {
            fitness -= 0.5;
        }
        
        return Math.max(0, fitness);
    }
    
    private double calculateComplexityScore(String payload) {
        double score = 0.0;
        
        // Reward diverse character sets
        if (payload.matches(".*[a-zA-Z].*")) score += 0.1;
        if (payload.matches(".*[0-9].*")) score += 0.1;
        if (payload.matches(".*[<>\"'(){}\\[\\]].*")) score += 0.2;
        if (payload.matches(".*[&|;].*")) score += 0.2;
        if (payload.matches(".*[%\\\\].*")) score += 0.1; // Encoding chars
        
        // Reward SQL keywords
        String lower = payload.toLowerCase();
        if (lower.contains("select") || lower.contains("union") || lower.contains("insert")) score += 0.3;
        if (lower.contains("script") || lower.contains("alert") || lower.contains("onload")) score += 0.3;
        
        return score;
    }
    
    private double calculateTypeSpecificScore(String payload, String category) {
        String lower = payload.toLowerCase();
        double score = 0.0;
        
        switch (category) {
            case "sqli":
                if (lower.contains("select")) score += 0.4;
                if (lower.contains("union")) score += 0.4;
                if (lower.contains("or 1=1")) score += 0.3;
                if (lower.contains("'") || lower.contains("\"")) score += 0.2;
                if (lower.contains("--") || lower.contains("#")) score += 0.2;
                break;
            case "xss":
                if (lower.contains("script")) score += 0.4;
                if (lower.contains("alert") || lower.contains("prompt")) score += 0.3;
                if (lower.contains("onerror") || lower.contains("onload")) score += 0.3;
                if (lower.contains("<") || lower.contains(">")) score += 0.2;
                if (lower.contains("javascript:")) score += 0.3;
                break;
            case "rce":
                if (lower.contains("system") || lower.contains("exec")) score += 0.4;
                if (lower.contains("id") || lower.contains("whoami")) score += 0.3;
                if (lower.contains(";") || lower.contains("|") || lower.contains("&")) score += 0.3;
                if (lower.contains("`") || lower.contains("$")) score += 0.2;
                break;
            case "ssrf":
                if (lower.contains("localhost") || lower.contains("127.0.0.1")) score += 0.4;
                if (lower.contains("http://") || lower.contains("https://")) score += 0.3;
                if (lower.contains("169.254.169.254")) score += 0.5; // Cloud metadata
                if (lower.contains("file://") || lower.contains("gopher://")) score += 0.3;
                break;
            default:
                score = 0.1; // Base score for other types
                break;
        }
        
        return score;
    }
    
    private double calculateTechStackCompatibility(String payload, TechStackInfo techStack) {
        double score = 0.0;
        String lower = payload.toLowerCase();
        
        // Language-specific compatibility
        if ("PHP".equalsIgnoreCase(techStack.language)) {
            if (lower.contains("system") || lower.contains("exec") || lower.contains("shell_exec")) score += 0.3;
            if (lower.contains("<?php") || lower.contains("?>")) score += 0.2;
        } else if ("Java".equalsIgnoreCase(techStack.language)) {
            if (lower.contains("runtime") || lower.contains("processbuilder")) score += 0.3;
            if (lower.contains("class.forname")) score += 0.2;
        }
        
        // Database-specific compatibility
        if ("MySQL".equalsIgnoreCase(techStack.database)) {
            if (lower.contains("load_file") || lower.contains("into outfile")) score += 0.3;
            if (lower.contains("benchmark") || lower.contains("sleep")) score += 0.2;
        } else if ("PostgreSQL".equalsIgnoreCase(techStack.database)) {
            if (lower.contains("pg_sleep") || lower.contains("current_database")) score += 0.3;
        }
        
        // Web server compatibility
        if ("Apache".equalsIgnoreCase(techStack.webServer)) {
            if (lower.contains("htaccess") || lower.contains("mod_")) score += 0.2;
        } else if ("IIS".equalsIgnoreCase(techStack.webServer)) {
            if (lower.contains("web.config") || lower.contains("aspx")) score += 0.2;
        }
        
        return score;
    }
    
    private double calculateEncodingDiversity(String payload) {
        double score = 0.0;
        
        // URL encoding
        if (payload.contains("%")) score += 0.1;
        
        // HTML encoding
        if (payload.contains("&lt;") || payload.contains("&gt;") || payload.contains("&quot;")) score += 0.1;
        
        // Unicode encoding
        if (payload.contains("\\u")) score += 0.1;
        
        // Base64 patterns
        if (payload.matches(".*[A-Za-z0-9+/]+=*")) score += 0.1;
        
        return score;
    }
    
    private double calculateBypassPotential(String payload, TechStackInfo techStack) {
        double score = 0.0;
        String lower = payload.toLowerCase();
        
        // WAF bypass techniques
        if (payload.contains("/*") || payload.contains("*/")) score += 0.2; // SQL comment bypass
        if (payload.matches(".*[a-zA-Z][\\s]{2,}[a-zA-Z].*")) score += 0.1; // Space padding
        if (payload.contains("concat") || payload.contains("char")) score += 0.2; // Concatenation bypass
        if (payload.contains("eval") || payload.contains("settimeout")) score += 0.2; // JS execution bypass
        
        // Case variation bypass
        if (payload.matches(".*[A-Z].*[a-z].*") || payload.matches(".*[a-z].*[A-Z].*")) score += 0.1;
        
        return score;
    }
    
    private List<PayloadIndividual> createNextGeneration(List<PayloadIndividual> population) {
        List<PayloadIndividual> nextGeneration = new ArrayList<>();
        
        // Keep elite individuals
        for (int i = 0; i < ELITE_COUNT && i < population.size(); i++) {
            nextGeneration.add(new PayloadIndividual(population.get(i)));
        }
        
        // Generate offspring through crossover and mutation
        while (nextGeneration.size() < POPULATION_SIZE) {
            PayloadIndividual parent1 = tournamentSelection(population);
            PayloadIndividual parent2 = tournamentSelection(population);
            
            PayloadIndividual offspring;
            if (random.nextDouble() < CROSSOVER_RATE) {
                offspring = crossover(parent1, parent2);
            } else {
                offspring = random.nextBoolean() ? new PayloadIndividual(parent1) : new PayloadIndividual(parent2);
            }
            
            if (random.nextDouble() < MUTATION_RATE) {
                offspring = mutate(offspring);
            }
            
            nextGeneration.add(offspring);
        }
        
        return nextGeneration;
    }
    
    private PayloadIndividual tournamentSelection(List<PayloadIndividual> population) {
        int tournamentSize = 3;
        PayloadIndividual best = population.get(random.nextInt(population.size()));
        
        for (int i = 1; i < tournamentSize; i++) {
            PayloadIndividual candidate = population.get(random.nextInt(population.size()));
            if (candidate.getFitness() > best.getFitness()) {
                best = candidate;
            }
        }
        
        return best;
    }
    
    private PayloadIndividual crossover(PayloadIndividual parent1, PayloadIndividual parent2) {
        String payload1 = parent1.getPayload();
        String payload2 = parent2.getPayload();
        
        // Simple crossover: combine parts of both payloads
        int crossoverPoint = Math.min(payload1.length(), payload2.length()) / 2;
        
        String offspring;
        if (payload1.length() > crossoverPoint && payload2.length() > crossoverPoint) {
            offspring = payload1.substring(0, crossoverPoint) + payload2.substring(crossoverPoint);
        } else {
            // Fallback to one-point crossover on shorter string
            offspring = random.nextBoolean() ? payload1 : payload2;
        }
        
        return new PayloadIndividual(offspring, parent1.getCategory());
    }
    
    private PayloadIndividual mutate(PayloadIndividual individual) {
        String payload = individual.getPayload();
        String category = individual.getCategory();
        
        // Various mutation strategies
        String mutated;
        int mutationType = random.nextInt(6);
        switch (mutationType) {
            case 0:
                mutated = addRandomEncoding(payload);
                break;
            case 1:
                mutated = addBypassTechnique(payload, category);
                break;
            case 2:
                mutated = modifyCase(payload);
                break;
            case 3:
                mutated = addComments(payload, category);
                break;
            case 4:
                mutated = addWhitespace(payload);
                break;
            default:
                mutated = addRandomCharacters(payload);
                break;
        }
        
        return new PayloadIndividual(mutated, category);
    }
    
    private String addRandomEncoding(String payload) {
        // Apply random encoding transformations
        String[] encodings = {"url", "html", "unicode", "base64"};
        String encoding = encodings[random.nextInt(encodings.length)];
        
        switch (encoding) {
            case "url":
                return urlEncode(payload, 0.3);
            case "html":
                return htmlEncode(payload, 0.3);
            case "unicode":
                return unicodeEncode(payload, 0.2);
            case "base64":
                return "decode('" + base64Encode(payload) + "')";
            default:
                return payload;
        }
    }
    
    private String addBypassTechnique(String payload, String category) {
        switch (category) {
            case "sqli":
                String[] techniques = {"/**/", "/*comment*/", "+", "%20", "%09"};
                String technique = techniques[random.nextInt(techniques.length)];
                return payload.replace(" ", technique);
            case "xss":
                if (payload.contains("<script>")) {
                    return payload.replace("<script>", "<ScRiPt>");
                } else if (payload.contains("alert")) {
                    return payload.replace("alert", "prompt");
                }
                return payload;
            case "rce":
                if (payload.contains(";")) {
                    return payload.replace(";", " && ");
                } else if (payload.contains("|")) {
                    return payload.replace("|", " || ");
                }
                return payload;
            default:
                return payload;
        }
    }
    
    private String modifyCase(String payload) {
        // Randomly modify case of characters
        StringBuilder modified = new StringBuilder();
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c) && random.nextDouble() < 0.3) {
                modified.append(Character.isLowerCase(c) ? Character.toUpperCase(c) : Character.toLowerCase(c));
            } else {
                modified.append(c);
            }
        }
        return modified.toString();
    }
    
    private String addComments(String payload, String category) {
        if ("sqli".equals(category)) {
            return payload.replace("SELECT", "/**/SELECT/**/");
        } else if ("xss".equals(category)) {
            return payload.replace("script", "scr<!---->ipt");
        }
        return payload;
    }
    
    private String addWhitespace(String payload) {
        // Add various whitespace characters
        String[] whitespaces = {" ", "\t", "\n", "\r", "\f", "%20", "%09", "%0a"};
        String ws = whitespaces[random.nextInt(whitespaces.length)];
        
        int insertPos = random.nextInt(payload.length() + 1);
        return payload.substring(0, insertPos) + ws + payload.substring(insertPos);
    }
    
    private String addRandomCharacters(String payload) {
        // Add random characters that might help in bypasses
        String[] chars = {"'", "\"", ";", "(", ")", "[", "]", "{", "}", "%", "*"};
        String randomChar = chars[random.nextInt(chars.length)];
        
        int insertPos = random.nextInt(payload.length() + 1);
        return payload.substring(0, insertPos) + randomChar + payload.substring(insertPos);
    }
    
    private void applyTechStackMutations(List<PayloadIndividual> population, TechStackInfo techStack) {
        for (PayloadIndividual individual : population) {
            if (random.nextDouble() < 0.1) { // 10% chance of tech-specific mutation
                String mutated = applyTechSpecificMutation(individual.getPayload(), techStack, individual.getCategory());
                individual.setPayload(mutated);
            }
        }
    }
    
    private String applyTechSpecificMutation(String payload, TechStackInfo techStack, String category) {
        // Apply technology-specific mutations
        if ("PHP".equalsIgnoreCase(techStack.language) && "rce".equals(category)) {
            if (payload.contains("system")) {
                return payload.replace("system", "exec");
            }
        } else if ("MySQL".equalsIgnoreCase(techStack.database) && "sqli".equals(category)) {
            if (payload.contains("SLEEP")) {
                return payload.replace("SLEEP", "BENCHMARK");
            }
        }
        
        return payload;
    }
    
    private void replaceWithEvolvedPayloads(ArrayNode originalPayloads, List<PayloadIndividual> population) {
        // Replace original payloads with best evolved ones
        originalPayloads.removeAll();
        
        for (int i = 0; i < Math.min(population.size(), 15); i++) {
            PayloadIndividual individual = population.get(i);
            ObjectNode payloadNode = originalPayloads.objectNode();
            payloadNode.put("payload", individual.getPayload());
            payloadNode.put("type", individual.getCategory());
            payloadNode.put("fitness_score", individual.getFitness());
            payloadNode.put("evolved", true);
            payloadNode.put("generation", "evolved");
            originalPayloads.add(payloadNode);
        }
    }
    
    private void addEvolutionStats(ArrayNode payloads, List<PayloadIndividual> population) {
        if (!population.isEmpty()) {
            double avgFitness = population.stream().mapToDouble(PayloadIndividual::getFitness).average().orElse(0.0);
            double maxFitness = population.stream().mapToDouble(PayloadIndividual::getFitness).max().orElse(0.0);
            
            ObjectNode statsNode = payloads.objectNode();
            statsNode.put("type", "evolution_stats");
            statsNode.put("average_fitness", avgFitness);
            statsNode.put("max_fitness", maxFitness);
            statsNode.put("population_diversity", calculatePopulationDiversity(population));
            payloads.add(statsNode);
        }
    }
    
    private double calculatePopulationDiversity(List<PayloadIndividual> population) {
        Set<String> uniquePayloads = new HashSet<>();
        for (PayloadIndividual individual : population) {
            uniquePayloads.add(individual.getPayload());
        }
        return (double) uniquePayloads.size() / population.size();
    }
    
    // Helper methods for encoding
    private String urlEncode(String input, double probability) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (random.nextDouble() < probability && c != ' ') {
                result.append(String.format("%%%02X", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String htmlEncode(String input, double probability) {
        return input.replace("<", random.nextDouble() < probability ? "&lt;" : "<")
                   .replace(">", random.nextDouble() < probability ? "&gt;" : ">")
                   .replace("\"", random.nextDouble() < probability ? "&quot;" : "\"")
                   .replace("'", random.nextDouble() < probability ? "&apos;" : "'");
    }
    
    private String unicodeEncode(String input, double probability) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (random.nextDouble() < probability && c > 31 && c < 127) {
                result.append(String.format("\\u%04x", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
    
    private String base64Encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes());
    }
    
    private void initializePayloadGenome() {
        // Initialize known successful payload patterns
        payloadGenome.put("sqli_classic", new PayloadDNA("' OR 1=1 --", 0.9));
        payloadGenome.put("xss_basic", new PayloadDNA("<script>alert('XSS')</script>", 0.8));
        payloadGenome.put("rce_unix", new PayloadDNA("; id", 0.85));
        
        // Initialize fitness history
        payloadFitness.put("' OR 1=1 --", 0.9);
        payloadFitness.put("<script>alert('XSS')</script>", 0.8);
        payloadFitness.put("; id", 0.85);
    }
    
    // Supporting classes
    private static class PayloadIndividual {
        private String payload;
        private String category;
        private double fitness;
        
        public PayloadIndividual(String payload, String category) {
            this.payload = payload;
            this.category = category;
            this.fitness = 0.0;
        }
        
        public PayloadIndividual(PayloadIndividual other) {
            this.payload = other.payload;
            this.category = other.category;
            this.fitness = other.fitness;
        }
        
        // Getters and setters
        public String getPayload() { return payload; }
        public void setPayload(String payload) { this.payload = payload; }
        public String getCategory() { return category; }
        public double getFitness() { return fitness; }
        public void setFitness(double fitness) { this.fitness = fitness; }
    }
    
    private static class PayloadDNA {
        private final String pattern;
        private final double baseEffectiveness;
        
        public PayloadDNA(String pattern, double baseEffectiveness) {
            this.pattern = pattern;
            this.baseEffectiveness = baseEffectiveness;
        }
        
        public String getPattern() { return pattern; }
        public double getBaseEffectiveness() { return baseEffectiveness; }
    }
}