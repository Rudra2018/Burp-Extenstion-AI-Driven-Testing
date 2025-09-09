package com.secure.ai.burp.models.ml;

import org.apache.commons.text.similarity.JaccardSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Advanced feature extraction for ML models
 * Extracts various types of features from HTTP requests, payloads, and contexts
 */
class FeatureExtractor {
    private static final Logger logger = LoggerFactory.getLogger(FeatureExtractor.class);
    
    private final StandardAnalyzer analyzer;
    private final JaccardSimilarity jaccardSimilarity;
    private final LevenshteinDistance levenshteinDistance;
    
    // Pre-compiled patterns for performance
    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]+>");
    private static final Pattern SCRIPT_PATTERN = Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern SQL_KEYWORD_PATTERN = Pattern.compile("\\b(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|CREATE|ALTER)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern NUMBER_PATTERN = Pattern.compile("\\d+");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s]+");
    private static final Pattern SPECIAL_CHARS_PATTERN = Pattern.compile("[^a-zA-Z0-9\\s]");
    
    // Vulnerability-specific patterns
    private static final Map<String, List<Pattern>> VULN_PATTERNS = Map.of(
        "xss", List.of(
            Pattern.compile("<script", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("eval\\s*\\(", Pattern.CASE_INSENSITIVE)
        ),
        "sqli", List.of(
            Pattern.compile("'\\s*(or|and)\\s*'", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bunion\\s+select\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile(";\\s*(drop|delete|update)\\s+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("1\\s*=\\s*1", Pattern.CASE_INSENSITIVE)
        ),
        "xxe", List.of(
            Pattern.compile("<!DOCTYPE", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<!ENTITY", Pattern.CASE_INSENSITIVE),
            Pattern.compile("SYSTEM\\s+[\"']", Pattern.CASE_INSENSITIVE)
        ),
        "cmdi", List.of(
            Pattern.compile("[;&|`]\\s*(cat|ls|dir|whoami|id)\\s", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\$\\([^)]+\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("`[^`]+`", Pattern.CASE_INSENSITIVE)
        )
    );
    
    public FeatureExtractor() {
        this.analyzer = new StandardAnalyzer();
        this.jaccardSimilarity = new JaccardSimilarity();
        this.levenshteinDistance = new LevenshteinDistance();
    }
    
    /**
     * Extract comprehensive features from input string and context
     */
    public float[] extractFeatures(String input, Map<String, Object> context) {
        try {
            List<Double> features = new ArrayList<>();
            
            // Basic string features
            features.addAll(extractBasicStringFeatures(input));
            
            // Lexical features
            features.addAll(extractLexicalFeatures(input));
            
            // Pattern-based features
            features.addAll(extractPatternFeatures(input));
            
            // Entropy and complexity features
            features.addAll(extractEntropyFeatures(input));
            
            // N-gram features
            features.addAll(extractNGramFeatures(input));
            
            // Context-aware features
            features.addAll(extractContextFeatures(input, context));
            
            // Statistical features
            features.addAll(extractStatisticalFeatures(input));
            
            // Convert to float array for ONNX
            return features.stream()
                .mapToDouble(Double::doubleValue)
                .mapToObj(d -> (float) d)
                .collect(Collectors.toList())
                .toArray(new Float[0])
                .clone(); // Convert Float[] to float[]
                
        } catch (Exception e) {
            logger.error("Feature extraction failed", e);
            return new float[100]; // Return zero vector of expected size
        }
    }
    
    private List<Double> extractBasicStringFeatures(String input) {
        List<Double> features = new ArrayList<>();
        
        if (input == null || input.isEmpty()) {
            // Return zero features for empty input
            return Collections.nCopies(10, 0.0);
        }
        
        features.add((double) input.length()); // 1. Length
        features.add((double) input.split("\\s+").length); // 2. Word count
        features.add((double) input.split("\n").length); // 3. Line count
        features.add((double) countUpperCase(input)); // 4. Uppercase chars
        features.add((double) countLowerCase(input)); // 5. Lowercase chars
        features.add((double) countDigits(input)); // 6. Digit chars
        features.add((double) countSpecialChars(input)); // 7. Special chars
        features.add((double) countWhitespace(input)); // 8. Whitespace chars
        features.add(calculateAlphaRatio(input)); // 9. Alpha ratio
        features.add(calculateDigitRatio(input)); // 10. Digit ratio
        
        return features;
    }
    
    private List<Double> extractLexicalFeatures(String input) {
        List<Double> features = new ArrayList<>();
        
        if (input == null || input.isEmpty()) {
            return Collections.nCopies(15, 0.0);
        }
        
        String lowerInput = input.toLowerCase();
        
        // HTML/XML features
        features.add((double) countMatches(HTML_TAG_PATTERN, input)); // 1. HTML tags
        features.add((double) countMatches(SCRIPT_PATTERN, input)); // 2. Script tags
        
        // SQL features
        features.add((double) countMatches(SQL_KEYWORD_PATTERN, input)); // 3. SQL keywords
        features.add(lowerInput.contains("union") ? 1.0 : 0.0); // 4. Union keyword
        features.add(lowerInput.contains("select") ? 1.0 : 0.0); // 5. Select keyword
        
        // JavaScript features
        features.add(lowerInput.contains("javascript:") ? 1.0 : 0.0); // 6. JS protocol
        features.add(lowerInput.contains("eval(") ? 1.0 : 0.0); // 7. Eval function
        features.add(lowerInput.contains("alert(") ? 1.0 : 0.0); // 8. Alert function
        
        // Encoding features
        features.add(lowerInput.contains("%") ? 1.0 : 0.0); // 9. URL encoding
        features.add(lowerInput.contains("&#") ? 1.0 : 0.0); // 10. HTML entities
        features.add(lowerInput.contains("\\x") ? 1.0 : 0.0); // 11. Hex encoding
        features.add(lowerInput.contains("\\u") ? 1.0 : 0.0); // 12. Unicode encoding
        
        // File system features
        features.add(lowerInput.contains("../") ? 1.0 : 0.0); // 13. Directory traversal
        features.add(lowerInput.contains("/etc/") ? 1.0 : 0.0); // 14. Unix paths
        features.add(lowerInput.contains("c:\\") ? 1.0 : 0.0); // 15. Windows paths
        
        return features;
    }
    
    private List<Double> extractPatternFeatures(String input) {
        List<Double> features = new ArrayList<>();
        
        if (input == null || input.isEmpty()) {
            return Collections.nCopies(20, 0.0);
        }
        
        // Vulnerability-specific pattern matching
        for (Map.Entry<String, List<Pattern>> entry : VULN_PATTERNS.entrySet()) {
            String vulnType = entry.getKey();
            List<Pattern> patterns = entry.getValue();
            
            double totalMatches = 0;
            for (Pattern pattern : patterns) {
                totalMatches += countMatches(pattern, input);
            }
            
            features.add(totalMatches); // Total matches for this vuln type
            features.add(totalMatches > 0 ? 1.0 : 0.0); // Binary indicator
        }
        
        // Additional pattern features
        features.add((double) countMatches(EMAIL_PATTERN, input)); // Email patterns
        features.add((double) countMatches(URL_PATTERN, input)); // URL patterns
        features.add((double) countMatches(NUMBER_PATTERN, input)); // Number patterns
        features.add((double) countMatches(SPECIAL_CHARS_PATTERN, input)); // Special chars
        
        // Quote patterns (SQL injection indicators)
        features.add((double) input.chars().mapToObj(c -> (char) c).mapToLong(c -> c == '\'' ? 1 : 0).sum());
        features.add((double) input.chars().mapToObj(c -> (char) c).mapToLong(c -> c == '"' ? 1 : 0).sum());
        
        // Parentheses patterns (function calls)
        features.add((double) input.chars().mapToObj(c -> (char) c).mapToLong(c -> c == '(' ? 1 : 0).sum());
        features.add((double) input.chars().mapToObj(c -> (char) c).mapToLong(c -> c == ')' ? 1 : 0).sum());
        
        return features;
    }
    
    private List<Double> extractEntropyFeatures(String input) {
        List<Double> features = new ArrayList<>();
        
        if (input == null || input.isEmpty()) {
            return Collections.nCopies(5, 0.0);
        }
        
        features.add(calculateShannonEntropy(input)); // 1. Shannon entropy
        features.add(calculateCharacterEntropy(input)); // 2. Character entropy
        features.add(calculateWordEntropy(input)); // 3. Word entropy
        features.add(calculateCompressionRatio(input)); // 4. Compression ratio
        features.add(calculateComplexityScore(input)); // 5. Complexity score
        
        return features;
    }
    
    private List<Double> extractNGramFeatures(String input) {
        List<Double> features = new ArrayList<>();
        
        if (input == null || input.isEmpty()) {
            return Collections.nCopies(15, 0.0);
        }
        
        // Character n-grams
        Map<String, Integer> bigramCounts = calculateCharacterNGrams(input, 2);
        Map<String, Integer> trigramCounts = calculateCharacterNGrams(input, 3);
        
        // Most common n-grams as features
        features.add((double) bigramCounts.getOrDefault("sc", 0)); // <s in scripts
        features.add((double) bigramCounts.getOrDefault("ri", 0)); // ri in script
        features.add((double) bigramCounts.getOrDefault("or", 0)); // or in SQL
        features.add((double) bigramCounts.getOrDefault("un", 0)); // un in union
        features.add((double) bigramCounts.getOrDefault("se", 0)); // se in select
        
        features.add((double) trigramCounts.getOrDefault("scr", 0)); // scr in script
        features.add((double) trigramCounts.getOrDefault("uni", 0)); // uni in union
        features.add((double) trigramCounts.getOrDefault("sel", 0)); // sel in select
        features.add((double) trigramCounts.getOrDefault("ale", 0)); // ale in alert
        features.add((double) trigramCounts.getOrDefault("eva", 0)); // eva in eval
        
        // Word n-grams
        String[] words = input.toLowerCase().split("\\W+");
        if (words.length > 1) {
            Map<String, Integer> wordBigrams = calculateWordNGrams(Arrays.asList(words), 2);
            features.add((double) wordBigrams.getOrDefault("union select", 0));
            features.add((double) wordBigrams.getOrDefault("or 1", 0));
            features.add((double) wordBigrams.getOrDefault("drop table", 0));
            features.add((double) wordBigrams.getOrDefault("script alert", 0));
            features.add((double) wordBigrams.getOrDefault("javascript void", 0));
        } else {
            features.addAll(Collections.nCopies(5, 0.0));
        }
        
        return features;
    }
    
    private List<Double> extractContextFeatures(String input, Map<String, Object> context) {
        List<Double> features = new ArrayList<>();
        
        if (context == null || context.isEmpty()) {
            return Collections.nCopies(10, 0.0);
        }
        
        // Technology context features
        @SuppressWarnings("unchecked")
        List<String> technologies = (List<String>) context.getOrDefault("technologies", List.of());
        
        features.add(technologies.contains("PHP") ? 1.0 : 0.0); // 1. PHP context
        features.add(technologies.contains("Java") ? 1.0 : 0.0); // 2. Java context
        features.add(technologies.contains("MySQL") ? 1.0 : 0.0); // 3. MySQL context
        features.add(technologies.contains("PostgreSQL") ? 1.0 : 0.0); // 4. PostgreSQL context
        features.add(technologies.contains("React") ? 1.0 : 0.0); // 5. React context
        features.add(technologies.contains("Angular") ? 1.0 : 0.0); // 6. Angular context
        
        // Parameter context
        @SuppressWarnings("unchecked")
        Map<String, String> parameters = (Map<String, String>) context.getOrDefault("parameters", Map.of());
        
        boolean hasEmailParam = parameters.values().stream().anyMatch(v -> v.equals("email"));
        boolean hasIntegerParam = parameters.values().stream().anyMatch(v -> v.equals("integer"));
        
        features.add(hasEmailParam ? 1.0 : 0.0); // 7. Email parameter context
        features.add(hasIntegerParam ? 1.0 : 0.0); // 8. Integer parameter context
        
        // Application context
        String host = (String) context.getOrDefault("host", "");
        features.add(host.contains("admin") ? 1.0 : 0.0); // 9. Admin context
        features.add(host.contains("api") ? 1.0 : 0.0); // 10. API context
        
        return features;
    }
    
    private List<Double> extractStatisticalFeatures(String input) {
        List<Double> features = new ArrayList<>();
        
        if (input == null || input.isEmpty()) {
            return Collections.nCopies(10, 0.0);
        }
        
        // Character frequency statistics
        Map<Character, Integer> charFreq = calculateCharacterFrequency(input);
        
        features.add((double) charFreq.size()); // 1. Unique characters
        features.add(calculateMean(charFreq.values())); // 2. Mean frequency
        features.add(calculateStandardDeviation(charFreq.values())); // 3. Std dev frequency
        features.add(calculateSkewness(charFreq.values())); // 4. Skewness
        features.add(calculateKurtosis(charFreq.values())); // 5. Kurtosis
        
        // Length statistics
        String[] words = input.split("\\W+");
        if (words.length > 0) {
            List<Integer> wordLengths = Arrays.stream(words).mapToInt(String::length).boxed().collect(Collectors.toList());
            features.add(calculateMean(wordLengths)); // 6. Mean word length
            features.add(calculateStandardDeviation(wordLengths)); // 7. Std dev word length
        } else {
            features.add(0.0);
            features.add(0.0);
        }
        
        // Repetition features
        features.add(calculateRepetitionScore(input)); // 8. Repetition score
        features.add(calculatePeriodicityScore(input)); // 9. Periodicity score
        features.add(calculateRandomnessScore(input)); // 10. Randomness score
        
        return features;
    }
    
    // Helper methods for feature calculation
    private int countUpperCase(String input) {
        return (int) input.chars().filter(Character::isUpperCase).count();
    }
    
    private int countLowerCase(String input) {
        return (int) input.chars().filter(Character::isLowerCase).count();
    }
    
    private int countDigits(String input) {
        return (int) input.chars().filter(Character::isDigit).count();
    }
    
    private int countSpecialChars(String input) {
        return (int) input.chars().filter(c -> !Character.isLetterOrDigit(c) && !Character.isWhitespace(c)).count();
    }
    
    private int countWhitespace(String input) {
        return (int) input.chars().filter(Character::isWhitespace).count();
    }
    
    private double calculateAlphaRatio(String input) {
        if (input.isEmpty()) return 0.0;
        long alphaCount = input.chars().filter(Character::isLetter).count();
        return (double) alphaCount / input.length();
    }
    
    private double calculateDigitRatio(String input) {
        if (input.isEmpty()) return 0.0;
        long digitCount = input.chars().filter(Character::isDigit).count();
        return (double) digitCount / input.length();
    }
    
    private int countMatches(Pattern pattern, String input) {
        Matcher matcher = pattern.matcher(input);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }
    
    private double calculateShannonEntropy(String input) {
        Map<Character, Integer> charFreq = calculateCharacterFrequency(input);
        double entropy = 0.0;
        int length = input.length();
        
        for (int freq : charFreq.values()) {
            double probability = (double) freq / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    private double calculateCharacterEntropy(String input) {
        return calculateShannonEntropy(input) / Math.log(256) * Math.log(2); // Normalize by max possible entropy
    }
    
    private double calculateWordEntropy(String input) {
        String[] words = input.toLowerCase().split("\\W+");
        if (words.length <= 1) return 0.0;
        
        Map<String, Integer> wordFreq = new HashMap<>();
        for (String word : words) {
            if (!word.isEmpty()) {
                wordFreq.merge(word, 1, Integer::sum);
            }
        }
        
        double entropy = 0.0;
        for (int freq : wordFreq.values()) {
            double probability = (double) freq / words.length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    private double calculateCompressionRatio(String input) {
        // Simplified compression ratio estimation
        Set<Character> uniqueChars = input.chars().mapToObj(c -> (char) c).collect(Collectors.toSet());
        return (double) uniqueChars.size() / input.length();
    }
    
    private double calculateComplexityScore(String input) {
        // Combine multiple complexity measures
        double entropy = calculateShannonEntropy(input);
        double compressionRatio = calculateCompressionRatio(input);
        double specialCharRatio = (double) countSpecialChars(input) / input.length();
        
        return (entropy + compressionRatio + specialCharRatio) / 3.0;
    }
    
    private Map<String, Integer> calculateCharacterNGrams(String input, int n) {
        Map<String, Integer> ngrams = new HashMap<>();
        
        if (input.length() < n) return ngrams;
        
        for (int i = 0; i <= input.length() - n; i++) {
            String ngram = input.substring(i, i + n).toLowerCase();
            ngrams.merge(ngram, 1, Integer::sum);
        }
        
        return ngrams;
    }
    
    private Map<String, Integer> calculateWordNGrams(List<String> words, int n) {
        Map<String, Integer> ngrams = new HashMap<>();
        
        if (words.size() < n) return ngrams;
        
        for (int i = 0; i <= words.size() - n; i++) {
            String ngram = String.join(" ", words.subList(i, i + n));
            ngrams.merge(ngram, 1, Integer::sum);
        }
        
        return ngrams;
    }
    
    private Map<Character, Integer> calculateCharacterFrequency(String input) {
        Map<Character, Integer> frequency = new HashMap<>();
        for (char c : input.toCharArray()) {
            frequency.merge(c, 1, Integer::sum);
        }
        return frequency;
    }
    
    private double calculateMean(Collection<Integer> values) {
        return values.stream().mapToInt(Integer::intValue).average().orElse(0.0);
    }
    
    private double calculateStandardDeviation(Collection<Integer> values) {
        if (values.isEmpty()) return 0.0;
        
        double mean = calculateMean(values);
        double variance = values.stream()
            .mapToDouble(v -> Math.pow(v - mean, 2))
            .average()
            .orElse(0.0);
            
        return Math.sqrt(variance);
    }
    
    private double calculateSkewness(Collection<Integer> values) {
        if (values.size() < 3) return 0.0;
        
        double mean = calculateMean(values);
        double stdDev = calculateStandardDeviation(values);
        
        if (stdDev == 0) return 0.0;
        
        return values.stream()
            .mapToDouble(v -> Math.pow((v - mean) / stdDev, 3))
            .average()
            .orElse(0.0);
    }
    
    private double calculateKurtosis(Collection<Integer> values) {
        if (values.size() < 4) return 0.0;
        
        double mean = calculateMean(values);
        double stdDev = calculateStandardDeviation(values);
        
        if (stdDev == 0) return 0.0;
        
        double kurtosis = values.stream()
            .mapToDouble(v -> Math.pow((v - mean) / stdDev, 4))
            .average()
            .orElse(0.0);
            
        return kurtosis - 3.0; // Excess kurtosis
    }
    
    private double calculateRepetitionScore(String input) {
        Map<Character, Integer> charFreq = calculateCharacterFrequency(input);
        int maxFreq = charFreq.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        return (double) maxFreq / input.length();
    }
    
    private double calculatePeriodicityScore(String input) {
        // Simplified periodicity detection
        int maxPeriod = Math.min(input.length() / 2, 10);
        double maxScore = 0.0;
        
        for (int period = 2; period <= maxPeriod; period++) {
            int matches = 0;
            int comparisons = 0;
            
            for (int i = 0; i < input.length() - period; i++) {
                if (input.charAt(i) == input.charAt(i + period)) {
                    matches++;
                }
                comparisons++;
            }
            
            double score = (double) matches / comparisons;
            maxScore = Math.max(maxScore, score);
        }
        
        return maxScore;
    }
    
    private double calculateRandomnessScore(String input) {
        // Based on runs test - simplified implementation
        if (input.length() < 2) return 0.0;
        
        int runs = 1;
        for (int i = 1; i < input.length(); i++) {
            if (input.charAt(i) != input.charAt(i - 1)) {
                runs++;
            }
        }
        
        // Normalize by expected runs for random sequence
        double expectedRuns = (2.0 * input.length()) / 3.0;
        return Math.min(runs / expectedRuns, 1.0);
    }
}