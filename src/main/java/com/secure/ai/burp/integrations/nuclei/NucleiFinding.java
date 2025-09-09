package com.secure.ai.burp.integrations.nuclei;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import java.util.List;
import java.util.Map;

class NucleiFinding {
    @SerializedName("template-id")
    private String templateId;
    
    @SerializedName("template-path")
    private String templatePath;
    
    private String type;
    private String host;
    private String matched_at;
    private String extracted_results;
    private String ip;
    private long timestamp;
    private String curl_command;
    private String matcher_status;
    private NucleiInfo info;
    
    // Nested classes for JSON structure
    public static class NucleiInfo {
        private String name;
        private String author;
        private String severity;
        private String description;
        private String reference;
        private List<String> tags;
        private String classification;
        private Map<String, Object> metadata;
        
        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public String getAuthor() { return author; }
        public void setAuthor(String author) { this.author = author; }
        
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        
        public String getReference() { return reference; }
        public void setReference(String reference) { this.reference = reference; }
        
        public List<String> getTags() { return tags; }
        public void setTags(List<String> tags) { this.tags = tags; }
        
        public String getClassification() { return classification; }
        public void setClassification(String classification) { this.classification = classification; }
        
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    }
    
    public static NucleiFinding fromJson(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, NucleiFinding.class);
    }
    
    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }
    
    public String getSeverity() {
        return info != null ? info.getSeverity() : "unknown";
    }
    
    public double getRiskScore() {
        String severity = getSeverity();
        switch (severity.toLowerCase()) {
            case "critical": return 9.5;
            case "high": return 8.0;
            case "medium": return 6.0;
            case "low": return 3.0;
            case "info": return 1.0;
            default: return 5.0;
        }
    }
    
    public boolean isCritical() {
        return "critical".equalsIgnoreCase(getSeverity());
    }
    
    public boolean isHighRisk() {
        return "high".equalsIgnoreCase(getSeverity()) || isCritical();
    }
    
    // Getters and setters
    public String getTemplateId() { return templateId; }
    public void setTemplateId(String templateId) { this.templateId = templateId; }
    
    public String getTemplatePath() { return templatePath; }
    public void setTemplatePath(String templatePath) { this.templatePath = templatePath; }
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public String getMatchedAt() { return matched_at; }
    public void setMatchedAt(String matched_at) { this.matched_at = matched_at; }
    
    public String getExtractedResults() { return extracted_results; }
    public void setExtractedResults(String extracted_results) { this.extracted_results = extracted_results; }
    
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    public String getCurlCommand() { return curl_command; }
    public void setCurlCommand(String curl_command) { this.curl_command = curl_command; }
    
    public String getMatcherStatus() { return matcher_status; }
    public void setMatcherStatus(String matcher_status) { this.matcher_status = matcher_status; }
    
    public NucleiInfo getInfo() { return info; }
    public void setInfo(NucleiInfo info) { this.info = info; }
    
    @Override
    public String toString() {
        return String.format("NucleiFinding{templateId='%s', severity='%s', host='%s'}", 
                           templateId, getSeverity(), host);
    }
}