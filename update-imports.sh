#!/bin/bash

# Script to update import statements after package restructuring

echo "🔄 Updating import statements across the codebase..."

# Function to update imports in a file
update_imports() {
    local file=$1
    echo "Updating imports in: $file"
    
    # Backup original file
    cp "$file" "$file.backup"
    
    # Update common import paths
    sed -i '' -e 's|com\.secure\.ai\.burp\.ml\.|com.secure.ai.burp.models.ml.|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.core\.ApplicationContext|com.secure.ai.burp.models.data.ApplicationContext|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.core\.RealTimeAnalysisDataClasses|com.secure.ai.burp.models.data.RealTimeAnalysisDataClasses|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.core\.RealTimeTrafficAnalyzer|com.secure.ai.burp.analyzers.traffic.RealTimeTrafficAnalyzer|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.core\.IntelligentPayloadGenerator|com.secure.ai.burp.generators.payload.IntelligentPayloadGenerator|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.core\.AISecurityEngine|com.secure.ai.burp.engine.AISecurityEngine|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.detection\.|com.secure.ai.burp.detectors.anomaly.|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.anomaly\.|com.secure.ai.burp.detectors.anomaly.|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.scanner\.|com.secure.ai.burp.detectors.vulnerability.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.nuclei\.|com.secure.ai.burp.integrations.nuclei.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.payloads\.|com.secure.ai.burp.generators.payload.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.traffic\.|com.secure.ai.burp.analyzers.traffic.|g' "$file"
    sed -i '' -e 's|com\.secure\.ai\.burp\.analysis\.|com.secure.ai.burp.analyzers.traffic.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.learning\.|com.secure.ai.burp.learners.adaptive.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.reporting\.|com.secure.ai.burp.utilities.reporting.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.poc\.|com.secure.ai.burp.testing.poc.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.standalone\.|com.secure.ai.burp.examples.standalone.|g' "$file"
    
    sed -i '' -e 's|com\.secure\.ai\.burp\.ui\.|com.secure.ai.burp.extension.|g' "$file"
    
    # Update package declarations
    if [[ "$file" == *"/extension/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp;|package com.secure.ai.burp.extension;|g' "$file"
        sed -i '' -e 's|package com\.secure\.ai\.burp\.ui;|package com.secure.ai.burp.extension;|g' "$file"
    elif [[ "$file" == *"/models/ml/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.ml;|package com.secure.ai.burp.models.ml;|g' "$file"
    elif [[ "$file" == *"/models/data/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.core;|package com.secure.ai.burp.models.data;|g' "$file"
    elif [[ "$file" == *"/engine/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.core;|package com.secure.ai.burp.engine;|g' "$file"
    elif [[ "$file" == *"/detectors/anomaly/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.detection;|package com.secure.ai.burp.detectors.anomaly;|g' "$file"
        sed -i '' -e 's|package com\.secure\.ai\.burp\.anomaly;|package com.secure.ai.burp.detectors.anomaly;|g' "$file"
    elif [[ "$file" == *"/detectors/vulnerability/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.scanner;|package com.secure.ai.burp.detectors.vulnerability;|g' "$file"
    elif [[ "$file" == *"/generators/payload/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.payloads;|package com.secure.ai.burp.generators.payload;|g' "$file"
    elif [[ "$file" == *"/analyzers/traffic/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.traffic;|package com.secure.ai.burp.analyzers.traffic;|g' "$file"
        sed -i '' -e 's|package com\.secure\.ai\.burp\.analysis;|package com.secure.ai.burp.analyzers.traffic;|g' "$file"
    elif [[ "$file" == *"/integrations/nuclei/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.nuclei;|package com.secure.ai.burp.integrations.nuclei;|g' "$file"
    elif [[ "$file" == *"/learners/adaptive/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.learning;|package com.secure.ai.burp.learners.adaptive;|g' "$file"
    elif [[ "$file" == *"/utilities/reporting/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.reporting;|package com.secure.ai.burp.utilities.reporting;|g' "$file"
    elif [[ "$file" == *"/testing/poc/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.poc;|package com.secure.ai.burp.testing.poc;|g' "$file"
    elif [[ "$file" == *"/examples/standalone/"* ]]; then
        sed -i '' -e 's|package com\.secure\.ai\.burp\.standalone;|package com.secure.ai.burp.examples.standalone;|g' "$file"
    fi
    
    echo "✅ Updated: $file"
}

# Find all Java files and update them
find src/main/java -name "*.java" -type f | while read -r file; do
    update_imports "$file"
done

echo "🎉 Import statements updated successfully!"
echo ""
echo "📋 Summary:"
echo "- Updated package declarations to match new structure"
echo "- Updated all import statements"
echo "- Backup files created with .backup extension"
echo ""
echo "🔍 To verify changes, check a few key files:"
echo "- src/main/java/com/secure/ai/burp/extension/AISecurityExtension.java"
echo "- src/main/java/com/secure/ai/burp/models/ml/AdvancedModelManager.java"
echo "- src/main/java/com/secure/ai/burp/testing/poc/ComprehensiveSecurityPOC.java"