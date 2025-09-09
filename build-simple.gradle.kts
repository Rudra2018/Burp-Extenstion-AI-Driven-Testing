plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.secure.ai"
version = "2.0.0"

repositories {
    mavenCentral()
    maven {
        name = "PortSwigger"
        url = uri("https://releases.portswigger.net/maven/")
    }
}

dependencies {
    // Burp Suite API (Montoya API)
    compileOnly("net.portswigger.burp.extender:burp-extender-montoya-api:1.0.0")
    
    // Essential ML libraries
    implementation("com.microsoft.onnxruntime:onnxruntime:1.16.1")
    
    // JSON processing
    implementation("com.fasterxml.jackson.core:jackson-core:2.15.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2")
    
    // HTTP clients
    implementation("com.squareup.okhttp3:okhttp:4.11.0")
    
    // Statistical analysis
    implementation("org.apache.commons:commons-math3:3.6.1")
    implementation("org.apache.commons:commons-text:1.10.0")
    
    // Database
    implementation("com.h2database:h2:2.2.220")
    
    // Security
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
    
    // XML/HTML processing
    implementation("org.jsoup:jsoup:1.16.1")
    
    // Process execution
    implementation("org.apache.commons:commons-exec:1.3")
    
    // Caching
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")
    
    // Logging
    implementation("org.slf4j:slf4j-api:2.0.7")
    implementation("ch.qos.logback:logback-classic:1.4.8")
    
    // Configuration
    implementation("com.typesafe:config:1.4.2")
}

tasks.test {
    useJUnitPlatform()
}

// Create the extension JAR
tasks.shadowJar {
    archiveFileName.set("ai-security-extension-${version}.jar")
    manifest {
        attributes["Main-Class"] = "com.secure.ai.burp.AISecurityExtension"
    }
    
    // Exclude conflicting files
    exclude("META-INF/*.SF")
    exclude("META-INF/*.DSA") 
    exclude("META-INF/*.RSA")
    
    // Merge service files
    mergeServiceFiles()
}

// Configure Java compilation
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
}

tasks.compileJava {
    options.encoding = "UTF-8"
}