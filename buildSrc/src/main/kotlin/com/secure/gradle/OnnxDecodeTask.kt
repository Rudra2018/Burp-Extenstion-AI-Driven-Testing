package com.secure.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.util.Base64

abstract class OnnxDecodeTask : DefaultTask() {
    @get:InputFile
    abstract val inputFile: File

    @get:OutputFile
    abstract val outputFile: File

    @TaskAction
    fun decode() {
        val encoded = inputFile.readText()
        val decoded = Base64.getDecoder().decode(encoded)
        outputFile.writeBytes(decoded)
    }
}
