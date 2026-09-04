package io.github.mgerhardy.trivy

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault
import javax.inject.Inject

/**
 * Scans the project source tree for hardcoded secrets (API keys, private keys,
 * passwords, tokens) using Trivy's secret scanner.
 *
 * Unlike [TrivyScanTask], this does NOT need lock files — it scans source files
 * directly for patterns matching known secret formats.
 *
 * Closes the "secret detection" compliance gap for:
 * - ISO 27001 A.8.9 (Configuration management — secrets)
 * - ISO 27001 A.8.28 (Secure coding — no hardcoded credentials)
 * - DORA Article 7(2)(a) — protection of information assets
 */
@DisableCachingByDefault(because = "Secret scan results depend on current source tree state")
abstract class TrivySecretScanTask @Inject constructor(
    private val execOps: ExecOperations
) : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val trivyBinary: RegularFileProperty

    @get:Internal
    abstract val scanTarget: DirectoryProperty

    /**
     * Output format for the secret scan report. Default: "json".
     * Supported: "table", "json", "sarif".
     */
    @get:Input
    abstract val outputFormat: Property<String>

    /**
     * Output file for the secret scan report.
     */
    @get:Optional @get:OutputFile
    abstract val outputFile: RegularFileProperty

    /**
     * Fail the build when secrets are found. Default: true.
     */
    @get:Input
    abstract val failOnSecret: Property<Boolean>

    /**
     * Severity levels to report. Default: "HIGH,CRITICAL".
     * Trivy classifies secret findings by severity based on the type
     * (e.g., private keys are CRITICAL, generic API tokens are HIGH).
     */
    @get:Input
    abstract val severity: Property<String>

    @get:Optional @get:Input
    abstract val cacheDir: Property<String>

    @get:Input
    abstract val excludeDirs: ListProperty<String>

    @get:Input
    abstract val skipFiles: ListProperty<String>

    @get:Input
    abstract val additionalArgs: ListProperty<String>

    @TaskAction
    fun scan() {
        val binary = trivyBinary.get().asFile.absolutePath
        val target = scanTarget.get().asFile

        val args = mutableListOf(binary, "fs")
        args.addAll(listOf("--scanners", "secret"))
        args.addAll(listOf("--severity", severity.get()))
        args.addAll(listOf("--format", outputFormat.get()))

        if (outputFile.isPresent) args.addAll(listOf("--output", outputFile.get().asFile.absolutePath))
        if (cacheDir.isPresent) args.addAll(listOf("--cache-dir", cacheDir.get()))

        // Secret scanning doesn't use the vuln DB, skip the update
        args.add("--skip-db-update")

        excludeDirs.get().forEach { args.addAll(listOf("--skip-dirs", it)) }
        skipFiles.get().forEach { args.addAll(listOf("--skip-files", it)) }

        if (failOnSecret.get()) args.addAll(listOf("--exit-code", "1"))

        args.addAll(additionalArgs.get())
        args.add(target.absolutePath)

        if (outputFile.isPresent) {
            outputFile.get().asFile.parentFile.mkdirs()
        }

        logger.lifecycle("Running secret scan on ${target.absolutePath} (severity: ${severity.get()})")
        val result = execOps.exec { spec ->
            spec.commandLine(args)
            spec.isIgnoreExitValue = true
        }

        when {
            failOnSecret.get() && result.exitValue == 1 ->
                throw GradleException("Trivy found hardcoded secrets in source code")
            result.exitValue != 0 && result.exitValue != 1 ->
                throw GradleException("Trivy secret scan failed with exit code ${result.exitValue}")
        }

        if (result.exitValue == 0) {
            logger.lifecycle("Secret scan passed — no secrets detected")
        }
    }
}
