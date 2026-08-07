package io.github.mgerhardy.trivy

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import org.gradle.process.ExecOperations
import java.io.File
import javax.inject.Inject

@DisableCachingByDefault(because = "Scan results depend on external vulnerability database")
abstract class TrivyScanTask @Inject constructor(
    private val execOps: ExecOperations
) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val trivyBinary: RegularFileProperty

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val scanTarget: DirectoryProperty

    @get:Internal
    abstract val lockFilesDir: DirectoryProperty

    @get:Input
    abstract val severity: Property<String>

    @get:Input
    abstract val additionalArgs: ListProperty<String>

    @get:Input
    abstract val outputFormat: Property<String>

    @get:Input
    abstract val failOnVulnerability: Property<Boolean>

    @get:Optional @get:OutputFile
    abstract val outputFile: RegularFileProperty

    @get:Optional @get:Input
    abstract val cacheDir: Property<String>

    @get:Input
    abstract val skipDbUpdate: Property<Boolean>

    @get:Optional @get:Input
    abstract val dbRepository: Property<String>

    @get:Input
    abstract val excludeDirs: ListProperty<String>

    @get:Input
    abstract val skipFiles: ListProperty<String>

    @get:Optional @get:Input
    abstract val ignoreFile: Property<String>

    @get:Optional @get:Input
    abstract val scanners: Property<String>

    @get:Input
    abstract val ignoreUnfixed: Property<Boolean>

    @TaskAction
    fun scan() {
        val binary = trivyBinary.get().asFile.absolutePath
        val target = scanTarget.get().asFile

        // Option C: Copy lock files into scan target, scan, cleanup in finally
        val copiedFiles = mutableListOf<File>()
        try {
            if (lockFilesDir.isPresent) {
                val lockDir = lockFilesDir.get().asFile
                if (lockDir.exists()) {
                    lockDir.walk()
                        .filter { it.isFile && (it.name == "gradle.lockfile" || it.name == "package-lock.json") }
                        .forEach { lock ->
                            val rel = lock.relativeTo(lockDir)
                            val dest = File(target, rel.path)
                            if (!dest.exists()) {
                                dest.parentFile.mkdirs()
                                lock.copyTo(dest)
                                copiedFiles.add(dest)
                            }
                        }
                }
            }

            val args = mutableListOf(binary, "fs")
            args.addAll(listOf("--severity", severity.get()))
            args.addAll(listOf("--format", outputFormat.get()))

            if (outputFile.isPresent) args.addAll(listOf("--output", outputFile.get().asFile.absolutePath))
            if (cacheDir.isPresent) args.addAll(listOf("--cache-dir", cacheDir.get()))
            if (skipDbUpdate.get()) args.add("--skip-db-update")
            if (dbRepository.isPresent) args.addAll(listOf("--db-repository", dbRepository.get()))
            if (ignoreUnfixed.get()) args.add("--ignore-unfixed")
            if (scanners.isPresent) args.addAll(listOf("--scanners", scanners.get()))
            if (ignoreFile.isPresent) args.addAll(listOf("--ignorefile", ignoreFile.get()))

            excludeDirs.get().forEach { args.addAll(listOf("--skip-dirs", it)) }
            skipFiles.get().forEach { args.addAll(listOf("--skip-files", it)) }

            if (failOnVulnerability.get()) args.addAll(listOf("--exit-code", "1"))
            args.addAll(additionalArgs.get())
            args.add(target.absolutePath)

            if (outputFile.isPresent) {
                outputFile.get().asFile.parentFile.mkdirs()
            }

            logger.lifecycle("Running Trivy scan on ${target.absolutePath} (severity: ${severity.get()})")
            val result = execOps.exec { spec ->
                spec.commandLine(args)
                spec.isIgnoreExitValue = true
            }
            when {
                failOnVulnerability.get() && result.exitValue == 1 ->
                    throw GradleException("Trivy found vulnerabilities with severity ${severity.get()}")
                result.exitValue != 0 ->
                    throw GradleException("Trivy exited with error code ${result.exitValue}")
            }
        } finally {
            copiedFiles.forEach { it.delete() }
        }
    }
}
