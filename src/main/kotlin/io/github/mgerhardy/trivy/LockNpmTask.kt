package io.github.mgerhardy.trivy

import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.concurrent.TimeUnit

@CacheableTask
abstract class LockNpmTask : DefaultTask() {

    @get:Internal
    abstract val projectDir: DirectoryProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val packageJsonFiles: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Input
    abstract val npmBinary: Property<String>

    @get:Input
    abstract val excludeProjects: ListProperty<String>

    @get:Input
    abstract val perProjectTimeoutSeconds: Property<Long>

    companion object {
        private val SKIP_DIRS = setOf(".git", ".gradle", "node_modules", "build", ".idea", ".kotlin")
    }

    @TaskAction
    fun generate() {
        val root = projectDir.get().asFile
        val outDir = outputDir.get().asFile
        val npm = npmBinary.get()
        val excluded = excludeProjects.get().toSet()
        val timeout = perProjectTimeoutSeconds.get()

        if (outDir.exists()) outDir.deleteRecursively()
        outDir.mkdirs()

        val npmProjects = root.walk()
            .onEnter { it.name !in SKIP_DIRS }
            .filter { it.name == "package.json" }
            .map { it.parentFile }
            .filter { dir ->
                val rel = dir.relativeTo(root).path.ifEmpty { "." }
                rel !in excluded
            }
            .toList()

        if (npmProjects.isEmpty()) {
            logger.lifecycle("No npm projects found in $root")
            return
        }

        val isWindows = TrivyDownloadTask.isWindows()
        val command = if (isWindows && !npm.contains(File.separator) && !npm.endsWith(".cmd")) "$npm.cmd" else npm

        for (dir in npmProjects) {
            val label = dir.relativeTo(root).path.ifEmpty { "." }
            val lockFile = File(dir, "package-lock.json")
            val lockExistedBefore = lockFile.exists()

            logger.lifecycle("Generating package-lock.json in $label")
            try {
                val cmdLine = if (isWindows) listOf("cmd", "/c", command, "install", "--package-lock-only")
                    else listOf(command, "install", "--package-lock-only")

                val process = ProcessBuilder(cmdLine)
                    .directory(dir)
                    .redirectErrorStream(false)
                    .start()

                val stderrFuture = java.util.concurrent.CompletableFuture.supplyAsync { process.errorStream.bufferedReader().readText() }
                process.inputStream.bufferedReader().readText() // drain stdout

                val finished = process.waitFor(timeout, TimeUnit.SECONDS)
                if (!finished) {
                    process.destroyForcibly()
                    stderrFuture.cancel(true)
                    logger.warn("  Timed out in $label after ${timeout}s")
                    continue
                }
                if (process.exitValue() != 0) {
                    val errMsg = stderrFuture.get().lines().firstOrNull { it.isNotBlank() } ?: "unknown error"
                    logger.warn("  Failed in $label: $errMsg")
                    continue
                }
                if (lockFile.exists()) {
                    val relativePath = dir.relativeTo(root).path.ifEmpty { "root" }
                    val targetDir = File(outDir, relativePath)
                    targetDir.mkdirs()
                    lockFile.copyTo(File(targetDir, "package-lock.json"), overwrite = true)
                    if (!lockExistedBefore) lockFile.delete()
                }
            } catch (e: Exception) {
                logger.warn("  Error in $label: ${e.message}")
            }
        }
        logger.lifecycle("npm lock files written to $outDir")
    }
}
