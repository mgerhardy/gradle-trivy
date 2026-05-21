package io.github.mgerhardy.trivy

import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File

class TrivyPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create("trivy", TrivyExtension::class.java)

        val gradleCaches = File(project.gradle.gradleUserHomeDir, "caches/trivy")
        val defaultInstallDir = project.layout.dir(
            extension.version.map { File(gradleCaches, "bin/$it") }
        )
        val defaultCacheDir = project.layout.dir(
            project.provider { File(gradleCaches, "db") }
        )

        extension.cacheDir.convention(defaultCacheDir)

        val effectiveInstallDir = extension.installDir.orElse(defaultInstallDir)
        val binaryFile = effectiveInstallDir.map { it.file(TrivyDownloadTask.binaryName()) }
        val effectiveBinary = extension.binaryPath.orElse(binaryFile)

        val gradleLockOutputDir = project.layout.buildDirectory.dir("trivy-locks/gradle")
        val npmLockOutputDir = project.layout.buildDirectory.dir("trivy-locks/npm")

        val scanTargetDir = extension.scanTarget.orElse(project.layout.projectDirectory)

        val downloadTask = project.tasks.register("trivyDownload", TrivyDownloadTask::class.java) {
            it.group = "trivy"
            it.description = "Downloads the Trivy binary"
            it.version.set(extension.version)
            it.checkForUpdates.set(extension.checkForUpdates)
            it.installDir.set(effectiveInstallDir)
            it.onlyIf { !extension.binaryPath.isPresent }
        }

        val npmTask = project.tasks.register("trivyLockNpm", LockNpmTask::class.java) {
            it.group = "trivy"
            it.description = "Generates package-lock.json for npm projects"
            it.projectDir.set(extension.npmProjectDir.orElse(scanTargetDir))
            it.outputDir.set(npmLockOutputDir)
            it.npmBinary.set(extension.npmBinary)
            it.excludeProjects.set(extension.excludeProjects)
            it.perProjectTimeoutSeconds.set(extension.perProjectTimeoutSeconds)
            // Narrowed inputs: only package.json files
            it.packageJsonFiles.from(
                scanTargetDir.map { dir ->
                    project.fileTree(dir) { tree ->
                        tree.include("**/package.json")
                        tree.exclude("**/node_modules/**", "**/build/**", "**/.git/**", "**/.gradle/**")
                    }
                }
            )
            it.onlyIf { !extension.skipNpm.get() }
        }

        val gradleTask = project.tasks.register("trivyLockGradle", LockGradleTask::class.java) {
            it.group = "trivy"
            it.description = "Generates Gradle dependency lock files"
            it.scanTarget.set(scanTargetDir)
            it.outputDir.set(gradleLockOutputDir)
            it.maxParallelLocks.set(extension.maxParallelLocks)
            it.excludeProjects.set(extension.excludeProjects)
            it.perProjectTimeoutSeconds.set(extension.perProjectTimeoutSeconds)
            // Narrowed inputs: only build script files
            it.buildScriptFiles.from(
                scanTargetDir.map { dir ->
                    project.fileTree(dir) { tree ->
                        tree.include(
                            "**/settings.gradle", "**/settings.gradle.kts",
                            "**/build.gradle", "**/build.gradle.kts",
                            "**/gradle.properties", "**/libs.versions.toml"
                        )
                        tree.exclude("**/node_modules/**", "**/build/**", "**/.git/**", "**/.gradle/**")
                    }
                }
            )
            it.onlyIf { !extension.skipGradle.get() }
        }

        project.tasks.register("trivyScan", TrivyScanTask::class.java) {
            it.group = "trivy"
            it.description = "Runs Trivy vulnerability scan"
            it.dependsOn(downloadTask, gradleTask, npmTask)
            it.trivyBinary.set(effectiveBinary)
            it.scanTarget.set(scanTargetDir)
            it.lockFilesDir.set(project.layout.buildDirectory.dir("trivy-locks"))
            it.severity.set(extension.severity)
            it.additionalArgs.set(extension.additionalArgs)
            it.outputFormat.set(extension.outputFormat)
            it.failOnVulnerability.set(extension.failOnVulnerability)
            it.outputFile.set(extension.outputFile)
            it.cacheDir.set(extension.cacheDir.map { d -> d.asFile.absolutePath })
            it.skipDbUpdate.set(extension.skipDbUpdate)
            it.dbRepository.set(extension.dbRepository)
            it.excludeDirs.set(extension.excludeDirs)
            it.skipFiles.set(extension.skipFiles)
            it.ignoreFile.set(extension.ignoreFile.map { f -> f.asFile.absolutePath })
            it.scanners.set(extension.scanners)
            it.ignoreUnfixed.set(extension.ignoreUnfixed)
        }
    }
}
