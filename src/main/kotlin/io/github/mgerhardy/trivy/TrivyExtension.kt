package io.github.mgerhardy.trivy

import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

abstract class TrivyExtension {
    abstract val version: Property<String>
    abstract val installDir: DirectoryProperty
    abstract val binaryPath: RegularFileProperty
    abstract val npmProjectDir: DirectoryProperty
    abstract val scanTarget: DirectoryProperty
    abstract val severity: Property<String>
    abstract val checkForUpdates: Property<Boolean>
    abstract val additionalArgs: ListProperty<String>
    abstract val outputFormat: Property<String>
    abstract val outputFile: RegularFileProperty
    abstract val cacheDir: DirectoryProperty
    abstract val failOnVulnerability: Property<Boolean>
    abstract val skipNpm: Property<Boolean>
    abstract val skipGradle: Property<Boolean>
    abstract val npmBinary: Property<String>

    // #1: DB control
    abstract val skipDbUpdate: Property<Boolean>
    abstract val dbRepository: Property<String>

    // #4: Exclude/ignore
    abstract val excludeDirs: ListProperty<String>
    abstract val skipFiles: ListProperty<String>
    abstract val ignoreFile: RegularFileProperty

    // #9: Scanners and ignoreUnfixed
    abstract val scanners: Property<String>
    abstract val ignoreUnfixed: Property<Boolean>

    // #10: Parallel lock generation
    abstract val maxParallelLocks: Property<Int>

    // Exclude specific subproject paths from lock generation
    abstract val excludeProjects: ListProperty<String>

    // Per-project timeout for lock generation (seconds)
    abstract val perProjectTimeoutSeconds: Property<Long>

    init {
        version.convention("0.70.0")
        severity.convention("HIGH,CRITICAL")
        checkForUpdates.convention(false)
        additionalArgs.convention(emptyList())
        outputFormat.convention("table")
        failOnVulnerability.convention(true)
        skipNpm.convention(false)
        skipGradle.convention(false)
        npmBinary.convention("npm")
        skipDbUpdate.convention(false)
        excludeDirs.convention(emptyList())
        skipFiles.convention(emptyList())
        ignoreUnfixed.convention(false)
        maxParallelLocks.convention(4)
        excludeProjects.convention(emptyList())
        perProjectTimeoutSeconds.convention(300)
    }
}
