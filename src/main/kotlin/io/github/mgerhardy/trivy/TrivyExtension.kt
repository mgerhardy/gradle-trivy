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

    // SBOM generation
    abstract val sbomFormat: Property<String>
    abstract val sbomOutputFile: RegularFileProperty

    // License compliance check
    abstract val licenseOutputFormat: Property<String>
    abstract val licenseOutputFile: RegularFileProperty
    abstract val licenseFailOnForbidden: Property<Boolean>
    abstract val licenseForbiddenCategories: ListProperty<String>
    abstract val licenseForbiddenLicenses: ListProperty<String>
    abstract val licenseAllowedLicenses: ListProperty<String>

    // Secret scanning
    abstract val secretOutputFormat: Property<String>
    abstract val secretOutputFile: RegularFileProperty
    abstract val secretFailOnSecret: Property<Boolean>
    abstract val secretSeverity: Property<String>
    abstract val secretExcludeDirs: ListProperty<String>
    abstract val secretSkipFiles: ListProperty<String>

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
        sbomFormat.convention("cyclonedx")
        licenseOutputFormat.convention("json")
        licenseFailOnForbidden.convention(true)
        licenseForbiddenCategories.convention(listOf("restricted", "forbidden"))
        licenseForbiddenLicenses.convention(emptyList())
        licenseAllowedLicenses.convention(emptyList())
        secretOutputFormat.convention("json")
        secretFailOnSecret.convention(true)
        secretSeverity.convention("HIGH,CRITICAL")
        secretExcludeDirs.convention(listOf(".git", ".gradle", "node_modules", "build"))
        secretSkipFiles.convention(emptyList())
        excludeProjects.convention(emptyList())
        perProjectTimeoutSeconds.convention(300)
    }
}
