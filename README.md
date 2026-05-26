# gradle-trivy-plugin

A Gradle plugin that auto-downloads [Trivy](https://github.com/aquasecurity/trivy) and generates lock files for npm and Java/Gradle builds to enable vulnerability scanning.

## Requirements

- **Gradle**: 7.0+
- **Java**: 11+
- **Platforms**: Linux (x86_64, ARM64), macOS (x86_64, ARM64), Windows (x86_64, ARM64)

## Quick start

Apply the plugin from the [Gradle Plugin Portal](https://plugins.gradle.org/plugin/io.github.mgerhardy.trivy):

```kotlin
plugins {
    id("io.github.mgerhardy.trivy") version "0.1.0"
}

trivy {
    severity.set("HIGH,CRITICAL")
}
```

Run a scan:

```bash
./gradlew trivyScan
```

This automatically downloads Trivy, generates lock files, and scans your project. The build fails if vulnerabilities are found.

<details>
<summary>Groovy DSL</summary>

```groovy
plugins {
    id 'io.github.mgerhardy.trivy' version '0.1.0'
}

trivy {
    severity = 'HIGH,CRITICAL'
}
```

</details>

## Tasks

| Task | Description |
|------|-------------|
| `trivyDownload` | Downloads the Trivy binary for your platform |
| `trivyLockNpm` | Generates `package-lock.json` via `npm install --package-lock-only` |
| `trivyLockGradle` | Generates `gradle.lockfile` for all Gradle projects in the scan target |
| `trivyScan` | Runs `trivy fs` against the project |

`trivyScan` automatically depends on all other tasks — you only need to run `trivyScan`.

## Configuration

### Common options

```kotlin
trivy {
    // Trivy version to download (default: "0.70.0")
    version.set("0.70.0")

    // Severity levels to report (default: "HIGH,CRITICAL")
    severity.set("HIGH,CRITICAL")

    // Output format: table, json, sarif, etc. (default: "table")
    outputFormat.set("json")

    // Write scan output to a file (no default — prints to stdout)
    outputFile.set(layout.buildDirectory.file("trivy-report.json"))

    // Fail the build when vulnerabilities are found (default: true)
    failOnVulnerability.set(true)

    // Directory to scan (default: project directory)
    scanTarget.set(layout.projectDirectory)

    // Skip npm lock file generation (default: false)
    skipNpm.set(false)

    // Skip Gradle lock file generation (default: false)
    skipGradle.set(false)
}
```

### Advanced options

```kotlin
trivy {
    // Override with a custom or system-wide Trivy binary (skips download)
    binaryPath.set(file("/usr/local/bin/trivy"))

    // Where to install the downloaded Trivy binary (default: ~/.gradle/caches/trivy/bin/<version>)
    installDir.set(layout.buildDirectory.dir("trivy"))

    // Check for newer Trivy versions on each run (default: false)
    checkForUpdates.set(false)

    // Additional CLI arguments passed directly to trivy
    additionalArgs.set(listOf("--timeout", "10m"))

    // Custom npm binary path (default: "npm")
    npmBinary.set("/usr/local/bin/npm")

    // Directory containing package.json for npm lock generation (default: scanTarget)
    npmProjectDir.set(layout.projectDirectory)

    // Exclude specific subproject paths from lock generation
    excludeProjects.set(listOf("legacy-module"))

    // Per-project timeout for lock generation in seconds (default: 300)
    perProjectTimeoutSeconds.set(300)

    // --- Database ---

    // Skip vulnerability DB update (default: false) — useful for CI with pre-warmed cache
    skipDbUpdate.set(true)

    // Use a private DB mirror
    dbRepository.set("ghcr.io/my-org/trivy-db")

    // --- Filtering ---

    // Directories to exclude from scanning (maps to --skip-dirs)
    excludeDirs.set(listOf("vendor", "testdata"))

    // Files to exclude from scanning (maps to --skip-files)
    skipFiles.set(listOf("go.sum"))

    // Path to .trivyignore file
    ignoreFile.set(file(".trivyignore"))

    // Only report vulnerabilities with available fixes (default: false)
    ignoreUnfixed.set(true)

    // Scanners to use: vuln, misconfig, secret, license (default: trivy default)
    scanners.set("vuln,secret")

    // --- Performance ---

    // Max parallel Gradle lock file generation processes (default: 4)
    maxParallelLocks.set(4)
}
```

## Multi-project builds

Apply the plugin to the **root project only**. Set `scanTarget` to the root directory — the plugin automatically discovers all Gradle subprojects and npm packages underneath it for lock file generation.

## CI caching

The plugin stores the Trivy binary and vulnerability DB under `~/.gradle/caches/trivy/`. Cache this directory for fast subsequent runs:

```yaml
# GitHub Actions
- uses: actions/cache@v4
  with:
    path: ~/.gradle/caches/trivy
    key: trivy-${{ hashFiles('build.gradle.kts') }}
```

On cache hit, skip the DB download:

```kotlin
trivy {
    skipDbUpdate.set(true)
}
```

## Using a system-wide Trivy

If Trivy is already installed, point `binaryPath` to it and the download step is skipped:

```kotlin
trivy {
    binaryPath.set(file("/usr/local/bin/trivy"))
}
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
