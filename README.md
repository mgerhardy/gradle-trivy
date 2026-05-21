# gradle-trivy-plugin

A Gradle plugin that auto-downloads [Trivy](https://github.com/aquasecurity/trivy) and generates lock files for npm and Java/Gradle builds to enable vulnerability scanning.

## Usage

```kotlin
plugins {
    id("io.github.mgerhardy.trivy") version "0.1.0"
}

trivy {
    version.set("0.70.0")
    severity.set("HIGH,CRITICAL")
}
```

## Tasks

| Task | Description |
|------|-------------|
| `trivyDownload` | Downloads the Trivy binary for your platform |
| `trivyLockNpm` | Generates `package-lock.json` via `npm install --package-lock-only` |
| `trivyLockGradle` | Generates `gradle.lockfile` for all Gradle projects in the scan target |
| `trivyScan` | Runs `trivy fs` against the project (auto-downloads Trivy first) |

## Configuration

```kotlin
trivy {
    // Trivy version to download (default: "0.70.0")
    version.set("0.70.0")

    // Where to install the downloaded Trivy binary (default: ~/.gradle/caches/trivy/bin/<version>)
    installDir.set(layout.buildDirectory.dir("trivy"))

    // Override with a custom or system-wide Trivy binary (skips download)
    binaryPath.set(file("/usr/local/bin/trivy"))

    // Directory containing package.json for npm lock generation
    npmProjectDir.set(layout.projectDirectory)

    // Directory to scan (also used to discover Gradle subprojects for lock generation)
    scanTarget.set(layout.projectDirectory)

    // Severity levels to report (default: "HIGH,CRITICAL")
    severity.set("HIGH,CRITICAL")

    // Output format: table, json, sarif, etc. (default: "table")
    outputFormat.set("table")

    // Write scan output to a file
    outputFile.set(layout.buildDirectory.file("trivy-report.json"))

    // Fail the build when vulnerabilities are found (default: true)
    failOnVulnerability.set(true)

    // Check for newer Trivy versions on each run (default: false)
    checkForUpdates.set(false)

    // Additional CLI arguments passed directly to trivy
    additionalArgs.set(listOf("--timeout", "10m"))

    // Skip npm lock file generation (default: false)
    skipNpm.set(false)

    // Skip Gradle lock file generation (default: false)
    skipGradle.set(false)

    // Custom npm binary path (default: "npm")
    npmBinary.set("/usr/local/bin/npm")

    // --- Database options ---

    // Skip vulnerability DB update (default: false) — useful for CI with pre-warmed cache
    skipDbUpdate.set(true)

    // Use a private DB mirror
    dbRepository.set("ghcr.io/my-org/trivy-db")

    // --- Filtering ---

    // Directories to exclude from scanning (maps to --skip-dirs)
    excludeDirs.set(listOf("vendor", "testdata", "node_modules"))

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

### CI caching example

The plugin stores the Trivy binary and vulnerability DB under `~/.gradle/caches/trivy/`. Cache this directory in CI for fast subsequent runs:

```yaml
# GitHub Actions
- uses: actions/cache@v4
  with:
    path: ~/.gradle/caches/trivy
    key: trivy-${{ hashFiles('build.gradle.kts') }}

# Then skip DB download on cache hit:
# trivy { skipDbUpdate.set(true) }
```

### Using a system-wide Trivy

If you already have Trivy installed, point `binaryPath` to it and the download step is skipped:

```kotlin
trivy {
    binaryPath.set(file("/usr/local/bin/trivy"))
}
```

## How it works

1. **Download** — `trivyDownload` fetches the Trivy binary to a persistent cache (`~/.gradle/caches/trivy/bin/<version>`). Retries with backoff on network failures.
2. **Lock generation** — `trivyLockGradle` discovers all Gradle projects under `scanTarget`, provisions missing wrapper files (including the `gradlew` script), and resolves dependencies in parallel. `trivyLockNpm` runs `npm install --package-lock-only` and cleans up generated lock files from source directories.
3. **Scan** — `trivyScan` merges lock files with the scan target and runs a single `trivy fs` pass.

## Caching

- **Trivy binary**: Cached per-version in `~/.gradle/caches/trivy/bin/<version>` — never re-downloaded.
- **Vulnerability DB**: Cached in `~/.gradle/caches/trivy/db/` — use `skipDbUpdate` to avoid re-downloading in CI.
- **Lock tasks**: Both `trivyLockGradle` and `trivyLockNpm` are `@CacheableTask` — Gradle skips them when inputs haven't changed.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
