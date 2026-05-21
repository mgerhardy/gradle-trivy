package io.github.mgerhardy.trivy

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.util.zip.ZipFile
import javax.inject.Inject

@DisableCachingByDefault(because = "Uses persistent install directory with manual up-to-date check")
abstract class TrivyDownloadTask @Inject constructor(
    private val execOps: ExecOperations
) : DefaultTask() {
    @get:Input
    abstract val version: Property<String>

    @get:Internal
    abstract val checkForUpdates: Property<Boolean>

    @get:OutputDirectory
    abstract val installDir: DirectoryProperty

    @TaskAction
    fun download() {
        val ver = version.get()
        val dir = installDir.get().asFile
        val binary = File(dir, binaryName())

        if (binary.exists()) {
            logger.lifecycle("Trivy $ver already present at ${binary.absolutePath}")
            checkForUpdate(ver)
            return
        }

        dir.mkdirs()
        val os = detectOs()
        val arch = detectArch()
        val ext = if (isWindows()) "zip" else "tar.gz"
        val archiveName = "trivy_${ver}_${os}-${arch}.${ext}"
        val url = "https://github.com/aquasecurity/trivy/releases/download/v${ver}/${archiveName}"

        logger.lifecycle("Downloading Trivy $ver from $url")
        val archiveFile = File(dir, archiveName)
        downloadWithRetry(url, archiveFile, maxRetries = 3)

        // Verify SHA256 checksum
        val checksumUrl = "https://github.com/aquasecurity/trivy/releases/download/v${ver}/trivy_${ver}_checksums.txt"
        verifyChecksum(archiveFile, archiveName, checksumUrl)

        if (isWindows()) {
            extractZip(archiveFile, dir)
        } else {
            execOps.exec { spec ->
                spec.workingDir(dir)
                spec.commandLine("tar", "xzf", archiveName)
            }
        }
        archiveFile.delete()
        if (!isWindows()) binary.setExecutable(true)
        logger.lifecycle("Trivy installed to ${binary.absolutePath}")
        checkForUpdate(ver)
    }

    private fun verifyChecksum(file: File, fileName: String, checksumUrl: String) {
        try {
            val checksumFile = File(file.parentFile, "checksums.txt")
            downloadFollowingRedirects(checksumUrl, checksumFile)
            val expectedHash = checksumFile.readLines()
                .map { it.trim().split("\\s+".toRegex(), limit = 2) }
                .firstOrNull { it.size == 2 && it[1] == fileName }
                ?.get(0)
            checksumFile.delete()
            if (expectedHash == null) {
                logger.warn("Checksum entry not found for $fileName — skipping verification")
                return
            }
            val actualHash = MessageDigest.getInstance("SHA-256").let { md ->
                file.inputStream().use { input ->
                    val buf = ByteArray(8192)
                    var n: Int
                    while (input.read(buf).also { n = it } != -1) md.update(buf, 0, n)
                }
                md.digest().joinToString("") { "%02x".format(it) }
            }
            if (actualHash != expectedHash) {
                file.delete()
                error("SHA256 mismatch for $fileName: expected $expectedHash, got $actualHash")
            }
            logger.lifecycle("SHA256 checksum verified for $fileName")
        } catch (e: Exception) {
            if (e.message?.contains("SHA256 mismatch") == true) throw e
            logger.warn("Could not verify checksum: ${e.message}")
        }
    }

    private fun downloadWithRetry(url: String, dest: File, maxRetries: Int) {
        var lastException: Exception? = null
        repeat(maxRetries) { attempt ->
            try {
                downloadFollowingRedirects(url, dest)
                return
            } catch (e: Exception) {
                lastException = e
                if (attempt < maxRetries - 1) {
                    val delay = (attempt + 1) * 2000L
                    logger.warn("Download attempt ${attempt + 1} failed: ${e.message}. Retrying in ${delay}ms...")
                    Thread.sleep(delay)
                    dest.delete()
                }
            }
        }
        throw lastException!!
    }

    private fun checkForUpdate(ver: String) {
        if (!checkForUpdates.getOrElse(false)) return
        try {
            val conn = URI("https://github.com/aquasecurity/trivy/releases/latest").toURL()
                .openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 3000
            conn.readTimeout = 3000
            conn.connect()
            val location = conn.getHeaderField("Location") ?: ""
            conn.disconnect()
            val latest = location.substringAfterLast("/v")
            if (latest.isNotEmpty() && latest != ver) {
                logger.warn("Trivy update available: $latest (currently using $ver)")
            }
        } catch (_: Exception) { }
    }

    private fun extractZip(zipFile: File, destDir: File) {
        val destCanonical = destDir.canonicalPath
        ZipFile(zipFile).use { zip ->
            zip.entries().asSequence().forEach { entry ->
                val target = File(destDir, entry.name)
                if (!target.canonicalPath.startsWith(destCanonical + File.separator) && target.canonicalPath != destCanonical) {
                    error("Zip entry '${entry.name}' would escape destination directory (zip slip)")
                }
                if (entry.isDirectory) {
                    target.mkdirs()
                } else {
                    target.parentFile.mkdirs()
                    zip.getInputStream(entry).use { input -> target.outputStream().use { input.copyTo(it) } }
                }
            }
        }
    }

    private fun downloadFollowingRedirects(url: String, dest: File, maxRedirects: Int = 5) {
        var currentUrl = url
        repeat(maxRedirects) {
            val conn = URI(currentUrl).toURL().openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 30000
            conn.readTimeout = 60000
            conn.connect()
            val code = conn.responseCode
            if (code in 301..308) {
                currentUrl = conn.getHeaderField("Location") ?: error("Redirect without Location header")
                conn.disconnect()
                return@repeat
            }
            if (code != 200) {
                conn.disconnect()
                error("Download failed with HTTP $code for $currentUrl")
            }
            conn.inputStream.use { input -> dest.outputStream().use { input.copyTo(it) } }
            conn.disconnect()
            return
        }
        error("Too many redirects downloading $url")
    }

    companion object {
        fun isWindows(): Boolean = System.getProperty("os.name").lowercase().contains("windows")

        fun detectOs(): String {
            val name = System.getProperty("os.name").lowercase()
            return when {
                name.contains("windows") -> "Windows"
                name.contains("linux") -> "Linux"
                name.contains("mac") || name.contains("darwin") -> "macOS"
                else -> error("Unsupported OS: $name")
            }
        }

        fun detectArch(): String {
            val arch = System.getProperty("os.arch").lowercase()
            return when {
                arch.contains("aarch64") || arch.contains("arm64") -> "ARM64"
                arch.contains("amd64") || arch.contains("x86_64") -> "64bit"
                else -> error("Unsupported architecture: $arch")
            }
        }

        fun binaryName(): String = if (isWindows()) "trivy.exe" else "trivy"
    }
}
