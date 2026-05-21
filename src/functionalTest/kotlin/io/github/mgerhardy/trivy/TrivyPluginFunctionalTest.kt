package io.github.mgerhardy.trivy

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TrivyPluginFunctionalTest {

    @Test
    fun `plugin applies and registers tasks`() {
        val projectDir = createTempProject()
        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("tasks", "--group=trivy")
            .build()

        assertTrue(result.output.contains("trivyDownload"))
        assertTrue(result.output.contains("trivyScan"))
        assertTrue(result.output.contains("trivyLockNpm"))
        assertTrue(result.output.contains("trivyLockGradle"))
    }

    @Test
    fun `trivyDownload is skipped when binaryPath is set`() {
        val projectDir = createTempProject("""
            trivy {
                binaryPath.set(file("fake-trivy"))
            }
        """.trimIndent())
        File(projectDir, "fake-trivy").apply { writeText("#!/bin/sh"); setExecutable(true) }

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("trivyDownload")
            .build()

        assertEquals(TaskOutcome.SKIPPED, result.task(":trivyDownload")?.outcome)
    }

    @Test
    fun `trivyLockGradle is skipped when skipGradle is true`() {
        val projectDir = createTempProject("""
            trivy {
                skipGradle.set(true)
            }
        """.trimIndent())

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("trivyLockGradle")
            .build()

        assertEquals(TaskOutcome.SKIPPED, result.task(":trivyLockGradle")?.outcome)
    }

    @Test
    fun `trivyLockNpm is skipped when skipNpm is true`() {
        val projectDir = createTempProject("""
            trivy {
                skipNpm.set(true)
            }
        """.trimIndent())

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("trivyLockNpm")
            .build()

        assertEquals(TaskOutcome.SKIPPED, result.task(":trivyLockNpm")?.outcome)
    }

    private fun createTempProject(extraConfig: String = ""): File {
        val dir = File.createTempFile("trivy-test", "").apply { delete(); mkdirs() }
        dir.deleteOnExit()
        File(dir, "settings.gradle.kts").writeText("rootProject.name = \"test-project\"")
        File(dir, "build.gradle.kts").writeText("""
            plugins {
                id("io.github.mgerhardy.trivy")
            }
            $extraConfig
        """.trimIndent())
        return dir
    }
}
