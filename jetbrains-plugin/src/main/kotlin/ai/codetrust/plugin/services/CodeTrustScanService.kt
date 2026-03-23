// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.services

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.concurrent.ConcurrentHashMap

/**
 * Project-level service that manages CodeTrust scanning operations.
 * Coordinates between the API client, findings manager, and UI components.
 */
@Service(Service.Level.PROJECT)
class CodeTrustScanService(private val project: Project) {
    private val log = Logger.getInstance(CodeTrustScanService::class.java)
    private val scanInProgress = ConcurrentHashMap<String, Boolean>()

    /**
     * Scan a single file asynchronously.
     * Results are stored in FindingsManager and UI is updated via notification.
     */
    fun scanFile(file: VirtualFile) {
        val path = file.path
        if (scanInProgress.putIfAbsent(path, true) != null) {
            return // scan already in progress for this file
        }

        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val content = String(file.contentsToByteArray(), Charsets.UTF_8)
                val findings = CodeTrustApiClient.scanCode(content, file.name)

                val manager = FindingsManager.getInstance(project)
                manager.updateFindings(path, findings)

                log.info("CodeTrust: scanned ${file.name} — ${findings.size} findings")
            } catch (e: Exception) {
                log.warn("CodeTrust: scan failed for ${file.name}", e)
            } finally {
                scanInProgress.remove(path)
            }
        }
    }

    /**
     * Scan all supported files in the project.
     */
    fun scanProject() {
        val baseDir = project.basePath ?: return
        val supportedExtensions = setOf(
            "py", "js", "ts", "jsx", "tsx", "go", "rs",
            "java", "kt", "cs", "cpp", "c", "h", "hpp",
            "rb", "php", "swift", "sql", "yaml", "yml",
            "tf", "dockerfile", "sh", "bash"
        )

        ApplicationManager.getApplication().executeOnPooledThread {
            val projectDir = com.intellij.openapi.vfs.LocalFileSystem.getInstance()
                .findFileByPath(baseDir) ?: return@executeOnPooledThread

            collectFiles(projectDir, supportedExtensions).forEach { file ->
                scanFile(file)
            }
        }
    }

    private fun collectFiles(
        dir: VirtualFile,
        extensions: Set<String>,
        maxDepth: Int = 10
    ): List<VirtualFile> {
        if (maxDepth <= 0) return emptyList()
        val results = mutableListOf<VirtualFile>()

        for (child in dir.children) {
            if (child.isDirectory) {
                val name = child.name
                if (name.startsWith(".") || name == "node_modules" ||
                    name == "__pycache__" || name == "venv" || name == ".venv" ||
                    name == "dist" || name == "build" || name == "target"
                ) {
                    continue
                }
                results.addAll(collectFiles(child, extensions, maxDepth - 1))
            } else {
                val ext = child.extension?.lowercase() ?: continue
                if (ext in extensions) {
                    results.add(child)
                }
            }
        }
        return results
    }

    companion object {
        fun getInstance(project: Project): CodeTrustScanService {
            return project.getService(CodeTrustScanService::class.java)
        }
    }
}
