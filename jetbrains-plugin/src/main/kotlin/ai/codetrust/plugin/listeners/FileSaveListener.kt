// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.listeners

import ai.codetrust.plugin.services.CodeTrustScanService
import ai.codetrust.plugin.settings.CodeTrustSettings
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.vfs.newvfs.BulkFileListener
import com.intellij.openapi.vfs.newvfs.events.VFileEvent
import com.intellij.openapi.vfs.newvfs.events.VFileContentChangeEvent

/**
 * Listens for file save events and triggers automatic CodeTrust scans.
 * Respects the scanOnSave setting.
 */
class FileSaveListener : BulkFileListener {
    override fun after(events: MutableList<out VFileEvent>) {
        val settings = CodeTrustSettings.getInstance().state
        if (!settings.scanOnSave) return
        if (settings.apiKey.isEmpty()) return

        val changedFiles = events
            .filterIsInstance<VFileContentChangeEvent>()
            .mapNotNull { it.file }
            .filter { file ->
                val ext = file.extension?.lowercase() ?: return@filter false
                ext in SUPPORTED_EXTENSIONS
            }

        if (changedFiles.isEmpty()) return

        for (project in ProjectManager.getInstance().openProjects) {
            val scanService = CodeTrustScanService.getInstance(project)
            for (file in changedFiles) {
                scanService.scanFile(file)
            }
        }
    }

    companion object {
        private val SUPPORTED_EXTENSIONS = setOf(
            "py", "js", "ts", "jsx", "tsx", "go", "rs",
            "java", "kt", "cs", "cpp", "c", "h", "hpp",
            "rb", "php", "swift", "sql", "yaml", "yml",
            "tf", "dockerfile", "sh", "bash"
        )
    }
}
