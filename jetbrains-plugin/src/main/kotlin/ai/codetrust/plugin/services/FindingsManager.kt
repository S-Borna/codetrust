// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.services

import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project
import com.intellij.util.messages.Topic
import java.util.concurrent.ConcurrentHashMap

/**
 * Project-level service that stores and manages scan findings.
 * Components subscribe to FindingsUpdateListener to react to changes.
 */
@Service(Service.Level.PROJECT)
class FindingsManager(private val project: Project) {
    private val findingsMap = ConcurrentHashMap<String, List<Finding>>()

    /** Get findings for a specific file path. */
    fun getFindings(filePath: String): List<Finding> {
        return findingsMap[filePath] ?: emptyList()
    }

    /** Get all findings across all scanned files. */
    fun getAllFindings(): Map<String, List<Finding>> {
        return findingsMap.toMap()
    }

    /** Update findings for a file and notify listeners. */
    fun updateFindings(filePath: String, findings: List<Finding>) {
        findingsMap[filePath] = findings
        project.messageBus.syncPublisher(FINDINGS_UPDATED).findingsUpdated(filePath, findings)
    }

    /** Clear findings for a specific file. */
    fun clearFindings(filePath: String) {
        findingsMap.remove(filePath)
        project.messageBus.syncPublisher(FINDINGS_UPDATED).findingsUpdated(filePath, emptyList())
    }

    /** Clear all findings across all files. */
    fun clearAll() {
        val paths = findingsMap.keys.toList()
        findingsMap.clear()
        paths.forEach { path ->
            project.messageBus.syncPublisher(FINDINGS_UPDATED).findingsUpdated(path, emptyList())
        }
    }

    /** Total count of findings at or above the given severity. */
    fun countBySeverity(minSeverity: Severity): Int {
        return findingsMap.values.flatten().count { it.severity.weight >= minSeverity.weight }
    }

    companion object {
        val FINDINGS_UPDATED: Topic<FindingsUpdateListener> = Topic.create(
            "CodeTrust Findings Updated",
            FindingsUpdateListener::class.java
        )

        fun getInstance(project: Project): FindingsManager {
            return project.getService(FindingsManager::class.java)
        }
    }
}

/** Listener interface for findings updates. */
interface FindingsUpdateListener {
    fun findingsUpdated(filePath: String, findings: List<Finding>)
}
