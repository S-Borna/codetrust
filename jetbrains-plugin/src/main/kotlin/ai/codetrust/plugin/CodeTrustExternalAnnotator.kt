// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin

import ai.codetrust.plugin.services.CodeTrustApiClient
import ai.codetrust.plugin.services.Finding
import ai.codetrust.plugin.services.FindingsManager
import ai.codetrust.plugin.services.Severity
import ai.codetrust.plugin.settings.CodeTrustSettings
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Editor
import com.intellij.psi.PsiFile

/**
 * External annotator that runs CodeTrust scans and displays findings
 * as inline editor annotations with severity-appropriate highlighting.
 */
class CodeTrustExternalAnnotator : ExternalAnnotator<CodeTrustExternalAnnotator.Input, List<Finding>>() {

    data class Input(val code: String, val filename: String, val filePath: String)

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): Input? {
        val settings = CodeTrustSettings.getInstance().state
        if (!settings.showInlineAnnotations) return null
        if (settings.apiKey.isEmpty()) return null

        val vFile = file.virtualFile ?: return null
        return Input(
            code = file.text,
            filename = vFile.name,
            filePath = vFile.path
        )
    }

    override fun doAnnotate(collectedInfo: Input?): List<Finding> {
        if (collectedInfo == null) return emptyList()
        val findings = CodeTrustApiClient.scanCode(collectedInfo.code, collectedInfo.filename)

        // Also update the findings manager
        val project = com.intellij.openapi.project.ProjectManager.getInstance().openProjects.firstOrNull()
        if (project != null) {
            FindingsManager.getInstance(project).updateFindings(collectedInfo.filePath, findings)
        }

        return findings
    }

    override fun apply(file: PsiFile, findings: List<Finding>, holder: AnnotationHolder) {
        val settings = CodeTrustSettings.getInstance().state
        val minSeverity = when (settings.minimumSeverity) {
            "BLOCK" -> Severity.BLOCK
            "WARN" -> Severity.WARN
            else -> Severity.INFO
        }

        val document = file.viewProvider.document ?: return

        for (finding in findings) {
            if (finding.severity.weight < minSeverity.weight) continue

            val lineNumber = (finding.line ?: 1) - 1
            if (lineNumber < 0 || lineNumber >= document.lineCount) continue

            val startOffset = document.getLineStartOffset(lineNumber)
            val endOffset = document.getLineEndOffset(lineNumber)

            val severity = when (finding.severity) {
                Severity.BLOCK -> HighlightSeverity.ERROR
                Severity.WARN -> HighlightSeverity.WARNING
                Severity.INFO -> HighlightSeverity.WEAK_WARNING
            }

            val message = buildString {
                append("[CodeTrust] ${finding.ruleId}: ${finding.message}")
                if (finding.suggestion != null) {
                    append("\nSuggestion: ${finding.suggestion}")
                }
            }

            holder.newAnnotation(severity, message)
                .range(startOffset, endOffset)
                .create()
        }
    }
}
