// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin

import ai.codetrust.plugin.services.CodeTrustApiClient
import ai.codetrust.plugin.services.Severity
import ai.codetrust.plugin.settings.CodeTrustSettings
import com.intellij.codeInspection.*
import com.intellij.psi.PsiFile

/**
 * Local inspection that integrates CodeTrust scanning into the IDE's
 * built-in inspection framework, enabling batch analysis and code cleanup.
 */
class CodeTrustInspection : LocalInspectionTool() {

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val settings = CodeTrustSettings.getInstance().state
        if (settings.apiKey.isEmpty()) return null

        val vFile = file.virtualFile ?: return null
        val findings = CodeTrustApiClient.scanCode(file.text, vFile.name)

        if (findings.isEmpty()) return null

        val document = file.viewProvider.document ?: return null
        val problems = mutableListOf<ProblemDescriptor>()

        for (finding in findings) {
            val lineNumber = (finding.line ?: 1) - 1
            if (lineNumber < 0 || lineNumber >= document.lineCount) continue

            val startOffset = document.getLineStartOffset(lineNumber)
            val endOffset = document.getLineEndOffset(lineNumber)
            val element = file.findElementAt(startOffset) ?: continue

            val highlightType = when (finding.severity) {
                Severity.BLOCK -> ProblemHighlightType.GENERIC_ERROR
                Severity.WARN -> ProblemHighlightType.GENERIC_ERROR_OR_WARNING
                Severity.INFO -> ProblemHighlightType.WEAK_WARNING
            }

            val description = "[${finding.ruleId}] ${finding.message}"
            problems.add(
                manager.createProblemDescriptor(
                    element,
                    description,
                    isOnTheFly,
                    emptyArray(),
                    highlightType
                )
            )
        }

        return problems.toTypedArray()
    }
}
