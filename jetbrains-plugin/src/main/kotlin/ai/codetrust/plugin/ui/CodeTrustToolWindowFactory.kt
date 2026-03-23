// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.ui

import ai.codetrust.plugin.services.Finding
import ai.codetrust.plugin.services.FindingsManager
import ai.codetrust.plugin.services.FindingsUpdateListener
import ai.codetrust.plugin.services.Severity
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.treeStructure.Tree
import java.awt.BorderLayout
import java.awt.Component
import javax.swing.*
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeCellRenderer
import javax.swing.tree.DefaultTreeModel

/**
 * Tool window factory for the CodeTrust findings panel.
 * Displays a tree of findings grouped by file with severity icons.
 */
class CodeTrustToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = CodeTrustToolWindowPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Findings", false)
        toolWindow.contentManager.addContent(content)
    }
}

/**
 * Panel displaying a tree of findings grouped by file path.
 * Double-clicking navigates to the finding location in the editor.
 */
class CodeTrustToolWindowPanel(private val project: Project) : JPanel(BorderLayout()) {
    private val rootNode = DefaultMutableTreeNode("CodeTrust Findings")
    private val treeModel = DefaultTreeModel(rootNode)
    private val tree = Tree(treeModel)
    private val statusLabel = JLabel("No findings")

    init {
        tree.cellRenderer = FindingCellRenderer()
        tree.isRootVisible = true

        tree.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseClicked(e: java.awt.event.MouseEvent) {
                if (e.clickCount == 2) {
                    val node = tree.lastSelectedPathComponent as? DefaultMutableTreeNode ?: return
                    val finding = node.userObject as? FindingNode ?: return
                    navigateToFinding(finding)
                }
            }
        })

        add(JBScrollPane(tree), BorderLayout.CENTER)
        add(statusLabel, BorderLayout.SOUTH)

        // Subscribe to findings updates
        project.messageBus.connect().subscribe(
            FindingsManager.FINDINGS_UPDATED,
            object : FindingsUpdateListener {
                override fun findingsUpdated(filePath: String, findings: List<Finding>) {
                    SwingUtilities.invokeLater { refreshTree() }
                }
            }
        )
    }

    private fun refreshTree() {
        rootNode.removeAllChildren()

        val allFindings = FindingsManager.getInstance(project).getAllFindings()
        var totalCount = 0

        for ((filePath, findings) in allFindings.toSortedMap()) {
            if (findings.isEmpty()) continue
            val shortPath = filePath.substringAfterLast("/")
            val fileNode = DefaultMutableTreeNode("$shortPath (${findings.size})")

            for (finding in findings.sortedByDescending { it.severity.weight }) {
                fileNode.add(DefaultMutableTreeNode(FindingNode(filePath, finding)))
                totalCount++
            }
            rootNode.add(fileNode)
        }

        treeModel.reload()
        statusLabel.text = "$totalCount finding(s) across ${allFindings.count { it.value.isNotEmpty() }} file(s)"

        // Expand all
        for (i in 0 until tree.rowCount) {
            tree.expandRow(i)
        }
    }

    private fun navigateToFinding(node: FindingNode) {
        val vFile = LocalFileSystem.getInstance().findFileByPath(node.filePath) ?: return
        val line = (node.finding.line ?: 1) - 1
        val descriptor = OpenFileDescriptor(project, vFile, line.coerceAtLeast(0), 0)
        FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
    }
}

/** Wrapper for displaying a finding in the tree. */
data class FindingNode(val filePath: String, val finding: Finding) {
    override fun toString(): String {
        val line = finding.line?.let { "L$it" } ?: "?"
        return "[$line] ${finding.severity.displayName}: ${finding.ruleId} — ${finding.message}"
    }
}

/** Custom tree cell renderer with severity-based icons. */
class FindingCellRenderer : DefaultTreeCellRenderer() {
    override fun getTreeCellRendererComponent(
        tree: JTree,
        value: Any?,
        sel: Boolean,
        expanded: Boolean,
        leaf: Boolean,
        row: Int,
        hasFocus: Boolean
    ): Component {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus)

        val node = (value as? DefaultMutableTreeNode)?.userObject
        if (node is FindingNode) {
            icon = when (node.finding.severity) {
                Severity.BLOCK -> UIManager.getIcon("OptionPane.errorIcon")
                Severity.WARN -> UIManager.getIcon("OptionPane.warningIcon")
                Severity.INFO -> UIManager.getIcon("OptionPane.informationIcon")
            }
        }

        return this
    }
}
