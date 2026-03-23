// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.actions

import ai.codetrust.plugin.services.CodeTrustScanService
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType

/**
 * Action to scan the currently focused file via CodeTrust.
 * Available from Tools menu and editor context menu.
 */
class ScanFileAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val file = e.getData(CommonDataKeys.VIRTUAL_FILE) ?: return

        CodeTrustScanService.getInstance(project).scanFile(file)

        NotificationGroupManager.getInstance()
            .getNotificationGroup("CodeTrust Notifications")
            .createNotification("Scanning ${file.name}...", NotificationType.INFORMATION)
            .notify(project)
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null && e.getData(CommonDataKeys.VIRTUAL_FILE) != null
    }
}
