// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.actions

import ai.codetrust.plugin.services.CodeTrustScanService
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType

/**
 * Action to scan all supported files in the project via CodeTrust.
 */
class ScanProjectAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        CodeTrustScanService.getInstance(project).scanProject()

        NotificationGroupManager.getInstance()
            .getNotificationGroup("CodeTrust Notifications")
            .createNotification("Scanning project...", NotificationType.INFORMATION)
            .notify(project)
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }
}
