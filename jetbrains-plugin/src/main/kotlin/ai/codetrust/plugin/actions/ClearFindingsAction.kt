// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.actions

import ai.codetrust.plugin.services.FindingsManager
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType

/**
 * Action to clear all stored CodeTrust findings for the project.
 */
class ClearFindingsAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        FindingsManager.getInstance(project).clearAll()

        NotificationGroupManager.getInstance()
            .getNotificationGroup("CodeTrust Notifications")
            .createNotification("All findings cleared.", NotificationType.INFORMATION)
            .notify(project)
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }
}
