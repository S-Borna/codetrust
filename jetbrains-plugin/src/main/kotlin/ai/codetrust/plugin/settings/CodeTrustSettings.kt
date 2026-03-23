// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

@State(
    name = "CodeTrustSettings",
    storages = [Storage("codetrust.xml")]
)
class CodeTrustSettings : PersistentStateComponent<CodeTrustSettings.State> {
    data class State(
        var apiEndpoint: String = "https://api.codetrust.ai",
        var apiKey: String = "",
        var scanOnSave: Boolean = true,
        var showInlineAnnotations: Boolean = true,
        var minimumSeverity: String = "WARN",
        var enabledLanguages: MutableSet<String> = mutableSetOf(
            "python", "javascript", "typescript", "go", "rust",
            "java", "kotlin", "csharp", "cpp", "c", "ruby",
            "php", "swift", "sql", "dockerfile", "yaml", "terraform"
        ),
        var connectionTimeoutMs: Int = 10_000,
        var scanTimeoutMs: Int = 30_000
    )

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    companion object {
        fun getInstance(): CodeTrustSettings {
            return ApplicationManager.getApplication()
                .getService(CodeTrustSettings::class.java)
        }
    }
}
