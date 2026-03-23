// Copyright (c) 2026 Said Borna. All rights reserved.
package ai.codetrust.plugin.settings

import com.intellij.openapi.options.Configurable
import javax.swing.*
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets

class CodeTrustConfigurable : Configurable {
    private var panel: JPanel? = null
    private var apiEndpointField: JTextField? = null
    private var apiKeyField: JPasswordField? = null
    private var scanOnSaveCheckbox: JCheckBox? = null
    private var inlineAnnotationsCheckbox: JCheckBox? = null
    private var severityCombo: JComboBox<String>? = null
    private var connectionTimeoutField: JSpinner? = null
    private var scanTimeoutField: JSpinner? = null

    override fun getDisplayName(): String = "CodeTrust"

    override fun createComponent(): JComponent {
        val settings = CodeTrustSettings.getInstance().state

        panel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply {
            fill = GridBagConstraints.HORIZONTAL
            insets = Insets(4, 4, 4, 4)
            anchor = GridBagConstraints.WEST
        }

        var row = 0

        // API Endpoint
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0
        panel!!.add(JLabel("API Endpoint:"), gbc)
        apiEndpointField = JTextField(settings.apiEndpoint, 40)
        gbc.gridx = 1; gbc.weightx = 1.0
        panel!!.add(apiEndpointField, gbc)

        // API Key
        row++
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0
        panel!!.add(JLabel("API Key:"), gbc)
        apiKeyField = JPasswordField(settings.apiKey, 40)
        gbc.gridx = 1; gbc.weightx = 1.0
        panel!!.add(apiKeyField, gbc)

        // Scan on save
        row++
        scanOnSaveCheckbox = JCheckBox("Scan on save", settings.scanOnSave)
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2
        panel!!.add(scanOnSaveCheckbox, gbc)
        gbc.gridwidth = 1

        // Inline annotations
        row++
        inlineAnnotationsCheckbox = JCheckBox("Show inline annotations", settings.showInlineAnnotations)
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2
        panel!!.add(inlineAnnotationsCheckbox, gbc)
        gbc.gridwidth = 1

        // Minimum severity
        row++
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0
        panel!!.add(JLabel("Minimum severity:"), gbc)
        severityCombo = JComboBox(arrayOf("INFO", "WARN", "BLOCK"))
        severityCombo!!.selectedItem = settings.minimumSeverity
        gbc.gridx = 1; gbc.weightx = 1.0
        panel!!.add(severityCombo, gbc)

        // Connection timeout
        row++
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0
        panel!!.add(JLabel("Connection timeout (ms):"), gbc)
        connectionTimeoutField = JSpinner(SpinnerNumberModel(settings.connectionTimeoutMs, 1000, 60000, 1000))
        gbc.gridx = 1; gbc.weightx = 1.0
        panel!!.add(connectionTimeoutField, gbc)

        // Scan timeout
        row++
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0
        panel!!.add(JLabel("Scan timeout (ms):"), gbc)
        scanTimeoutField = JSpinner(SpinnerNumberModel(settings.scanTimeoutMs, 1000, 120000, 1000))
        gbc.gridx = 1; gbc.weightx = 1.0
        panel!!.add(scanTimeoutField, gbc)

        // Spacer
        row++
        gbc.gridx = 0; gbc.gridy = row; gbc.weighty = 1.0; gbc.gridwidth = 2
        panel!!.add(JPanel(), gbc)

        return panel!!
    }

    override fun isModified(): Boolean {
        val settings = CodeTrustSettings.getInstance().state
        return apiEndpointField?.text != settings.apiEndpoint ||
                String(apiKeyField?.password ?: charArrayOf()) != settings.apiKey ||
                scanOnSaveCheckbox?.isSelected != settings.scanOnSave ||
                inlineAnnotationsCheckbox?.isSelected != settings.showInlineAnnotations ||
                severityCombo?.selectedItem != settings.minimumSeverity ||
                (connectionTimeoutField?.value as? Int) != settings.connectionTimeoutMs ||
                (scanTimeoutField?.value as? Int) != settings.scanTimeoutMs
    }

    override fun apply() {
        val settings = CodeTrustSettings.getInstance()
        settings.loadState(
            CodeTrustSettings.State(
                apiEndpoint = apiEndpointField?.text ?: "https://api.codetrust.ai",
                apiKey = String(apiKeyField?.password ?: charArrayOf()),
                scanOnSave = scanOnSaveCheckbox?.isSelected ?: true,
                showInlineAnnotations = inlineAnnotationsCheckbox?.isSelected ?: true,
                minimumSeverity = severityCombo?.selectedItem as? String ?: "WARN",
                connectionTimeoutMs = (connectionTimeoutField?.value as? Int) ?: 10_000,
                scanTimeoutMs = (scanTimeoutField?.value as? Int) ?: 30_000
            )
        )
    }

    override fun reset() {
        val settings = CodeTrustSettings.getInstance().state
        apiEndpointField?.text = settings.apiEndpoint
        apiKeyField?.text = settings.apiKey
        scanOnSaveCheckbox?.isSelected = settings.scanOnSave
        inlineAnnotationsCheckbox?.isSelected = settings.showInlineAnnotations
        severityCombo?.selectedItem = settings.minimumSeverity
        connectionTimeoutField?.value = settings.connectionTimeoutMs
        scanTimeoutField?.value = settings.scanTimeoutMs
    }
}
