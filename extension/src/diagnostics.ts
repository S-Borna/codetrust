/**
 * Diagnostic provider for the CodeTrust VS Code extension.
 * Converts API findings into VS Code diagnostics (squiggly lines).
 */

import * as vscode from "vscode";
import type { Finding, Severity, SeverityThreshold, PackageResult, DockerImageResult } from "./types";

/** Minimum severity values for filtering. */
const SEVERITY_RANK: Record<Severity, number> = {
    INFO: 0,
    WARN: 1,
    BLOCK: 2,
};

const THRESHOLD_RANK: Record<SeverityThreshold, number> = {
    INFO: 0,
    WARN: 1,
    BLOCK: 2,
};

/** Map CodeTrust severity to VS Code diagnostic severity. */
function toVscodeSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
        case "BLOCK":
            return vscode.DiagnosticSeverity.Error;
        case "WARN":
            return vscode.DiagnosticSeverity.Warning;
        case "INFO":
            return vscode.DiagnosticSeverity.Information;
    }
}

/** Manages VS Code diagnostics from CodeTrust scan results. */
export class DiagnosticProvider {
    private readonly collection: vscode.DiagnosticCollection;

    constructor() {
        this.collection = vscode.languages.createDiagnosticCollection("codetrust");
    }

    /** Get the diagnostic collection for disposal. */
    get diagnosticCollection(): vscode.DiagnosticCollection {
        return this.collection;
    }

    /** Clear all diagnostics. */
    clear(): void {
        this.collection.clear();
    }

    /** Clear diagnostics for a specific document. */
    clearForDocument(uri: vscode.Uri): void {
        this.collection.delete(uri);
    }

    /** Set diagnostics from code scan findings. */
    setFindingsDiagnostics(
        uri: vscode.Uri,
        findings: Finding[],
        threshold: SeverityThreshold,
    ): void {
        const filtered = findings.filter(
            (f) => SEVERITY_RANK[f.severity] >= THRESHOLD_RANK[threshold],
        );

        const diagnostics = filtered.map((finding) =>
            this.findingToDiagnostic(finding),
        );

        this.collection.set(uri, diagnostics);
    }

    /** Append import verification results as diagnostics. */
    appendImportDiagnostics(
        uri: vscode.Uri,
        document: vscode.TextDocument,
        results: PackageResult[],
        threshold: SeverityThreshold,
    ): void {
        const existing = [...(this.collection.get(uri) ?? [])];
        const newDiags: vscode.Diagnostic[] = [];

        for (const result of results) {
            if (SEVERITY_RANK[result.severity] < THRESHOLD_RANK[threshold]) {
                continue;
            }

            const line = findImportLine(document, result.package);
            const range = line >= 0
                ? document.lineAt(line).range
                : new vscode.Range(0, 0, 0, 0);

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${result.status}] ${result.package}: ${result.message}`,
                toVscodeSeverity(result.severity),
            );
            diagnostic.source = "CodeTrust";
            diagnostic.code = `import-${result.status.toLowerCase()}`;
            if (result.suggestion) {
                diagnostic.message += ` → ${result.suggestion}`;
            }
            newDiags.push(diagnostic);
        }

        this.collection.set(uri, [...existing, ...newDiags]);
    }

    /** Append Docker verification results as diagnostics. */
    appendDockerDiagnostics(
        uri: vscode.Uri,
        document: vscode.TextDocument,
        results: DockerImageResult[],
        threshold: SeverityThreshold,
    ): void {
        const existing = [...(this.collection.get(uri) ?? [])];
        const newDiags: vscode.Diagnostic[] = [];

        for (const result of results) {
            if (SEVERITY_RANK[result.severity] < THRESHOLD_RANK[threshold]) {
                continue;
            }

            const line = findDockerImageLine(document, result.image, result.tag);
            const range = line >= 0
                ? document.lineAt(line).range
                : new vscode.Range(0, 0, 0, 0);

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${result.status}] ${result.image}:${result.tag}: ${result.message}`,
                toVscodeSeverity(result.severity),
            );
            diagnostic.source = "CodeTrust";
            diagnostic.code = `docker-${result.status.toLowerCase()}`;
            if (result.suggestion) {
                diagnostic.message += ` → ${result.suggestion}`;
            }
            newDiags.push(diagnostic);
        }

        this.collection.set(uri, [...existing, ...newDiags]);
    }

    /** Convert a Finding into a VS Code Diagnostic. */
    private findingToDiagnostic(finding: Finding): vscode.Diagnostic {
        const lineNum = Math.max(0, finding.line - 1);
        const range = new vscode.Range(lineNum, 0, lineNum, Number.MAX_SAFE_INTEGER);

        const message = finding.suggestion
            ? `${finding.message} → ${finding.suggestion}`
            : finding.message;

        const diagnostic = new vscode.Diagnostic(
            range,
            message,
            toVscodeSeverity(finding.severity),
        );

        diagnostic.source = "CodeTrust";
        diagnostic.code = finding.rule_id;
        return diagnostic;
    }

    /** Dispose the diagnostic collection. */
    dispose(): void {
        this.collection.dispose();
    }
}

/** Find the line number where a package is imported. */
function findImportLine(document: vscode.TextDocument, packageName: string): number {
    const text = document.getText();
    const lines = text.split("\n");

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (
            line.includes(`import ${packageName}`) ||
            line.includes(`from ${packageName}`) ||
            line.includes(`require("${packageName}")`) ||
            line.includes(`require('${packageName}')`) ||
            line.includes(`"${packageName}"`) ||
            line.includes(`'${packageName}'`)
        ) {
            return i;
        }
    }

    return -1;
}

/** Find the line number where a Docker image is referenced. */
function findDockerImageLine(
    document: vscode.TextDocument,
    image: string,
    tag: string,
): number {
    const text = document.getText();
    const lines = text.split("\n");
    const needle = `${image}:${tag}`;
    const needleNoTag = `FROM ${image}`;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.includes(needle) || line.includes(needleNoTag)) {
            return i;
        }
    }

    return -1;
}
