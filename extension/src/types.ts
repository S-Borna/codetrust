/**
 * Shared TypeScript types for the CodeTrust VS Code extension.
 * Maps to the Python backend Pydantic models.
 */

/** Severity levels matching src/models/enums.py */
export type Severity = "BLOCK" | "WARN" | "INFO";

/** Verify status matching src/models/enums.py */
export type VerifyStatus =
  | "VERIFIED"
  | "NOT_FOUND"
  | "DEPRECATED"
  | "VERSION_MISMATCH"
  | "TIMEOUT"
  | "ERROR"
  | "SKIPPED";

/** Supported languages matching src/models/enums.py */
export type Language = "python" | "javascript" | "typescript" | "go" | "rust";

/** Scan type selection */
export type ScanType = "static" | "deep";

/** Severity threshold for filtering diagnostics */
export type SeverityThreshold = "INFO" | "WARN" | "BLOCK";

/** A single finding from static/AST/deep scan */
export interface Finding {
  rule_id: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  suggestion: string;
  confidence: number;
}

/** Response from POST /v1/scan/static */
export interface StaticScanResponse {
  total_findings: number;
  blocks: number;
  warnings: number;
  infos: number;
  findings: Finding[];
  verdict: string;
}

/** Response from POST /v1/scan/ast */
export interface AstScanResponse {
  total_findings: number;
  blocks: number;
  warnings: number;
  infos: number;
  findings: Finding[];
  verdict: string;
}

/** Response from POST /v1/scan/deep */
export interface DeepScanResponse {
  total_findings: number;
  blocks: number;
  warnings: number;
  infos: number;
  verdict: string;
  static_findings: Finding[];
  ast_findings: Finding[];
  import_results: PackageResult[];
  docker_results: DockerImageResult[];
  sandbox_result: SandboxResult | null;
  latency_ms: number;
}

/** Single package verification result */
export interface PackageResult {
  package: string;
  registry: string;
  status: VerifyStatus;
  severity: Severity;
  requested_version: string;
  latest_version: string;
  message: string;
  suggestion: string;
  deprecated_since: string;
  cached: boolean;
}

/** Docker image result */
export interface DockerImageResult {
  image: string;
  tag: string;
  status: VerifyStatus;
  severity: Severity;
  message: string;
  suggestion: string;
  available_tags: string[];
}

/** Sandbox execution result */
export interface SandboxResult {
  success: boolean;
  exit_code: number;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  execution_time_ms: number;
}

/** Response from POST /v1/verify/imports */
export interface VerifyImportsResponse {
  verified: number;
  failed: number;
  warnings: number;
  results: PackageResult[];
  latency_ms: number;
  cached_ratio: number;
}

/** Response from POST /v1/verify/dockerfile */
export interface VerifyDockerResponse {
  verified: number;
  failed: number;
  results: DockerImageResult[];
  latency_ms: number;
}

/** Response from GET /v1/status */
export interface HealthResponse {
  status: string;
  version: string;
}

/** Extension configuration (maps to contributes.configuration) */
export interface ExtensionConfig {
  apiUrl: string;
  apiKey: string;
  scanOnSave: boolean;
  severityThreshold: SeverityThreshold;
  enabledLanguages: Language[];
  scanType: ScanType;
  verifyImportsOnSave: boolean;
  timeout: number;
}

/** VS Code language ID to CodeTrust language mapping */
export const LANGUAGE_MAP: Record<string, Language> = {
  python: "python",
  javascript: "javascript",
  typescript: "typescript",
  typescriptreact: "typescript",
  javascriptreact: "javascript",
  go: "go",
  rust: "rust",
};

/** Dockerfile-related language IDs */
export const DOCKERFILE_LANGUAGE_IDS = new Set(["dockerfile"]);
