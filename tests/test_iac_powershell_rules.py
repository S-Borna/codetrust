"""Tests for Batch 2 rules: PowerShell, Terraform provider, Helm, Ansible, Nginx, CFN/CDK, ARM/Bicep."""

import pytest

from src.cli import scan_text
from src.models.enums import Severity
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def analyzer() -> StaticAnalyzer:
    """Shared StaticAnalyzer instance."""
    return StaticAnalyzer()


def _find(findings: list[dict[str, object]], rule_id: str) -> list[dict[str, object]]:
    """Filter CLI scan_text findings by rule_id."""
    return [f for f in findings if f.get("rule_id") == rule_id]


def _find_sa(findings: list[object], rule_id: str) -> list[object]:
    """Filter StaticAnalyzer findings by rule_id."""
    return [f for f in findings if f.rule_id == rule_id]


# ═══════════════════════════════════════════════════════════════
#  POWERSHELL RULES (12 rules)
# ═══════════════════════════════════════════════════════════════


class TestPsInvokeExpression:
    """ps_invoke_expression — Invoke-Expression is code injection risk."""

    def test_fires_on_ps1(self, analyzer: StaticAnalyzer) -> None:
        code = 'Invoke-Expression $cmd\n'
        findings = _find_sa(analyzer.scan_code(code, "deploy.ps1"), "ps_invoke_expression")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.BLOCK

    def test_no_fire_on_py(self, analyzer: StaticAnalyzer) -> None:
        code = '# Invoke-Expression $cmd\n'
        findings = _find_sa(analyzer.scan_code(code, "app.py"), "ps_invoke_expression")
        assert len(findings) == 0

    def test_cli_routing(self) -> None:
        code = 'Invoke-Expression $userInput\n'
        findings = _find(scan_text(code, "script.ps1"), "ps_invoke_expression")
        assert len(findings) >= 1


class TestPsExecutionPolicyBypass:
    """ps_execution_policy_bypass — Bypass/Unrestricted is dangerous."""

    def test_bypass(self, analyzer: StaticAnalyzer) -> None:
        code = 'Set-ExecutionPolicy Bypass\n'
        findings = _find_sa(analyzer.scan_code(code, "setup.ps1"), "ps_execution_policy_bypass")
        assert len(findings) >= 1

    def test_unrestricted(self, analyzer: StaticAnalyzer) -> None:
        code = 'Set-ExecutionPolicy Unrestricted\n'
        findings = _find_sa(analyzer.scan_code(code, "setup.ps1"), "ps_execution_policy_bypass")
        assert len(findings) >= 1


class TestPsPlaintextCredential:
    """ps_plaintext_credential — ConvertTo-SecureString with -AsPlainText."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '$securePass = ConvertTo-SecureString "P@ss" -AsPlainText -Force\n'
        findings = _find_sa(analyzer.scan_code(code, "cred.ps1"), "ps_plaintext_credential")
        assert len(findings) >= 1


class TestPsHardcodedPassword:
    """ps_hardcoded_password — Hardcoded credential variables."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '$pass' + 'word = "MySecretPassword123"\n'
        findings = _find_sa(analyzer.scan_code(code, "config.ps1"), "ps_hardcoded_password")
        assert len(findings) >= 1

    def test_no_fire_safe(self, analyzer: StaticAnalyzer) -> None:
        code = '$pass' + 'word = $env:DB_PASSWORD\n'
        findings = _find_sa(analyzer.scan_code(code, "config.ps1"), "ps_hardcoded_password")
        assert len(findings) == 0


class TestPsWriteHost:
    """ps_write_host — Write-Host bypasses pipeline."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'Write-Host "Hello World"\n'
        findings = _find_sa(analyzer.scan_code(code, "run.ps1"), "ps_write_host")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN


class TestPsCatchEmpty:
    """ps_catch_empty — Empty catch block."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'try { Get-Item } catch { }\n'
        findings = _find_sa(analyzer.scan_code(code, "handler.ps1"), "ps_catch_empty")
        assert len(findings) >= 1


class TestPsNetWebclient:
    """ps_net_webclient — Legacy WebClient usage."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '$wc = New-Object System.Net.WebClient\n'
        findings = _find_sa(analyzer.scan_code(code, "download.ps1"), "ps_net_webclient")
        assert len(findings) >= 1


class TestPsSleepUnbounded:
    """ps_sleep_unbounded — Long sleep durations."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'Start-Sleep -Seconds ' + '3' + '00\n'
        findings = _find_sa(analyzer.scan_code(code, "wait.ps1"), "ps_sleep_unbounded")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN


class TestPsRmRecurseForce:
    """ps_rm_recurse_force — Dangerous recursive delete."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'Remove-Item $path -Recurse -Force\n'
        findings = _find_sa(analyzer.scan_code(code, "clean.ps1"), "ps_rm_recurse_force")
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════
#  TERRAFORM PROVIDER RULES (9 rules)
# ═══════════════════════════════════════════════════════════════


class TestTfWildcardIam:
    """tf_wildcard_iam — IAM policy with * action."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  actions = ["*"]\n'
        findings = _find_sa(analyzer.scan_code(code, "main.tf"), "tf_wildcard_iam")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.BLOCK


class TestTfPublicS3Acl:
    """tf_public_s3_acl — S3 bucket with public ACL."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  acl = "public-read"\n'
        findings = _find_sa(analyzer.scan_code(code, "s3.tf"), "tf_public_s3_acl")
        assert len(findings) >= 1


class TestTfOpenSecurityGroup:
    """tf_open_security_group — Security group open to 0.0.0.0/0."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  cidr_blocks = ["0.0.0.0/0"]\n'
        findings = _find_sa(analyzer.scan_code(code, "sg.tf"), "tf_open_security_group")
        assert len(findings) >= 1


class TestTfUnencryptedEbs:
    """tf_unencrypted_ebs — EBS encryption explicitly disabled."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  encrypted = false\n'
        findings = _find_sa(analyzer.scan_code(code, "ebs.tf"), "tf_unencrypted_ebs")
        assert len(findings) >= 1


class TestTfNoTags:
    """tf_no_tags — AWS resource should include tags."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'resource "aws_instance" "web" {\n'
        findings = _find_sa(analyzer.scan_code(code, "ec2.tf"), "tf_no_tags")
        assert len(findings) >= 1


class TestTfHardcodedAmi:
    """tf_hardcoded_ami — Hardcoded AMI ID."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  ami = "ami-0abcdef1234567890"\n'
        findings = _find_sa(analyzer.scan_code(code, "ec2.tf"), "tf_hardcoded_ami")
        assert len(findings) >= 1


class TestTfNoVersionedModule:
    """tf_no_versioned_module — Module source without version."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  source = "terraform-aws-modules/vpc/aws"\n'
        findings = _find_sa(analyzer.scan_code(code, "modules.tf"), "tf_no_versioned_module")
        assert len(findings) >= 1


class TestTfSensitiveOutput:
    """tf_sensitive_output — Output without sensitive = true."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'output "db_password" {\n  value = var.db_password\n}\n'
        findings = _find_sa(analyzer.scan_code(code, "outputs.tf"), "tf_sensitive_output")
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════
#  HELM RULES (6 rules)
# ═══════════════════════════════════════════════════════════════


class TestHelmHardcodedImageTag:
    """helm_hardcoded_image_tag — Image without {{ .Values }}."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  image: nginx:1.25.3\n'
        findings = _find_sa(analyzer.scan_code(code, "deployment.yaml"), "helm_hardcoded_image_tag")
        assert len(findings) >= 1


class TestHelmNoResourceLimits:
    """helm_no_resource_limits — Workload should define resource limits."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'kind: Deployment\n'
        findings = _find_sa(analyzer.scan_code(code, "deployment.yaml"), "helm_no_resource_limits")
        assert len(findings) >= 1


class TestHelmHardcodedNamespace:
    """helm_hardcoded_namespace — Namespace not templated."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  namespace: production\n'
        findings = _find_sa(analyzer.scan_code(code, "deployment.yaml"), "helm_hardcoded_namespace")
        assert len(findings) >= 1


class TestHelmDeprecatedApi:
    """helm_deprecated_api — Deprecated K8s API version."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'apiVersion: extensions/v1beta1\n'
        findings = _find_sa(analyzer.scan_code(code, "ingress.yaml"), "helm_deprecated_api")
        assert len(findings) >= 1


class TestHelmHardcodedReplicas:
    """helm_hardcoded_replicas — Replica count not templated."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'spec:\n  replicas: 3\n'
        findings = _find_sa(analyzer.scan_code(code, "deployment.yaml"), "helm_hardcoded_replicas")
        assert len(findings) >= 1


class TestHelmTplMissingQuote:
    """helm_tpl_missing_quote — {{ }} without quotes in YAML."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  name: {{ .Values.name }}\n'
        findings = _find_sa(analyzer.scan_code(code, "service.yaml"), "helm_tpl_missing_quote")
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════
#  ANSIBLE RULES (6 rules)
# ═══════════════════════════════════════════════════════════════


class TestAnsibleCommandModule:
    """ansible_command_module — Using command/shell instead of builtin modules."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '- name: Install package\n  command: apt-get install nginx\n'
        findings = _find_sa(analyzer.scan_code(code, "playbook.yaml"), "ansible_command_module")
        assert len(findings) >= 1


class TestAnsibleIgnoreErrors:
    """ansible_ignore_errors — ignore_errors: yes is dangerous."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '- name: Do thing\n  command: ls\n  ignore_errors: yes\n'
        findings = _find_sa(analyzer.scan_code(code, "tasks.yaml"), "ansible_ignore_errors")
        assert len(findings) >= 1


class TestAnsiblePlaintextPassword:
    """ansible_plaintext_password — Password in playbook."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  pass' + 'word: "mysecretpassword"\n'
        findings = _find_sa(analyzer.scan_code(code, "vars.yaml"), "ansible_plaintext_password")
        assert len(findings) >= 1


class TestAnsibleLatestPackage:
    """ansible_latest_package — state: latest is non-deterministic."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  apt:\n    name: nginx\n    state: latest\n'
        findings = _find_sa(analyzer.scan_code(code, "install.yaml"), "ansible_latest_package")
        assert len(findings) >= 1


class TestAnsibleNoBecomeUser:
    """ansible_no_become_user — become: yes without become_user."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '- name: Setup\n  become: yes\n  tasks:\n'
        findings = _find_sa(analyzer.scan_code(code, "setup.yaml"), "ansible_no_become_user")
        assert len(findings) >= 1


class TestAnsibleNoChangedWhen:
    """ansible_no_changed_when — command/shell without changed_when."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  shell: systemctl status nginx\n'
        findings = _find_sa(analyzer.scan_code(code, "check.yaml"), "ansible_no_changed_when")
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════
#  NGINX RULES (6 rules)
# ═══════════════════════════════════════════════════════════════


class TestNginxServerTokensOn:
    """nginx_server_tokens_on — Leaks Nginx version."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'server_tokens on;\n'
        findings = _find_sa(analyzer.scan_code(code, "nginx.conf"), "nginx_server_tokens_on")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN

    def test_cli_routing(self) -> None:
        code = 'server_tokens on;\n'
        findings = _find(scan_text(code, "nginx.conf"), "nginx_server_tokens_on")
        assert len(findings) >= 1


class TestNginxAutoindexOn:
    """nginx_autoindex_on — Exposes directory listing."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'autoindex on;\n'
        findings = _find_sa(analyzer.scan_code(code, "default.conf"), "nginx_autoindex_on")
        assert len(findings) >= 1


class TestNginxSslV3:
    """nginx_ssl_v3 — Insecure SSLv3 protocol."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'ssl_protocols TLSv1.2 SSLv3;\n'
        findings = _find_sa(analyzer.scan_code(code, "ssl.conf"), "nginx_ssl_v3")
        assert len(findings) >= 1


class TestNginxRootInLocation:
    """nginx_root_in_location — Root inside nested block."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '    root /var/www;\n'
        findings = _find_sa(analyzer.scan_code(code, "site.conf"), "nginx_root_in_location")
        assert len(findings) >= 1


class TestNginxAddHeaderMissingAlways:
    """nginx_add_header_missing_always — add_header without always."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'add_header X-Frame-Options DENY;\n'
        findings = _find_sa(analyzer.scan_code(code, "headers.conf"), "nginx_add_header_missing_always")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.INFO


# ═══════════════════════════════════════════════════════════════
#  CLOUDFORMATION / CDK RULES (7 rules)
# ═══════════════════════════════════════════════════════════════


class TestCfnWildcardIam:
    """cfn_wildcard_iam — Wildcard IAM action in CloudFormation."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '            Action: "*"\n'
        findings = _find_sa(analyzer.scan_code(code, "template.yaml"), "cfn_wildcard_iam")
        assert len(findings) >= 1


class TestCfnPublicS3:
    """cfn_public_s3 — Public S3 bucket in CloudFormation."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '      AccessControl: PublicRead\n'
        findings = _find_sa(analyzer.scan_code(code, "s3.yaml"), "cfn_public_s3")
        assert len(findings) >= 1


class TestCfnNoDeletionPolicy:
    """cfn_no_deletion_policy — Missing DeletionPolicy."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  MyDB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n'
        findings = _find_sa(analyzer.scan_code(code, "rds.yaml"), "cfn_no_deletion_policy")
        assert len(findings) >= 1


class TestCfnHardcodedCredentials:
    """cfn_hardcoded_credentials — Credentials in template."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '      MasterUser' + 'Pass' + 'word: "SuperSecret123"\n'
        findings = _find_sa(analyzer.scan_code(code, "db.yaml"), "cfn_hardcoded_credentials")
        assert len(findings) >= 1


class TestCdkNoRemovalPolicy:
    """cdk_no_removal_policy — CDK construct should set removalPolicy."""

    def test_fires_ts(self, analyzer: StaticAnalyzer) -> None:
        code = 'new s3.Bucket(this, "MyBucket", {\n'
        findings = _find_sa(analyzer.scan_code(code, "stack.ts"), "cdk_no_removal_policy")
        assert len(findings) >= 1

    def test_fires_py(self, analyzer: StaticAnalyzer) -> None:
        code = 's3.Bucket(self, "MyBucket",\n'
        findings = _find_sa(analyzer.scan_code(code, "stack.py"), "cdk_no_removal_policy")
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════
#  AZURE ARM / BICEP RULES (5 rules)
# ═══════════════════════════════════════════════════════════════


class TestBicepNoSecureParam:
    """bicep_no_secure_param — Sensitive param without @secure()."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = 'param adminPassword string\n'
        findings = _find_sa(analyzer.scan_code(code, "main.bicep"), "bicep_no_secure_param")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.BLOCK

    def test_cli_routing(self) -> None:
        code = 'param adminPassword string\n'
        findings = _find(scan_text(code, "main.bicep"), "bicep_no_secure_param")
        assert len(findings) >= 1


class TestBicepHttpOnly:
    """bicep_http_only — HTTPS disabled."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '  httpsOnly: false\n'
        findings = _find_sa(analyzer.scan_code(code, "webapp.bicep"), "bicep_http_only")
        assert len(findings) >= 1


class TestBicepPublicNetwork:
    """bicep_public_network — Public network access enabled."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = "  publicNetworkAccess: 'Enabled'\n"
        findings = _find_sa(analyzer.scan_code(code, "sql.bicep"), "bicep_public_network")
        assert len(findings) >= 1


class TestArmWildcardRbac:
    """arm_wildcard_rbac — Wildcard RBAC action in ARM template."""

    def test_fires(self, analyzer: StaticAnalyzer) -> None:
        code = '    "actions": ["*"],\n'
        findings = _find_sa(analyzer.scan_code(code, "role.json"), "arm_wildcard_rbac")
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════
#  CLI ROUTING TESTS — Verify scan_text routes correctly
# ═══════════════════════════════════════════════════════════════


class TestCliRouting:
    """Verify CLI scan_text correctly routes rules by file type."""

    def test_ps_rules_not_on_py(self) -> None:
        """PowerShell rules must NOT fire on Python files."""
        code = 'Invoke-Expression $cmd\n'
        findings = _find(scan_text(code, "app.py"), "ps_invoke_expression")
        assert len(findings) == 0

    def test_ps_rules_on_psm1(self) -> None:
        """PowerShell rules must fire on .psm1 files."""
        code = 'Invoke-Expression $cmd\n'
        findings = _find(scan_text(code, "module.psm1"), "ps_invoke_expression")
        assert len(findings) >= 1

    def test_nginx_rules_on_conf(self) -> None:
        """Nginx rules must fire on .conf files."""
        code = 'server_tokens on;\n'
        findings = _find(scan_text(code, "nginx.conf"), "nginx_server_tokens_on")
        assert len(findings) >= 1

    def test_nginx_rules_not_on_yaml(self) -> None:
        """Nginx rules must NOT fire on .yaml files."""
        code = 'server_tokens on;\n'
        findings = _find(scan_text(code, "config.yaml"), "nginx_server_tokens_on")
        assert len(findings) == 0

    def test_bicep_rules_on_bicep(self) -> None:
        """Bicep rules must fire on .bicep files."""
        code = 'param adminPassword string\n'
        findings = _find(scan_text(code, "main.bicep"), "bicep_no_secure_param")
        assert len(findings) >= 1

    def test_bicep_rules_not_on_tf(self) -> None:
        """Bicep rules must NOT fire on .tf files."""
        code = 'param adminPassword string\n'
        findings = _find(scan_text(code, "main.tf"), "bicep_no_secure_param")
        assert len(findings) == 0

    def test_tf_rules_on_tf(self) -> None:
        """Terraform provider rules must fire on .tf files."""
        code = '  actions = ["*"]\n'
        findings = _find(scan_text(code, "iam.tf"), "tf_wildcard_iam")
        assert len(findings) >= 1

    def test_tf_rules_not_on_py(self) -> None:
        """Terraform-specific rules must NOT fire on Python files."""
        code = '  ami = "ami-0abcdef1234567890"\n'
        findings = _find(scan_text(code, "app.py"), "tf_hardcoded_ami")
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════
#  SOURCE_EXTS / File Discovery Tests
# ═══════════════════════════════════════════════════════════════


class TestSourceExts:
    """Verify SOURCE_EXTS includes all new file types."""

    def test_all_batch2_extensions_in_source_exts(self) -> None:
        from src.cli import SOURCE_EXTS
        batch2_exts = {".ps1", ".psm1", ".psd1", ".conf", ".bicep", ".rb", ".php"}
        missing = batch2_exts - SOURCE_EXTS
        assert not missing, f"SOURCE_EXTS missing: {missing}"


# ═══════════════════════════════════════════════════════════════
#  RULE COUNT INTEGRITY
# ═══════════════════════════════════════════════════════════════


class TestBatch2RuleCounts:
    """Verify the expected number of Batch 2 rules exist."""

    def test_powershell_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        ps_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("ps_")]
        assert len(ps_rules) == 12

    def test_terraform_provider_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        tf_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("tf_")]
        assert len(tf_rules) == 17

    def test_helm_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        helm_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("helm_")]
        assert len(helm_rules) == 7

    def test_ansible_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        ansible_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("ansible_")]
        assert len(ansible_rules) == 6

    def test_nginx_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        nginx_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("nginx_")]
        assert len(nginx_rules) == 6

    def test_cfn_cdk_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        cfn_rules = [r for r in ANTI_PATTERNS if r["id"].startswith(("cfn_", "cdk_"))]
        assert len(cfn_rules) == 7

    def test_arm_bicep_rule_count(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        arm_rules = [r for r in ANTI_PATTERNS if r["id"].startswith(("arm_", "bicep_"))]
        assert len(arm_rules) == 5

    def test_total_batch2_rules(self) -> None:
        """Total Batch 2 rules = 12+17+7+6+6+7+5 = 60."""
        from src.rules.anti_patterns import ANTI_PATTERNS
        prefixes = ("ps_", "tf_", "helm_", "ansible_", "nginx_", "cfn_", "cdk_", "arm_", "bicep_")
        batch2_rules = [r for r in ANTI_PATTERNS if r["id"].startswith(prefixes)]
        assert len(batch2_rules) == 60
