"""Tests for the configuration file scanner (QP-012)."""

from __future__ import annotations

from pathlib import Path

from qproof.scanner.config import scan_configs

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONFIGS_DIR = Path(__file__).parent / "fixtures" / "sample_configs"


def _find_by_algo(findings: list, algo_id: str) -> list:
    """Filter findings by algorithm_id."""
    return [f for f in findings if f.algorithm_id == algo_id]


# ---------------------------------------------------------------------------
# TLS detection
# ---------------------------------------------------------------------------


class TestConfigScanner:
    """Tests for scan_configs against the sample_configs fixture."""

    def test_scan_finds_tls10_in_nginx(self) -> None:
        """TLS 1.0 detected in nginx.conf ssl_protocols directive."""
        findings = scan_configs(CONFIGS_DIR)
        tls10 = _find_by_algo(findings, "TLS-1.0")
        nginx_tls10 = [
            f for f in tls10
            if f.file_path.name == "nginx.conf"
        ]
        assert len(nginx_tls10) >= 1
        assert any("TLSv1" in f.matched_text for f in nginx_tls10)

    def test_scan_finds_tls11_in_nginx(self) -> None:
        """TLS 1.1 detected in nginx.conf ssl_protocols directive."""
        findings = scan_configs(CONFIGS_DIR)
        tls11 = _find_by_algo(findings, "TLS-1.1")
        nginx_tls11 = [
            f for f in tls11
            if f.file_path.name == "nginx.conf"
        ]
        assert len(nginx_tls11) >= 1

    def test_scan_finds_ssh_rsa_key(self) -> None:
        """SSH-RSA detected from id_rsa.pub file."""
        findings = scan_configs(CONFIGS_DIR)
        ssh_rsa = _find_by_algo(findings, "SSH-RSA")
        pub_findings = [
            f for f in ssh_rsa
            if f.file_path.name == "id_rsa.pub"
        ]
        assert len(pub_findings) >= 1
        assert pub_findings[0].context == "SSH RSA public key"

    def test_scan_finds_ed25519_ssh_key(self) -> None:
        """Ed25519 detected from id_ed25519.pub file."""
        findings = scan_configs(CONFIGS_DIR)
        ed25519 = _find_by_algo(findings, "Ed25519")
        pub_findings = [
            f for f in ed25519
            if f.file_path.name == "id_ed25519.pub"
        ]
        assert len(pub_findings) >= 1
        assert pub_findings[0].context == "SSH Ed25519 public key"

    def test_scan_finds_3des_in_sshd(self) -> None:
        """3DES cipher detected in sshd_config."""
        findings = scan_configs(CONFIGS_DIR)
        triple_des = _find_by_algo(findings, "3DES")
        sshd_findings = [
            f for f in triple_des
            if f.file_path.name == "sshd_config"
        ]
        assert len(sshd_findings) >= 1

    def test_scan_finds_dh_in_sshd(self) -> None:
        """Diffie-Hellman key exchange detected in sshd_config."""
        findings = scan_configs(CONFIGS_DIR)
        dh = _find_by_algo(findings, "DH")
        sshd_findings = [
            f for f in dh
            if f.file_path.name == "sshd_config"
        ]
        assert len(sshd_findings) >= 1

    def test_scan_finds_hmac_sha1_in_sshd(self) -> None:
        """HMAC-SHA1 MAC detected in sshd_config."""
        findings = scan_configs(CONFIGS_DIR)
        hmac_sha1 = _find_by_algo(findings, "HMAC-SHA1")
        sshd_findings = [
            f for f in hmac_sha1
            if f.file_path.name == "sshd_config"
        ]
        assert len(sshd_findings) >= 1

    def test_scan_finds_jwt_rs256(self) -> None:
        """JWT-RS256 detected from jwt_config.json or .env file."""
        findings = scan_configs(CONFIGS_DIR)
        jwt_rs256 = _find_by_algo(findings, "JWT-RS256")
        assert len(jwt_rs256) >= 1
        sources = {f.file_path.name for f in jwt_rs256}
        # Should be found in at least one of these files
        assert sources & {"jwt_config.json", ".env"}

    def test_scan_finds_sha1_in_openssl(self) -> None:
        """SHA-1 default_md detected in openssl.cnf."""
        findings = scan_configs(CONFIGS_DIR)
        sha1 = _find_by_algo(findings, "SHA-1")
        openssl_findings = [
            f for f in sha1
            if f.file_path.name == "openssl.cnf"
        ]
        assert len(openssl_findings) >= 1

    def test_scan_finds_rsa_pem_header(self) -> None:
        """RSA private key PEM header detected in server.pem."""
        findings = scan_configs(CONFIGS_DIR)
        rsa = _find_by_algo(findings, "RSA")
        pem_findings = [
            f for f in rsa
            if f.file_path.name == "server.pem"
        ]
        assert len(pem_findings) >= 1
        assert pem_findings[0].context == "RSA private key in PEM format"

    def test_findings_have_source_config(self) -> None:
        """All findings from the config scanner have source='config'."""
        findings = scan_configs(CONFIGS_DIR)
        assert len(findings) > 0
        for f in findings:
            assert f.source == "config", (
                f"Finding for {f.algorithm_id} in {f.file_path.name} "
                f"has source='{f.source}' instead of 'config'"
            )

    def test_scan_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory returns empty list."""
        findings = scan_configs(tmp_path)
        assert findings == []

    def test_scan_nonexistent_dir(self) -> None:
        """Non-existent directory returns empty list."""
        findings = scan_configs(Path("/tmp/qproof_nonexistent_config_dir"))
        assert findings == []

    def test_no_duplicate_per_line(self) -> None:
        """No (file, line, algorithm_id) duplicates in output."""
        findings = scan_configs(CONFIGS_DIR)
        keys = [
            (str(f.file_path), f.line_number, f.algorithm_id)
            for f in findings
        ]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"
