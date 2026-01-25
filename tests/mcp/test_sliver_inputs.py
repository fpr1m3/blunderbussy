"""
Tests for sliver-server.py Pydantic input models.

Tests input validation without requiring Sliver C2 to be installed.
Focus on boundary conditions, type validation, field validators, and enums.
"""

import pytest
from pydantic import ValidationError


# =============================================================================
# ListenerStartInput Tests
# =============================================================================

class TestListenerStartInput:
    """Tests for ListenerStartInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from sliver_server import ListenerStartInput
        inp = ListenerStartInput(protocol="mtls", port=8888)
        assert inp.protocol == "mtls"
        assert inp.port == 8888
        assert inp.host == "0.0.0.0"  # default
        assert inp.domain is None
        assert inp.persistent is False

    def test_valid_full(self):
        """Test valid input with all fields."""
        from sliver_server import ListenerStartInput
        inp = ListenerStartInput(
            protocol="https",
            host="192.168.1.1",
            port=443,
            domain="cdn.example.com",
            persistent=True
        )
        assert inp.protocol == "https"
        assert inp.host == "192.168.1.1"
        assert inp.port == 443
        assert inp.domain == "cdn.example.com"
        assert inp.persistent is True

    def test_valid_protocols(self):
        """Test all valid protocol values."""
        from sliver_server import ListenerStartInput
        for proto in ["mtls", "https", "http", "dns", "wg"]:
            inp = ListenerStartInput(protocol=proto, port=8888)
            assert inp.protocol == proto

    def test_protocol_case_insensitive(self):
        """Test protocol validation is case insensitive."""
        from sliver_server import ListenerStartInput
        inp = ListenerStartInput(protocol="MTLS", port=8888)
        assert inp.protocol == "mtls"

        inp = ListenerStartInput(protocol="Https", port=8888)
        assert inp.protocol == "https"

    def test_invalid_protocol(self):
        """Test invalid protocol is rejected."""
        from sliver_server import ListenerStartInput
        with pytest.raises(ValidationError) as exc_info:
            ListenerStartInput(protocol="tcp", port=8888)
        assert "protocol" in str(exc_info.value).lower()

    def test_port_at_bounds(self):
        """Test port at valid boundaries."""
        from sliver_server import ListenerStartInput
        # Lower bound
        inp = ListenerStartInput(protocol="mtls", port=1)
        assert inp.port == 1

        # Upper bound
        inp = ListenerStartInput(protocol="mtls", port=65535)
        assert inp.port == 65535

    def test_port_below_range(self):
        """Test port below 1 is rejected."""
        from sliver_server import ListenerStartInput
        with pytest.raises(ValidationError):
            ListenerStartInput(protocol="mtls", port=0)

    def test_port_above_range(self):
        """Test port above 65535 is rejected."""
        from sliver_server import ListenerStartInput
        with pytest.raises(ValidationError):
            ListenerStartInput(protocol="mtls", port=65536)

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import ListenerStartInput
        with pytest.raises(ValidationError) as exc_info:
            ListenerStartInput(protocol="mtls", port=8888, extra="bad")
        assert "extra" in str(exc_info.value).lower()


# =============================================================================
# ListenerStopInput Tests
# =============================================================================

class TestListenerStopInput:
    """Tests for ListenerStopInput model."""

    def test_valid_input(self):
        """Test valid listener stop input."""
        from sliver_server import ListenerStopInput
        inp = ListenerStopInput(job_id=1)
        assert inp.job_id == 1

    def test_missing_job_id(self):
        """Test missing job_id raises error."""
        from sliver_server import ListenerStopInput
        with pytest.raises(ValidationError):
            ListenerStopInput()

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import ListenerStopInput
        with pytest.raises(ValidationError):
            ListenerStopInput(job_id=1, extra="bad")


# =============================================================================
# ImplantGenerateInput Tests
# =============================================================================

class TestImplantGenerateInput:
    """Tests for ImplantGenerateInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from sliver_server import ImplantGenerateInput
        inp = ImplantGenerateInput(
            name="test-implant",
            os="linux",
            arch="amd64",
            c2_urls=["mtls://10.10.14.5:8888"]
        )
        assert inp.name == "test-implant"
        assert inp.os == "linux"
        assert inp.arch == "amd64"
        assert inp.c2_urls == ["mtls://10.10.14.5:8888"]
        assert inp.format == "exe"  # default
        assert inp.beacon is True  # default
        assert inp.beacon_interval == 60  # default
        assert inp.jitter == 30  # default
        assert inp.evasion is True  # default

    def test_valid_full(self):
        """Test valid input with all fields."""
        from sliver_server import ImplantGenerateInput
        inp = ImplantGenerateInput(
            name="win-beacon",
            os="windows",
            arch="386",
            c2_urls=["https://cdn.example.com:443", "mtls://backup.example.com:8888"],
            format="shared",
            beacon=False,
            beacon_interval=120,
            jitter=50,
            evasion=False
        )
        assert inp.name == "win-beacon"
        assert inp.os == "windows"
        assert inp.arch == "386"
        assert len(inp.c2_urls) == 2
        assert inp.format == "shared"
        assert inp.beacon is False
        assert inp.beacon_interval == 120
        assert inp.jitter == 50
        assert inp.evasion is False

    def test_valid_os_values(self):
        """Test all valid OS values."""
        from sliver_server import ImplantGenerateInput
        for os_val in ["windows", "linux", "darwin"]:
            inp = ImplantGenerateInput(
                name="test",
                os=os_val,
                arch="amd64",
                c2_urls=["mtls://10.10.14.5:8888"]
            )
            assert inp.os == os_val

    def test_os_case_insensitive(self):
        """Test OS validation is case insensitive."""
        from sliver_server import ImplantGenerateInput
        inp = ImplantGenerateInput(
            name="test",
            os="WINDOWS",
            arch="amd64",
            c2_urls=["mtls://10.10.14.5:8888"]
        )
        assert inp.os == "windows"

    def test_invalid_os(self):
        """Test invalid OS is rejected."""
        from sliver_server import ImplantGenerateInput
        with pytest.raises(ValidationError) as exc_info:
            ImplantGenerateInput(
                name="test",
                os="freebsd",
                arch="amd64",
                c2_urls=["mtls://10.10.14.5:8888"]
            )
        assert "os" in str(exc_info.value).lower()

    def test_valid_arch_values(self):
        """Test all valid architecture values."""
        from sliver_server import ImplantGenerateInput
        for arch_val in ["amd64", "386", "arm64"]:
            inp = ImplantGenerateInput(
                name="test",
                os="linux",
                arch=arch_val,
                c2_urls=["mtls://10.10.14.5:8888"]
            )
            assert inp.arch == arch_val

    def test_arch_case_insensitive(self):
        """Test arch validation is case insensitive."""
        from sliver_server import ImplantGenerateInput
        inp = ImplantGenerateInput(
            name="test",
            os="linux",
            arch="AMD64",
            c2_urls=["mtls://10.10.14.5:8888"]
        )
        assert inp.arch == "amd64"

    def test_invalid_arch(self):
        """Test invalid architecture is rejected."""
        from sliver_server import ImplantGenerateInput
        with pytest.raises(ValidationError) as exc_info:
            ImplantGenerateInput(
                name="test",
                os="linux",
                arch="mips",
                c2_urls=["mtls://10.10.14.5:8888"]
            )
        assert "arch" in str(exc_info.value).lower()

    def test_valid_format_values(self):
        """Test all valid format values."""
        from sliver_server import ImplantGenerateInput
        for fmt in ["exe", "shared", "shellcode", "service"]:
            inp = ImplantGenerateInput(
                name="test",
                os="linux",
                arch="amd64",
                c2_urls=["mtls://10.10.14.5:8888"],
                format=fmt
            )
            assert inp.format == fmt

    def test_format_case_insensitive(self):
        """Test format validation is case insensitive."""
        from sliver_server import ImplantGenerateInput
        inp = ImplantGenerateInput(
            name="test",
            os="linux",
            arch="amd64",
            c2_urls=["mtls://10.10.14.5:8888"],
            format="SHELLCODE"
        )
        assert inp.format == "shellcode"

    def test_invalid_format(self):
        """Test invalid format is rejected."""
        from sliver_server import ImplantGenerateInput
        with pytest.raises(ValidationError) as exc_info:
            ImplantGenerateInput(
                name="test",
                os="linux",
                arch="amd64",
                c2_urls=["mtls://10.10.14.5:8888"],
                format="pe"
            )
        assert "format" in str(exc_info.value).lower()

    def test_empty_name_rejected(self):
        """Test empty name is rejected."""
        from sliver_server import ImplantGenerateInput
        with pytest.raises(ValidationError):
            ImplantGenerateInput(
                name="",
                os="linux",
                arch="amd64",
                c2_urls=["mtls://10.10.14.5:8888"]
            )

    def test_missing_c2_urls(self):
        """Test missing c2_urls raises error."""
        from sliver_server import ImplantGenerateInput
        with pytest.raises(ValidationError):
            ImplantGenerateInput(name="test", os="linux", arch="amd64")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import ImplantGenerateInput
        with pytest.raises(ValidationError):
            ImplantGenerateInput(
                name="test",
                os="linux",
                arch="amd64",
                c2_urls=["mtls://10.10.14.5:8888"],
                extra="bad"
            )


# =============================================================================
# ExecuteInput Tests
# =============================================================================

class TestExecuteInput:
    """Tests for ExecuteInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from sliver_server import ExecuteInput
        inp = ExecuteInput(session_id="abc123", command="whoami")
        assert inp.session_id == "abc123"
        assert inp.command == "whoami"
        assert inp.args == []  # default
        assert inp.output is True  # default

    def test_valid_full(self):
        """Test valid input with all fields."""
        from sliver_server import ExecuteInput
        inp = ExecuteInput(
            session_id="abc123",
            command="/bin/ls",
            args=["-la", "/tmp"],
            output=False
        )
        assert inp.command == "/bin/ls"
        assert inp.args == ["-la", "/tmp"]
        assert inp.output is False

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from sliver_server import ExecuteInput
        with pytest.raises(ValidationError):
            ExecuteInput(session_id="", command="whoami")

    def test_empty_command_rejected(self):
        """Test empty command is rejected."""
        from sliver_server import ExecuteInput
        with pytest.raises(ValidationError):
            ExecuteInput(session_id="abc123", command="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import ExecuteInput
        with pytest.raises(ValidationError):
            ExecuteInput(session_id="abc123", command="whoami", extra="bad")


# =============================================================================
# DownloadInput Tests
# =============================================================================

class TestDownloadInput:
    """Tests for DownloadInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from sliver_server import DownloadInput
        inp = DownloadInput(session_id="abc123", remote_path="/etc/passwd")
        assert inp.session_id == "abc123"
        assert inp.remote_path == "/etc/passwd"
        assert inp.filename is None  # optional

    def test_valid_with_filename(self):
        """Test valid input with optional filename."""
        from sliver_server import DownloadInput
        inp = DownloadInput(
            session_id="abc123",
            remote_path="/etc/passwd",
            filename="passwd_backup.txt"
        )
        assert inp.filename == "passwd_backup.txt"

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from sliver_server import DownloadInput
        with pytest.raises(ValidationError):
            DownloadInput(session_id="", remote_path="/etc/passwd")

    def test_empty_remote_path_rejected(self):
        """Test empty remote_path is rejected."""
        from sliver_server import DownloadInput
        with pytest.raises(ValidationError):
            DownloadInput(session_id="abc123", remote_path="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import DownloadInput
        with pytest.raises(ValidationError):
            DownloadInput(session_id="abc123", remote_path="/etc/passwd", extra="bad")


# =============================================================================
# UploadInput Tests
# =============================================================================

class TestUploadInput:
    """Tests for UploadInput model."""

    def test_valid_input(self):
        """Test valid upload input."""
        from sliver_server import UploadInput
        inp = UploadInput(
            session_id="abc123",
            local_path="/tmp/payload.sh",
            remote_path="/tmp/script.sh"
        )
        assert inp.session_id == "abc123"
        assert inp.local_path == "/tmp/payload.sh"
        assert inp.remote_path == "/tmp/script.sh"

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from sliver_server import UploadInput
        with pytest.raises(ValidationError):
            UploadInput(session_id="", local_path="/tmp/file", remote_path="/tmp/file")

    def test_empty_local_path_rejected(self):
        """Test empty local_path is rejected."""
        from sliver_server import UploadInput
        with pytest.raises(ValidationError):
            UploadInput(session_id="abc123", local_path="", remote_path="/tmp/file")

    def test_empty_remote_path_rejected(self):
        """Test empty remote_path is rejected."""
        from sliver_server import UploadInput
        with pytest.raises(ValidationError):
            UploadInput(session_id="abc123", local_path="/tmp/file", remote_path="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import UploadInput
        with pytest.raises(ValidationError):
            UploadInput(
                session_id="abc123",
                local_path="/tmp/file",
                remote_path="/tmp/file",
                extra="bad"
            )


# =============================================================================
# PortfwdAddInput Tests
# =============================================================================

class TestPortfwdAddInput:
    """Tests for PortfwdAddInput model."""

    def test_valid_input(self):
        """Test valid port forward input."""
        from sliver_server import PortfwdAddInput
        inp = PortfwdAddInput(
            session_id="abc123",
            local_port=8080,
            remote_host="192.168.1.100",
            remote_port=3389
        )
        assert inp.session_id == "abc123"
        assert inp.local_port == 8080
        assert inp.remote_host == "192.168.1.100"
        assert inp.remote_port == 3389

    def test_port_at_bounds(self):
        """Test ports at valid boundaries."""
        from sliver_server import PortfwdAddInput
        # Lower bounds
        inp = PortfwdAddInput(
            session_id="abc123",
            local_port=1,
            remote_host="host",
            remote_port=1
        )
        assert inp.local_port == 1
        assert inp.remote_port == 1

        # Upper bounds
        inp = PortfwdAddInput(
            session_id="abc123",
            local_port=65535,
            remote_host="host",
            remote_port=65535
        )
        assert inp.local_port == 65535
        assert inp.remote_port == 65535

    def test_local_port_below_range(self):
        """Test local_port below range is rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="abc123",
                local_port=0,
                remote_host="host",
                remote_port=80
            )

    def test_local_port_above_range(self):
        """Test local_port above range is rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="abc123",
                local_port=65536,
                remote_host="host",
                remote_port=80
            )

    def test_remote_port_below_range(self):
        """Test remote_port below range is rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="abc123",
                local_port=8080,
                remote_host="host",
                remote_port=0
            )

    def test_remote_port_above_range(self):
        """Test remote_port above range is rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="abc123",
                local_port=8080,
                remote_host="host",
                remote_port=65536
            )

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="",
                local_port=8080,
                remote_host="host",
                remote_port=80
            )

    def test_empty_remote_host_rejected(self):
        """Test empty remote_host is rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="abc123",
                local_port=8080,
                remote_host="",
                remote_port=80
            )

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import PortfwdAddInput
        with pytest.raises(ValidationError):
            PortfwdAddInput(
                session_id="abc123",
                local_port=8080,
                remote_host="host",
                remote_port=80,
                extra="bad"
            )


# =============================================================================
# SocksStartInput Tests
# =============================================================================

class TestSocksStartInput:
    """Tests for SocksStartInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from sliver_server import SocksStartInput
        inp = SocksStartInput(session_id="abc123")
        assert inp.session_id == "abc123"
        assert inp.port == 1080  # default

    def test_valid_with_port(self):
        """Test valid input with custom port."""
        from sliver_server import SocksStartInput
        inp = SocksStartInput(session_id="abc123", port=9050)
        assert inp.port == 9050

    def test_port_at_bounds(self):
        """Test port at valid boundaries."""
        from sliver_server import SocksStartInput
        # Lower bound
        inp = SocksStartInput(session_id="abc123", port=1)
        assert inp.port == 1

        # Upper bound
        inp = SocksStartInput(session_id="abc123", port=65535)
        assert inp.port == 65535

    def test_port_below_range(self):
        """Test port below range is rejected."""
        from sliver_server import SocksStartInput
        with pytest.raises(ValidationError):
            SocksStartInput(session_id="abc123", port=0)

    def test_port_above_range(self):
        """Test port above range is rejected."""
        from sliver_server import SocksStartInput
        with pytest.raises(ValidationError):
            SocksStartInput(session_id="abc123", port=65536)

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from sliver_server import SocksStartInput
        with pytest.raises(ValidationError):
            SocksStartInput(session_id="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import SocksStartInput
        with pytest.raises(ValidationError):
            SocksStartInput(session_id="abc123", port=1080, extra="bad")


# =============================================================================
# ListenersListInput Tests
# =============================================================================

class TestListenersListInput:
    """Tests for ListenersListInput model (no required params)."""

    def test_valid_empty(self):
        """Test valid empty input."""
        from sliver_server import ListenersListInput
        inp = ListenersListInput()
        # Model should be valid with no parameters

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import ListenersListInput
        with pytest.raises(ValidationError):
            ListenersListInput(extra="bad")


# =============================================================================
# SessionsListInput Tests
# =============================================================================

class TestSessionsListInput:
    """Tests for SessionsListInput model (no required params)."""

    def test_valid_empty(self):
        """Test valid empty input."""
        from sliver_server import SessionsListInput
        inp = SessionsListInput()
        # Model should be valid with no parameters

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import SessionsListInput
        with pytest.raises(ValidationError):
            SessionsListInput(extra="bad")


# =============================================================================
# BeaconsListInput Tests
# =============================================================================

class TestBeaconsListInput:
    """Tests for BeaconsListInput model (no required params)."""

    def test_valid_empty(self):
        """Test valid empty input."""
        from sliver_server import BeaconsListInput
        inp = BeaconsListInput()
        # Model should be valid with no parameters

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from sliver_server import BeaconsListInput
        with pytest.raises(ValidationError):
            BeaconsListInput(extra="bad")
