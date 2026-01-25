"""
Tests for pwncat-server.py Pydantic input models.

Tests input validation without requiring pwncat-cs to be installed.
Focus on boundary conditions, type validation, and extra field rejection.
"""

import pytest
from pydantic import ValidationError


# =============================================================================
# ListenInput Tests
# =============================================================================

class TestListenInput:
    """Tests for ListenInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input with just port."""
        from pwncat_server import ListenInput
        inp = ListenInput(port=4444)
        assert inp.port == 4444
        assert inp.host == "0.0.0.0"
        assert inp.timeout is None

    def test_valid_full(self):
        """Test valid input with all fields."""
        from pwncat_server import ListenInput
        inp = ListenInput(port=8080, host="192.168.1.1", timeout=60.0)
        assert inp.port == 8080
        assert inp.host == "192.168.1.1"
        assert inp.timeout == 60.0

    def test_port_at_lower_bound(self):
        """Test port at minimum value (1)."""
        from pwncat_server import ListenInput
        inp = ListenInput(port=1)
        assert inp.port == 1

    def test_port_at_upper_bound(self):
        """Test port at maximum value (65535)."""
        from pwncat_server import ListenInput
        inp = ListenInput(port=65535)
        assert inp.port == 65535

    def test_port_below_range(self):
        """Test port value of 0 is rejected."""
        from pwncat_server import ListenInput
        with pytest.raises(ValidationError) as exc_info:
            ListenInput(port=0)
        assert "greater than or equal to 1" in str(exc_info.value).lower()

    def test_port_above_range(self):
        """Test port value above 65535 is rejected."""
        from pwncat_server import ListenInput
        with pytest.raises(ValidationError) as exc_info:
            ListenInput(port=70000)
        assert "less than or equal to 65535" in str(exc_info.value).lower()

    def test_port_negative(self):
        """Test negative port is rejected."""
        from pwncat_server import ListenInput
        with pytest.raises(ValidationError):
            ListenInput(port=-1)

    def test_timeout_at_lower_bound(self):
        """Test timeout at minimum value (1)."""
        from pwncat_server import ListenInput
        inp = ListenInput(port=4444, timeout=1)
        assert inp.timeout == 1

    def test_timeout_below_minimum(self):
        """Test timeout below minimum is rejected."""
        from pwncat_server import ListenInput
        with pytest.raises(ValidationError) as exc_info:
            ListenInput(port=4444, timeout=0.5)
        assert "greater than or equal to 1" in str(exc_info.value).lower()

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import ListenInput
        with pytest.raises(ValidationError) as exc_info:
            ListenInput(port=4444, unknown_field="bad")
        assert "extra" in str(exc_info.value).lower()

    def test_missing_required_port(self):
        """Test missing required port field."""
        from pwncat_server import ListenInput
        with pytest.raises(ValidationError) as exc_info:
            ListenInput()
        assert "port" in str(exc_info.value).lower()


# =============================================================================
# ConnectInput Tests
# =============================================================================

class TestConnectInput:
    """Tests for ConnectInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from pwncat_server import ConnectInput
        inp = ConnectInput(host="10.10.10.5", port=4444)
        assert inp.host == "10.10.10.5"
        assert inp.port == 4444
        assert inp.platform == "linux"  # default

    def test_valid_with_platform_linux(self):
        """Test valid input with linux platform."""
        from pwncat_server import ConnectInput
        inp = ConnectInput(host="10.10.10.5", port=4444, platform="linux")
        assert inp.platform == "linux"

    def test_valid_with_platform_windows(self):
        """Test valid input with windows platform."""
        from pwncat_server import ConnectInput
        inp = ConnectInput(host="10.10.10.5", port=4444, platform="windows")
        assert inp.platform == "windows"

    def test_platform_case_insensitive(self):
        """Test platform validation is case insensitive."""
        from pwncat_server import ConnectInput
        inp = ConnectInput(host="10.10.10.5", port=4444, platform="LINUX")
        assert inp.platform == "linux"

    def test_invalid_platform(self):
        """Test invalid platform is rejected."""
        from pwncat_server import ConnectInput
        with pytest.raises(ValidationError) as exc_info:
            ConnectInput(host="10.10.10.5", port=4444, platform="macos")
        assert "platform" in str(exc_info.value).lower()

    def test_port_below_range(self):
        """Test port below valid range."""
        from pwncat_server import ConnectInput
        with pytest.raises(ValidationError):
            ConnectInput(host="10.10.10.5", port=0)

    def test_port_above_range(self):
        """Test port above valid range."""
        from pwncat_server import ConnectInput
        with pytest.raises(ValidationError):
            ConnectInput(host="10.10.10.5", port=65536)

    def test_empty_host_rejected(self):
        """Test empty host string is rejected."""
        from pwncat_server import ConnectInput
        with pytest.raises(ValidationError) as exc_info:
            ConnectInput(host="", port=4444)
        assert "min_length" in str(exc_info.value).lower() or "at least" in str(exc_info.value).lower()

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import ConnectInput
        with pytest.raises(ValidationError):
            ConnectInput(host="10.10.10.5", port=4444, extra="bad")


# =============================================================================
# CommandInput Tests
# =============================================================================

class TestCommandInput:
    """Tests for CommandInput model."""

    def test_valid_input(self):
        """Test valid command input."""
        from pwncat_server import CommandInput
        inp = CommandInput(session_id="a1b2c3d4", command="whoami")
        assert inp.session_id == "a1b2c3d4"
        assert inp.command == "whoami"

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import CommandInput
        with pytest.raises(ValidationError):
            CommandInput(session_id="", command="whoami")

    def test_empty_command_rejected(self):
        """Test empty command is rejected."""
        from pwncat_server import CommandInput
        with pytest.raises(ValidationError):
            CommandInput(session_id="a1b2c3d4", command="")

    def test_missing_session_id(self):
        """Test missing session_id."""
        from pwncat_server import CommandInput
        with pytest.raises(ValidationError):
            CommandInput(command="whoami")

    def test_missing_command(self):
        """Test missing command."""
        from pwncat_server import CommandInput
        with pytest.raises(ValidationError):
            CommandInput(session_id="a1b2c3d4")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import CommandInput
        with pytest.raises(ValidationError):
            CommandInput(session_id="a1b2c3d4", command="whoami", extra="bad")


# =============================================================================
# ModuleInput Tests
# =============================================================================

class TestModuleInput:
    """Tests for ModuleInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from pwncat_server import ModuleInput
        inp = ModuleInput(session_id="a1b2c3d4", module="enumerate.system.uname")
        assert inp.session_id == "a1b2c3d4"
        assert inp.module == "enumerate.system.uname"
        assert inp.options == {}  # default

    def test_valid_with_options(self):
        """Test valid input with options."""
        from pwncat_server import ModuleInput
        inp = ModuleInput(
            session_id="a1b2c3d4",
            module="enumerate.system.uname",
            options={"verbose": True}
        )
        assert inp.options == {"verbose": True}

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import ModuleInput
        with pytest.raises(ValidationError):
            ModuleInput(session_id="", module="enumerate.system.uname")

    def test_empty_module_rejected(self):
        """Test empty module is rejected."""
        from pwncat_server import ModuleInput
        with pytest.raises(ValidationError):
            ModuleInput(session_id="a1b2c3d4", module="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import ModuleInput
        with pytest.raises(ValidationError):
            ModuleInput(session_id="a1b2c3d4", module="test", extra="bad")


# =============================================================================
# FileTransferInput Tests
# =============================================================================

class TestFileTransferInput:
    """Tests for FileTransferInput model."""

    def test_valid_input(self):
        """Test valid file transfer input."""
        from pwncat_server import FileTransferInput
        inp = FileTransferInput(
            session_id="a1b2c3d4",
            local_path="/tmp/file.txt",
            remote_path="/home/user/file.txt"
        )
        assert inp.session_id == "a1b2c3d4"
        assert inp.local_path == "/tmp/file.txt"
        assert inp.remote_path == "/home/user/file.txt"

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import FileTransferInput
        with pytest.raises(ValidationError):
            FileTransferInput(
                session_id="",
                local_path="/tmp/file.txt",
                remote_path="/home/user/file.txt"
            )

    def test_empty_local_path_rejected(self):
        """Test empty local_path is rejected."""
        from pwncat_server import FileTransferInput
        with pytest.raises(ValidationError):
            FileTransferInput(
                session_id="a1b2c3d4",
                local_path="",
                remote_path="/home/user/file.txt"
            )

    def test_empty_remote_path_rejected(self):
        """Test empty remote_path is rejected."""
        from pwncat_server import FileTransferInput
        with pytest.raises(ValidationError):
            FileTransferInput(
                session_id="a1b2c3d4",
                local_path="/tmp/file.txt",
                remote_path=""
            )

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import FileTransferInput
        with pytest.raises(ValidationError):
            FileTransferInput(
                session_id="a1b2c3d4",
                local_path="/tmp/file.txt",
                remote_path="/home/user/file.txt",
                extra="bad"
            )


# =============================================================================
# EnumerateAllInput Tests
# =============================================================================

class TestEnumerateAllInput:
    """Tests for EnumerateAllInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from pwncat_server import EnumerateAllInput, EnumerationCategory
        inp = EnumerateAllInput(session_id="a1b2c3d4")
        assert inp.session_id == "a1b2c3d4"
        # Check default categories
        assert EnumerationCategory.SYSTEM in inp.categories
        assert EnumerationCategory.USER in inp.categories
        assert EnumerationCategory.NETWORK in inp.categories

    def test_valid_with_categories(self):
        """Test valid input with specific categories."""
        from pwncat_server import EnumerateAllInput, EnumerationCategory
        inp = EnumerateAllInput(
            session_id="a1b2c3d4",
            categories=[EnumerationCategory.FILE, EnumerationCategory.SOFTWARE]
        )
        assert EnumerationCategory.FILE in inp.categories
        assert EnumerationCategory.SOFTWARE in inp.categories

    def test_valid_timeout_at_bounds(self):
        """Test timeout at boundary values."""
        from pwncat_server import EnumerateAllInput
        # Lower bound
        inp = EnumerateAllInput(session_id="a1b2c3d4", timeout_per_module=5.0)
        assert inp.timeout_per_module == 5.0

        # Upper bound
        inp = EnumerateAllInput(session_id="a1b2c3d4", timeout_per_module=300.0)
        assert inp.timeout_per_module == 300.0

    def test_timeout_below_minimum(self):
        """Test timeout below minimum is rejected."""
        from pwncat_server import EnumerateAllInput
        with pytest.raises(ValidationError):
            EnumerateAllInput(session_id="a1b2c3d4", timeout_per_module=4.9)

    def test_timeout_above_maximum(self):
        """Test timeout above maximum is rejected."""
        from pwncat_server import EnumerateAllInput
        with pytest.raises(ValidationError):
            EnumerateAllInput(session_id="a1b2c3d4", timeout_per_module=301.0)

    def test_invalid_category(self):
        """Test invalid category is rejected."""
        from pwncat_server import EnumerateAllInput
        with pytest.raises(ValidationError):
            EnumerateAllInput(session_id="a1b2c3d4", categories=["invalid"])

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import EnumerateAllInput
        with pytest.raises(ValidationError):
            EnumerateAllInput(session_id="a1b2c3d4", extra="bad")


# =============================================================================
# PrivescSuggestInput Tests
# =============================================================================

class TestPrivescSuggestInput:
    """Tests for PrivescSuggestInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from pwncat_server import PrivescSuggestInput
        inp = PrivescSuggestInput(session_id="a1b2c3d4")
        assert inp.session_id == "a1b2c3d4"
        assert inp.run_enumeration is True  # default

    def test_valid_with_options(self):
        """Test valid input with options."""
        from pwncat_server import PrivescSuggestInput
        inp = PrivescSuggestInput(session_id="a1b2c3d4", run_enumeration=False)
        assert inp.run_enumeration is False

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import PrivescSuggestInput
        with pytest.raises(ValidationError):
            PrivescSuggestInput(session_id="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import PrivescSuggestInput
        with pytest.raises(ValidationError):
            PrivescSuggestInput(session_id="a1b2c3d4", extra="bad")


# =============================================================================
# PrivescAutoInput Tests
# =============================================================================

class TestPrivescAutoInput:
    """Tests for PrivescAutoInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from pwncat_server import PrivescAutoInput
        inp = PrivescAutoInput(session_id="a1b2c3d4")
        assert inp.session_id == "a1b2c3d4"
        assert inp.techniques is None  # default
        assert inp.stop_on_success is True  # default

    def test_valid_with_techniques(self):
        """Test valid input with specific techniques."""
        from pwncat_server import PrivescAutoInput
        inp = PrivescAutoInput(
            session_id="a1b2c3d4",
            techniques=["sudo", "suid"],
            stop_on_success=False
        )
        assert inp.techniques == ["sudo", "suid"]
        assert inp.stop_on_success is False

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import PrivescAutoInput
        with pytest.raises(ValidationError):
            PrivescAutoInput(session_id="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import PrivescAutoInput
        with pytest.raises(ValidationError):
            PrivescAutoInput(session_id="a1b2c3d4", extra="bad")


# =============================================================================
# PersistInstallInput Tests
# =============================================================================

class TestPersistInstallInput:
    """Tests for PersistInstallInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from pwncat_server import PersistInstallInput
        inp = PersistInstallInput(session_id="a1b2c3d4", method="ssh_authorized_keys")
        assert inp.session_id == "a1b2c3d4"
        assert inp.method == "ssh_authorized_keys"
        assert inp.options == {}  # default

    def test_valid_with_options(self):
        """Test valid input with options."""
        from pwncat_server import PersistInstallInput
        inp = PersistInstallInput(
            session_id="a1b2c3d4",
            method="passwd_user",
            options={"username": "backdoor", "password": "secret"}
        )
        assert inp.options == {"username": "backdoor", "password": "secret"}

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import PersistInstallInput
        with pytest.raises(ValidationError):
            PersistInstallInput(session_id="", method="ssh_authorized_keys")

    def test_empty_method_rejected(self):
        """Test empty method is rejected."""
        from pwncat_server import PersistInstallInput
        with pytest.raises(ValidationError):
            PersistInstallInput(session_id="a1b2c3d4", method="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import PersistInstallInput
        with pytest.raises(ValidationError):
            PersistInstallInput(
                session_id="a1b2c3d4",
                method="ssh_authorized_keys",
                extra="bad"
            )


# =============================================================================
# SessionInput Tests
# =============================================================================

class TestSessionInput:
    """Tests for SessionInput model."""

    def test_valid_input(self):
        """Test valid session input."""
        from pwncat_server import SessionInput
        inp = SessionInput(session_id="a1b2c3d4")
        assert inp.session_id == "a1b2c3d4"

    def test_empty_session_id_rejected(self):
        """Test empty session_id is rejected."""
        from pwncat_server import SessionInput
        with pytest.raises(ValidationError):
            SessionInput(session_id="")

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import SessionInput
        with pytest.raises(ValidationError):
            SessionInput(session_id="a1b2c3d4", extra="bad")


# =============================================================================
# GetLhostInput Tests
# =============================================================================

class TestGetLhostInput:
    """Tests for GetLhostInput model."""

    def test_valid_default(self):
        """Test valid input with default interface."""
        from pwncat_server import GetLhostInput
        inp = GetLhostInput()
        assert inp.interface == "tun0"  # default

    def test_valid_with_interface(self):
        """Test valid input with custom interface."""
        from pwncat_server import GetLhostInput
        inp = GetLhostInput(interface="eth0")
        assert inp.interface == "eth0"

    def test_extra_fields_forbidden(self):
        """Test extra fields are rejected."""
        from pwncat_server import GetLhostInput
        with pytest.raises(ValidationError):
            GetLhostInput(interface="tun0", extra="bad")
