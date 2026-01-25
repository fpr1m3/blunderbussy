"""
Tests for msf-server.py Pydantic input models.

Tests input validation without requiring Metasploit to be installed.
Focus on boundary conditions, type validation, and enum fields.
"""

import pytest
from pydantic import ValidationError


# =============================================================================
# SearchModulesInput Tests
# =============================================================================

class TestSearchModulesInput:
    """Tests for SearchModulesInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input with just query."""
        from msf_server import SearchModulesInput, ResponseFormat
        inp = SearchModulesInput(query="ssh")
        assert inp.query == "ssh"
        assert inp.module_type is None  # default
        assert inp.limit == 50  # default
        assert inp.response_format == ResponseFormat.MARKDOWN  # default

    def test_valid_full(self):
        """Test valid input with all fields."""
        from msf_server import SearchModulesInput, ModuleType, ResponseFormat
        inp = SearchModulesInput(
            query="smb",
            module_type=ModuleType.EXPLOIT,
            limit=100,
            response_format=ResponseFormat.JSON
        )
        assert inp.query == "smb"
        assert inp.module_type == ModuleType.EXPLOIT
        assert inp.limit == 100
        assert inp.response_format == ResponseFormat.JSON

    def test_query_min_length(self):
        """Test query must have at least 1 character."""
        from msf_server import SearchModulesInput
        with pytest.raises(ValidationError) as exc_info:
            SearchModulesInput(query="")
        assert "min_length" in str(exc_info.value).lower() or "at least" in str(exc_info.value).lower()

    def test_query_max_length(self):
        """Test query max length of 200."""
        from msf_server import SearchModulesInput
        # Should pass at exactly 200
        inp = SearchModulesInput(query="a" * 200)
        assert len(inp.query) == 200

        # Should fail at 201
        with pytest.raises(ValidationError):
            SearchModulesInput(query="a" * 201)

    def test_limit_at_lower_bound(self):
        """Test limit at minimum value (1)."""
        from msf_server import SearchModulesInput
        inp = SearchModulesInput(query="test", limit=1)
        assert inp.limit == 1

    def test_limit_at_upper_bound(self):
        """Test limit at maximum value (500)."""
        from msf_server import SearchModulesInput
        inp = SearchModulesInput(query="test", limit=500)
        assert inp.limit == 500

    def test_limit_below_range(self):
        """Test limit below 1 is rejected."""
        from msf_server import SearchModulesInput
        with pytest.raises(ValidationError):
            SearchModulesInput(query="test", limit=0)

    def test_limit_above_range(self):
        """Test limit above 500 is rejected."""
        from msf_server import SearchModulesInput
        with pytest.raises(ValidationError):
            SearchModulesInput(query="test", limit=501)

    def test_valid_module_types(self):
        """Test all valid module types."""
        from msf_server import SearchModulesInput, ModuleType
        for mod_type in [ModuleType.EXPLOIT, ModuleType.AUXILIARY,
                         ModuleType.POST, ModuleType.PAYLOAD]:
            inp = SearchModulesInput(query="test", module_type=mod_type)
            assert inp.module_type == mod_type

    def test_invalid_module_type(self):
        """Test invalid module type is rejected."""
        from msf_server import SearchModulesInput
        with pytest.raises(ValidationError):
            SearchModulesInput(query="test", module_type="invalid")

    def test_valid_response_formats(self):
        """Test valid response formats."""
        from msf_server import SearchModulesInput, ResponseFormat
        for fmt in [ResponseFormat.MARKDOWN, ResponseFormat.JSON]:
            inp = SearchModulesInput(query="test", response_format=fmt)
            assert inp.response_format == fmt

    def test_invalid_response_format(self):
        """Test invalid response format is rejected."""
        from msf_server import SearchModulesInput
        with pytest.raises(ValidationError):
            SearchModulesInput(query="test", response_format="xml")


# =============================================================================
# ModuleInfoInput Tests
# =============================================================================

class TestModuleInfoInput:
    """Tests for ModuleInfoInput model."""

    def test_valid_input(self):
        """Test valid module info input."""
        from msf_server import ModuleInfoInput, ModuleType
        inp = ModuleInfoInput(
            module_type=ModuleType.EXPLOIT,
            module="multi/http/apache_mod_cgi_bash_env_exec"
        )
        assert inp.module_type == ModuleType.EXPLOIT
        assert inp.module == "multi/http/apache_mod_cgi_bash_env_exec"

    def test_all_module_types_valid(self):
        """Test all module types are accepted."""
        from msf_server import ModuleInfoInput, ModuleType
        for mod_type in ModuleType:
            inp = ModuleInfoInput(module_type=mod_type, module="test/module")
            assert inp.module_type == mod_type

    def test_empty_module_rejected(self):
        """Test empty module string is rejected."""
        from msf_server import ModuleInfoInput, ModuleType
        with pytest.raises(ValidationError):
            ModuleInfoInput(module_type=ModuleType.EXPLOIT, module="")

    def test_missing_module_type(self):
        """Test missing module_type raises error."""
        from msf_server import ModuleInfoInput
        with pytest.raises(ValidationError):
            ModuleInfoInput(module="test/module")

    def test_missing_module(self):
        """Test missing module raises error."""
        from msf_server import ModuleInfoInput, ModuleType
        with pytest.raises(ValidationError):
            ModuleInfoInput(module_type=ModuleType.EXPLOIT)


# =============================================================================
# ExploitInput Tests
# =============================================================================

class TestExploitInput:
    """Tests for ExploitInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from msf_server import ExploitInput
        inp = ExploitInput(
            module="unix/ftp/vsftpd_234_backdoor",
            rhosts="10.10.10.5"
        )
        assert inp.module == "unix/ftp/vsftpd_234_backdoor"
        assert inp.rhosts == "10.10.10.5"
        assert inp.rport is None
        assert inp.lhost is None
        assert inp.lport == 4444  # default
        assert inp.payload is None
        assert inp.additional_options is None

    def test_valid_full(self):
        """Test valid input with all fields."""
        from msf_server import ExploitInput
        inp = ExploitInput(
            module="unix/ftp/vsftpd_234_backdoor",
            rhosts="10.10.10.5",
            rport=21,
            lhost="10.10.14.5",
            lport=4445,
            payload="cmd/unix/interact",
            additional_options={"VERBOSE": "true"}
        )
        assert inp.rport == 21
        assert inp.lhost == "10.10.14.5"
        assert inp.lport == 4445
        assert inp.payload == "cmd/unix/interact"
        assert inp.additional_options == {"VERBOSE": "true"}

    def test_empty_module_rejected(self):
        """Test empty module is rejected."""
        from msf_server import ExploitInput
        with pytest.raises(ValidationError):
            ExploitInput(module="", rhosts="10.10.10.5")

    def test_empty_rhosts_rejected(self):
        """Test empty rhosts is rejected."""
        from msf_server import ExploitInput
        with pytest.raises(ValidationError):
            ExploitInput(module="test/module", rhosts="")

    def test_rport_valid_range(self):
        """Test rport at valid boundaries."""
        from msf_server import ExploitInput
        # Lower bound
        inp = ExploitInput(module="test/mod", rhosts="10.10.10.5", rport=1)
        assert inp.rport == 1

        # Upper bound
        inp = ExploitInput(module="test/mod", rhosts="10.10.10.5", rport=65535)
        assert inp.rport == 65535

    def test_rport_below_range(self):
        """Test rport below range is rejected."""
        from msf_server import ExploitInput
        with pytest.raises(ValidationError):
            ExploitInput(module="test/mod", rhosts="10.10.10.5", rport=0)

    def test_rport_above_range(self):
        """Test rport above range is rejected."""
        from msf_server import ExploitInput
        with pytest.raises(ValidationError):
            ExploitInput(module="test/mod", rhosts="10.10.10.5", rport=65536)

    def test_lport_valid_range(self):
        """Test lport at valid boundaries."""
        from msf_server import ExploitInput
        # Lower bound
        inp = ExploitInput(module="test/mod", rhosts="10.10.10.5", lport=1)
        assert inp.lport == 1

        # Upper bound
        inp = ExploitInput(module="test/mod", rhosts="10.10.10.5", lport=65535)
        assert inp.lport == 65535

    def test_lport_below_range(self):
        """Test lport below range is rejected."""
        from msf_server import ExploitInput
        with pytest.raises(ValidationError):
            ExploitInput(module="test/mod", rhosts="10.10.10.5", lport=0)

    def test_lport_above_range(self):
        """Test lport above range is rejected."""
        from msf_server import ExploitInput
        with pytest.raises(ValidationError):
            ExploitInput(module="test/mod", rhosts="10.10.10.5", lport=65536)


# =============================================================================
# AuxiliaryInput Tests
# =============================================================================

class TestAuxiliaryInput:
    """Tests for AuxiliaryInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from msf_server import AuxiliaryInput
        inp = AuxiliaryInput(
            module="scanner/ssh/ssh_login",
            rhosts="10.10.10.5"
        )
        assert inp.module == "scanner/ssh/ssh_login"
        assert inp.rhosts == "10.10.10.5"
        assert inp.options is None

    def test_valid_with_options(self):
        """Test valid input with options."""
        from msf_server import AuxiliaryInput
        inp = AuxiliaryInput(
            module="scanner/ssh/ssh_login",
            rhosts="10.10.10.5",
            options={"USERNAME": "admin", "PASS_FILE": "/wordlists/passwords.txt"}
        )
        assert inp.options == {"USERNAME": "admin", "PASS_FILE": "/wordlists/passwords.txt"}

    def test_empty_module_rejected(self):
        """Test empty module is rejected."""
        from msf_server import AuxiliaryInput
        with pytest.raises(ValidationError):
            AuxiliaryInput(module="", rhosts="10.10.10.5")

    def test_empty_rhosts_rejected(self):
        """Test empty rhosts is rejected."""
        from msf_server import AuxiliaryInput
        with pytest.raises(ValidationError):
            AuxiliaryInput(module="scanner/ssh/ssh_login", rhosts="")


# =============================================================================
# SessionInteractInput Tests
# =============================================================================

class TestSessionInteractInput:
    """Tests for SessionInteractInput model."""

    def test_valid_input(self):
        """Test valid session interact input."""
        from msf_server import SessionInteractInput
        inp = SessionInteractInput(session_id=1, command="whoami")
        assert inp.session_id == 1
        assert inp.command == "whoami"

    def test_session_id_at_lower_bound(self):
        """Test session_id at minimum value (0)."""
        from msf_server import SessionInteractInput
        inp = SessionInteractInput(session_id=0, command="id")
        assert inp.session_id == 0

    def test_session_id_negative_rejected(self):
        """Test negative session_id is rejected."""
        from msf_server import SessionInteractInput
        with pytest.raises(ValidationError):
            SessionInteractInput(session_id=-1, command="whoami")

    def test_empty_command_rejected(self):
        """Test empty command is rejected."""
        from msf_server import SessionInteractInput
        with pytest.raises(ValidationError):
            SessionInteractInput(session_id=1, command="")

    def test_missing_session_id(self):
        """Test missing session_id raises error."""
        from msf_server import SessionInteractInput
        with pytest.raises(ValidationError):
            SessionInteractInput(command="whoami")

    def test_missing_command(self):
        """Test missing command raises error."""
        from msf_server import SessionInteractInput
        with pytest.raises(ValidationError):
            SessionInteractInput(session_id=1)


# =============================================================================
# SessionUpgradeInput Tests
# =============================================================================

class TestSessionUpgradeInput:
    """Tests for SessionUpgradeInput model."""

    def test_valid_minimal(self):
        """Test minimal valid input."""
        from msf_server import SessionUpgradeInput
        inp = SessionUpgradeInput(session_id=1, lhost="10.10.14.5")
        assert inp.session_id == 1
        assert inp.lhost == "10.10.14.5"
        assert inp.lport == 4433  # default

    def test_valid_full(self):
        """Test valid input with all fields."""
        from msf_server import SessionUpgradeInput
        inp = SessionUpgradeInput(session_id=1, lhost="10.10.14.5", lport=5555)
        assert inp.lport == 5555

    def test_session_id_negative_rejected(self):
        """Test negative session_id is rejected."""
        from msf_server import SessionUpgradeInput
        with pytest.raises(ValidationError):
            SessionUpgradeInput(session_id=-1, lhost="10.10.14.5")

    def test_lport_valid_range(self):
        """Test lport at valid boundaries."""
        from msf_server import SessionUpgradeInput
        # Lower bound
        inp = SessionUpgradeInput(session_id=1, lhost="10.10.14.5", lport=1)
        assert inp.lport == 1

        # Upper bound
        inp = SessionUpgradeInput(session_id=1, lhost="10.10.14.5", lport=65535)
        assert inp.lport == 65535

    def test_lport_out_of_range(self):
        """Test lport out of range is rejected."""
        from msf_server import SessionUpgradeInput
        with pytest.raises(ValidationError):
            SessionUpgradeInput(session_id=1, lhost="10.10.14.5", lport=0)
        with pytest.raises(ValidationError):
            SessionUpgradeInput(session_id=1, lhost="10.10.14.5", lport=65536)


# =============================================================================
# JobStopInput Tests
# =============================================================================

class TestJobStopInput:
    """Tests for JobStopInput model."""

    def test_valid_input(self):
        """Test valid job stop input."""
        from msf_server import JobStopInput
        inp = JobStopInput(job_id="0")
        assert inp.job_id == "0"

    def test_missing_job_id(self):
        """Test missing job_id raises error."""
        from msf_server import JobStopInput
        with pytest.raises(ValidationError):
            JobStopInput()


# =============================================================================
# PayloadsInput Tests
# =============================================================================

class TestPayloadsInput:
    """Tests for PayloadsInput model."""

    def test_valid_input(self):
        """Test valid payloads input."""
        from msf_server import PayloadsInput
        inp = PayloadsInput(module="unix/ftp/vsftpd_234_backdoor")
        assert inp.module == "unix/ftp/vsftpd_234_backdoor"

    def test_empty_module_rejected(self):
        """Test empty module is rejected."""
        from msf_server import PayloadsInput
        with pytest.raises(ValidationError):
            PayloadsInput(module="")

    def test_missing_module(self):
        """Test missing module raises error."""
        from msf_server import PayloadsInput
        with pytest.raises(ValidationError):
            PayloadsInput()
