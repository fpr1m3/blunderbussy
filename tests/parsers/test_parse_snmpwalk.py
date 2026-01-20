"""Unit tests for parse-snmpwalk.py parser."""
import importlib.util
from pathlib import Path

import pytest

# Import the parser module with hyphenated name
PARSER_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "enrichment" / "parsers" / "parse-snmpwalk.py"
spec = importlib.util.spec_from_file_location("parse_snmpwalk", PARSER_PATH)
parse_snmpwalk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_snmpwalk)


class TestGetOidName:
    """Tests for OID name resolution."""

    def test_exact_match(self):
        assert parse_snmpwalk.get_oid_name('1.3.6.1.2.1.1.1') == 'sysDescr'

    def test_base_oid_match(self):
        # sysDescr OID with suffix
        assert parse_snmpwalk.get_oid_name('1.3.6.1.2.1.1.1.0') == 'sysDescr'

    def test_sysname(self):
        assert parse_snmpwalk.get_oid_name('1.3.6.1.2.1.1.5') == 'sysName'

    def test_interface_descr(self):
        assert parse_snmpwalk.get_oid_name('1.3.6.1.2.1.2.2.1.2') == 'ifDescr'
        assert parse_snmpwalk.get_oid_name('1.3.6.1.2.1.2.2.1.2.1') == 'ifDescr'

    def test_process_name(self):
        assert parse_snmpwalk.get_oid_name('1.3.6.1.2.1.25.4.2.1.2') == 'hrSWRunName'

    def test_unknown_oid(self):
        result = parse_snmpwalk.get_oid_name('1.3.6.1.999.999.999')
        assert 'oid-' in result or result == 'unknown'


class TestParseSnmpValue:
    """Tests for SNMP value parsing."""

    def test_string_with_quotes(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('STRING: "Linux server"')
        assert value_type == 'STRING'
        assert value == 'Linux server'

    def test_string_without_quotes(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('STRING: Some value')
        assert value_type == 'STRING'
        assert value == 'Some value'

    def test_integer(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('INTEGER: 42')
        assert value_type == 'INTEGER'
        assert value == 42

    def test_gauge32(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('Gauge32: 12345')
        assert value_type == 'Gauge32'
        assert value == 12345

    def test_counter32(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('Counter32: 98765')
        assert value_type == 'Counter32'
        assert value == 98765

    def test_counter64(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('Counter64: 123456789012')
        assert value_type == 'Counter64'
        assert value == 123456789012

    def test_timeticks(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('Timeticks: (12345678) 1 day, 10:17:36.78')
        assert value_type == 'Timeticks'
        assert value['raw'] == 12345678
        assert '1 day' in value['formatted']

    def test_oid(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('OID: .1.3.6.1.4.1.8072.3.2.10')
        assert value_type == 'OID'
        assert '1.3.6.1.4.1.8072' in value

    def test_ipaddress(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('IpAddress: 192.168.1.100')
        assert value_type == 'IpAddress'
        assert value == '192.168.1.100'

    def test_hex_string_mac(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('Hex-STRING: 00 11 22 33 44 55')
        assert value_type == 'Hex-STRING'
        assert value == '00:11:22:33:44:55'

    def test_hex_string_non_mac(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('Hex-STRING: 01 02 03 04')
        assert value_type == 'Hex-STRING'
        assert '01' in value

    def test_null_value(self):
        value_type, value = parse_snmpwalk.parse_snmp_value('No Such Instance')
        assert value_type == 'NULL'
        assert value is None


class TestParseSnmpLine:
    """Tests for single line parsing."""

    def test_numeric_oid_format(self):
        line = '.1.3.6.1.2.1.1.1.0 = STRING: "Linux server"'
        result = parse_snmpwalk.parse_snmp_line(line)

        assert result is not None
        assert result['oid'] == '1.3.6.1.2.1.1.1.0'
        assert result['oid_name'] == 'sysDescr'
        assert result['type'] == 'STRING'
        assert result['value'] == 'Linux server'

    def test_iso_format(self):
        line = 'iso.3.6.1.2.1.1.5.0 = STRING: "router01"'
        result = parse_snmpwalk.parse_snmp_line(line)

        assert result is not None
        assert result['oid'] == '1.3.6.1.2.1.1.5.0'
        assert result['oid_name'] == 'sysName'
        assert result['value'] == 'router01'

    def test_mib_name_format(self):
        line = 'SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01'
        result = parse_snmpwalk.parse_snmp_line(line)

        assert result is not None
        assert 'SNMPv2-MIB' in result['oid']
        assert result['oid_name'] == 'sysORLastChange'

    def test_empty_line(self):
        assert parse_snmpwalk.parse_snmp_line('') is None

    def test_comment_line(self):
        assert parse_snmpwalk.parse_snmp_line('# This is a comment') is None

    def test_integer_value(self):
        line = '.1.3.6.1.2.1.1.7.0 = INTEGER: 72'
        result = parse_snmpwalk.parse_snmp_line(line)

        assert result['type'] == 'INTEGER'
        assert result['value'] == 72


class TestExtractSystemInfo:
    """Tests for system information extraction."""

    def test_extracts_sys_descr(self):
        entries = [{'oid_name': 'sysDescr', 'value': 'Linux server 5.4.0'}]
        info = parse_snmpwalk.extract_system_info(entries)
        assert info['description'] == 'Linux server 5.4.0'

    def test_extracts_sys_name(self):
        entries = [{'oid_name': 'sysName', 'value': 'server01.example.com'}]
        info = parse_snmpwalk.extract_system_info(entries)
        assert info['name'] == 'server01.example.com'

    def test_extracts_sys_contact(self):
        entries = [{'oid_name': 'sysContact', 'value': 'admin@example.com'}]
        info = parse_snmpwalk.extract_system_info(entries)
        assert info['contact'] == 'admin@example.com'

    def test_extracts_sys_location(self):
        entries = [{'oid_name': 'sysLocation', 'value': 'Datacenter Rack A12'}]
        info = parse_snmpwalk.extract_system_info(entries)
        assert info['location'] == 'Datacenter Rack A12'

    def test_extracts_uptime_formatted(self):
        entries = [{'oid_name': 'sysUpTime', 'value': {'raw': 12345678, 'formatted': '1 day, 10:17:36.78'}}]
        info = parse_snmpwalk.extract_system_info(entries)
        assert '1 day' in info['uptime']

    def test_extracts_memory_size(self):
        entries = [{'oid_name': 'hrMemorySize', 'value': 8192000}]
        info = parse_snmpwalk.extract_system_info(entries)
        assert info['memory_size'] == 8192000


class TestExtractInterfaces:
    """Tests for network interface extraction."""

    def test_extracts_interface_description(self):
        entries = [
            {'oid': '1.3.6.1.2.1.2.2.1.2.1', 'oid_name': 'ifDescr', 'value': 'eth0'}
        ]
        interfaces = parse_snmpwalk.extract_interfaces(entries)
        assert len(interfaces) == 1
        assert interfaces[0]['description'] == 'eth0'

    def test_extracts_mac_address(self):
        entries = [
            {'oid': '1.3.6.1.2.1.2.2.1.6.1', 'oid_name': 'ifPhysAddress', 'value': '00:11:22:33:44:55'}
        ]
        interfaces = parse_snmpwalk.extract_interfaces(entries)
        assert interfaces[0]['mac_address'] == '00:11:22:33:44:55'

    def test_extracts_multiple_interfaces(self):
        entries = [
            {'oid': '1.3.6.1.2.1.2.2.1.2.1', 'oid_name': 'ifDescr', 'value': 'lo'},
            {'oid': '1.3.6.1.2.1.2.2.1.2.2', 'oid_name': 'ifDescr', 'value': 'eth0'},
            {'oid': '1.3.6.1.2.1.2.2.1.2.3', 'oid_name': 'ifDescr', 'value': 'eth1'},
        ]
        interfaces = parse_snmpwalk.extract_interfaces(entries)
        assert len(interfaces) == 3
        descriptions = [i['description'] for i in interfaces]
        assert 'lo' in descriptions
        assert 'eth0' in descriptions
        assert 'eth1' in descriptions


class TestExtractProcesses:
    """Tests for running process extraction."""

    def test_extracts_process_name(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.4.2.1.2.1024', 'oid_name': 'hrSWRunName', 'value': 'apache2'}
        ]
        processes = parse_snmpwalk.extract_processes(entries)
        assert len(processes) == 1
        assert processes[0]['name'] == 'apache2'

    def test_extracts_process_path(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.4.2.1.4.1024', 'oid_name': 'hrSWRunPath', 'value': '/usr/sbin/apache2'}
        ]
        processes = parse_snmpwalk.extract_processes(entries)
        assert processes[0]['path'] == '/usr/sbin/apache2'

    def test_extracts_process_parameters(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.4.2.1.5.1024', 'oid_name': 'hrSWRunParameters', 'value': '-DFOREGROUND'}
        ]
        processes = parse_snmpwalk.extract_processes(entries)
        assert processes[0]['parameters'] == '-DFOREGROUND'

    def test_extracts_process_status(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.4.2.1.7.1024', 'oid_name': 'hrSWRunStatus', 'value': 1}
        ]
        processes = parse_snmpwalk.extract_processes(entries)
        assert processes[0]['status'] == 'running'


class TestExtractStorage:
    """Tests for storage information extraction."""

    def test_extracts_storage_description(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.2.3.1.3.1', 'oid_name': 'hrStorageDescr', 'value': '/dev/sda1'}
        ]
        storage = parse_snmpwalk.extract_storage(entries)
        assert len(storage) == 1
        assert storage[0]['description'] == '/dev/sda1'

    def test_calculates_storage_bytes(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.2.3.1.4.1', 'oid_name': 'hrStorageAllocationUnits', 'value': 4096},
            {'oid': '1.3.6.1.2.1.25.2.3.1.5.1', 'oid_name': 'hrStorageSize', 'value': 1000000},
        ]
        storage = parse_snmpwalk.extract_storage(entries)
        assert storage[0]['size_bytes'] == 4096 * 1000000

    def test_calculates_percent_used(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.2.3.1.4.1', 'oid_name': 'hrStorageAllocationUnits', 'value': 4096},
            {'oid': '1.3.6.1.2.1.25.2.3.1.5.1', 'oid_name': 'hrStorageSize', 'value': 100},
            {'oid': '1.3.6.1.2.1.25.2.3.1.6.1', 'oid_name': 'hrStorageUsed', 'value': 50},
        ]
        storage = parse_snmpwalk.extract_storage(entries)
        assert storage[0]['percent_used'] == 50.0


class TestExtractInstalledSoftware:
    """Tests for installed software extraction."""

    def test_extracts_software_name(self):
        entries = [
            {'oid': '1.3.6.1.2.1.25.6.3.1.2.1', 'oid_name': 'hrSWInstalledName', 'value': 'openssh-server-8.2p1'}
        ]
        software = parse_snmpwalk.extract_installed_software(entries)
        assert len(software) == 1
        assert software[0]['name'] == 'openssh-server-8.2p1'


class TestIdentifyInterestingEntries:
    """Tests for security-interesting entry identification."""

    def test_identifies_net_snmp_extend(self):
        entries = [
            {'oid_name': 'nsExtendCommand', 'value': '/usr/bin/env'}
        ]
        interesting = parse_snmpwalk.identify_interesting_entries(entries)
        assert any('NET-SNMP Extend' in i for i in interesting)

    def test_identifies_system_description(self):
        entries = [
            {'oid_name': 'sysDescr', 'value': 'Linux server 5.4.0-89-generic'}
        ]
        interesting = parse_snmpwalk.identify_interesting_entries(entries)
        assert any('System:' in i for i in interesting)

    def test_identifies_sensitive_keywords(self):
        entries = [
            {'oid_name': 'someOid', 'value': 'contains password secret data'}
        ]
        interesting = parse_snmpwalk.identify_interesting_entries(entries)
        assert any('Sensitive keyword' in i for i in interesting)


class TestParseSnmpwalkBasic:
    """Integration tests for basic snmpwalk parsing."""

    def test_parses_basic_sample(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert result['type'] == 'snmpwalk'
        assert result['stats']['total_entries'] > 0

    def test_extracts_system_info(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert result['system_info']['description'] is not None
        assert 'Linux' in result['system_info']['description']
        assert result['system_info']['name'] == 'server01.example.com'
        assert result['system_info']['contact'] == 'admin@example.com'
        assert result['system_info']['location'] == 'Datacenter Rack A12'

    def test_extracts_interfaces(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert len(result['interfaces']) > 0
        descriptions = [i.get('description') for i in result['interfaces']]
        assert 'lo' in descriptions
        assert 'eth0' in descriptions

    def test_extracts_ip_addresses(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert len(result['ip_addresses']) > 0
        addresses = [a['address'] for a in result['ip_addresses']]
        assert '10.10.10.5' in addresses

    def test_extracts_processes(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert len(result['processes']) > 0
        process_names = [p.get('name') for p in result['processes']]
        assert 'apache2' in process_names
        assert 'mysqld' in process_names

    def test_extracts_storage(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert len(result['storage']) > 0
        descriptions = [s.get('description') for s in result['storage']]
        assert any('memory' in d.lower() for d in descriptions if d)

    def test_extracts_installed_software(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert len(result['installed_software']) > 0
        software_names = [s.get('name') for s in result['installed_software']]
        assert any('openssh' in n.lower() for n in software_names if n)


class TestParseSnmpwalkNetSnmp:
    """Tests for NET-SNMP specific output parsing."""

    def test_parses_net_snmp_sample(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_net-snmp.txt")

        assert result['type'] == 'snmpwalk'
        assert result['stats']['total_entries'] > 0

    def test_extracts_target_from_comment(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_net-snmp.txt")

        # Target may be extracted from filename or content
        # The comment has -c public 192.168.1.50
        assert result['community'] == 'public' or result['target'] is not None

    def test_identifies_extend_commands(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_net-snmp.txt")

        interesting = result['stats']['interesting']
        assert any('NET-SNMP Extend' in i or 'nsExtend' in i for i in interesting)

    def test_parses_iso_format(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_net-snmp.txt")

        # Should have parsed iso.3.6.1... format entries
        assert result['system_info']['description'] is not None
        assert 'Linux' in result['system_info']['description']

    def test_parses_mib_name_format(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_net-snmp.txt")

        # Should have parsed SNMPv2-MIB:: and NET-SNMP-EXTEND-MIB:: format entries
        assert result['stats']['total_entries'] > 5


class TestParseSnmpwalkOutput:
    """Tests for output structure and required fields."""

    def test_output_has_required_fields(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        required_fields = ['type', 'target', 'entries', 'system_info', 'interfaces',
                          'ip_addresses', 'processes', 'storage', 'installed_software',
                          'users', 'stats', 'raw_file', 'parsed_at']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_stats_structure(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        assert 'total_entries' in result['stats']
        assert 'interesting' in result['stats']
        assert isinstance(result['stats']['interesting'], list)

    def test_system_info_structure(self, snmpwalk_fixtures):
        result = parse_snmpwalk.parse_snmpwalk(snmpwalk_fixtures / "sample_basic.txt")

        expected_keys = ['description', 'contact', 'name', 'location', 'uptime',
                        'object_id', 'services', 'num_users', 'num_processes', 'memory_size']
        for key in expected_keys:
            assert key in result['system_info'], f"Missing system_info key: {key}"


class TestEmptyAndMinimalInput:
    """Tests for edge cases with empty or minimal input."""

    def test_empty_file(self, tmp_path):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        result = parse_snmpwalk.parse_snmpwalk(empty_file)

        assert result['type'] == 'snmpwalk'
        assert result['stats']['total_entries'] == 0
        assert len(result['processes']) == 0
        assert len(result['interfaces']) == 0

    def test_file_with_only_comments(self, tmp_path):
        comment_file = tmp_path / "comments.txt"
        comment_file.write_text("# This is a comment\n# Another comment\n")

        result = parse_snmpwalk.parse_snmpwalk(comment_file)

        assert result['type'] == 'snmpwalk'
        assert result['stats']['total_entries'] == 0

    def test_single_entry(self, tmp_path):
        single_file = tmp_path / "single.txt"
        single_file.write_text('.1.3.6.1.2.1.1.1.0 = STRING: "Test System"')

        result = parse_snmpwalk.parse_snmpwalk(single_file)

        assert result['stats']['total_entries'] == 1
        assert result['system_info']['description'] == 'Test System'

    def test_target_from_filename(self, tmp_path):
        target_file = tmp_path / "192.168.1.100_snmpwalk.txt"
        target_file.write_text('.1.3.6.1.2.1.1.1.0 = STRING: "System"')

        result = parse_snmpwalk.parse_snmpwalk(target_file)

        assert result['target'] == '192.168.1.100'


class TestExtractUsersFromProcesses:
    """Tests for user extraction from process information."""

    def test_extracts_user_from_home_path(self):
        processes = [
            {'path': '/home/admin/scripts/backup.py', 'parameters': ''}
        ]
        users = parse_snmpwalk.extract_users_from_processes(processes)
        assert 'admin' in users

    def test_extracts_user_from_parameters(self):
        processes = [
            {'path': '/usr/sbin/mysqld', 'parameters': '--user=mysql'}
        ]
        users = parse_snmpwalk.extract_users_from_processes(processes)
        assert 'mysql' in users

    def test_no_users_when_not_present(self):
        processes = [
            {'path': '/usr/sbin/apache2', 'parameters': '-DFOREGROUND'}
        ]
        users = parse_snmpwalk.extract_users_from_processes(processes)
        assert len(users) == 0
