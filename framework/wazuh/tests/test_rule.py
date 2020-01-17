# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open
import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh import rule
        from wazuh.results import AffectedItemsWazuhResult, WazuhResult
        from wazuh.exception import WazuhError

rule_ossec_conf = {
    'ruleset': {
        'decoder_dir': ['ruleset/decoders', 'etc/decoders'],
        'rule_dir': ['ruleset/rules', 'etc/rules'],
        'rule_exclude': ['0215-policy_rules.xml'],
        'list': ['etc/lists/audit-keys', 'etc/lists/amazon/aws-eventnames', 'etc/lists/security-eventchannel']
    }
}

other_rule_ossec_conf = {
    'ruleset': {
        'decoder_dir': ['ruleset/decoders', 'etc/decoders'],
        'rule_dir': ['ruleset/rules', 'etc/rules'],
        'rule_exclude': ['0010-rules_config.xml'],
        'list': ['etc/lists/audit-keys', 'etc/lists/amazon/aws-eventnames', 'etc/lists/security-eventchannel']
    }
}



rule_contents = '''
<group name="ossec,">
  <rule id="501" level="3" overwrite="no">
    <if_sid>500</if_sid>
    <if_fts />
    <options>alert_by_email</options>
    <match>Agent started</match>
    <description>New ossec agent connected.</description>
    <group>pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.3</group>
    <list field="user" lookup="match_key">etc/lists/list-user</list>
    <field name="netinfo.iface.name">ens33</field>
    <regex>$(\\d+.\\d+.\\d+.\\d+)</regex>
  </rule>
</group>
    '''

mocked_items = {'items': [], 'totalItems': 0}


def rules_files(file_path):
    """
    Returns a list of rules names
    :param file_path: A glob file path containing *.xml in the end.
    :return: A generator
    """
    return map(lambda x: file_path.replace('*.xml', f'rules{x}.xml'), range(2))


@pytest.mark.parametrize('func', [
    rule.get_rules_files,
    rule.get_rules
])
@pytest.mark.parametrize('status', [
    None,
    'all',
    'enabled',
    'disabled',
    'random'
])
@patch('wazuh.rule.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_status_include(mock_config, status, func):
    """Test getting rules using status filter."""
    m = mock_open(read_data=rule_contents)
    if status == 'random':
        with pytest.raises(WazuhError, match='.* 1202 .*'):
            func(status=status)
    else:
        with patch('builtins.open', m):
            d_files = func(status=status).to_dict()
            assert d_files['total_affected_items'] == len(d_files['affected_items']) and \
                   len(d_files['affected_items']) != 0
            if status == 'all' or status == 'enabled':
                assert d_files['affected_items'][0]['status'] == 'enabled'
                assert d_files['affected_items'][2]['status'] == 'enabled'
            if status != 'enabled':
                index_disabled = next((index for (index, d) in enumerate(
                    d_files['affected_items']) if d["status"] == "disabled"), None)
                assert d_files['affected_items'][index_disabled]['file'] == '0215-policy_rules.xml'


@pytest.mark.parametrize('func', [
    rule.get_rules_files,
    rule.get_rules
])
@pytest.mark.parametrize('path', [
    None,
    'ruleset/rules',
    'random'
])
@patch('wazuh.configuration.get_ossec_conf', return_value=other_rule_ossec_conf)
def test_get_rules_file_path(mock_config, path, func):
    """Test getting rules using status filter."""
    with patch('wazuh.rule.common.maximum_database_limit', 5000):
        if path == 'random':
            d_files = func(path=path).to_dict()
            assert d_files['total_affected_items'] == 0
            assert len(d_files['affected_items']) == 0
        else:
            d_files = func(path=path, limit=4500).to_dict()  # Limit
            assert d_files['total_affected_items'] == len(d_files['affected_items']) and \
                   len(d_files['affected_items']) != 0
            assert d_files['affected_items'][0]['path'] == 'ruleset/rules'


@pytest.mark.parametrize('func', [
    rule.get_rules_files,
    rule.get_rules
])
@pytest.mark.parametrize('file_', [
    ['0010-rules_config.xml'],
    ['0040-imapd_rules.xml'],
    ['0095-sshd_rules.xml']
])
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_file_param(mock_config, file_, func):
    """Test getting rules using status filter."""
    d_files = func(file=file_)
    assert [d_files.affected_items[0]['file']] == file_
    if func == rule.get_rules_files:
        assert d_files.total_affected_items == 1
    else:
        assert d_files.total_affected_items == len(d_files.affected_items)


@patch('wazuh.configuration.get_ossec_conf', return_value=None)
def test_failed_get_rules_file(mock_config):
    """
    Test failed get_rules_file function when ossec.conf don't have ruleset section
    """
    with pytest.raises(WazuhError, match=".* 1200 .*"):
        rule.get_rules_files()


@pytest.mark.parametrize('arg', [
    {'group': 'user1'},
    {'pci': 'user1'},
    {'gpg13': '10.0'},
    {'gdpr': 'IV_35.7.a'},
    {'hipaa': '164.312.a'},
    {'nist_800_53': 'AU.1'},
    {'rule_ids': ['510']},
    {'level': '2'},
    {'level': '2-2'},
    {'rule_ids': ['1', '2', '4', '8']},
    {'rule_ids': ['3']}  # No exists
])
@patch('wazuh.configuration.get_ossec_conf', return_value=other_rule_ossec_conf)
def test_get_rules(mock_config, arg):
    """Test get_rules function."""
    result = rule.get_rules(**arg)

    assert isinstance(result, AffectedItemsWazuhResult)
    for rule_ in result.to_dict()['affected_items']:
        if list(arg.keys())[0] != 'level':
            assert arg[list(arg.keys())[0]] in rule_[list(arg.keys())[0]]
        else:
            try:
                found = arg[list(arg.keys())[0]] in str(rule_[list(arg.keys())[0]])
                if found:
                    assert True
                assert str(rule_[list(arg.keys())[0]]) in arg[list(arg.keys())[0]]
            except WazuhError as e:
                assert 'rule_ids' in arg.keys()
                assert e.code == 1208


def test_failed_get_rules():
    """Test error 1203 in get_rules function."""
    with pytest.raises(WazuhError, match=".* 1203 .*"):
        rule.get_rules(level='2-3-4')


@pytest.mark.parametrize('arg', [
    {'search_text': None},
    {'search_text': "rules1", "complementary_search": False}
])
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_groups(mock_config, arg):
    result = rule.get_groups(**arg)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 0
    assert result.total_affected_items > 0


@pytest.mark.parametrize('requirement', [
    'pci', 'gdpr', 'hipaa', 'nist_800_53', 'gpg13'
])
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_requirement(mocked_config, requirement):
    result = rule.get_requirement(requirement=requirement)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 0
    assert result.total_affected_items > 0


@pytest.mark.parametrize('requirement', [
    'a', 'b', 'c'
])
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_requirement_invalid(mocked_config, requirement):
    result = rule.get_requirement(requirement=requirement)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 1
    assert result.total_affected_items == 0


@pytest.mark.parametrize('file_', [
    {'0010-rules_config.xml': str},
    {'0040-imapd_rules.xml': str},
    {'0095-sshd_rules.xml': str},
    {'no_exists.xml': 1415}
])
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_download(mock_config, file_):
    """Test getting rules using status filter."""
    try:
        d_files = rule.get_file(list(file_.keys())[0])
        assert isinstance(d_files, str)
    except WazuhError as e:
        assert e.code == file_[list(file_.keys())[0]]


@pytest.mark.parametrize('file_', [
    {'ruleset/rules/no_exists_os_error.xml': 1414},
    {'no_exists_unk_error.xml': 1414}
])
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_download_failed(mock_config, file_):
    """Test getting rules using status filter."""
    with patch('wazuh.rule.get_rules_files', return_value=AffectedItemsWazuhResult(
            all_msg='test', affected_items=[{'path': list(file_.keys())[0]}])):
        try:
            rule.get_file(list(file_.keys())[0])
            assert False
        except WazuhError as e:
            assert e.code == file_[list(file_.keys())[0]]
