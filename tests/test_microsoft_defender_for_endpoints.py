import pytest
import sys
import os
import logging
import json
from unittest.mock import patch, call
sys.path.append(os.getcwd())
from products.microsoft_defender_for_endpoints import DefenderForEndpoints
from common import Tag

@pytest.fixture
def dfe_product():
    with patch.object(DefenderForEndpoints, "__init__", lambda x, y: None):
        return DefenderForEndpoints(None)

def test_build_query_with_supported_fields(dfe_product : DefenderForEndpoints):
    """
    Verify build_query() can handle all filter options
    """
    filters = {
        'days':7,
        'minutes':10,
        'hostname':'workstation1',
        'username':'admin'
    }

    assert dfe_product.build_query(filters) == '| where Timestamp > ago(7d) | where Timestamp > ago(10m) ' + \
                      '| where DeviceName contains "workstation1" | where AccountName contains "admin"'
    
def test_build_query_with_unsupported_field(dfe_product: DefenderForEndpoints, mocker):
    """
    Verify build_query() gracefully handles unsupported filter options
    """
    filters = {
        'foo': 'bar'
    }

    mocker.patch('help.log_echo', return_value=None)
    dfe_product.log = logging.getLogger('pytest_surveyor')

    assert dfe_product.build_query(filters) == ''

def test_process_search(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify process_search() does not alter a given query
    """
    query = 'DeviceFileEvents | where FileName="foo bar"'

    mocked_post_advanced_query = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._post_advanced_query')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._add_results')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._get_default_header', return_value=None)

    dfe_product.log = logging.getLogger('pytest_surveyor')
    dfe_product._token = 'test_token_value'
    dfe_product.process_search(Tag('test123'), {}, query)
    mocked_post_advanced_query.assert_called_once_with(data={'Query': query}, headers=None)

def test_nested_process_search(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify nested_process_search() translates the given definition file correctly
    """
    mocked_process_search = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints.process_search')

    dfe_product.log = logging.getLogger('pytest_surveyor')

    with open(os.path.join(os.getcwd(), 'tests','data','dfe_surveyor_testing.json')) as f:
        programs = json.load(f)

    for program, criteria in programs.items():
        dfe_product.nested_process_search(Tag(program), criteria, {})

    mocked_process_search.assert_has_calls(
        [
            call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where FolderPath has_any ('notepad.exe') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceFileEvents | where FolderPath has_any ('current_date.txt') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceNetworkEvents | where RemoteIP has_any ('127.0.0.1') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where ProcessCommandLine has_any ('MiniDump') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceFileCertificateInfo | where Signer has_any ('Microsoft Publisher') | join kind=inner DeviceProcessEvents on $left.SHA1 == $right.SHA1 | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceNetworkEvents | where RemoteUrl has_any ('raw.githubusercontent.com') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where ProcessVersionInfoInternalFileName has_any ('powershell') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "union withsource=sourceTable DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents | where MD5 has_any ('asdfasdfasdfasdf') | extend proc_name = iff(sourceTable==\"DeviceProcessEvents\", FolderPath, InitiatingProcessFolderPath) | extend username = iff(sourceTable==\"DeviceProcessEvents\", AccountName, InitiatingProcessAccountName) | extend cmdline = iff(sourceTable==\"DeviceProcessEvents\", ProcessCommandLine, InitiatingProcessCommandLine) | project DeviceName, proc_name, username, cmdline | project-rename FolderPath=proc_name, AccountName=username, ProcessCommandLine=cmdline | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "union withsource=sourceTable DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents | where SHA1 has_any ('qwerqwerqwerqwer') | extend proc_name = iff(sourceTable==\"DeviceProcessEvents\", FolderPath, InitiatingProcessFolderPath) | extend username = iff(sourceTable==\"DeviceProcessEvents\", AccountName, InitiatingProcessAccountName) | extend cmdline = iff(sourceTable==\"DeviceProcessEvents\", ProcessCommandLine, InitiatingProcessCommandLine) | project DeviceName, proc_name, username, cmdline | project-rename FolderPath=proc_name, AccountName=username, ProcessCommandLine=cmdline | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "union withsource=sourceTable DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents | where SHA256 has_any ('zxcvzxcvzxcv') | extend proc_name = iff(sourceTable==\"DeviceProcessEvents\", FolderPath, InitiatingProcessFolderPath) | extend username = iff(sourceTable==\"DeviceProcessEvents\", AccountName, InitiatingProcessAccountName) | extend cmdline = iff(sourceTable==\"DeviceProcessEvents\", ProcessCommandLine, InitiatingProcessCommandLine) | project DeviceName, proc_name, username, cmdline | project-rename FolderPath=proc_name, AccountName=username, ProcessCommandLine=cmdline | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceImageLoadEvents | where FolderPath has_any ('pcwutl.dll') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('multiple_values', data=None), {}, "DeviceProcessEvents | where FolderPath has_any ('svchost.exe', 'cmd.exe') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('single_query', data=None), {}, "DeviceProcessEvents | where FileName contains \"rundll.exe\""),
            call(Tag('multiple_query', data=None), {}, "DeviceProcessEvents | where ProcessCommandLine contains \"-enc\""),
            call(Tag('multiple_query', data=None), {}, "DeviceImageLoadEvents | where FileName contains \"malware.dll\""),
            call(Tag('field_translation', data=None), {}, "union withsource=sourceTable DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents | where SHA1 has_any ('868b82e6f64ba1382d19378617fbd9f88fda1d87') | extend proc_name = iff(sourceTable==\"DeviceProcessEvents\", FolderPath, InitiatingProcessFolderPath) | extend username = iff(sourceTable==\"DeviceProcessEvents\", AccountName, InitiatingProcessAccountName) | extend cmdline = iff(sourceTable==\"DeviceProcessEvents\", ProcessCommandLine, InitiatingProcessCommandLine) | project DeviceName, proc_name, username, cmdline | project-rename FolderPath=proc_name, AccountName=username, ProcessCommandLine=cmdline | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "union withsource=sourceTable DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents | where MD5 has_any ('3082699dd8831685e69c237637671577') | extend proc_name = iff(sourceTable==\"DeviceProcessEvents\", FolderPath, InitiatingProcessFolderPath) | extend username = iff(sourceTable==\"DeviceProcessEvents\", AccountName, InitiatingProcessAccountName) | extend cmdline = iff(sourceTable==\"DeviceProcessEvents\", ProcessCommandLine, InitiatingProcessCommandLine) | project DeviceName, proc_name, username, cmdline | project-rename FolderPath=proc_name, AccountName=username, ProcessCommandLine=cmdline | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "union withsource=sourceTable DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents | where SHA256 has_any ('6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5') | extend proc_name = iff(sourceTable==\"DeviceProcessEvents\", FolderPath, InitiatingProcessFolderPath) | extend username = iff(sourceTable==\"DeviceProcessEvents\", AccountName, InitiatingProcessAccountName) | extend cmdline = iff(sourceTable==\"DeviceProcessEvents\", ProcessCommandLine, InitiatingProcessCommandLine) | project DeviceName, proc_name, username, cmdline | project-rename FolderPath=proc_name, AccountName=username, ProcessCommandLine=cmdline | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where SHA1 has_any ('0de422eddb71f0c119888da7edf1a716df4f4d31') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where MD5 has_any ('3896ff04bf87dabb38a6057a61312de7') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceProcessEvents | where SHA256 has_any ('061d9b82a348514cff4debc4cfacb0b73a356e4e8be14022310cf537981e9bfb') | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceFileEvents | where SHA1 has_any ('3f302c0ba1308d437efbd549a9291386d2e1f1c7') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceFileEvents | where MD5 has_any ('1e17a3e0531151fd473c68c532943b26') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceFileEvents | where SHA256 has_any ('f1801c46da23f109842d5004db8fb787dcfc958dd50d744e52fff0d32e8a007f') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceImageLoadEvents | where SHA1 has_any ('0650f91a37e9f20df9178546547cffe942534665') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceImageLoadEvents | where MD5 has_any ('3a90eb31cfb418f2ecdf996dfb85c94e') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
            call(Tag('field_translation', data=None), {}, "DeviceImageLoadEvents | where SHA256 has_any ('cf958d621bf5188e1ce17fdc056b1aee6b0aa24e26b5cf529c92b20821e05824') | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine"),
        ],
        any_order = True
    )

def test_nested_process_search_unsupported_field(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify nested_process_search() gracefully handles an unsupported field in a definition file
    """
    mocked_process_search = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints.process_search')

    criteria = {'foo': 'bar'}

    dfe_product.log = logging.getLogger('pytest_surveyor')

    dfe_product.nested_process_search(Tag('unsupported_field'), criteria, {})
    mocked_process_search.assert_not_called()

def test_process_search_build_query(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify process_search() correctly merges a given query with filter options
    """
    query = 'DeviceFileEvents | where FileName="bar foo"'
    filters = {
        'days':1,
        'minutes':2,
        'hostname':'server1',
        'username':'guest'
    }

    mocked_post_advanced_query = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._post_advanced_query')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._add_results')
    mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._get_default_header', return_value=None)

    dfe_product.log = logging.getLogger('pytest_surveyor')
    dfe_product._token = 'test_token_value'
    dfe_product.process_search(Tag('test123'), filters, query)
    mocked_post_advanced_query.assert_called_once_with(data={'Query': 'DeviceFileEvents | where FileName="bar foo" | where Timestamp > ago(1d) | where Timestamp > ago(2m) | where DeviceName contains "server1" | where AccountName contains "guest"'}, headers=None)

def test_nested_process_search_build_query(dfe_product : DefenderForEndpoints, mocker):
    """
    Verify nested_process_search() correctly merges a given query with filter options
    """
    criteria = {'query': 'DeviceFileEvents | where FileName="bar foo"'}
    filters = {
        'days':1,
        'minutes':2,
        'hostname':'server1',
        'username':'guest'
    }

    mocked_process_search = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints.process_search')

    dfe_product.nested_process_search(Tag('test123'), criteria, filters)
    mocked_process_search.assert_called_once_with(Tag('test123', data=None), {}, 'DeviceFileEvents | where FileName="bar foo" | where Timestamp > ago(1d) | where Timestamp > ago(2m) | where DeviceName contains "server1" | where AccountName contains "guest"')