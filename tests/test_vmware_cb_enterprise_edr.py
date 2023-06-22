import pytest
import sys
import os
import logging
import json
from datetime import datetime, timedelta
from unittest.mock import patch
sys.path.append(os.getcwd())
from products.vmware_cb_enterprise_edr import CbEnterpriseEdr
from common import Tag


@pytest.fixture
def cbc_product():
    with patch.object(CbEnterpriseEdr, "__init__", lambda x, y: None):
      return CbEnterpriseEdr(None)


def test_build_query_with_supported_field(cbc_product : CbEnterpriseEdr):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin'
    }

    cbc_product._device_group = ['accounting dept']
    cbc_product._device_policy = ['strict']

    result = cbc_product.build_query(filters)

    assert result == 'device_name:workstation1 process_username:admin (device_group:"accounting dept") (device_policy:"strict")'


def test_build_query_with_days(cbc_product: CbEnterpriseEdr):
    filters = {
        'days': 7
    }

    cbc_product._device_group = None
    cbc_product._device_policy = None

    result = cbc_product.build_query(filters)

    assert result.startswith('device_timestamp:[')
    assert result.endswith(']')
    assert ' TO ' in result
    timespan = result.replace('device_timestamp:[','').replace(']','').split(' TO ')
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    assert datetime.strptime(timespan[1], time_format) - timedelta(days=7) == datetime.strptime(timespan[0], time_format)


def test_build_query_with_min(cbc_product: CbEnterpriseEdr):
    filters = {
        'minutes': 30
    }

    cbc_product._device_group = None
    cbc_product._device_policy = None

    result = cbc_product.build_query(filters)

    assert result.startswith('device_timestamp:[')
    assert result.endswith(']')
    assert ' TO ' in result
    timespan = result.replace('device_timestamp:[','').replace(']','').split(' TO ')
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    assert datetime.strptime(timespan[1], time_format) - timedelta(minutes=30) == datetime.strptime(timespan[0], time_format)


def test_build_query_with_unsupported_field(cbc_product : CbEnterpriseEdr):
    filters = {
      "useless key": "asdfasdasdf"
    }

    cbc_product._device_group = None
    cbc_product._device_policy = None
    cbc_product.log = logging.getLogger('pytest_surveyor')

    result = cbc_product.build_query(filters)

    assert result == ''


def test_divide_chunks(cbc_product : CbEnterpriseEdr):
    entries = ['a','b','c','d','e']
    expected_results = [['a','b','c'],['d','e']]
    count = 3
    i = 0

    results = cbc_product.divide_chunks(l=entries, n=count)
    for item in results:
        assert item == expected_results[i]
        i += 1


def test_process_search(cbc_product : CbEnterpriseEdr, mocker):
    cbc_product._device_group = None
    cbc_product._device_policy = None
    cbc_product._results = {}
    mocker.patch.object(cbc_product, 'perform_query')
    cbc_product.process_search(Tag('test_field'), {}, 'process_name:cmd.exe')
    cbc_product.perform_query.assert_called_once_with(Tag('test_field'), 'process_name:cmd.exe')


def test_nested_process_search(cbc_product : CbEnterpriseEdr, mocker):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 'cbc_surveyor_testing.json')) as f:
        programs = json.load(f)
    
    cbc_product.log = logging.getLogger('pytest_surveyor')
    cbc_product._device_policy = None
    cbc_product._device_group = None
    cbc_product._results = {}
    cbc_product._conn = mocker.Mock()
    mocker.patch.object(cbc_product, 'perform_query')

    expected_calls = [
        mocker.call(Tag('field_translation'), '(process_name:notepad.exe)'),
        mocker.call(Tag('field_translation'), '(netconn_ipv4:127.0.0.1)'),
        mocker.call(Tag('field_translation'), '(process_cmdline:MiniDump)'),
        mocker.call(Tag('field_translation'), '(process_publisher:Microsoft)'),
        mocker.call(Tag('field_translation'), '(netconn_domain:raw.githubusercontent.com)'),
        mocker.call(Tag('field_translation'), '(process_internal_name:powershell)'),
        mocker.call(Tag('field_translation'), '(hash:asdfasdfasdfasdf)'),
        mocker.call(Tag('field_translation'), '(hash:zxcvzxcvzxcv)'),
        mocker.call(Tag('field_translation'), '((hash:3082699dd8831685e69c237637671577 OR hash:6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5))'),
        mocker.call(Tag('multiple_values'), '(process_name:svchost.exe OR process_name:cmd.exe)'),
        mocker.call(Tag('single_query'), '(process_name:rundll.exe)'),
        mocker.call(Tag('multiple_query'), '((process_cmdline:-enc) OR (modload_name:malware.dll))'),
        mocker.call(Tag('field_translation'), '((process_hash:3896ff04bf87dabb38a6057a61312de7 OR process_hash:061d9b82a348514cff4debc4cfacb0b73a356e4e8be14022310cf537981e9bfb))'),
        mocker.call(Tag('field_translation'), '((filemod_hash:1e17a3e0531151fd473c68c532943b26 OR filemod_hash:f1801c46da23f109842d5004db8fb787dcfc958dd50d744e52fff0d32e8a007f))'),
        mocker.call(Tag('field_translation'), '((modload_hash:3a90eb31cfb418f2ecdf996dfb85c94e OR modload_hash:cf958d621bf5188e1ce17fdc056b1aee6b0aa24e26b5cf529c92b20821e05824))')
    ]

    for program, criteria in programs.items():
        cbc_product.nested_process_search(Tag(program), criteria, {})
    cbc_product.perform_query.assert_has_calls(expected_calls, any_order=True)
