import pytest
import sys
import os
import logging
import json
from unittest.mock import patch
from cbapi.response.models import Process
sys.path.append(os.getcwd())
from products.vmware_cb_response import CbResponse
from common import Tag


@pytest.fixture
def cbr_product():
    with patch.object(CbResponse, "__init__", lambda x, y: None):
      return CbResponse(None)


def test_build_query_with_supported_field(cbr_product : CbResponse):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin', 
        'days': 1,
        'minutes': 10
    }

    cbr_product._sensor_group = ['accounting dept']

    result = cbr_product.build_query(filters)

    assert result == 'hostname:workstation1 username:admin start:-1440m start:-10m (group:"accounting dept")'


def test_build_query_with_unsupported_field(cbr_product : CbResponse):
    filters = {
      "useless key": "asdfasdasdf"
    }

    cbr_product._sensor_group = None
    cbr_product.log = logging.getLogger('pytest_surveyor')

    result = cbr_product.build_query(filters)

    assert result == ''


def test_process_search(cbr_product : CbResponse, mocker):
    cbr_product.log = logging.getLogger('pytest_surveyor')
    cbr_product._sensor_group = None
    cbr_product._results = {}
    cbr_product._conn = mocker.Mock()
    mocker.patch.object(cbr_product._conn, 'select')
    cbr_product.process_search(Tag('test_tag'), {}, 'process_name:cmd.exe')

    cbr_product._conn.select.assert_called_once_with(Process)
    cbr_product._conn.select.return_value.where.assert_called_once_with('process_name:cmd.exe')

def test_nested_process_search(cbr_product : CbResponse, mocker):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 'cbr_surveyor_testing.json')) as f:
        programs = json.load(f)
    
    cbr_product.log = logging.getLogger('pytest_surveyor')
    cbr_product._sensor_group = None
    cbr_product._results = {}
    cbr_product._conn = mocker.Mock()
    mocker.patch.object(cbr_product._conn, 'select')

    expected_calls = [
        mocker.call('(process_name:notepad.exe)'),
        mocker.call('(ipaddr:127.0.0.1)'),
        mocker.call('(cmdline:MiniDump)'),
        mocker.call('(digsig_publisher:Microsoft)'),
        mocker.call('(domain:raw.githubusercontent.com)'),
        mocker.call('(internal_name:powershell)'),
        mocker.call('(url:https://google.com)'),
        mocker.call('(filemod:current_date.txt)'),
        mocker.call('(modload:pcwutl.dll)'),
        mocker.call('(md5:asdfasdfasdfasdf)'),
        mocker.call('(sha1:qwerqwerqwerqwer)'),
        mocker.call('(sha256:zxcvzxcvzxcv)'),
        mocker.call('(process_name:svchost.exe OR process_name:cmd.exe)'),
        mocker.call('(process_name:rundll.exe)'),
        mocker.call('((cmdline:-enc) OR (modload:malware.dll))'),
        mocker.call('((md5:3082699dd8831685e69c237637671577) OR (sha256:6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5))'),
        mocker.call('((md5:3896ff04bf87dabb38a6057a61312de7) OR (sha256:061d9b82a348514cff4debc4cfacb0b73a356e4e8be14022310cf537981e9bfb))'),
        mocker.call('((filewrite_md5:1e17a3e0531151fd473c68c532943b26) OR (filewrite_sha256:f1801c46da23f109842d5004db8fb787dcfc958dd50d744e52fff0d32e8a007f))'),
        mocker.call('((md5:3a90eb31cfb418f2ecdf996dfb85c94e) OR (sha256:cf958d621bf5188e1ce17fdc056b1aee6b0aa24e26b5cf529c92b20821e05824))')
    ]

    for program, criteria in programs.items():
        cbr_product.nested_process_search(Tag(program), criteria, {})
    cbr_product._conn.select.return_value.where.assert_has_calls(expected_calls, any_order=True)
