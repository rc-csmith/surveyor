import pytest
import sys
import os
import logging
import json
from unittest.mock import patch
sys.path.append(os.getcwd())
from products.cortex_xdr import CortexXDR, Query
from common import Tag


@pytest.fixture
def cortex_product():
    with patch.object(CortexXDR, "__init__", lambda x, y: None):
        return CortexXDR(None)

def test_build_query_with_supported_field(cortex_product : CortexXDR):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin'
    }

    result, timestamp = cortex_product.build_query(filters)

    assert result == ' | filter agent_hostname contains "workstation1" | filter action_process_username contains "admin" or actor_primary_username contains "admin"'

def test_build_query_with_days(cortex_product : CortexXDR):
    filters = {
        'days': 7
    }

    result, timestamp = cortex_product.build_query(filters)

    assert timestamp == 7 * 24 * 60 * 60 * 1000

def test_build_query_with_min(cortex_product : CortexXDR):
    filters = {
        'minutes': 5
    }

    result, timestamp = cortex_product.build_query(filters)

    assert timestamp == 5 * 60 * 1000

def test_build_query_with_unsupported_field(cortex_product : CortexXDR):
    filters = {
      "useless key": "asdfasdasdf"
    }

    cortex_product.log = logging.getLogger('pytest_surveyor')

    result, timestamp = cortex_product.build_query(filters)

    assert result == ''

def test_process_search(cortex_product : CortexXDR):
    cortex_product._queries = {}
    cortex_product.log = logging.getLogger('pytest_surveyor')

    cortex_product.process_search(Tag('test_query'), {}, 'FieldA=ValueB')

    assert len(cortex_product._queries[Tag('test_query')]) == 1
    assert cortex_product._queries[Tag('test_query')][0].parameter is None
    assert cortex_product._queries[Tag('test_query')][0].operator is None
    assert cortex_product._queries[Tag('test_query')][0].search_value is None
    assert cortex_product._queries[Tag('test_query')][0].full_query == 'FieldA=ValueB'
    assert cortex_product._queries[Tag('test_query')][0].relative_time_ms == 14 * 24 * 60 * 60 * 1000

def test_nested_process_search(cortex_product : CortexXDR):
    cortex_product._queries = {}
    cortex_product.log = logging.getLogger('pytest_surveyor')

    with open(os.path.join(os.getcwd(), 'tests','data','cortex_surveyor_testing.json')) as f:
        programs = json.load(f)
    
    for program, criteria in programs.items():
        cortex_product.nested_process_search(Tag(program), criteria, {})
    
    assert len(cortex_product._queries) == 5

    assert len(cortex_product._queries[Tag('field_translation')]) == 22
    relative_ts = 14 * 24 * 60 * 60 * 1000
    assert Query(relative_ts, 'action_process_image_name', 'contains', '"cmd.exe"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_remote_ip', 'contains', '"8.8.8.8"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_command_line', 'contains', '"grep"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_signature_vendor', 'contains', '"Microsoft Corporation"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_module_path', 'contains', '"asdf.dll"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_path', 'contains', '"helloworld.txt"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_registry_key_name', 'contains', '"HKCU"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_md5', 'contains', '"asdfasdfasdf"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_sha256', 'contains', '"qwerqwerqwer"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_remote_port', 'contains', '"80"') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_md5', 'in', '("3082699dd8831685e69c237637671577")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_md5', 'in', '("3082699dd8831685e69c237637671577")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_module_md5', 'in', '("3082699dd8831685e69c237637671577")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_sha256', 'in', '("6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_sha256', 'in', '("6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_module_sha256', 'in', '("6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_md5', 'in', '("3896ff04bf87dabb38a6057a61312de7")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_process_image_sha256', 'in', '("061d9b82a348514cff4debc4cfacb0b73a356e4e8be14022310cf537981e9bfb")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_md5', 'in', '("1e17a3e0531151fd473c68c532943b26")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_file_sha256', 'in', '("f1801c46da23f109842d5004db8fb787dcfc958dd50d744e52fff0d32e8a007f")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_module_md5', 'in', '("3a90eb31cfb418f2ecdf996dfb85c94e")') in cortex_product._queries[Tag('field_translation')]
    assert Query(relative_ts, 'action_module_sha256', 'in', '("cf958d621bf5188e1ce17fdc056b1aee6b0aa24e26b5cf529c92b20821e05824")') in cortex_product._queries[Tag('field_translation')]

    assert len(cortex_product._queries[Tag('multiple_values')]) == 1
    assert Query(relative_ts, 'action_process_image_name', 'in', '("*svchost.exe*", "*services.exe*")') in cortex_product._queries[Tag('multiple_values')]

    assert len(cortex_product._queries[Tag('single_query')]) == 1
    assert Query(relative_ts, None, None, None, 'FieldA=ValueB') in cortex_product._queries[Tag('single_query')]

    assert len(cortex_product._queries[Tag('multiple_query')]) == 2
    assert Query(relative_ts, None, None, None, 'FieldA=ValueB') in cortex_product._queries[Tag('multiple_query')]
    assert Query(relative_ts, None, None, None, 'FieldC=ValueD') in cortex_product._queries[Tag('multiple_query')]

def test_nested_process_search_unsupported_field(cortex_product : CortexXDR):
    criteria = {'foo': 'bar'}
    cortex_product._queries = {}
    cortex_product.log = logging.getLogger('pytest_surveyor')

    cortex_product.nested_process_search(Tag('unsupported_field'), criteria, {})

    assert len(cortex_product._queries) == 1
    assert cortex_product._queries[Tag('unsupported_field')] == []

def test_process_queries_full_query(cortex_product : CortexXDR, mocker):
    cortex_product._queries = {}
    cortex_product._results = {}

    cortex_product._url = 'https://cortex.xdr.domain'
    mocker.patch('products.cortex_xdr.CortexXDR._get_default_header', return_value = {})

    criteria = {'query': ['FieldA=cmd.exe']}
    cortex_product.nested_process_search(Tag('single_test'), criteria, {})

    cortex_product.log = logging.getLogger('pytest_surveyor')

    json_response = {'reply': []}
    response_mock = mocker.Mock()
    response_mock.json.return_value = json_response

    cortex_product._session = mocker.Mock()
    mocker.patch('products.cortex_xdr.CortexXDR._get_xql_results', return_value= [[], 0])
    mocked_func = mocker.patch.object(cortex_product._session, 'post', return_value=response_mock)

    cortex_product._process_queries()

    params = {
        'request_data':{
            'query': 'FieldA=cmd.exe | fields agent_hostname, action_process_image_path, action_process_username, action_process_image_command_line, actor_process_image_path, actor_primary_username, actor_process_command_line, event_id',
            'tenants': [],
            'timeframe':{'relativeTime': 14*24*60*60*1000 }
        }
    }

    mocked_func.assert_called_once_with('https://cortex.xdr.domain/public_api/v1/xql/start_xql_query/', headers={}, data=json.dumps(params))

def test_process_queries_query_parameter(cortex_product : CortexXDR, mocker):
    cortex_product._queries = {}
    cortex_product._results = {}

    cortex_product._url = 'https://cortex.xdr.domain'
    mocker.patch('products.cortex_xdr.CortexXDR._get_default_header', return_value = {})

    criteria = {'process_name': ['cmd.exe']}
    cortex_product.nested_process_search(Tag('single_test'), criteria, {})

    cortex_product.log = logging.getLogger('pytest_surveyor')

    json_response = {'reply': []}
    response_mock = mocker.Mock()
    response_mock.json.return_value = json_response

    cortex_product._session = mocker.Mock()
    mocker.patch('products.cortex_xdr.CortexXDR._get_xql_results', return_value= [[], 0])
    mocked_func = mocker.patch.object(cortex_product._session, 'post', return_value=response_mock)

    cortex_product._process_queries()

    params = {
        'request_data':{
            'query': 'dataset=xdr_data | filter action_process_image_name contains "cmd.exe" | fields agent_hostname, action_process_image_path, action_process_username, action_process_image_command_line, actor_process_image_path, actor_primary_username, actor_process_command_line, event_id',
            'tenants': [],
            'timeframe':{'relativeTime': 14*24*60*60*1000 }
        }
    }

    mocked_func.assert_called_once_with('https://cortex.xdr.domain/public_api/v1/xql/start_xql_query/', headers={}, data=json.dumps(params))