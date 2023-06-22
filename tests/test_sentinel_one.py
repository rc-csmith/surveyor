import pytest
import sys
import os
import logging
import json
from datetime import datetime, timedelta
from unittest.mock import patch
sys.path.append(os.getcwd())
from products.sentinel_one import SentinelOne, Query
from common import Tag

@pytest.fixture
def s1_product():
    with patch.object(SentinelOne, "__init__", lambda x, y: None):
        return SentinelOne(None)

def test_build_query_with_supported_field_dv(s1_product : SentinelOne):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin'
    }
    s1_product._pq = False
    base, from_date, to_date = s1_product.build_query(filters)

    assert base == 'EndpointName containscis "workstation1" AND UserName containscis "admin"'

def test_build_query_time_filter_min(s1_product : SentinelOne):
    filters = {
        'minutes': 10
    }
    s1_product._pq = False
    base, from_date, to_date = s1_product.build_query(filters)

    assert to_date - timedelta(minutes=10) == from_date

def test_build_query_time_filter_day(s1_product : SentinelOne):
    filters = {
        'days': 7
    }
    s1_product._pq = False
    base, from_date, to_date = s1_product.build_query(filters)

    assert to_date - timedelta(days=7) == from_date

def test_build_query_with_supported_field_pq(s1_product : SentinelOne):
    filters = {
        'hostname': 'workstation2',
        'username': 'admin1'
    }
    s1_product._pq = True

    base, from_date, to_date = s1_product.build_query(filters)

    assert base == 'endpoint.name contains "workstation2" and src.process.user contains "admin1"'

def test_build_query_unsupported_keys(s1_product : SentinelOne):
    filters = {
        "useless key": "asdfasdfasdf"
    }
    s1_product._pq = False
    s1_product.log = logging.getLogger('pytest_surveyor')

    base, from_date, to_date = s1_product.build_query(filters)

    assert base == ''

def test_divide_chunks(s1_product : SentinelOne):
    entries = ['a','b','c','d','e']
    expected_results = [['a','b','c'],['d','e']]
    count = 3
    i = 0

    results = s1_product.divide_chunks(l=entries, n=count)
    for item in results:
        assert item == expected_results[i]
        i += 1

def test_process_search(s1_product : SentinelOne):
    s1_product.log = logging.getLogger('pytest_surveyor')
    s1_product._queries = {}

    s1_product.process_search(Tag('test_query'), {}, 'FileName containsCIS "svchost.exe"')

    assert len(s1_product._queries[Tag('test_query')]) == 1
    assert s1_product._queries[Tag('test_query')][0].parameter is None
    assert s1_product._queries[Tag('test_query')][0].operator is None
    assert s1_product._queries[Tag('test_query')][0].search_value is None
    assert s1_product._queries[Tag('test_query')][0].full_query == 'FileName containsCIS "svchost.exe"'
    assert s1_product._queries[Tag('test_query')][0].end_date - timedelta(days=14) == s1_product._queries[Tag('test_query')][0].start_date

def test_nested_process_search_dv(s1_product : SentinelOne):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 's1_surveyor_testing.json')) as f:
        programs = json.load(f)

    s1_product._queries = {}
    s1_product.log = logging.getLogger('pytest_surveyor')
    s1_product._pq = False

    for program, criteria in programs.items():
        s1_product.nested_process_search(Tag(program), criteria, {})
    
    assert len(s1_product._queries) == 5

    assert len(s1_product._queries[Tag('field_translation')]) == 25
    sdate = s1_product._queries[Tag('field_translation')][0].start_date
    edate = s1_product._queries[Tag('field_translation')][0].end_date
    assert Query(sdate, edate, 'ProcessName', 'containscis', '"notepad.exe"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'IP', 'containscis', '"127.0.0.1"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'CmdLine', 'containscis', '"MiniDump"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Publisher', 'containscis', '"Microsoft Publisher"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'DNS', 'containscis', '"raw.githubusercontent.com"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtFileInternalName', 'containscis', '"powershell"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Url', 'containscis', '"https://google.com"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'FilePath', 'containscis', '"current_date.txt"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'ModulePath', 'containscis', '"pcwutl.dll"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'SrcProcDisplayName', 'containscis', '"Evil Stuff Here"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Md5', 'containscis', '"asdfasdfasdfasdf"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Sha1', 'containscis', '"qwerqwerqwerqwer"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Sha256', 'containscis', '"zxcvzxcvzxcv"', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Sha1', 'in contains anycase', '("868b82e6f64ba1382d19378617fbd9f88fda1d87")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Md5', 'in contains anycase', '("3082699dd8831685e69c237637671577")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'Sha256', 'in contains anycase', '("6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtProcImageSha1', 'in contains anycase', '("0de422eddb71f0c119888da7edf1a716df4f4d31")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtProcImageMd5', 'in contains anycase', '("3896ff04bf87dabb38a6057a61312de7")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtProcImageSha256', 'in contains anycase', '("061d9b82a348514cff4debc4cfacb0b73a356e4e8be14022310cf537981e9bfb")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtFileSha1', 'in contains anycase', '("3f302c0ba1308d437efbd549a9291386d2e1f1c7")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtFileMd5', 'in contains anycase', '("1e17a3e0531151fd473c68c532943b26")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'TgtFileSha256', 'in contains anycase', '("f1801c46da23f109842d5004db8fb787dcfc958dd50d744e52fff0d32e8a007f")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'ModuleSha1', 'in contains anycase', '("0650f91a37e9f20df9178546547cffe942534665")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'ModuleMd5', 'in contains anycase', '("3a90eb31cfb418f2ecdf996dfb85c94e")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'ModuleSha256', 'in contains anycase', '("cf958d621bf5188e1ce17fdc056b1aee6b0aa24e26b5cf529c92b20821e05824")', None) in s1_product._queries[Tag('field_translation')]

    assert len(s1_product._queries[Tag('multiple_values')]) == 1
    sdate = s1_product._queries[Tag('multiple_values')][0].start_date
    edate = s1_product._queries[Tag('multiple_values')][0].end_date    
    assert Query(sdate, edate, 'ProcessName', 'in contains anycase', '("svchost.exe", "cmd.exe")', None) in s1_product._queries[Tag('multiple_values')]
    
    assert len(s1_product._queries[Tag('single_query')]) == 1
    sdate = s1_product._queries[Tag('single_query')][0].start_date
    edate = s1_product._queries[Tag('single_query')][0].end_date    
    assert Query(sdate, edate, 'query', 'raw', 'FileName containscis "rundll.exe"', None) in s1_product._queries[Tag('single_query')]
    
    assert len(s1_product._queries[Tag('multiple_query')]) == 1
    sdate = s1_product._queries[Tag('multiple_query')][0].start_date
    edate = s1_product._queries[Tag('multiple_query')][0].end_date
    assert Query(sdate, edate, 'query', 'raw', '(ProcessCmdLine contains "-enc") OR (ModulePath contains "malware.dll")', None) in s1_product._queries[Tag('multiple_query')]

def test_nested_process_search_pq(s1_product : SentinelOne):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 's1_surveyor_testing.json')) as f:
        programs = json.load(f)

    s1_product._queries = {}
    s1_product.log = logging.getLogger('pytest_surveyor')
    s1_product._pq = True

    for program, criteria in programs.items():
        s1_product.nested_process_search(Tag(program), criteria, {})
    
    assert len(s1_product._queries) == 5

    assert len(s1_product._queries[Tag('field_translation')]) == 34
    sdate = s1_product._queries[Tag('field_translation')][0].start_date
    edate = s1_product._queries[Tag('field_translation')][0].end_date
    assert Query(sdate, edate, 'tgt.process.name', 'in', '("notepad.exe")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'dst.ip.address', 'in', '("127.0.0.1")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.cmdline', 'in', '("MiniDump")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.publisher', 'in', '("Microsoft Publisher")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'url.address', 'in', '("raw.githubusercontent.com")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.internalName', 'in', '("powershell")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'url.address', 'in', '("https://google.com")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.path', 'in', '("current_date.txt")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.path', 'in', '("pcwutl.dll")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.displayName', 'in', '("Evil Stuff Here")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.md5', 'in', '("asdfasdfasdfasdf")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.sha256', 'in', '("zxcvzxcvzxcv")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.sha1', 'in', '("qwerqwerqwerqwer")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.md5', 'in', '("asdfasdfasdfasdf")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha256', 'in', '("zxcvzxcvzxcv")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha1', 'in', '("qwerqwerqwerqwer")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.md5', 'in', '("asdfasdfasdfasdf")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.sha1', 'in', '("qwerqwerqwerqwer")', None) in s1_product._queries[Tag('field_translation')]
    
    assert Query(sdate, edate, 'tgt.process.image.md5', 'in', '("3082699dd8831685e69c237637671577")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.sha256', 'in', '("6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.sha1', 'in', '("868b82e6f64ba1382d19378617fbd9f88fda1d87")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.md5', 'in', '("3082699dd8831685e69c237637671577")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha256', 'in', '("6430986b78211872682c2ef434614950d6c5a0a06f7540dfbfcf58aeee08c5c5")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha1', 'in', '("868b82e6f64ba1382d19378617fbd9f88fda1d87")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.md5', 'in', '("3082699dd8831685e69c237637671577")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.sha1', 'in', '("868b82e6f64ba1382d19378617fbd9f88fda1d87")', None) in s1_product._queries[Tag('field_translation')]
     
    assert Query(sdate, edate, 'tgt.process.image.md5', 'in', '("3896ff04bf87dabb38a6057a61312de7")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.sha256', 'in', '("061d9b82a348514cff4debc4cfacb0b73a356e4e8be14022310cf537981e9bfb")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.process.image.sha1', 'in', '("0de422eddb71f0c119888da7edf1a716df4f4d31")', None) in s1_product._queries[Tag('field_translation')]

    assert Query(sdate, edate, 'tgt.file.md5', 'in', '("1e17a3e0531151fd473c68c532943b26")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha256', 'in', '("f1801c46da23f109842d5004db8fb787dcfc958dd50d744e52fff0d32e8a007f")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'tgt.file.sha1', 'in', '("3f302c0ba1308d437efbd549a9291386d2e1f1c7")', None) in s1_product._queries[Tag('field_translation')]

    assert Query(sdate, edate, 'module.md5', 'in', '("3a90eb31cfb418f2ecdf996dfb85c94e")', None) in s1_product._queries[Tag('field_translation')]
    assert Query(sdate, edate, 'module.sha1', 'in', '("0650f91a37e9f20df9178546547cffe942534665")', None) in s1_product._queries[Tag('field_translation')]


    assert len(s1_product._queries[Tag('multiple_values')]) == 1
    sdate = s1_product._queries[Tag('multiple_values')][0].start_date
    edate = s1_product._queries[Tag('multiple_values')][0].end_date    
    assert Query(sdate, edate, 'tgt.process.name', 'in', '("svchost.exe", "cmd.exe")', None) in s1_product._queries[Tag('multiple_values')]
    
    assert len(s1_product._queries[Tag('single_query')]) == 1
    sdate = s1_product._queries[Tag('single_query')][0].start_date
    edate = s1_product._queries[Tag('single_query')][0].end_date    
    assert Query(sdate, edate, None, None, None, 'FileName containscis "rundll.exe"') in s1_product._queries[Tag('single_query')]
    
    assert len(s1_product._queries[Tag('multiple_query')]) == 1
    sdate = s1_product._queries[Tag('multiple_query')][0].start_date
    edate = s1_product._queries[Tag('multiple_query')][0].end_date
    assert Query(sdate, edate, None, None, None, '(ProcessCmdLine contains "-enc") or (ModulePath contains "malware.dll")') in s1_product._queries[Tag('multiple_query')]

def test_nested_process_search_unsupported_field(s1_product : SentinelOne):
    criteria = {'foo': 'bar'}
    s1_product._queries = {}
    s1_product._pq = False
    s1_product.log = logging.getLogger('pytest_surveyor')

    s1_product.nested_process_search(Tag('unsupported_field'), criteria, {})

    assert len(s1_product._queries) == 0

def test_get_query_text_handles_same_field_dv(s1_product : SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = False
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, 'ProcessName', 'containscis', '"svchost.exe"')],
        Tag('valueB'): [Query(sdate, edate, 'ProcessName', 'containscis', '"cmd.exe"')]
    }

    assert s1_product._get_query_text() == [(Tag('valueA,valueB', data=','), 'ProcessName in contains anycase ("svchost.exe", "cmd.exe")')]

def test_get_query_text_handles_different_fields_dv(s1_product : SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = False
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, 'ProcessName', 'containscis', '"posh.exe"')],
        Tag('valueB'): [Query(sdate, edate, 'ModulePath', 'containscis', '"evil.dll"')]
    }

    assert s1_product._get_query_text() == [
        (Tag('valueA', data=''), 'ProcessName in contains anycase ("posh.exe")'),
        (Tag('valueB', data=''), 'ModulePath in contains anycase ("evil.dll")')]

def test_get_query_text_handles_parameters_pq(s1_product: SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, 'endpoint.name', 'contains', '"dc01"')]
    }

    assert s1_product._get_query_text() == [
        (Tag('valueA', data=None), 'endpoint.name contains "dc01"')
    ]

def test_get_query_text_handles_full_query_pq(s1_product : SentinelOne):
    sdate = datetime.now()
    edate = sdate - timedelta(days=7)
    s1_product._pq = True
    s1_product._queries = {
        Tag('valueA'): [Query(sdate, edate, None, None, None, 'src.process.name contains "explorer.exe"')]
    }

    assert s1_product._get_query_text() == [
        (Tag('valueA', data=None), 'src.process.name contains "explorer.exe"')
    ]
