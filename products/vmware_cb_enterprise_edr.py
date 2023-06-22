import datetime
import logging

from typing import Generator
import cbc_sdk.errors # type: ignore
from cbc_sdk.rest_api import CBCloudAPI # type: ignore
from cbc_sdk.platform import Process # type: ignore

from common import Product, Result, Tag, hash_translation

SUPPORTED_HASH_TYPES: dict[str,dict[str,str]] = {
    'hash':{
        'MD5': 'hash',
        'SHA-256': 'hash'
    },
    'process_hash':{
        'MD5': 'process_hash',
        'SHA-256': 'process_hash'
    },
    'filemod_hash':{
        'MD5': 'filemod_hash',
        'SHA-256': 'filemod_hash'
    },
    'modload_hash':{
        'MD5': 'modload_hash',
        'SHA-256': 'modload_hash'
    }
}

PARAMETER_MAPPING: dict[str, str] = {
    'process_name': 'process_name',
    'ipaddr': 'netconn_ipv4',
    'cmdline': 'process_cmdline',
    'digsig_publisher': 'process_publisher',
    'domain': 'netconn_domain',
    'internal_name': 'process_internal_name',
    'md5':'hash',
    'sha256':'hash'
}

def _convert_relative_time(relative_time) -> str:
    """
    Convert a Cb Response relative time boundary (i.e., start:-1440m) to a device_timestamp:
    device_timestamp:[2019-06-02T00:00:00Z TO 2019-06-03T23:59:00Z]
    """
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    minus_minutes = relative_time.split(':')[1].split('m')[0].split('-')[1]
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(minutes=int(minus_minutes))
    device_timestamp = 'device_timestamp:[{0} TO {1}]'.format(start_time.strftime(time_format),
                                                              end_time.strftime(time_format))
    return device_timestamp


class CbEnterpriseEdr(Product):
    product: str = 'cbc'
    _conn: CBCloudAPI  # CB Cloud API

    def __init__(self, profile: str, **kwargs):
        self._device_group = kwargs['device_group'] if 'device_group' in kwargs else None
        self._device_policy = kwargs['device_policy'] if 'device_group' in kwargs else None

        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self) -> None:
        if self.profile:
            cb_conn = CBCloudAPI(profile=self.profile)
        else:
            cb_conn = CBCloudAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict) -> str:
        query_base = []

        for key, value in filters.items():
            if key == "days":
                minutes_back = f'start:-{value * 1440}m'
                minutes_back = _convert_relative_time(minutes_back)
                query_base.append(minutes_back)
            elif key == "minutes":
                minutes_back = f'start:-{value}m'
                minutes_back = _convert_relative_time(minutes_back)
                query_base.append(minutes_back)
            elif key == "hostname":
                device_name = f'device_name:{value}'
                query_base.append(device_name)
            elif key == "username":
                user_name = f'process_username:{value}'
                query_base.append(user_name)
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        if self._device_group:
            device_group = []
            for name in self._device_group:
                device_group.append(f'device_group:"{name}"')
            query_base.append('(' + ' OR '.join(device_group) + ')')

        if self._device_policy:
            device_policy = []
            for name in self._device_policy:
                device_policy.append(f'device_policy:"{name}"')
            query_base.append('(' + ' OR '.join(device_policy) + ')')

        return ' '.join(query_base)

    def divide_chunks(self, l: list, n: int) -> Generator:
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def perform_query(self, tag: Tag, query: str) -> set[Result]:
        results = set()
        try:
            self.log.debug(f'Query {tag}: {query}')

            process = self._conn.select(Process)

            # noinspection PyUnresolvedReferences
            for proc in process.where(query):
                deets = proc.get_details()
                
                hostname = deets['device_name'] if 'device_name' in deets else 'None'
                user = deets['process_username'][0] if 'process_username' in deets else 'None'
                proc_name = deets['process_name'] if 'process_name' in deets else 'None'
                cmdline = deets['process_cmdline'][0] if 'process_cmdline' in deets else 'None'
                ts = deets['device_timestamp'] if 'device_timestamp' in deets else 'None'
                proc_guid = deets['process_guid'] if 'process_guid' in deets else 'Non'
                
                result = Result(hostname, user, proc_name, cmdline, (ts, proc_guid,))
                
                results.add(result)
        except cbc_sdk.errors.ApiError as e:
            self._echo(f'CbC SDK Error (see log for details): {e}', logging.ERROR)
            self.log.exception(e)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        return results

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        query += f' {self.build_query(base_query)}' if base_query != {} else ''
        results = self.perform_query(tag, query)

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results: list = []

        for search_field, terms in criteria.items():
            if search_field == 'query':
                if isinstance(terms, list):
                    if len(terms) > 1:
                        query = '(('+ ') OR ('.join(terms) + '))'
                    else:
                        query = '(' + terms[0] + ')'
                else:
                    query = terms
                query += f' {self.build_query(base_query)}' if base_query != {} else ''
                results += self.perform_query(tag, query)
            elif search_field in SUPPORTED_HASH_TYPES.keys():
                query_term_list = []
                hash_dict = hash_translation(terms, SUPPORTED_HASH_TYPES[search_field])
                for hash_type, hash_values in hash_dict.items():
                    query_term_list.append('(' + ' OR '.join('%s:%s' %(hash_type, hash_value) for hash_value in hash_values) + ')')
                if len(query_term_list) > 0:
                    query = '(' + ' OR '.join(query_term_list) + ')'
                    query += f' {self.build_query(base_query)}' if base_query != {} else ''
                    results += self.perform_query(tag, query)
                else:
                    self._echo(f'None of the provided hashes are supported by product {self.product}',
                        logging.WARNING)
            else:
                chunked_terms = list(self.divide_chunks(terms, 100))

                for chunk in chunked_terms:
                    # quote terms with spaces in them
                    terms = [(f'"{term}"' if ' ' in term else term) for term in chunk]

                    if search_field not in PARAMETER_MAPPING:
                        self._echo(f'Query filter {search_field} is not supported by product {self.product}',
                                logging.WARNING)
                        continue

                    query = '(' + ' OR '.join('%s:%s' % (PARAMETER_MAPPING[search_field], term) for term in terms) + ')'
                    query += f' {self.build_query(base_query)}' if base_query != {} else ''
                    results += self.perform_query(tag, query)

        self.log.debug(f'Nested search results: {len(results)}')
        self._add_results(list(results), tag)

    def get_other_row_headers(self) -> list[str]:
        return ['Device Timestamp', 'Process GUID']
