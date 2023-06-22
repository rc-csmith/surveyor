import logging

from cbapi.response import CbEnterpriseResponseAPI # type: ignore
from cbapi.response.models import Process # type: ignore

from common import Product, Tag, Result, hash_translation

SUPPORTED_HASH_TYPES: dict[str, dict[str,str]] = {
    'hash':{
        'MD5': 'md5',
        'SHA-256': 'sha256'
    },
    'process_hash':{
        'MD5': 'md5',
        'SHA-256': 'sha256'
    },
    'filemod_hash':{
        'MD5': 'filewrite_md5',
        'SHA-256': 'filewrite_sha256'
    },
    'modload_hash':{
        'MD5': 'md5',
        'SHA-256': 'sha256'
    }
}

class CbResponse(Product):
    product: str = 'cbr'
    _conn: CbEnterpriseResponseAPI  # CB Response API

    def __init__(self, profile: str, **kwargs):
        self._sensor_group = kwargs['sensor_group'] if 'sensor_group' in kwargs else None

        super().__init__(self.product, profile, **kwargs)

    def _authenticate(self) -> None:
        if self.profile:
            cb_conn = CbEnterpriseResponseAPI(profile=self.profile)
        else:
            cb_conn = CbEnterpriseResponseAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict) -> str:
        query_base = []

        for key, value in filters.items():
            if key == 'days':
                query_base.append('start:-%dm' % (value * 1440))
            elif key == 'minutes':
                query_base.append('start:-%dm' % value)
            elif key == 'hostname':
                query_base.append('hostname:%s' % value)
            elif key == 'username':
                query_base.append('username:%s' % value)
            else:
                self._echo(f'Query filter {key} is not supported by product {self.product}', logging.WARNING)

        if self._sensor_group:
            sensor_group = []
            for name in self._sensor_group:
                sensor_group.append('group:"%s"' % name)            
            query_base.append('(' + ' OR '.join(sensor_group) + ')')
        
        return ' '.join(query_base)

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        results = set()

        query += f' {self.build_query(base_query)}' if base_query != {} else ''
        self._echo(query)

        try:
            # noinspection PyUnresolvedReferences
            for proc in self._conn.select(Process).where(query):
                result = Result(proc.hostname.lower(), proc.username.lower(), proc.path, proc.cmdline,
                                (proc.start, proc.id))
                results.add(result)
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results: set = set()
        base_query_str = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                if search_field in SUPPORTED_HASH_TYPES.keys():
                    query_terms_list = []
                    hash_dict = hash_translation(terms, SUPPORTED_HASH_TYPES[search_field])
                    for hash_type, hash_values in hash_dict.items():
                        query_terms_list.append('(' + ' OR '.join('%s:%s' %(hash_type, hash_value) for hash_value in hash_values) + ')')
                    if len(query_terms_list) > 0:
                        query = '(' + ' OR '.join(query_terms_list) + ')'
                        query += f' {base_query_str}' if base_query_str != '' else ''
                        self.process_search(tag, {}, query)
                    else:
                        self._echo(f'None of the provided hashes are supported by product {self.product}',
                                   logging.WARNING)
                else:
                    if search_field == 'query':
                        if isinstance(terms, list):
                            if len(terms) > 1:
                                query = '((' + ') OR ('.join(terms) + '))'                            
                            else:
                                query = '(' + terms[0] + ')'
                        else:
                            query = terms
                    else:
                        terms = [(f'"{term}"' if ' ' in term else term) for term in terms]
                        query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'

                    query += f' {base_query_str}' if base_query_str != '' else ''
                    self.process_search(tag, {}, query)
        except Exception as e:
            self._echo(f'Error (see log for details): {e}', logging.ERROR)
            self.log.exception(e)
            pass
        except KeyboardInterrupt:
            self._echo("Caught CTRL-C. Returning what we have . . .")

        self._add_results(list(results), tag)

    def get_other_row_headers(self) -> list[str]:
        return ['Process Start', 'Process GUID']
