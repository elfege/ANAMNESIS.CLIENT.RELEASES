"""HTTP to the gateway: opaque envelopes out, opaque sealed replies back.

The gateway sees the bearer token, the username, the opaque project id and ciphertext; content, queries,
S and the response key travel only inside the envelope (contract S6). The bearer token itself must never
travel in clear text, so plain http:// is accepted for a loopback gateway only (a local test stack).
"""

import base64
import ipaddress
import re
from urllib.parse import quote, urlsplit

import httpx

from .errors import EmbeddingRefused, LocalStateError, MemoryClientError, Refused, ServiceUnavailable

CODE = re.compile(r'^[a-z][a-z0-9_]{2,63}$')
ENVELOPE = 'application/octet-stream'
# Failures raised while the connection was being made, before any byte of the request was written: the
# request certainly did not reach the gateway. Every other transport error leaves the outcome unknown.
NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)


def require_safe_base_url(base_url) -> str:
    """https:// anywhere; http:// only to a loopback host, so the bearer token never crosses a network in clear."""
    if not isinstance(base_url, str):
        raise LocalStateError('base_url_invalid')
    parts = urlsplit(base_url)
    if parts.scheme not in ('https', 'http') or not parts.hostname or parts.username or parts.password:
        raise LocalStateError('base_url_invalid')
    if parts.scheme == 'http':
        host = parts.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == 'localhost'
        if not loopback:
            raise LocalStateError('base_url_must_use_https')
    return base_url


class MemoryHttp:
    def __init__(self, base_url: str, username: str, token: str | None, *, http: httpx.Client | None = None,
                 timeout: float = 60.0):
        require_safe_base_url(base_url)
        self.root = base_url.rstrip('/') + '/' + quote(username, safe='') + '/api'
        self.token = token
        self.http = http or httpx.Client(timeout=timeout, follow_redirects=False)

    def _bearer(self) -> dict:
        if not self.token:
            raise MemoryClientError('api_token_required')
        return {'Authorization': 'Bearer ' + self.token}

    @staticmethod
    def _raise(response: httpx.Response):
        try:
            detail = response.json().get('detail')
        except (ValueError, AttributeError):
            detail = None
        retry = response.headers.get('retry-after')
        retry_after = int(retry) if retry and retry.isdigit() else None
        if isinstance(detail, str) and CODE.match(detail):
            error = EmbeddingRefused if detail == 'embedding_vector_invalid' else Refused
            refusal = error(detail, status=response.status_code, retry_after=retry_after)
            blob = response.headers.get('x-memory-sealed-new-share')
            if isinstance(blob, str) and len(blob) <= 180:
                try:
                    raw = base64.b64decode(blob + '=' * (-len(blob) % 4), altchars=b'-_', validate=True)
                except ValueError:
                    raw = b''
                if len(raw) == 133:
                    refusal.sealed_new_share = raw
            raise refusal
        text = detail if isinstance(detail, str) else None
        if response.status_code == 503:
            raise ServiceUnavailable('service_unavailable', status=503, retry_after=retry_after, detail=text)
        raise MemoryClientError(f'http_{response.status_code}', status=response.status_code, retry_after=retry_after,
                                detail=text)

    def capabilities(self) -> dict:
        response = self.http.get(self.root, headers=self._bearer())
        if response.status_code != 200:
            self._raise(response)
        return response.json()

    def attestation(self) -> bytes:
        """Public and bearer-free: the document is verified by the client, never trusted because of who relayed it."""
        response = self.http.get(self.root + '/attestation')
        if response.status_code != 200:
            self._raise(response)
        try:
            return base64.b64decode(response.json()['attestation'], validate=True)
        except (KeyError, TypeError, ValueError):
            raise MemoryClientError('attestation_response_invalid') from None

    def device(self, operation: str, envelope: bytes) -> bytes:
        response = self.http.post(f'{self.root}/devices/{operation}', content=envelope,
                                  headers={**self._bearer(), 'Content-Type': ENVELOPE})
        if response.status_code != 200:
            self._raise(response)
        return response.content

    def device_log(self) -> dict:
        response = self.http.get(self.root + '/devices/log', headers=self._bearer())
        if response.status_code != 200:
            self._raise(response)
        return response.json()

    def memory(self, verb: str, envelope: bytes, *, idempotency_key: str, project_id: str | None = None,
               token_budget: int | None = None, details: str | None = None) -> tuple[bytes, str | None]:
        params = {name: value for name, value in (('project_id', project_id), ('token_budget', token_budget),
                                                  ('details', details)) if value is not None}
        response = self.http.post(f'{self.root}/{verb}', content=envelope, params=params,
                                  headers={**self._bearer(), 'Content-Type': ENVELOPE, 'Idempotency-Key': idempotency_key})
        if response.status_code != 200:
            self._raise(response)
        return response.content, response.headers.get('x-memory-receipt')

    def close(self) -> None:
        self.http.close()
