"""Saved client configuration: where the gateway is, whose memory, what enclave to accept, how to wait.

Nothing has a default the user did not save except the transient-retry schedule, whose defaults are stated
once here and saved with the rest by `anamnesis-memory init` (edit `client.json` to change them). The base
URL, the username and the attestation policy (the published measurements; the trust anchor is pinned in the
package) come from `init`.

The attestation policy is read through a loader. Every shipped entry point uses `attestation.load_policy`,
which accepts AWS Nitro only; the qualification tests pass their own test-only loader, which is the only way
a non-Nitro verifier can exist in a process.
"""

from dataclasses import asdict, dataclass, field
import hashlib
from pathlib import Path
from typing import Callable

from .attestation import load_policy
from .custody import read_private_json, write_private_json
from .errors import LocalStateError
from .transport import require_safe_base_url

CONFIG_FILE = 'client.json'


@dataclass(frozen=True)
class TransientRetry:
    """How long the client waits on a TRANSIENT service fault (503, 502, 504, 429) before giving up.

    attempts: retries after the first try; the delay doubles from initial_delay_seconds up to
    max_delay_seconds. A Retry-After the service sends wins, but never beyond max_delay_seconds: a longer
    wait gives up at once (the work stays pending and a rerun resumes it).
    """
    attempts: int = 3
    initial_delay_seconds: float = 2.0
    max_delay_seconds: float = 60.0

    @classmethod
    def load(cls, value) -> 'TransientRetry':
        if value is None:
            return cls()
        if not isinstance(value, dict) or set(value) - set(cls.__dataclass_fields__):
            raise LocalStateError('client_config_invalid')
        retry = cls(**value)
        if (type(retry.attempts) is not int or not 0 <= retry.attempts <= 20
                or not isinstance(retry.initial_delay_seconds, (int, float)) or not isinstance(retry.max_delay_seconds, (int, float))
                or not 0 < retry.initial_delay_seconds <= retry.max_delay_seconds <= 3600):
            raise LocalStateError('client_config_invalid')
        return retry

    def delay(self, attempt: int, retry_after: int | None) -> float | None:
        """The wait before retry number `attempt` (0-based), or None to give up now."""
        if attempt >= self.attempts:
            return None
        if retry_after is not None:
            return float(retry_after) if retry_after <= self.max_delay_seconds else None
        return min(self.max_delay_seconds, self.initial_delay_seconds * (2 ** attempt))


@dataclass(frozen=True)
class ClientConfig:
    base_url: str
    username: str
    attestation: object  # AttestationPolicy, or a test-only policy object with verify() and to_json()
    custody: str = 'auto'
    transient_retry: TransientRetry = field(default_factory=TransientRetry)

    def __post_init__(self):
        require_safe_base_url(self.base_url)
        from urllib.parse import urlsplit
        if urlsplit(self.base_url).hostname == 'anamnesis.chat' and getattr(self.attestation, 'kind', None) == 'nitro':
            from .attestation import AttestationRefused
            from .release import installed_policy
            if self.attestation.to_json() != installed_policy().to_json():
                raise AttestationRefused('production_policy_not_in_installed_release')

    @property
    def account_key(self) -> str:
        """A stable local name for this (gateway, username) pair; it never leaves the device."""
        return hashlib.sha256(f'{self.base_url.rstrip("/")}|{self.username}'.encode('utf-8')).hexdigest()[:32]

    def to_json(self) -> dict:
        return {'base_url': self.base_url, 'username': self.username, 'attestation': self.attestation.to_json(),
                'custody': self.custody, 'transient_retry': asdict(self.transient_retry)}

    @classmethod
    def from_json(cls, value, *, policy_loader: Callable = load_policy) -> 'ClientConfig':
        if not isinstance(value, dict) or set(value) - {'base_url', 'username', 'attestation', 'custody', 'transient_retry'}:
            raise LocalStateError('client_config_invalid')
        base_url, username = value.get('base_url'), value.get('username')
        if not isinstance(base_url, str) or not isinstance(username, str) or not username:
            raise LocalStateError('client_config_invalid')
        return cls(base_url.rstrip('/'), username, policy_loader(value.get('attestation')), value.get('custody', 'auto'),
                   TransientRetry.load(value.get('transient_retry')))

    def save(self, home: Path) -> None:
        write_private_json(Path(home) / CONFIG_FILE, self.to_json())

    @classmethod
    def load(cls, home: Path, *, policy_loader: Callable = load_policy) -> 'ClientConfig':
        value = read_private_json(Path(home) / CONFIG_FILE, None)
        if value is None:
            raise LocalStateError('client_not_initialised')
        return cls.from_json(value, policy_loader=policy_loader)
