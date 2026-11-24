"""Where the client keeps what only it may hold: S, a rotation candidate S', the device key and the API token.

The operating-system keyring when one is really available (the optional `keyring` package with a working
backend), otherwise one owner-only file (0600, in a 0700 directory, written atomically). Nothing here is
ever sent anywhere, and the recovery phrase is never stored at all (contract 4a M4: shown once).
"""

import json
import os
from pathlib import Path
import stat
import tempfile

SERVICE = 'anamnesis.chat memory client'


class CustodyError(RuntimeError):
    pass


class FileCustody:
    kind = 'file'

    def __init__(self, path: Path):
        self.path = Path(path)

    def _check(self) -> None:
        info = self.path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CustodyError('custody_file_not_owner_only')

    def load(self) -> dict | None:
        if not self.path.exists():
            return None
        self._check()
        try:
            record = json.loads(self.path.read_text(encoding='utf-8'))
        except ValueError:
            raise CustodyError('custody_file_unreadable') from None
        if not isinstance(record, dict):
            raise CustodyError('custody_file_unreadable')
        return record

    def save(self, record: dict) -> None:
        write_private_json(self.path, record)

    def delete(self) -> None:
        if self.path.exists():
            self.path.unlink()


class KeyringCustody:
    kind = 'keyring'

    def __init__(self, keyring_module, account_key: str):
        self._keyring, self._account = keyring_module, account_key

    def load(self) -> dict | None:
        value = self._keyring.get_password(SERVICE, self._account)
        if value is None:
            return None
        try:
            record = json.loads(value)
        except ValueError:
            raise CustodyError('custody_keyring_unreadable') from None
        if not isinstance(record, dict):
            raise CustodyError('custody_keyring_unreadable')
        return record

    def save(self, record: dict) -> None:
        self._keyring.set_password(SERVICE, self._account, json.dumps(record, sort_keys=True))

    def delete(self) -> None:
        if self._keyring.get_password(SERVICE, self._account) is not None:
            self._keyring.delete_password(SERVICE, self._account)


def usable_keyring(module=None):
    """The keyring module when a real backend answers, else None (no fail/null/chainer-of-nothing backends)."""
    if module is None:
        try:
            import keyring as module  # optional dependency
        except ImportError:
            return None
    try:
        backend = module.get_keyring()
        priority = getattr(backend, 'priority', 0)
    except Exception:  # noqa: BLE001 - a broken desktop keyring must fall back, never crash the client
        return None
    name = type(backend).__module__ + '.' + type(backend).__name__
    if not isinstance(priority, (int, float)) or priority <= 0 or name.endswith(('fail.Keyring', 'null.Keyring')):
        return None
    return module


def open_custody(home: Path, account_key: str, preference: str, *, keyring_module=None):
    """preference is saved client configuration: 'auto' (keyring when usable), 'keyring' (required) or 'file'."""
    if preference not in ('auto', 'keyring', 'file'):
        raise CustodyError('custody_preference_invalid')
    if preference != 'file':
        module = usable_keyring(keyring_module)
        if module is not None:
            return KeyringCustody(module, account_key)
        if preference == 'keyring':
            raise CustodyError('custody_keyring_unavailable')
    return FileCustody(Path(home) / 'secrets' / f'{account_key}.json')


def write_private_json(path: Path, value) -> None:
    """Owner-only, atomic: a 0700 directory, a 0600 temporary file in it, fsync, then rename over the old one."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix='.tmp-', suffix='.json')
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def read_private_json(path: Path, default):
    path = Path(path)
    if not path.exists():
        return default
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise CustodyError('state_file_not_owner_only')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except ValueError:
        raise CustodyError('state_file_unreadable') from None
