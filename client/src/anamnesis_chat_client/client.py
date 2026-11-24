"""The minimal memory client that holds the tenant secret S (TODO 5659; contract 4a, device signatures).

Every request is sealed on this device to an enclave key this device verified itself, carries S, and is
answered in a reply only this device can open. The client follows the contract's client rules:

- `request_replayed` and `manifest_version_conflict`: the SAME document again in a FRESH envelope, once.
- `request_sealed_before_enclave_boot` and `enclave_key_unknown`: fetch and verify the attestation, re-seal once.
- `share_rotated`: retry once with the current S if custody holds a newer one; if a rotation candidate S' is
  pending, settle it first (S' then S), then retry with whichever is current; otherwise surface.
- `embedding_vector_invalid`: never resent automatically (pricing lane 85486); surfaced as "could not be processed".
- `key_share_invalid`, `tenant_not_enrolled`, `tenant_has_data_without_registry` on a settled S: an ALARM,
  never a re-enrolment, never discarding S (QC 72138 F3).

Coded refusals are plaintext the untrusted parent relays: only a reply sealed to this request and signed by the
attested enclave proves anything. So no secret is ever discarded because of a refusal code:

- Enrolment: the first S is persisted (as pending) before the request leaves and is never dropped on a refusal;
  `resume_enrolment` probes it, and `recover` replaces it with the account's current S.
- Rotation (contract 4a.2, QC 72162): one candidate S' at a time, persisted before the request leaves, kept with
  S. Any outcome other than the enclave's signed reply is ambiguous and settled by probing `devices/list` with S'
  first, then S; whichever answers with a signed view is current. S' is dropped only when it certainly never
  left this device, or when S answered with a signed view AFTER the rotate envelope's replay window (plus the
  future skew) closed, so a withheld envelope can no longer commit it. Both refused: an alarm, both kept.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
from typing import Callable
from uuid import UUID

import httpx

from . import __version__
from .attestation import AttestedEnclave
from .bip39 import new_entropy, phrase_from_entropy, recovery_entropy
from .config import ClientConfig
from .custody import open_custody, read_private_json, write_private_json
from .errors import (CREDENTIAL_ALARMS, CredentialAlarm, LocalStateError, MemoryClientError, MemorySetAside, Refused,
                     ServiceUnavailable)
from .sealing import (DeviceKey, RecoveryKeys, SealedRequest, SealingError, b64url, decode_b64, new_share, seal_request,
                      verify_registry_view, verify_device_log)
from .transport import NOT_SENT, MemoryHttp

FRESH_ENVELOPE = frozenset({'request_replayed', 'manifest_version_conflict'})
RESEAL = frozenset({'request_sealed_before_enclave_boot', 'enclave_key_unknown'})
CLIENT_NAME = 'anamnesis-chat-client'
CANDIDATE_FIELDS = ('candidate_share', 'candidate_expires_at')


@dataclass(frozen=True)
class Enrolment:
    """A first-device enrolment prepared locally: the phrase is shown once and must be typed back."""
    phrase: str
    share: bytes
    device: DeviceKey
    recovery: RecoveryKeys
    key_storage: str


@dataclass(frozen=True)
class Rotation:
    """The outcome of a rotation or of settling one.

    rotated: S' is now this device's S. Otherwise S is current (the registry view proves it) and, when
    pending_until is set, the candidate S' is kept until then, because the rotate envelope could still be
    delivered; `settle-rotation` after that time drops it (or adopts it, if it was committed meanwhile).
    reason: the code the rotate request itself was answered with, when it did not complete.
    """
    rotated: bool
    registry: dict
    pending_until: str | None = None
    reason: str | None = None

    def to_json(self) -> dict:
        body = {'rotated': self.rotated, 'registry': self.registry}
        if self.pending_until is not None:
            body['candidate_pending_until'] = self.pending_until
        if self.reason is not None:
            body['reason'] = self.reason
        return body


def utc_millis(value) -> str:
    """Contract section 4: occurred_at is RFC 3339 UTC with the Z suffix and exactly millisecond precision."""
    if isinstance(value, str):
        moment = datetime.fromisoformat(value.strip().replace('z', 'Z'))
    elif isinstance(value, datetime):
        moment = value
    else:
        raise MemoryClientError('timestamp_invalid')
    if moment.tzinfo is None:
        raise MemoryClientError('timestamp_without_zone')
    moment = moment.astimezone(timezone.utc)
    return moment.strftime('%Y-%m-%dT%H:%M:%S.') + f'{moment.microsecond // 1000:03d}Z'


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def record_id(source: dict) -> str:
    """ObjectIdDerivation (contract schema): computed identically by every client and by the enclave."""
    return hashlib.sha256('|'.join(['cm1', source['client']['name'], source['session_id'], source['message_id'],
                                    str(source['revision']), source['content_hash']]).encode('utf-8')).hexdigest()


def published_int(limits: dict, name: str, *, minimum: int = 1) -> int:
    """A limit the gateway publishes in its capabilities; the client never substitutes a value of its own."""
    value = limits.get(name)
    if type(value) is not int or value < minimum:
        raise ServiceUnavailable('memory_limits_unavailable', detail=name)
    return value


class MemoryClient:
    def __init__(self, config: ClientConfig, *, home: Path, http: httpx.Client | None = None, custody=None,
                 keyring_module=None, clock=None):
        self.config, self.home = config, Path(home)
        self.custody = custody or open_custody(self.home, config.account_key, config.custody,
                                               keyring_module=keyring_module)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.api = MemoryHttp(config.base_url, config.username, (self._record() or {}).get('api_token'), http=http)
        self._enclave: AttestedEnclave | None = None
        self._capabilities: dict | None = None

    # -- local custody and state ------------------------------------------------------------------------
    def _record(self) -> dict:
        return self.custody.load() or {}

    def _store(self, **changes) -> dict:
        record = self._record()
        for key, value in changes.items():
            if value is None:
                record.pop(key, None)
            else:
                record[key] = value
        self.custody.save(record)
        return record

    @property
    def state_path(self) -> Path:
        return self.home / 'state' / f'{self.config.account_key}.json'

    def _state(self) -> dict:
        return read_private_json(self.state_path, {})

    def _save_state(self, state: dict) -> None:
        write_private_json(self.state_path, state)

    def set_api_token(self, token: str) -> None:
        if not isinstance(token, str) or not token.strip():
            raise LocalStateError('api_token_required')
        self._store(api_token=token.strip())
        self.api.token = token.strip()

    def _share(self, name: str = 'share') -> bytes:
        value = self._record().get(name)
        if value is None:
            raise LocalStateError('not_enrolled_on_this_device' if name == 'share' else f'{name}_absent')
        return decode_b64(value, length=32)

    def _device_key(self) -> DeviceKey | None:
        record = self._record()
        pem, encryption = record.get('device_key'), record.get('device_encryption_key')
        if pem is None:
            return None
        return DeviceKey.from_pem(pem.encode('ascii'), encryption.encode('ascii') if encryption else None)

    @staticmethod
    def _device_identifier(item):
        return item.get('device_id') or item.get('label')

    @property
    def rotation_requires_phrase(self) -> bool:
        device = self._device_key()
        return device is None or not device.phase2

    @property
    def enrolled(self) -> bool:
        return 'share' in self._record()

    # -- discovery -----------------------------------------------------------------------------------------
    def capabilities(self, *, refresh: bool = False) -> dict:
        if self._capabilities is None or refresh:
            self._capabilities = self.api.capabilities()
        return self._capabilities

    def _limits(self) -> dict:
        limits = self.capabilities().get('limits')
        return limits if isinstance(limits, dict) else {}

    @property
    def tenant_public_id(self) -> str:
        """The account's tenant id, PINNED in custody once this device holds a secret for it.

        Before that it is the authenticated capabilities answer (trust on first use, for this token's own
        account). After it, a different answer from the gateway is an alarm, never a silent re-binding.
        """
        served = self.capabilities().get('tenant_public_id')
        try:
            served = str(UUID(str(served)))
        except ValueError:
            raise ServiceUnavailable('tenant_identity_unavailable') from None
        pinned = self._record().get('tenant_public_id')
        if pinned is not None and pinned != served:
            raise CredentialAlarm('tenant_identity_changed')
        return served

    def enclave(self, *, refresh: bool = False) -> AttestedEnclave:
        """Fetched from the gateway, VERIFIED here against the saved policy; never trusted for who relayed it."""
        if self._enclave is None or refresh:
            self._enclave = self.config.attestation.verify(self.api.attestation())
        return self._enclave

    # -- rollback detection (design 0.5.5, contract B2): detection only, after the fact --------------------
    def _observe(self, registry: dict | None = None, manifests: dict | None = None) -> list[str]:
        """A lower registry version is refused (an alarm); a lower manifest version is a warning (contract 3.8)."""
        state, warnings = self._state(), []
        if registry is not None:
            seen = state.get('registry', {'epoch': 0, 'version': 0})
            epoch, version = int(registry['epoch']), int(registry['version'])
            if epoch < seen['epoch'] or version < seen['version']:
                raise CredentialAlarm('registry_rollback_detected')
            state['registry'] = {'epoch': epoch, 'version': version}
        if manifests:
            known = state.setdefault('manifests', {})
            for segment, version in manifests.items():
                if version is None:
                    continue
                if int(version) < known.get(segment, 0):
                    warnings.append('manifest_rollback_detected')  # keep the highest version seen
                    continue
                known[segment] = int(version)
        self._save_state(state)
        return warnings

    # -- devices this device authorised (contract 4a.2: alert on any device the client did not authorise) ----
    def _own_label(self) -> str | None:
        pem = self._record().get('device_key')
        return DeviceKey.from_pem(pem.encode('ascii')).device_id if pem else None

    def _trust_devices(self, view: dict) -> None:
        """At enrolment or recovery the user is present and establishes the device set (trust on first use)."""
        state = self._state()
        labels = {self._device_identifier(item) for item in view['devices'] if isinstance(item, dict)}
        state['devices_known'] = sorted(label for label in labels | {self._own_label()} if isinstance(label, str))
        self._save_state(state)

    def _annotated(self, view: dict) -> dict:
        """The signed view, plus the devices this client never authorised (an alert for the user)."""
        known = set(self._state().get('devices_known', [])) | {self._own_label()}
        unknown = sorted(self._device_identifier(item) for item in view['devices']
                         if isinstance(item, dict) and self._device_identifier(item) not in known)
        result = dict(view)
        if unknown:
            result['unrecognised_devices'] = unknown
        return result

    # -- one sealed round trip -----------------------------------------------------------------------------
    @staticmethod
    def _classify(error: Refused) -> Refused:
        if error.code in CREDENTIAL_ALARMS:
            return CredentialAlarm(error.code, status=error.status)
        if error.code == 'generation_detached':
            return MemorySetAside(error.code, status=error.status)
        return error

    def _round_trip(self, send: Callable[[SealedRequest], bytes], document: dict, *, operation: str,
                    share_name: str | None = 'share', recovery: RecoveryKeys | None = None,
                    project_id: str | None = None, retry: bool = True, settle: bool = True, device_key: DeviceKey | None = None):
        """Seal, send and open, applying the contract's retry rules. send(sealed request) -> reply bytes."""
        fresh_used = resealed = share_retried = False
        verified_candidate = None
        device = device_key or self._device_key()
        signed_device = device if device is not None and device.phase2 else None
        share = self._share(share_name) if share_name else None
        while True:
            enclave = self.enclave()
            sealed = seal_request(enclave.enclave_public_key, self.tenant_public_id, document, operation=operation,
                                  key_share=share, recovery=recovery, project_id=project_id, clock=self.clock,
                                  device=signed_device if recovery is None else None,
                                  device_id=signed_device.device_id if signed_device is not None and recovery is not None else None)
            try:
                reply = send(sealed)
            except Refused as error:
                if retry and error.code in FRESH_ENVELOPE and not fresh_used:
                    fresh_used = True  # the SAME document in a FRESH envelope (new request_id and issued_at)
                    continue
                if retry and error.code in RESEAL and not resealed:
                    resealed, self._enclave = True, None
                    continue
                if retry and error.code == 'share_rotated' and not share_retried and share_name == 'share':
                    share_retried = True
                    blob = getattr(error, 'sealed_new_share', None)
                    newer = None
                    if blob is not None and signed_device is not None:
                        try:
                            epoch, newer = signed_device.open_share(blob, tenant_public_id=self.tenant_public_id)
                        except SealingError:
                            raise CredentialAlarm('sealed_share_invalid') from None
                        if epoch < self._state().get('registry', {}).get('epoch', 0):
                            raise CredentialAlarm('registry_rollback_detected')
                        verified_candidate = newer
                    if newer is None:
                        newer = self._newer_share(share, settle=settle)
                    if newer is not None:
                        share = newer
                        continue
                raise self._classify(error) from None
            try:
                opened = sealed.open(reply)
                if verified_candidate is not None:
                    # A header is untrusted. Adopt its candidate only after this enclave accepted it and sealed a reply.
                    self._store(share=b64url(verified_candidate))
                return opened, enclave
            except SealingError as error:
                raise MemoryClientError(str(error)) from None

    def _newer_share(self, share: bytes, *, settle: bool) -> bytes | None:
        """After share_rotated: a newer S already in custody, or the pending candidate S' if it is now current."""
        current = self._share()
        if current != share:
            return current
        if settle and 'candidate_share' in self._record() and self.settle_rotation().rotated:
            return self._share()
        return None

    def _device(self, route: str, document: dict, *, send: Callable | None = None, **kwargs) -> tuple[dict, dict]:
        operation = 'device.' + route
        opened, enclave = self._round_trip(send or (lambda sealed: self.api.device(route, sealed.envelope)), document,
                                           operation=operation, **kwargs)
        try:
            view = verify_registry_view(opened, signing_public_key=enclave.signing_public_key,
                                        tenant_public_id=self.tenant_public_id)
        except SealingError as error:
            raise CredentialAlarm(str(error)) from None
        state = self._state()
        if view.get('auth_phase') == 2:
            try:
                proof = verify_device_log(opened, tenant_public_id=self.tenant_public_id,
                                          previous=state.get('device_log'))
            except SealingError as error:
                raise CredentialAlarm(str(error)) from None
            record = self.api.device_log()
            for head in record.get('heads', []):
                size = head.get('log_size')
                if (head.get('registry_id') == proof['registry_id'] and type(size) is int
                        and 0 < size <= len(proof['heads']) and proof['heads'][size - 1] != head.get('log_head')):
                    raise CredentialAlarm('device_log_equivocation')
            if any(row.get('registry_id') == proof['registry_id'] for row in record.get('equivocations', [])):
                raise CredentialAlarm('device_log_equivocation')
            state['device_log'] = proof
            self._save_state(state)
        elif self._device_key() is not None and self._device_key().phase2:
            raise CredentialAlarm('device_authentication_downgraded')
        self._observe(registry=view)
        return opened, view

    def _memory(self, verb: str, document: dict, *, operation: str, project_id: str | None = None,
                token_budget: int | None = None, details: str | None = None) -> dict:
        receipts = []

        def send(sealed):
            body, receipt = self.api.memory(verb, sealed.envelope, idempotency_key=self._idempotency_key(),
                                            project_id=project_id, token_budget=token_budget, details=details)
            receipts.append(receipt)
            return body

        reply, _ = self._round_trip(send, document, operation=operation, project_id=project_id)
        segment = reply.get('segment') if isinstance(reply.get('segment'), dict) else {}
        manifests = dict(segment.get('manifests') or {})
        if 'key' in segment and segment.get('manifest_version') is not None:
            manifests[segment['key']] = segment['manifest_version']
        registry = reply.get('registry')
        proof = self._state().get('device_log')
        if proof is not None:
            size = registry.get('log_size') if isinstance(registry, dict) else None
            if type(size) is not int or size < len(proof['heads']):
                raise CredentialAlarm('device_log_rollback_detected')
            if size > len(proof['heads']):
                self.devices()
                proof = self._state()['device_log']
            if size and proof['heads'][size - 1] != registry.get('log_head'):
                raise CredentialAlarm('device_log_fork_detected')
        warnings = self._observe(registry=registry, manifests=manifests)
        if warnings:
            reply['warnings'] = sorted(set(warnings))
        reply['receipt'] = receipts[-1] if receipts else None
        return reply

    def _idempotency_key(self) -> str:
        limits = self._limits()
        low = published_int(limits, 'idempotency_key_min_chars')
        high = published_int(limits, 'idempotency_key_max_chars', minimum=low)
        length = max(low, min(high, 43))  # 43 base64url characters carry 256 random bits
        return secrets.token_urlsafe(length)[:length]

    # -- devices (contract 4a.2) ---------------------------------------------------------------------------
    def begin_enrolment(self, *, key_storage: str = 'software') -> Enrolment:
        record = self._record()
        if 'share' in record:
            raise LocalStateError('already_enrolled_on_this_device')
        if 'pending_share' in record:
            raise LocalStateError('enrolment_pending_resume_it')
        if key_storage not in ('software', 'hardware'):
            raise LocalStateError('key_storage_invalid')
        if key_storage == 'hardware':
            raise LocalStateError('hardware_key_provider_unavailable')
        entropy = new_entropy()
        device = DeviceKey.generate()
        if record.get('auth_phase') == 1:
            device = DeviceKey.from_pem(device.to_pem())
        return Enrolment(phrase_from_entropy(entropy), new_share(), device, RecoveryKeys(entropy), key_storage)

    def complete_enrolment(self, enrolment: Enrolment, typed_phrase: str) -> dict:
        """Only after the user typed the phrase back; S, the device key and the tenant are persisted BEFORE sending."""
        if ' '.join(str(typed_phrase).lower().split()) != enrolment.phrase:
            raise LocalStateError('recovery_phrase_not_confirmed')
        tenant = self.tenant_public_id
        self._store(pending_share=b64url(enrolment.share), device_key=enrolment.device.to_pem().decode('ascii'),
                    key_storage=enrolment.key_storage, tenant_public_id=tenant,
                    device_encryption_key=(enrolment.device.encryption_pem().decode('ascii')
                                           if enrolment.device.phase2 else None))
        return self._send_enrolment(enrolment.share, enrolment.device, enrolment.recovery, enrolment.key_storage)

    def _send_enrolment(self, share, device, recovery, key_storage) -> dict:
        document = {'key_share': b64url(share), 'device_public_key': b64url(device.public_key), 'algorithm': 'ES256',
                    'key_storage': key_storage, 'recovery_public_key': b64url(recovery.public_key),
                    'recovery_encryption_public_key': b64url(recovery.encryption_public_key)}
        if device.phase2:
            document['device_encryption_public_key'] = b64url(device.encryption_public_key)
        try:
            _, view = self._device('enrol-first', document, share_name=None, settle=False)
        except Refused as error:
            # A refusal code is plaintext the parent relays: the pending S is KEPT (it may be the account's S if the
            # enclave acted and the answer was replaced). resume_enrolment probes it; recover replaces it.
            if error.code in ('tenant_already_enrolled', 'tenant_has_data_without_registry'):
                raise CredentialAlarm(error.code, status=error.status) from None
            raise
        self._store(share=self._record()['pending_share'], pending_share=None)
        self._trust_devices(view)
        return self._annotated(view)

    def resume_enrolment(self, phrase: str) -> dict:
        """After a lost enrolment reply: probe with the pending S; re-send it only if the account is not enrolled."""
        recovery = RecoveryKeys(recovery_entropy(phrase))
        record = self._record()
        if 'pending_share' not in record:
            raise LocalStateError('no_pending_enrolment')
        try:
            _, view = self._device('list', {}, share_name='pending_share', settle=False)
        except CredentialAlarm as alarm:
            if alarm.code != 'tenant_not_enrolled':
                raise
            return self._send_enrolment(self._share('pending_share'), self._device_key(),
                                        recovery, record.get('key_storage', 'software'))
        self._store(share=record['pending_share'], pending_share=None)
        self._trust_devices(view)
        return self._annotated(view)

    def devices(self) -> dict:
        return self._annotated(self._device('list', {})[1])

    def _replay_horizon(self) -> timedelta:
        """How long a sealed request can still be executed: the published replay window plus the future skew."""
        limits = self._limits()
        return timedelta(seconds=published_int(limits, 'replay_window_seconds')
                         + published_int(limits, 'replay_future_skew_seconds', minimum=0))

    def _drop_candidate(self) -> None:
        self._store(**{name: None for name in CANDIDATE_FIELDS})

    def rotate(self, phrase: str | None = None) -> Rotation:
        """Rotate with this device, or a legacy recovery proof; keep every candidate until its outcome is certain."""
        device = self._device_key()
        recovery = None if device is not None and device.phase2 else RecoveryKeys(recovery_entropy(phrase))
        if 'candidate_share' in self._record():
            pending = self.settle_rotation()
            if pending.rotated:
                return pending  # the earlier rotation did commit: that is this request's answer
            if pending.pending_until is not None:
                raise LocalStateError('rotation_pending', detail=pending.pending_until)
        horizon = self._replay_horizon()
        before = self._state().get('registry', {}).get('epoch', 0)
        candidate = new_share()
        sent = []

        def send(sealed):
            issued = datetime.fromisoformat(sealed.binding['issued_at'])
            self._store(candidate_share=b64url(candidate), candidate_expires_at=(issued + horizon).isoformat())
            sent.append(sealed)
            return self.api.device('rotate', sealed.envelope)

        try:
            _, view = self._device('rotate', {'new_key_share': b64url(candidate)}, send=send, recovery=recovery,
                                   retry=False, settle=False)
        except NOT_SENT:
            self._drop_candidate()  # the connection failed before the request was written: S' never left
            raise
        except (MemoryClientError, httpx.HTTPError) as error:
            if not sent:
                raise  # failed before anything was sealed and sent; no candidate was stored
            outcome = self.settle_rotation()  # ANY other outcome is ambiguous (contract 4a.2)
            reason = error.code if isinstance(error, MemoryClientError) else 'network_' + type(error).__name__
            return outcome if outcome.rotated else replace(outcome, reason=reason)
        if view['epoch'] <= before:
            raise CredentialAlarm('rotation_epoch_not_advanced')  # S and S' both kept
        self._store(share=b64url(candidate), **{name: None for name in CANDIDATE_FIELDS})
        return Rotation(True, self._annotated(view))

    def settle_rotation(self) -> Rotation:
        """Ambiguous rotation outcome: S' first, then S (contract 4a.2). S' never raises an alarm by itself."""
        record = self._record()
        if 'candidate_share' not in record:
            raise LocalStateError('no_rotation_pending')
        try:
            _, view = self._device('list', {}, share_name='candidate_share', settle=False)
        except Refused:
            pass  # a candidate refused (never committed, or forged): settled by S below
        else:
            # S' opened the tenant and the enclave signed the view: S' is the current S.
            self._store(share=record['candidate_share'], **{name: None for name in CANDIDATE_FIELDS})
            return Rotation(True, self._annotated(view))
        expires = record.get('candidate_expires_at')
        if expires is None:  # a candidate saved before expiry tracking: count its window from now
            expires = (self.clock() + self._replay_horizon()).isoformat()
            self._store(candidate_expires_at=expires)
        probed_at = self.clock()
        try:
            _, view = self._device('list', {}, settle=False)
        except Refused as refused:
            # Both S' and S refused (stale, invalid or set aside): the alarm; both are kept, nothing is re-enrolled.
            raise CredentialAlarm(refused.code, status=refused.status,
                                  detail='both S and the rotation candidate were refused') from None
        if probed_at >= datetime.fromisoformat(expires):
            # S is current, and it was probed after the rotate envelope could last execute: S' can never commit.
            self._drop_candidate()
            return Rotation(False, self._annotated(view))
        return Rotation(False, self._annotated(view), pending_until=expires)

    def recover(self, phrase: str) -> Rotation:
        """Zero devices, S unknown (M5): the enclave returns S sealed to the phrase key; then S is rotated."""
        recovery = RecoveryKeys(recovery_entropy(phrase))
        record = self._record()
        if 'recovery_device_key' in record:
            device = DeviceKey.from_pem(record['recovery_device_key'].encode(),
                                       record['recovery_device_encryption_key'].encode())
        else:
            device = DeviceKey.generate()
            self._store(recovery_device_key=device.to_pem().decode('ascii'),
                        recovery_device_encryption_key=device.encryption_pem().decode('ascii'))
        tenant = self.tenant_public_id
        document = {'device_public_key': b64url(device.public_key), 'algorithm': 'ES256',
                    'key_storage': 'software', 'device_encryption_public_key': b64url(device.encryption_public_key)}
        opened, view = self._device('recover', document, share_name=None, recovery=recovery, settle=False, device_key=device)
        try:
            share = recovery.open_blob(decode_b64(opened.get('recovery_wrapped_share')))
        except SealingError as error:
            raise CredentialAlarm(str(error)) from None
        self._store(share=b64url(share), device_key=device.to_pem().decode('ascii'), pending_share=None,
                    device_encryption_key=(device.encryption_pem().decode('ascii') if view.get('auth_phase') == 2 else None),
                    auth_phase=view.get('auth_phase', 1), recovery_device_key=None,
                    recovery_device_encryption_key=None, tenant_public_id=tenant, key_storage='software')
        self._trust_devices(view)
        return self.rotate(phrase)

    # -- memory (contract sections 3.1 to 3.5) --------------------------------------------------------------
    def save(self, records: list[dict] | None = None, *, raw_content: str | None = None,
             source: dict | None = None, project_id: str | None = None) -> dict:
        """Save canonical records, or exact original UTF-8 text through the raw_content convenience argument.

        raw_content is an alias for the same encrypted content, not a separate unmetered or plaintext upload.
        A supplied source must describe those exact bytes; without a source this is a manual save.
        """
        if raw_content is not None:
            if records is not None or not isinstance(raw_content, str) or not raw_content:
                raise LocalStateError('save_content_ambiguous_or_invalid')
            if source is None:
                return self.save_text(raw_content, project_id=project_id)
            records = [{'source': source, 'content': raw_content}]
        elif records is None or source is not None:
            raise LocalStateError('save_records_required')
        document = {'records': records}
        if project_id is not None:
            document['project'] = {'project_id': project_id}
        return self._memory('save', document, operation='save', project_id=project_id)

    def save_text(self, text: str, *, project_id: str | None = None, occurred_at=None) -> dict:
        """A manual save: a batch of one, deduplicated when the same text is saved again."""
        if not isinstance(text, str) or not text.strip():
            raise LocalStateError('save_content_required')
        digest = content_hash(text)
        source = {'client': {'name': CLIENT_NAME, 'version': __version__}, 'kind': 'manual_mcp',
                  'session_id': 'manual', 'message_id': digest[:32], 'revision': '1', 'role': 'user',
                  'occurred_at': utc_millis(occurred_at or self.clock()), 'captured_at': utc_millis(self.clock()),
                  'captured_by': 'manual_mcp', 'content_hash': digest}
        return self.save([{'source': source, 'content': text}], project_id=project_id)

    def recall(self, query: str, *, top_k: int = 8, cursor: int = 0, project_id: str | None = None,
               token_budget: int | None = None, details: str | None = None) -> dict:
        document = {'mode': 'recall', 'query': query, 'top_k': top_k, 'cursor': cursor}
        return self._memory('recall', document, operation='recall', project_id=project_id,
                            token_budget=token_budget, details=details)

    def continue_(self, *, format: str = 'text', limit: int | None = None, max_chars: int | None = None,
                  cursor: str | None = None, session_anchor: str | None = None, project_id: str | None = None,
                  token_budget: int | None = None) -> dict:
        document = {'mode': 'continue', 'format': format}
        for name, value in (('limit', limit), ('max_chars', max_chars), ('cursor', cursor),
                            ('session_anchor', session_anchor)):
            if value is not None:
                document[name] = value
        return self._memory('continue', document, operation='continue', project_id=project_id, token_budget=token_budget)

    def raw(self, record_ids: list[str], *, cursor: int = 0, max_bytes: int | None = None,
            project_id: str | None = None) -> dict:
        """Originals by record id, paged; `raw` is not routed (D3), so it travels as recall's mode `raw`."""
        document = {'mode': 'raw', 'selector': {'record_ids': list(record_ids)}, 'cursor': cursor}
        if max_bytes is not None:
            document['max_bytes'] = max_bytes
        return self._memory('recall', document, operation='raw', project_id=project_id)

    def close(self) -> None:
        self.api.close()
