"""Client half of the protected-memory envelope and of contract 4a's sealed payload.

Wire (envelope v1, the enclave's EnvelopeCodec): request = header(magic 'ACM1', version 1,
sha256(enclave X25519 key), client ephemeral X25519 key, 12-byte nonce) || AES-256-GCM(payload) with the
header and the tenant's 16 UUID bytes as authenticated data; the key is HKDF-SHA-256 over the X25519 shared
secret, salted with client key || enclave key. The response is sealed to the same ephemeral key.

Payload (contract 4a.1): {binding, key_share, signature?, document}, with ten binding fields and S as
unpadded base64url. A phase-2 device signs the whole binding with its ES256 identity and uses a separate
P-256 encryption key for share updates. Recovery uses the phrase-derived signing key over the same
binding. Existing phase-1 custody keeps its legacy wire until explicit recovery.

This module carries no server code on purpose: the client and the enclave are two implementations of one
contract, and the qualification tests check them against each other byte for byte.
"""

from dataclasses import dataclass
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import struct
from uuid import UUID

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC, VERSION = b'ACM1', 1
REQUEST_HEADER = struct.Struct('>4sB32s32s12s')
RESPONSE_HEADER = struct.Struct('>4sB12s')
TAG_BYTES = 16
INFO_REQUEST = b'anamnesis.chat protected memory envelope v1 request'
INFO_RESPONSE = b'anamnesis.chat protected memory envelope v1 response'
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
BINDING_PREFIX = b'cm1-binding|'
SEALED_BOX_INFO = b'anamnesis.chat recovery sealed box v1'
SHARE_BYTES = 32
BINDING_FIELDS = ('operation', 'project_id', 'request_id', 'issued_at', 'payload_sha256', 'response_key',
                  'tenant_hint', 'device_id', 'enclave_key_id', 'generation_id')
REGISTRY_VIEW_SCHEMA = 'anamnesis.chat tenant registry view v1'


class SealingError(ValueError):
    pass


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def decode_b64(value, *, length: int | None = None) -> bytes:
    """Unpadded base64url (the contract) or padded standard base64 (what the built worker emits for blobs)."""
    if not isinstance(value, str) or not value:
        raise SealingError('base64_value_invalid')
    try:
        if any(char in value for char in '+/='):
            raw = base64.b64decode(value, validate=True)
        else:
            raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except ValueError:
        raise SealingError('base64_value_invalid') from None
    if length is not None and len(raw) != length:
        raise SealingError('base64_value_invalid')
    return raw


def _hkdf(material: bytes, *, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(material)


def new_share() -> bytes:
    return os.urandom(SHARE_BYTES)


def check_share(share) -> bytes:
    if type(share) is not bytes or len(share) != SHARE_BYTES:
        raise SealingError('key_share_invalid')
    return share


def enclave_key_id(enclave_public_key: bytes) -> bytes:
    return hashlib.sha256(enclave_public_key).digest()


class RecoveryKeys:
    """R (P-256, ES256 proofs) and W (X25519, opens the enclave's recovery blob), derived from the entropy.

    Derived on demand and never persisted. The scalar comes from 48 bytes of HKDF output reduced modulo
    the group order, so it carries no modulo bias (contract 4a.2, recovery blob paragraph).
    """

    def __init__(self, entropy: bytes):
        if type(entropy) is not bytes or len(entropy) not in (16, 20, 24, 28, 32):
            raise SealingError('bip39_entropy_required')
        scalar = int.from_bytes(_hkdf(entropy, info=b'anamnesis.chat recovery signing v1', length=48), 'big')
        self._signing = ec.derive_private_key(scalar % (P256_ORDER - 1) + 1, ec.SECP256R1())
        self._encryption = X25519PrivateKey.from_private_bytes(_hkdf(entropy, info=b'anamnesis.chat recovery encryption v1'))

    @property
    def public_key(self) -> bytes:
        return self._signing.public_key().public_bytes(serialization.Encoding.X962,
                                                       serialization.PublicFormat.UncompressedPoint)

    @property
    def encryption_public_key(self) -> bytes:
        return self._encryption.public_key().public_bytes_raw()

    def prove(self, binding: dict) -> bytes:
        der = self._signing.sign(BINDING_PREFIX + canonical_json(binding), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    def open_blob(self, blob: bytes) -> bytes:
        """The enclave's sealed box: ephemeral X25519 key (32) || nonce (12) || AES-256-GCM(S)."""
        if type(blob) is not bytes or len(blob) < 32 + 12 + TAG_BYTES:
            raise SealingError('recovery_blob_invalid')
        peer = X25519PublicKey.from_public_bytes(blob[:32])
        key = _hkdf(self._encryption.exchange(peer) + blob[:32] + self.encryption_public_key, info=SEALED_BOX_INFO)
        try:
            return AESGCM(key).decrypt(blob[32:44], blob[44:], blob[:32])
        except InvalidTag:
            raise SealingError('recovery_blob_rejected') from None


class DeviceKey:
    """This device's ES256 identity key (contract 4a.2). Phase 1 registers it; phase 2 signs with it."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, encryption_key=None):
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != 'secp256r1':
            raise SealingError('device_key_invalid')
        if encryption_key is not None and (not isinstance(encryption_key, ec.EllipticCurvePrivateKey)
                                           or encryption_key.curve.name != 'secp256r1'):
            raise SealingError('device_encryption_key_invalid')
        self._private, self._encryption = private_key, encryption_key

    @classmethod
    def generate(cls) -> 'DeviceKey':
        return cls(ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes, encryption_pem: bytes | None = None) -> 'DeviceKey':
        try:
            return cls(serialization.load_pem_private_key(pem, password=None),
                       serialization.load_pem_private_key(encryption_pem, password=None) if encryption_pem else None)
        except (TypeError, ValueError):
            raise SealingError('device_key_invalid') from None

    def to_pem(self) -> bytes:
        return self._private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption())

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes(serialization.Encoding.X962,
                                                       serialization.PublicFormat.UncompressedPoint)

    @property
    def device_id(self) -> str:
        return hashlib.sha256(self.public_key).hexdigest()

    @property
    def phase2(self) -> bool:
        return self._encryption is not None

    def encryption_pem(self) -> bytes:
        if not self.phase2:
            raise SealingError('device_encryption_key_required')
        return self._encryption.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption())

    @property
    def encryption_public_key(self) -> bytes:
        if not self.phase2:
            raise SealingError('device_encryption_key_required')
        return self._encryption.public_key().public_bytes(serialization.Encoding.X962,
                                                          serialization.PublicFormat.UncompressedPoint)

    def signature(self, binding: dict) -> dict:
        der = self._private.sign(BINDING_PREFIX + canonical_json(binding), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return {'device_id': self.device_id, 'algorithm': 'ES256',
                'value': b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}

    def open_share(self, blob: bytes, *, tenant_public_id) -> tuple[int, bytes]:
        if not self.phase2 or type(blob) is not bytes or len(blob) != 133:
            raise SealingError('sealed_share_invalid')
        epoch, point, nonce = int.from_bytes(blob[:8], 'big'), blob[8:73], blob[73:85]
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
            key = _hkdf(self._encryption.exchange(ec.ECDH(), peer),
                        info=b'anamnesis.chat device sealed share v1' + point + self.encryption_public_key)
            aad = (b'cm1-device-share|' + UUID(str(tenant_public_id)).bytes + bytes.fromhex(self.device_id)
                   + epoch.to_bytes(8, 'big'))
            return epoch, AESGCM(key).decrypt(nonce, blob[85:], aad)
        except (InvalidTag, ValueError):
            raise SealingError('sealed_share_invalid') from None


@dataclass(frozen=True)
class SealedRequest:
    envelope: bytes
    client_private_key: bytes
    enclave_public_key: bytes
    binding: dict

    def open(self, response: bytes) -> dict:
        return open_response(self.client_private_key, self.enclave_public_key, response)


def sealed_payload(document: dict, *, operation: str, tenant_public_id, response_key: bytes, enclave_public_key: bytes,
                   key_share: bytes | None, recovery: RecoveryKeys | None = None, project_id: str | None = None,
                   generation_id: str | None = None, clock=None, device: DeviceKey | None = None,
                   device_id: str | None = None) -> dict:
    """Seal the full binding, signed by the device or by its recovery key when required."""
    if not isinstance(document, dict) or 'request_id' in document or 'issued_at' in document:
        raise SealingError('document_invalid')
    issued = (clock or (lambda: datetime.now(timezone.utc)))()
    binding = {'operation': operation, 'project_id': project_id, 'request_id': b64url(os.urandom(16)),
               'issued_at': issued.isoformat(), 'payload_sha256': hashlib.sha256(canonical_json(document)).hexdigest(),
               'response_key': b64url(response_key), 'tenant_hint': str(UUID(str(tenant_public_id))),
               'device_id': device_id if device_id is not None else (device.device_id if device is not None else None),
               'enclave_key_id': enclave_key_id(enclave_public_key).hex(), 'generation_id': generation_id}
    if tuple(binding) != BINDING_FIELDS:  # explicit, so the invariant survives python -O
        raise SealingError('binding_invalid')
    payload = {'binding': binding, 'document': document}
    if key_share is not None:
        payload['key_share'] = b64url(check_share(key_share))
    if recovery is not None:
        payload['signature'] = {'algorithm': 'ES256', 'recovery_public_key': b64url(recovery.public_key),
                                'value': b64url(recovery.prove(binding))}
    elif device is not None:
        payload['signature'] = device.signature(binding)
    return payload


def seal_request(enclave_public_key: bytes, tenant_public_id, document: dict, *, operation: str,
                 key_share: bytes | None, recovery: RecoveryKeys | None = None, project_id: str | None = None,
                 generation_id: str | None = None, clock=None, device: DeviceKey | None = None,
                 device_id: str | None = None) -> SealedRequest:
    if type(enclave_public_key) is not bytes or len(enclave_public_key) != 32:
        raise SealingError('enclave_public_key_required')
    tenant = UUID(str(tenant_public_id)).bytes
    client_private = X25519PrivateKey.generate()
    client_public = client_private.public_key().public_bytes_raw()
    payload = sealed_payload(document, operation=operation, tenant_public_id=tenant_public_id, response_key=client_public,
                             enclave_public_key=enclave_public_key, key_share=key_share, recovery=recovery,
                             project_id=project_id, generation_id=generation_id, clock=clock, device=device, device_id=device_id)
    nonce = os.urandom(12)
    header = REQUEST_HEADER.pack(MAGIC, VERSION, enclave_key_id(enclave_public_key), client_public, nonce)
    shared = client_private.exchange(X25519PublicKey.from_public_bytes(enclave_public_key))
    key = _hkdf(shared, info=INFO_REQUEST, salt=client_public + enclave_public_key)
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(payload), header + tenant)
    return SealedRequest(header + ciphertext, client_private.private_bytes_raw(), enclave_public_key, payload['binding'])


def open_response(client_private_key: bytes, enclave_public_key: bytes, envelope: bytes) -> dict:
    if type(envelope) is not bytes or len(envelope) < RESPONSE_HEADER.size + TAG_BYTES:
        raise SealingError('envelope_too_short')
    header, ciphertext = envelope[:RESPONSE_HEADER.size], envelope[RESPONSE_HEADER.size:]
    magic, version, nonce = RESPONSE_HEADER.unpack(header)
    if magic != MAGIC or version != VERSION:
        raise SealingError('envelope_version_unsupported')
    private = X25519PrivateKey.from_private_bytes(client_private_key)
    client_public = private.public_key().public_bytes_raw()
    shared = private.exchange(X25519PublicKey.from_public_bytes(enclave_public_key))
    try:
        plaintext = AESGCM(_hkdf(shared, info=INFO_RESPONSE, salt=client_public + enclave_public_key)).decrypt(
            nonce, ciphertext, header)
    except InvalidTag:
        raise SealingError('envelope_rejected') from None
    try:
        reply = json.loads(plaintext.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise SealingError('envelope_payload_invalid') from None
    if not isinstance(reply, dict):
        raise SealingError('envelope_payload_invalid')
    return reply


def verify_registry_view(reply: dict, *, signing_public_key: bytes, tenant_public_id) -> dict:
    """A device reply's registry view, accepted only under the attested enclave's signature and for this tenant."""
    view, signature = reply.get('registry'), reply.get('enclave_signature')
    if not isinstance(view, dict) or view.get('schema') != REGISTRY_VIEW_SCHEMA:
        raise SealingError('registry_view_invalid')
    try:
        Ed25519PublicKey.from_public_bytes(signing_public_key).verify(decode_b64(signature), canonical_json(view))
    except (InvalidSignature, SealingError, ValueError):
        raise SealingError('registry_signature_invalid') from None
    if view.get('tenant_public_id') != str(UUID(str(tenant_public_id))):
        raise SealingError('registry_tenant_mismatch')
    if type(view.get('epoch')) is not int or type(view.get('version')) is not int or not isinstance(view.get('devices'), list):
        raise SealingError('registry_view_invalid')
    return view


def verify_device_log(reply: dict, *, tenant_public_id, previous: dict | None = None) -> dict:
    """Recompute the chain committed by an already signature-verified phase-2 registry view."""
    view, entries = reply.get('registry'), reply.get('device_log')
    if not isinstance(view, dict) or view.get('auth_phase') != 2:
        raise SealingError('device_log_inconsistent')
    transparency = view.get('transparency')
    if not isinstance(transparency, dict) or not isinstance(entries, list):
        raise SealingError('device_log_inconsistent')
    registry_id = transparency.get('registry_id')
    try:
        raw_id = bytes.fromhex(registry_id)
        if len(raw_id) != 16:
            raise ValueError
    except (TypeError, ValueError):
        raise SealingError('device_log_inconsistent') from None
    previous = previous or {}
    if previous.get('registry_id', registry_id) != registry_id:
        raise SealingError('device_registry_replaced')
    head = hashlib.sha256(b'cm1-device-log-genesis|' + raw_id + UUID(str(tenant_public_id)).bytes).hexdigest()
    heads, devices = [], {}
    fields = {'seq', 'event', 'device_id', 'by', 'at', 'epoch', 'prev'}
    for seq, entry in enumerate(entries, 1):
        if (not isinstance(entry, dict) or set(entry) != fields or entry['seq'] != seq or entry['prev'] != head
                or entry['event'] not in {'enrol-first', 'pair', 'recover', 'revoke', 'rotate'}):
            raise SealingError('device_log_inconsistent')
        head = hashlib.sha256(b'cm1-device-log|' + canonical_json(entry)).hexdigest()
        heads.append(head)
        if entry['event'] in {'enrol-first', 'pair', 'recover'}:
            devices[entry['device_id']] = False
        elif entry['event'] == 'revoke':
            devices[entry['device_id']] = True
    if len(heads) != transparency.get('log_size') or (heads[-1] if heads else None) != transparency.get('log_head'):
        raise SealingError('device_log_inconsistent')
    known = previous.get('heads', [])
    if len(heads) < len(known) or view.get('version', 0) < previous.get('version', 0):
        raise SealingError('device_log_rollback_detected')
    if heads[:len(known)] != known:
        raise SealingError('device_log_fork_detected')
    listed = {item.get('device_id'): item.get('revoked_at') is not None for item in view.get('devices', [])}
    if listed != devices:
        raise SealingError('device_list_inconsistent')
    return {'registry_id': registry_id, 'heads': heads, 'version': view['version']}
