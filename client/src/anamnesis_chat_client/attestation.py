"""The client verifies the enclave itself: the gateway only relays the attestation document (QC 81681).

A document is accepted only when (1) it is an AWS Nitro attestation document whose certificate chain starts
at the AWS Nitro Enclaves root certificate PINNED IN THIS PACKAGE (the SHA-256 of its DER encoding, below;
never taken from a file, a setting or the gateway), and (2) its measured PCR0 and PCR8 equal the published
measurements in the client's SAVED policy. Only then are the enclave's envelope key (X25519) and receipt key
(Ed25519) used. Nothing here trusts the gateway's word, and nothing a policy file says can widen the anchor.

There is deliberately no other attestation kind in the shipped package. The end-to-end tests bring their
own test-only verifier through the library's policy-loader seam, so a test authority can never be configured
in a real installation: every shipped entry point (the CLI, `ClientConfig.load`) uses `load_policy` below,
which accepts AWS Nitro only.

The Nitro reader is a minimal definite-length CBOR / COSE_Sign1 (ES384) reader with chain verification, with
the same scope and the same refusals as the enclave lane's vendored reader (a nonce is required too), kept
free of server code so the client that holds S depends on nothing but `cryptography`. Freshness: the document
timestamp must be within the saved skew of this device's clock; the gateway may serve one document to many
callers for a few seconds (a short saved cache), so there is no per-client challenge.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

NITRO_KIND = 'nitro'
# The AWS Nitro Enclaves root certificate (AWS_NitroEnclaves_Root-G1), pinned by the SHA-256 of its DER encoding
# as AWS publishes it. A document whose cabundle does not start with exactly this certificate is refused.
AWS_NITRO_ROOT_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b'
PCR = re.compile(r'^[0-9a-f]{96}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
NONCE_BYTES = (8, 64)  # the enclave lane's reader bound (nitro_attestation.NitroAttestationVerifier)


class AttestationRefused(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise AttestationRefused(code)


@dataclass(frozen=True)
class AttestedEnclave:
    kind: str
    pcr0: str
    pcr8: str
    enclave_public_key: bytes
    signing_public_key: bytes


@dataclass(frozen=True)
class AttestationPolicy:
    """Saved client configuration, never a default: the published measurements of the enclave to accept.

    The trust anchor is not part of the policy: it is the AWS root pinned above, so a policy file cannot name a
    root of its own (unknown fields are refused) and cannot select any other kind of attestation.
    """
    kind: str
    pcr0: str
    pcr8: str
    max_skew_seconds: int = 300

    @classmethod
    def load(cls, value: dict) -> 'AttestationPolicy':
        _require(isinstance(value, dict), 'attestation_policy_required')
        _require(value.get('kind') == NITRO_KIND, 'attestation_kind_unsupported')
        _require(set(value) <= set(cls.__dataclass_fields__), 'attestation_policy_unknown_field')
        try:
            policy = cls(**value)
        except TypeError:
            raise AttestationRefused('attestation_policy_required') from None
        _require(isinstance(policy.pcr0, str) and PCR.match(policy.pcr0) is not None
                 and isinstance(policy.pcr8, str) and PCR.match(policy.pcr8) is not None, 'attestation_measurements_required')
        _require(type(policy.max_skew_seconds) is int and 1 <= policy.max_skew_seconds <= 3600, 'attestation_skew_invalid')
        return policy

    def to_json(self) -> dict:
        return asdict(self)

    def verifier(self, *, clock=None) -> 'NitroVerifier':
        return NitroVerifier(AWS_NITRO_ROOT_SHA256, max_skew_seconds=self.max_skew_seconds, clock=clock)

    def verify(self, document: bytes, *, clock=None) -> AttestedEnclave:
        enclave = self.verifier(clock=clock).verify(document)
        _require(enclave.kind == self.kind, 'attestation_kind_mismatch')
        _require(enclave.pcr0 == self.pcr0 and enclave.pcr8 == self.pcr8, 'attestation_measurements_rejected')
        return enclave


def load_policy(value) -> AttestationPolicy:
    """The policy loader of every shipped entry point: AWS Nitro only, the root pinned in this package."""
    return AttestationPolicy.load(value)


def attested(kind, pcr0, pcr8, enclave_hex, signing_hex) -> AttestedEnclave:
    """An attested enclave from verified fields (also used by the test-only verifier of the qualification suite)."""
    _require(all(isinstance(v, str) for v in (pcr0, pcr8, enclave_hex, signing_hex)), 'attestation_document_invalid')
    _require(PCR.match(pcr0) is not None and PCR.match(pcr8) is not None, 'attestation_pcrs_invalid')
    _require(HEX64.match(enclave_hex) is not None and HEX64.match(signing_hex) is not None, 'attestation_key_invalid')
    return AttestedEnclave(kind, pcr0, pcr8, bytes.fromhex(enclave_hex), bytes.fromhex(signing_hex))


# ---- Nitro: minimal CBOR + COSE_Sign1 reader ---------------------------------------------------------
class _Tag:
    __slots__ = ('tag', 'value')

    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class _Cbor:
    def __init__(self, data: bytes):
        self.data, self.offset = data, 0

    def _take(self, size):
        _require(0 <= size and self.offset + size <= len(self.data), 'attestation_cbor_invalid')
        chunk = self.data[self.offset:self.offset + size]
        self.offset += size
        return chunk

    def _argument(self, additional):
        if additional < 24:
            return additional
        _require(additional in (24, 25, 26, 27), 'attestation_cbor_invalid')
        return int.from_bytes(self._take(1 << (additional - 24)), 'big')

    def _indefinite_container(self, major, depth):
        """Real NSM payload maps use CBOR's indefinite-length container form."""
        result = {} if major == 5 else []
        while True:
            _require(self.offset < len(self.data), 'attestation_cbor_invalid')
            if self.data[self.offset] == 0xff:
                self.offset += 1
                return result
            _require(len(result) < 1 << 16, 'attestation_cbor_invalid')
            value = self.item(depth + 1)
            if major == 5:
                _require(isinstance(value, (int, str)) and value not in result, 'attestation_cbor_invalid')
                result[value] = self.item(depth + 1)
            else:
                result.append(value)

    def item(self, depth=0):
        _require(depth <= 16, 'attestation_cbor_invalid')
        initial = self._take(1)[0]
        major, additional = initial >> 5, initial & 0x1f
        if major == 7:
            _require(additional in (20, 21, 22), 'attestation_cbor_invalid')
            return {20: False, 21: True, 22: None}[additional]
        if additional == 31 and major in (4, 5):
            return self._indefinite_container(major, depth)
        argument = self._argument(additional)
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            return bytes(self._take(argument))
        if major == 3:
            try:
                return self._take(argument).decode('utf-8')
            except UnicodeDecodeError:
                raise AttestationRefused('attestation_cbor_invalid') from None
        if major in (4, 5):
            _require(argument <= 1 << 16, 'attestation_cbor_invalid')
        if major == 4:
            return [self.item(depth + 1) for _ in range(argument)]
        if major == 5:
            result = {}
            for _ in range(argument):
                key = self.item(depth + 1)
                _require(isinstance(key, (int, str)) and key not in result, 'attestation_cbor_invalid')
                result[key] = self.item(depth + 1)
            return result
        return _Tag(argument, self.item(depth + 1))


def _decode(data: bytes):
    _require(type(data) is bytes and bool(data), 'attestation_cbor_invalid')
    decoder = _Cbor(data)
    value = decoder.item()
    _require(decoder.offset == len(data), 'attestation_cbor_invalid')
    return value


def _encode_head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([(major << 5) | argument])
    for additional, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < (1 << (8 * size)):
            return bytes([(major << 5) | additional]) + argument.to_bytes(size, 'big')
    raise AttestationRefused('attestation_cbor_invalid')


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    """COSE Sig_structure ['Signature1', protected, b'', payload], CBOR encoded."""
    context = b'Signature1'
    return (_encode_head(4, 4) + _encode_head(3, len(context)) + context + _encode_head(2, len(protected)) + protected
            + _encode_head(2, 0) + _encode_head(2, len(payload)) + payload)


def _certificate(der, code) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except (TypeError, ValueError):
        raise AttestationRefused(code) from None


def _issued(child: x509.Certificate, issuer: x509.Certificate, code: str) -> None:
    _require(child.issuer == issuer.subject, code)
    key = issuer.public_key()
    _require(isinstance(key, ec.EllipticCurvePublicKey), code)
    try:
        key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
    except InvalidSignature:
        raise AttestationRefused(code) from None


class NitroVerifier:
    """AWS Nitro attestation: COSE_Sign1 (ES384) by a leaf chained to the PINNED root; debug mode refused.

    `root_sha256` is the pin. Every shipped path passes AWS_NITRO_ROOT_SHA256; only the qualification tests
    build a verifier with a synthetic root, to run the enclave lane's vectors through this reader.
    """

    def __init__(self, root_sha256: str, *, max_skew_seconds: int = 300, clock=None):
        _require(isinstance(root_sha256, str) and HEX64.match(root_sha256.lower()) is not None,
                 'attestation_root_pin_required')
        self.root_sha256, self.max_skew_seconds = root_sha256.lower(), max_skew_seconds
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def verify(self, document: bytes) -> AttestedEnclave:
        outer = _decode(document)
        if isinstance(outer, _Tag):
            _require(outer.tag == 18, 'attestation_cose_tag_unsupported')
            outer = outer.value
        _require(isinstance(outer, list) and len(outer) == 4 and isinstance(outer[0], bytes) and isinstance(outer[1], dict)
                 and isinstance(outer[2], bytes) and isinstance(outer[3], bytes), 'attestation_cose_structure_invalid')
        protected_bytes, payload_bytes, signature = outer[0], outer[2], outer[3]
        protected = _decode(protected_bytes)
        _require(isinstance(protected, dict) and protected.get(1) == -35, 'attestation_cose_algorithm_unsupported')
        payload = _decode(payload_bytes)
        _require(isinstance(payload, dict), 'attestation_payload_invalid')
        try:
            module_id, digest, timestamp = payload['module_id'], payload['digest'], payload['timestamp']
            pcrs, leaf_der, bundle = payload['pcrs'], payload['certificate'], payload['cabundle']
        except KeyError:
            raise AttestationRefused('attestation_payload_fields_missing') from None
        _require(isinstance(module_id, str) and module_id and digest == 'SHA384' and type(timestamp) is int
                 and timestamp > 0 and isinstance(pcrs, dict) and type(leaf_der) is bytes and isinstance(bundle, list)
                 and 1 <= len(bundle) <= 8 and all(type(item) is bytes for item in bundle), 'attestation_payload_fields_invalid')
        for index in (0, 1, 2):
            _require(type(pcrs.get(index)) is bytes and len(pcrs[index]) == 48, 'attestation_pcrs_invalid')
        _require(pcrs[0] != bytes(48), 'attestation_debug_mode')
        public_key, user_data, nonce = payload.get('public_key'), payload.get('user_data'), payload.get('nonce')
        # Parity with the enclave lane's reader: the key binding AND a bounded nonce are required.
        _require(type(public_key) is bytes and len(public_key) == 32 and type(user_data) is bytes and len(user_data) == 32
                 and type(nonce) is bytes and NONCE_BYTES[0] <= len(nonce) <= NONCE_BYTES[1],
                 'attestation_key_binding_missing')
        # The pinned root, byte for byte: the bundle's first certificate must hash to the pin.
        _require(hashlib.sha256(bundle[0]).hexdigest() == self.root_sha256, 'attestation_root_mismatch')
        moment = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
        _require(abs((self.clock() - moment).total_seconds()) <= self.max_skew_seconds, 'attestation_timestamp_skew')
        chain = [_certificate(der, 'attestation_cabundle_invalid') for der in bundle]
        leaf = _certificate(leaf_der, 'attestation_leaf_invalid')
        _require(chain[0].subject == chain[0].issuer, 'attestation_root_not_self_signed')
        _issued(chain[0], chain[0], 'attestation_root_signature_invalid')
        for child, issuer in zip(chain[1:], chain[:-1]):
            _issued(child, issuer, 'attestation_chain_invalid')
        _issued(leaf, chain[-1], 'attestation_leaf_chain_invalid')
        for certificate in (*chain, leaf):
            _require(certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc,
                     'attestation_certificate_expired')
        _require(len(signature) == 96, 'attestation_signature_malformed')
        leaf_key = leaf.public_key()
        _require(isinstance(leaf_key, ec.EllipticCurvePublicKey) and leaf_key.curve.name == 'secp384r1',
                 'attestation_leaf_key_unsupported')
        try:
            leaf_key.verify(encode_dss_signature(int.from_bytes(signature[:48], 'big'), int.from_bytes(signature[48:], 'big')),
                            _sig_structure(protected_bytes, payload_bytes), ec.ECDSA(hashes.SHA384()))
        except InvalidSignature:
            raise AttestationRefused('attestation_signature_invalid') from None
        pcr8 = pcrs.get(8)
        pcr8_hex = pcr8.hex() if type(pcr8) is bytes and len(pcr8) == 48 else '0' * 96
        return attested(NITRO_KIND, pcrs[0].hex(), pcr8_hex, public_key.hex(), user_data.hex())
