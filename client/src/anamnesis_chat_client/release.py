"""One reviewed immutable worker release, authenticated by the installed client package, never the gateway.

A different measurement requires an explicit newly authenticated package/release. This module has no
network trust update, mutable latest pointer, alternative root, or runtime override.
"""
import hashlib
from importlib.resources import files
import json

from .attestation import AWS_NITRO_ROOT_SHA256, AttestationPolicy, AttestationRefused

PUBLIC_RELEASE_SHA256 = '4288b00eaa51082f730140124f0c72c718ed54c185221be4c526439273db3649'
PRODUCTION_GATEWAY = 'https://anamnesis.chat'


def installed_release():
    try:
        entry = files(__package__).joinpath('public_release.json')
        if not entry.is_file():
            raise OSError()
        raw = entry.read_bytes()
    except OSError:
        raise AttestationRefused('installed_release_record_unavailable') from None
    if hashlib.sha256(raw).hexdigest() != PUBLIC_RELEASE_SHA256:
        raise AttestationRefused('installed_release_record_changed')
    value = json.loads(raw)
    if (value['schema'] != 'anamnesis.memory.client-release.v1' or value['gateway'] != PRODUCTION_GATEWAY
            or value['aws_nitro_root_sha256'] != AWS_NITRO_ROOT_SHA256):
        raise AttestationRefused('installed_release_record_invalid')
    policy = AttestationPolicy.load(value['attestation_policy'])
    if (policy.pcr0 == '0' * 96 or policy.pcr8 == '0' * 96 or value['worker_artifact']['eif_signed'] is not True
            or policy.pcr0 != value['worker_artifact']['pcr0'] or policy.pcr8 != value['worker_artifact']['pcr8']):
        raise AttestationRefused('installed_release_record_invalid')
    return value


def installed_policy():
    value = installed_release()
    if value.get('audience') != 'production':
        raise AttestationRefused('production_release_not_published')
    return AttestationPolicy.load(value['attestation_policy'])
