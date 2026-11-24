"""What the client tells its caller. Codes are the contract's wire codes (section 4a.1), never invented."""


class MemoryClientError(RuntimeError):
    def __init__(self, code: str, *, status: int | None = None, retry_after: int | None = None, detail: str | None = None):
        super().__init__(code)
        self.code, self.status, self.retry_after, self.detail = code, status, retry_after, detail


class Refused(MemoryClientError):
    """A coded refusal the service answered; the request had no effect unless the contract says otherwise."""


class CredentialAlarm(Refused):
    """QC 72138 F3: a settled current S was refused (key_share_invalid, tenant_not_enrolled,
    tenant_has_data_without_registry), or both S' and S were. The client alarms the user, never re-enrols
    and never discards S."""


class MemorySetAside(Refused):
    """generation_detached: this S opens a generation that was set aside after a contested start over."""


class EmbeddingRefused(Refused):
    """embedding_vector_invalid: "this text could not be processed". Never resent automatically (pricing 85486):
    the same input fails the same way, and a resend would bill the customer again for the service's fault."""


class ServiceUnavailable(MemoryClientError):
    """Memory is not available (coming soon, a transient outage, or an uncoded failure)."""


class LocalStateError(MemoryClientError):
    """The local configuration or custody does not allow the operation (not enrolled, already enrolled, ...)."""


CREDENTIAL_ALARMS = frozenset({'key_share_invalid', 'tenant_not_enrolled', 'tenant_has_data_without_registry',
                               'device_unknown', 'device_revoked', 'device_signature_invalid'})

# Service faults worth waiting for: the gateway or the enclave could not serve the request right now. A save
# refused this way is retried after a wait and is never split or marked as too large.
TRANSIENT_STATUSES = frozenset({429, 502, 503, 504})


def is_transient(error: MemoryClientError) -> bool:
    # embedding_vector_invalid is answered 503 but is never resent automatically (pricing 85486).
    if isinstance(error, EmbeddingRefused):
        return False
    return isinstance(error, ServiceUnavailable) or error.status in TRANSIENT_STATUSES
