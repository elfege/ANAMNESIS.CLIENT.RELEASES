"""BIP-39 recovery phrases (English list), entropy in and out.

Contract 4a M4: the 24-word phrase encodes 32 bytes of entropy; the recovery keys are derived from
the ENTROPY bytes, never from the word string, so no PBKDF2 seed is computed here. The word list is
the canonical BIP-39 English list, pinned by its SHA-256 and checked on first use.
"""

from functools import lru_cache
import hashlib
from importlib import resources
import secrets
import unicodedata

WORDLIST_SHA256 = '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'
ENTROPY_BYTES = 32  # 24 words


class PhraseError(ValueError):
    pass


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    raw = resources.files(__package__).joinpath('bip39_english.txt').read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise PhraseError('bip39_wordlist_tampered')
    words = tuple(raw.decode('ascii').split())
    if len(words) != 2048:
        raise PhraseError('bip39_wordlist_tampered')
    return words


def new_entropy() -> bytes:
    return secrets.token_bytes(ENTROPY_BYTES)


def phrase_from_entropy(entropy: bytes) -> str:
    if type(entropy) is not bytes or len(entropy) not in (16, 20, 24, 28, 32):
        raise PhraseError('bip39_entropy_invalid')
    checksum_bits = len(entropy) * 8 // 32
    value = (int.from_bytes(entropy, 'big') << checksum_bits) | (hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits))
    count = (len(entropy) * 8 + checksum_bits) // 11
    words = wordlist()
    return ' '.join(words[(value >> (11 * (count - 1 - index))) & 0x7FF] for index in range(count))


def recovery_entropy(phrase: str) -> bytes:
    """The recovery phrase of contract 4a M4: exactly 24 words (32 bytes of entropy), never a shorter BIP-39 phrase."""
    if isinstance(phrase, str) and len(phrase.split()) != ENTROPY_BYTES * 3 // 4:
        raise PhraseError('recovery_phrase_must_be_24_words')
    entropy = entropy_from_phrase(phrase)
    if len(entropy) != ENTROPY_BYTES:
        raise PhraseError('recovery_phrase_must_be_24_words')
    return entropy


def entropy_from_phrase(phrase: str) -> bytes:
    """Strict: known words, a valid length and a matching checksum; surrounding whitespace and case are forgiven."""
    if not isinstance(phrase, str):
        raise PhraseError('bip39_phrase_invalid')
    tokens = unicodedata.normalize('NFKD', phrase).lower().split()
    if len(tokens) not in (12, 15, 18, 21, 24):
        raise PhraseError('bip39_phrase_length_invalid')
    index = {word: position for position, word in enumerate(wordlist())}
    try:
        value = 0
        for token in tokens:
            value = (value << 11) | index[token]
    except KeyError:
        raise PhraseError('bip39_phrase_word_unknown') from None
    checksum_bits = len(tokens) * 11 // 33
    entropy = (value >> checksum_bits).to_bytes(len(tokens) * 11 // 33 * 32 // 8, 'big')
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if (value & ((1 << checksum_bits) - 1)) != expected:
        raise PhraseError('bip39_phrase_checksum_invalid')
    return entropy
