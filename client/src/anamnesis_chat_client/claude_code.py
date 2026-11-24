"""Capture original Claude Code conversation records, including tools, thinking and metadata blocks.

The encrypted content is the exact UTF-8 JSONL record, including its original line ending. Process metadata,
invalid records and compaction summaries are counted as exclusions, never mislabeled original conversation.
Revision strings carry the original SHA256, byte length and fragment offsets within the existing contract.
An owner-only revision-aware ledger resumes partial saves without discarding old ledgers or custody.
Oversized originals are fragmented at UTF-8 boundaries and can be reconstructed with hash verification.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import time
from uuid import UUID

from . import __version__
from .client import CLIENT_NAME, MemoryClient, content_hash, published_int, record_id, utc_millis
from .custody import read_private_json, write_private_json
from .errors import EmbeddingRefused, MemoryClientError, ServiceUnavailable, is_transient
from .sealing import REQUEST_HEADER, TAG_BYTES, canonical_json, sealed_payload

CLAUDE_CODE = 'claude-code'
CONVERSATION_TYPES = frozenset({'user', 'assistant', 'system', 'tool'})
RAW_REVISION = 'jsonl-v1'
# The only answers that mean "this batch is too large": the enclave's pre-effect token-cap refusal and HTTP 413
# (the gateway's or a proxy's body bound). Every other refusal leaves the batch as it is.
TOO_LARGE_CODES = frozenset({'reservation_token_cap_exceeded', 'http_413'})


@dataclass(frozen=True)
class Turn:
    uuid: str
    session_id: str
    role: str
    occurred_at: str
    text: str
    position: int
    parent_uuid: str | None = None


def read_turns(path: Path) -> tuple[list[Turn], Counter]:
    turns, skipped, seen = [], Counter(), set()
    with open(path, 'rb') as handle:
        for position, raw in enumerate(handle):
            if not raw.strip():
                skipped['blank_line'] += 1
                continue
            try:
                text = raw.decode('utf-8')
                entry = json.loads(text)
            except (UnicodeError, ValueError):
                skipped['unparseable_line'] += 1
                continue
            if not isinstance(entry, dict):
                skipped['non_conversation_entry'] += 1
                continue
            if entry.get('isCompactSummary') is True or entry.get('type') == 'summary':
                skipped['compaction_summary'] += 1
                continue
            if entry.get('type') not in CONVERSATION_TYPES:
                skipped['non_conversation_entry'] += 1
                continue
            digest = hashlib.sha256(raw).hexdigest()
            uuid = entry.get('uuid') or 'raw-' + digest
            session, stamp = entry.get('sessionId'), entry.get('timestamp')
            role = entry['type']
            if (not isinstance(uuid, str) or not uuid or len(uuid) > 256 or not isinstance(session, str)
                    or not session or len(session) > 256):
                skipped['incomplete_entry'] += 1
                continue
            if (uuid, digest) in seen:
                skipped['duplicate_uuid'] += 1
                continue
            try:
                occurred_at = utc_millis(stamp)
            except (MemoryClientError, ValueError, TypeError):
                skipped['timestamp_invalid'] += 1
                continue
            seen.add((uuid, digest))
            parent = entry.get('parentUuid') if isinstance(entry.get('parentUuid'), str) else None
            turns.append(Turn(uuid, session, role, occurred_at, text, position, parent))
    return turns, skipped


def revision(digest: str, total: int, start: int, end: int) -> str:
    return f'{RAW_REVISION}.{digest}.{total}.{start}.{end}'


def revision_parts(value: str) -> tuple[str, int, int, int]:
    try:
        schema, digest, total, start, end = value.split('.')
        total, start, end = int(total), int(start), int(end)
        if schema != RAW_REVISION or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError()
        if not 0 <= start < end <= total:
            raise ValueError()
        return digest, total, start, end
    except (AttributeError, TypeError, ValueError):
        raise MemoryClientError('import_fragment_provenance_invalid') from None


def source_for(turn: Turn, captured_at: str) -> dict:
    source = {'client': {'name': CLAUDE_CODE, 'version': f'{CLIENT_NAME}/{__version__}'}, 'kind': 'claude_code',
              'session_id': turn.session_id, 'message_id': turn.uuid,
              'revision': revision(content_hash(turn.text), len(turn.text.encode('utf-8')), 0, len(turn.text.encode('utf-8'))),
              'role': turn.role,
              'occurred_at': turn.occurred_at, 'captured_at': captured_at, 'captured_by': 'import',
              'position': turn.position, 'content_hash': content_hash(turn.text)}
    if turn.parent_uuid and len(turn.parent_uuid) <= 256:
        source['parent_message_id'] = turn.parent_uuid
    return source


@dataclass
class ImportReport:
    sessions: list = field(default_factory=list)
    turns: int = 0
    already_imported: int = 0
    saved: int = 0
    duplicates: int = 0
    requests: int = 0
    retries: int = 0
    skipped: Counter = field(default_factory=Counter)
    too_large: list = field(default_factory=list)
    not_processed: list = field(default_factory=list)

    def to_json(self) -> dict:
        return {'sessions': self.sessions, 'turns': self.turns, 'already_imported': self.already_imported,
                'saved': self.saved, 'duplicates': self.duplicates, 'requests': self.requests, 'retries': self.retries,
                'skipped': dict(self.skipped), 'too_large': self.too_large, 'not_processed': self.not_processed,
                'capture': 'original_conversation_jsonl', 'whole_file': False}


class SessionLedger:
    """Old UUID-keyed ledgers remain intact; new done keys are complete content/revision record IDs."""

    def __init__(self, client: MemoryClient, session_id: str):
        name = hashlib.sha256(f'{client.config.account_key}|{session_id}'.encode('utf-8')).hexdigest()[:40]
        self.path = client.home / 'state' / 'imports' / f'{name}.json'
        self.value = read_private_json(self.path, {'session_id': session_id, 'done': {}, 'skipped': {}})
        if self.value.get('session_id') != session_id:
            raise MemoryClientError('import_ledger_mismatch')
        if any(not isinstance(self.value.get(name), dict) for name in ('done', 'skipped')):
            raise MemoryClientError('import_ledger_invalid')
        self.value.setdefault('originals', {})
        if not isinstance(self.value['originals'], dict):
            raise MemoryClientError('import_ledger_invalid')

    @staticmethod
    def original_key(turn: Turn) -> str:
        return hashlib.sha256((turn.uuid + '\0' + content_hash(turn.text)).encode()).hexdigest()

    def original(self, turn):
        return self.value['originals'].get(self.original_key(turn))

    def plan(self, turn, records):
        key = self.original_key(turn)
        if key not in self.value['originals']:
            self.value['originals'][key] = {
                'message_id': turn.uuid, 'digest': content_hash(turn.text), 'bytes': len(turn.text.encode('utf-8')),
                'position': turn.position, 'sequence': len(self.value['originals']),
                'parts': [item['source'] for item in records],
            }
            self.record()
        return self.value['originals'][key]

    def replace_part(self, old, new):
        old_id = record_id(old['source'])
        for original in self.value['originals'].values():
            for position, source in enumerate(original['parts']):
                if record_id(source) == old_id:
                    original['parts'][position:position + 1] = [item['source'] for item in new]
                    self.record()
                    return
        raise MemoryClientError('import_fragment_not_planned')

    def done(self, identity: str) -> bool:
        return identity in self.value['done']

    def skipped(self, identity: str) -> str | None:
        return self.value['skipped'].get(identity)

    def record(self, done: dict | None = None, skipped: dict | None = None) -> None:
        self.value['done'].update(done or {})
        for identity in done or {}:
            self.value['skipped'].pop(identity, None)
        self.value['skipped'].update(skipped or {})
        write_private_json(self.path, self.value)


@dataclass(frozen=True)
class BatchBudget:
    """What one save may carry, derived only from the gateway's published limits."""
    content_bytes: int
    envelope_bytes: int
    plaintext_bytes: int
    tokens: int
    records: int
    chunk_tokens: int
    overlap_tokens: int
    overhead_bytes: int

    def tokens_for(self, content_bytes: int) -> int:
        """An upper bound on the tokens the enclave plans for one record: byte-level tokenizers count at most one
        token per byte, and every further chunk repeats `overlap` tokens of its predecessor."""
        step = self.chunk_tokens - self.overlap_tokens
        return content_bytes + self.overlap_tokens * max(0, math.ceil((content_bytes - self.chunk_tokens) / step))


class ClaudeCodeImport:
    def __init__(self, client: MemoryClient, *, project_id: str | None = None, retry_skipped: bool = False,
                 sleep=time.sleep):
        self.client, self.project_id, self.retry_skipped, self.sleep = client, project_id, retry_skipped, sleep

    def _budget(self) -> BatchBudget:
        limits = self.client._limits()
        embed = (limits.get('operations') or {}).get('embed') or {}
        chunk = published_int(limits, 'chunk_tokens')
        overlap = published_int(limits, 'chunk_overlap_tokens', minimum=0)
        if overlap >= chunk:
            raise ServiceUnavailable('memory_limits_unavailable', detail='chunk_overlap_tokens')
        plaintext = published_int(embed, 'max_plaintext_bytes')
        # The sealed payload around an empty batch, measured with this import's own project id: everything but
        # the records. Keys are their real sizes (32 bytes); only the tenant and the time vary in content.
        moment = datetime(2000, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc)  # a timestamp printed at its longest
        empty = sealed_payload(self._document([]), operation='save', tenant_public_id=UUID(int=0),
                               response_key=bytes(32), enclave_public_key=bytes(32), key_share=bytes(32),
                               project_id=self.project_id, clock=lambda: moment)
        return BatchBudget(content_bytes=plaintext, envelope_bytes=published_int(limits, 'max_envelope_bytes'),
                           plaintext_bytes=plaintext + published_int(limits, 'envelope_metadata_allowance_bytes', minimum=0),
                           tokens=published_int(embed, 'max_embedding_tokens'),
                           records=published_int(limits, 'max_records_per_save'), chunk_tokens=chunk,
                           overlap_tokens=overlap, overhead_bytes=len(canonical_json(empty)))

    def _document(self, records: list[dict]) -> dict:
        document = {'records': records}
        if self.project_id is not None:
            document['project'] = {'project_id': self.project_id}
        return document

    def batches(self, records: list[dict]) -> list[list[dict]]:
        budget = self._budget()
        payload_limit = min(budget.plaintext_bytes, budget.envelope_bytes - REQUEST_HEADER.size - TAG_BYTES)
        batches, current, content, tokens, size = [], [], 0, 0, budget.overhead_bytes
        for item in records:
            item_content = len(item['content'].encode('utf-8'))
            item_tokens = budget.tokens_for(item_content)
            item_size = len(canonical_json(item)) + 1
            if current and (content + item_content > budget.content_bytes or tokens + item_tokens > budget.tokens
                            or size + item_size > payload_limit or len(current) >= budget.records):
                batches.append(current)
                current, content, tokens, size = [], 0, 0, budget.overhead_bytes
            current.append(item)
            content, tokens, size = content + item_content, tokens + item_tokens, size + item_size
        if current:
            batches.append(current)
        return batches

    def _fits(self, item, budget):
        size = len(item['content'].encode('utf-8'))
        payload_limit = min(budget.plaintext_bytes, budget.envelope_bytes - REQUEST_HEADER.size - TAG_BYTES)
        return (size <= budget.content_bytes and budget.tokens_for(size) <= budget.tokens
                and len(canonical_json(item)) + 1 + budget.overhead_bytes <= payload_limit)

    @staticmethod
    def _fragment(item, start, end):
        digest, total, offset, _ = revision_parts(item['source']['revision'])
        raw = item['content'].encode('utf-8')[start:end]
        text = raw.decode('utf-8')
        source = {**item['source'], 'revision': revision(digest, total, offset + start, offset + end),
                  'content_hash': content_hash(text)}
        return {'source': source, 'content': text}

    def _partition(self, item, budget):
        if self._fits(item, budget):
            return [item]
        # Binary search on characters, never cutting a multi-byte UTF-8 code point.
        records, text, offset = [], item['content'], 0
        while text:
            low, high = 1, len(text)
            best = 0
            while low <= high:
                middle = (low + high) // 2
                size = len(text[:middle].encode('utf-8'))
                candidate = self._fragment(item, offset, offset + size)
                if self._fits(candidate, budget):
                    best, low = middle, middle + 1
                else:
                    high = middle - 1
            if not best:
                raise MemoryClientError('import_limits_too_small')
            size = len(text[:best].encode('utf-8'))
            records.append(self._fragment(item, offset, offset + size))
            offset += size
            text = text[best:]
        return records

    def run(self, path: Path) -> ImportReport:
        turns, skipped = read_turns(Path(path))
        report = ImportReport(turns=len(turns), skipped=skipped)
        captured_at = utc_millis(self.client.clock())
        budget = self._budget()
        by_session: dict[str, list[Turn]] = {}
        for turn in turns:
            by_session.setdefault(turn.session_id, []).append(turn)
        for session_id, session_turns in by_session.items():
            ledger = SessionLedger(self.client, session_id)
            report.sessions.append(session_id)
            pending = []
            for turn in session_turns:
                original = ledger.original(turn)
                if original is None:
                    item = {'source': source_for(turn, captured_at), 'content': turn.text}
                    original = ledger.plan(turn, self._partition(item, budget))
                raw = turn.text.encode('utf-8')
                sources = original['parts']
                if all(ledger.done(record_id(source)) for source in sources):
                    report.already_imported += 1
                    continue
                for source in sources:
                    identity = record_id(source)
                    if ledger.done(identity):
                        continue
                    if ledger.skipped(identity) == 'not_processed' and not self.retry_skipped:
                        report.skipped['previously_not_processed'] += 1
                        continue
                    digest, total, start, end = revision_parts(source['revision'])
                    if digest != original['digest'] or total != len(raw):
                        raise MemoryClientError('import_fragment_provenance_invalid')
                    text = raw[start:end].decode('utf-8')
                    if content_hash(text) != source['content_hash']:
                        raise MemoryClientError('import_fragment_hash_mismatch')
                    pending.append({'source': source, 'content': text})
            for batch in self.batches(pending):
                self._send(batch, ledger, report)
        return report

    def reconstruct(self, session_id: str, *, message_id: str | None = None, digest: str | None = None) -> bytes:
        """Retrieve every planned part, validate its source/hash/range, then return complete original record bytes.

        The default exports the latest captured revision of each UUID in original transcript order. A particular
        prior revision can be selected by message_id and digest. Missing/unprocessed fragments refuse output.
        """
        ledger = SessionLedger(self.client, session_id)
        selected = {}
        for original in ledger.value['originals'].values():
            if message_id is not None and original['message_id'] != message_id:
                continue
            if digest is not None and original['digest'] != digest:
                continue
            key = original['message_id']
            if key not in selected or original['sequence'] > selected[key]['sequence']:
                selected[key] = original
        if not selected:
            raise MemoryClientError('import_original_not_found')
        result = []
        for original in sorted(selected.values(), key=lambda value: value['position']):
            sources = original['parts']
            if not sources or not all(ledger.done(record_id(source)) for source in sources):
                raise MemoryClientError('import_original_not_saved')
            pieces, offset = [], 0
            # One selector per request stays inside every supported server's published raw-selector bound.
            for source in sources:
                identity = record_id(source)
                reply = self.client.raw([identity], project_id=self.project_id)
                if reply.get('missing') or reply.get('next_cursor') is not None or len(reply.get('pages', [])) != 1:
                    raise MemoryClientError('import_original_missing')
                page = reply['pages'][0]
                try:
                    raw = page['text'].encode('utf-8')
                    actual = page['source']
                    digest_value, total, start, end = revision_parts(actual['revision'])
                    valid = (page['record']['record_id'] == identity and record_id(actual) == identity
                             and actual['message_id'] == original['message_id'] and actual['session_id'] == session_id
                             and digest_value == original['digest'] and total == original['bytes']
                             and start == offset and end == offset + len(raw)
                             and content_hash(page['text']) == source['content_hash'])
                except (KeyError, TypeError, AttributeError, UnicodeError):
                    raise MemoryClientError('import_original_integrity_invalid') from None
                if not valid:
                    raise MemoryClientError('import_original_integrity_invalid')
                pieces.append(raw)
                offset += len(raw)
            raw = b''.join(pieces)
            if len(raw) != original['bytes'] or hashlib.sha256(raw).hexdigest() != original['digest']:
                raise MemoryClientError('import_original_integrity_invalid')
            result.append(raw)
        return b''.join(result)

    def _save(self, batch: list[dict], report: ImportReport) -> dict:
        """One batch, retried as it is on a transient fault; raises the last error when the retries run out."""
        retry = self.client.config.transient_retry
        attempt = 0
        while True:
            report.requests += 1
            try:
                return self.client.save(batch, project_id=self.project_id)
            except EmbeddingRefused:
                raise
            except MemoryClientError as error:
                delay = retry.delay(attempt, error.retry_after) if is_transient(error) else None
                if delay is None:
                    raise
            attempt += 1
            report.retries += 1
            self.sleep(delay)

    def _send(self, batch: list[dict], ledger: SessionLedger, report: ImportReport) -> None:
        try:
            reply = self._save(batch, report)
        except EmbeddingRefused:
            # Never resent automatically: the same text fails the same way and would be billed again.
            ledger.record(skipped={record_id(item['source']): 'not_processed' for item in batch})
            report.not_processed.extend(item['source']['message_id'] for item in batch)
            return
        except MemoryClientError as error:
            if error.code not in TOO_LARGE_CODES:
                raise  # the batch stays pending: a rerun resumes it
            if len(batch) == 1:
                item = batch[0]
                text = item['content']
                if len(text) < 2:
                    raise MemoryClientError('import_limits_too_small') from error
                middle = len(text[:len(text) // 2].encode('utf-8'))
                total = len(text.encode('utf-8'))
                fragments = [self._fragment(item, 0, middle), self._fragment(item, middle, total)]
                ledger.replace_part(item, fragments)
                for fragment in fragments:
                    self._send([fragment], ledger, report)
                return
            half = len(batch) // 2
            self._send(batch[:half], ledger, report)
            self._send(batch[half:], ledger, report)
            return
        expected = {record_id(item['source']): record_id(item['source']) for item in batch}
        done = {}
        for answered in reply.get('records', []):
            uuid = expected.get(answered.get('record_id'))
            if uuid is None or answered.get('status') not in ('saved', 'duplicate'):
                raise MemoryClientError('save_reply_does_not_match_request')
            done[uuid] = answered['record_id']
            if answered['status'] == 'saved':
                report.saved += 1
            else:
                report.duplicates += 1
        if set(done) != set(expected.values()):
            raise MemoryClientError('save_reply_does_not_match_request')
        ledger.record(done=done)
