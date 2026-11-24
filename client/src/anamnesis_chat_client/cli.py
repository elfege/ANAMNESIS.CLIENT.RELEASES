"""anamnesis-memory: the command-line face of the client that holds S.

Answers are JSON on stdout, and only answers: the recovery phrase and every prompt go to stderr, so
`anamnesis-memory enrol > answer.json` never writes the phrase to a file. Exit status: 0 done, 2 refused by
the service (or a rotation that did not complete), 3 an ALARM (credential, rollback, set-aside memory, or a
device this client never authorised: stop and look), 4 local state or configuration, 5 service unavailable.
Secrets never go on the command line: the API token and the recovery phrase are read from stdin.

The attestation policy accepts AWS Nitro only (the root is pinned in the package). `main` takes a
`policy_loader` for the qualification tests' test-only verifier; the installed command never passes one.
"""

import argparse
import json
import os
from pathlib import Path
import sys

import httpx

from . import __version__
from .attestation import AttestationRefused, load_policy
from .bip39 import PhraseError
from .claude_code import ClaudeCodeImport
from .client import MemoryClient
from .config import ClientConfig
from .custody import CustodyError
from .errors import CredentialAlarm, LocalStateError, MemoryClientError, MemorySetAside, Refused, ServiceUnavailable
from .release import PRODUCTION_GATEWAY, installed_policy, installed_release

HOME_ENV = 'ANAMNESIS_CHAT_CLIENT_HOME'


def default_home() -> Path:
    configured = os.environ.get(HOME_ENV)
    if configured:
        return Path(configured)
    base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    return Path(base) / 'anamnesis-chat-client'


def _line(prompt: str) -> str:
    print(prompt, file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line:
        raise LocalStateError('stdin_closed')
    return line.strip()


def _secret(prompt: str) -> str:
    if sys.stdin.isatty():
        import getpass
        value = getpass.getpass(prompt + ' ', stream=sys.stderr)
        if not value:
            raise LocalStateError('stdin_closed')
        return value.strip()
    return _line(prompt)


def _out(value) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=False), flush=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog='anamnesis-memory', description='anamnesis.chat protected memory client')
    root.add_argument('--home', type=Path, default=None, help=f'client directory (default ${HOME_ENV} or ~/.config)')
    root.add_argument('--version', action='version', version=__version__)
    commands = root.add_subparsers(dest='command', required=True)

    connect = commands.add_parser('connect', help='connect this device using the independently authenticated installed release')
    connect.add_argument('--username', required=True)
    connect.add_argument('--custody', choices=('auto', 'keyring', 'file'), default='auto')
    commands.add_parser('release-info', help='show the immutable release bundled with this client; no account request')

    init = commands.add_parser('init', help='save the gateway, username and attestation policy; read the API token from stdin')
    init.add_argument('--base-url', required=True)
    init.add_argument('--username', required=True)
    init.add_argument('--attestation-policy', type=Path, required=True, help='JSON file: the published PCR0 and PCR8')
    init.add_argument('--custody', choices=('auto', 'keyring', 'file'), default='auto')

    enrol = commands.add_parser('enrol', help='create S and the 24-word phrase here and enrol this first device')
    enrol.add_argument('--key-storage', choices=('software', 'hardware'), default='software')
    commands.add_parser('resume-enrolment', help='after a lost enrolment reply; reads the phrase from stdin')
    commands.add_parser('devices', help='the enclave-signed device registry')
    commands.add_parser('rotate', help='rotate S (phase 1 needs the phrase, read from stdin)')
    commands.add_parser('settle-rotation', help='resolve an interrupted rotation (S\' first, then S)')
    commands.add_parser('recover', help='no device left: recover S with the phrase (stdin), then rotate it')

    save = commands.add_parser('save', help='save text (argument or stdin)')
    save.add_argument('text', nargs='?')
    save.add_argument('--project-id')

    recall = commands.add_parser('recall', help='semantic recall')
    recall.add_argument('query')
    recall.add_argument('--top-k', type=int, default=8)
    recall.add_argument('--cursor', type=int, default=0)
    recall.add_argument('--project-id')
    recall.add_argument('--token-budget', type=int)
    recall.add_argument('--details')

    cont = commands.add_parser('continue', help='chronological continuation')
    cont.add_argument('--format', choices=('text', 'index'), default='text')
    cont.add_argument('--limit', type=int)
    cont.add_argument('--max-chars', type=int)
    cont.add_argument('--cursor')
    cont.add_argument('--session')
    cont.add_argument('--project-id')
    cont.add_argument('--token-budget', type=int)

    raw = commands.add_parser('raw', help='original text by record id')
    raw.add_argument('record_ids', nargs='+')
    raw.add_argument('--cursor', type=int, default=0)
    raw.add_argument('--max-bytes', type=int)
    raw.add_argument('--project-id')

    imports = commands.add_parser('import-claude-code', help='import a Claude Code session JSONL (resumable)')
    imports.add_argument('path', type=Path)
    imports.add_argument('--project-id')
    imports.add_argument('--retry-skipped', action='store_true', help='resend turns the service could not process before')
    export = commands.add_parser('export-claude-code', help='reconstruct hash-verified original JSONL from saved parts')
    export.add_argument('session_id')
    export.add_argument('output', type=Path)
    export.add_argument('--message-id')
    export.add_argument('--digest')
    export.add_argument('--project-id')
    return root


def _registry_status(view: dict) -> int:
    """A view listing a device this client never authorised is shown, then answered as an alarm."""
    if view.get('unrecognised_devices'):
        _err('alarm', MemoryClientError('device_not_authorised_here'))
        return 3
    return 0


def _rotation_status(outcome) -> int:
    _out(outcome.to_json())
    if not outcome.rotated:
        _err('refused', MemoryClientError(outcome.reason or 'rotation_not_completed'))
        return 2
    return _registry_status(outcome.registry)


def run(arguments, *, http=None, keyring_module=None, policy_loader=load_policy) -> int:
    args = parser().parse_args(arguments)
    home = args.home or default_home()
    if args.command == 'release-info':
        _out(installed_release())
        return 0
    if args.command == 'connect':
        if not args.username or not all(c.isascii() and (c.isalnum() or c in '_-') for c in args.username):
            raise LocalStateError('username_invalid')
        policy = installed_policy()  # rejects qualification-only records and any altered embedded measurements
        config = ClientConfig(PRODUCTION_GATEWAY, args.username, policy, args.custody)
        if (home / 'client.json').exists():
            # Connecting never replaces a saved identity, release policy, API token or device custody implicitly.
            existing = ClientConfig.load(home, policy_loader=policy_loader)
            if (existing.base_url != config.base_url or existing.username != config.username
                    or existing.attestation.to_json() != config.attestation.to_json()):
                raise LocalStateError('client_already_initialised')
            _out({'configured': True, 'already_configured': True, 'memory_address': PRODUCTION_GATEWAY + '/' + args.username,
                  'next': 'enrol only for your first device; existing device custody is preserved'})
            return 0
        client = MemoryClient(config, home=home, http=http, keyring_module=keyring_module)
        try:
            client.set_api_token(_secret('Paste your access key (input hidden, then Enter):'))
            tenant = client.tenant_public_id
            client.enclave()  # verify the actual AWS document against installed pins before declaring connection
            config.save(home)
            _out({'connected': True, 'tenant_public_id': tenant, 'memory_address': PRODUCTION_GATEWAY + '/' + args.username,
                  'next': 'run anamnesis-memory enrol to create this device recovery information locally'})
        finally:
            client.close()
        return 0
    if args.command == 'init':
        try:
            policy = policy_loader(json.loads(args.attestation_policy.read_text(encoding='utf-8')))
        except (OSError, ValueError) as error:  # AttestationRefused is a ValueError: a bad saved policy is local
            raise LocalStateError(str(error) if isinstance(error, AttestationRefused) else 'attestation_policy_unreadable') from None
        config = ClientConfig(args.base_url.rstrip('/'), args.username, policy, args.custody)
        config.save(home)
        client = MemoryClient(config, home=home, http=http, keyring_module=keyring_module)
        client.set_api_token(_secret('API token (memory scopes), then Enter:'))
        _out({'initialised': True, 'custody': client.custody.kind, 'tenant_public_id': client.tenant_public_id})
        return 0
    try:
        config = ClientConfig.load(home, policy_loader=policy_loader)
    except AttestationRefused as error:  # the SAVED policy is not acceptable here: local configuration, no alarm
        raise LocalStateError(str(error)) from None
    client = MemoryClient(config, home=home, http=http, keyring_module=keyring_module)
    try:
        if args.command == 'enrol':
            enrolment = client.begin_enrolment(key_storage=args.key_storage)
            # The phrase goes to stderr with the prompts, never to stdout, which carries the JSON answer only.
            print('RECOVERY PHRASE (shown once, write it down; it is never stored or sent):', file=sys.stderr)
            print(enrolment.phrase, file=sys.stderr, flush=True)
            view = client.complete_enrolment(enrolment, _line('Type the 24 words back to confirm:'))
            _out({'enrolled': True, 'registry': view})
            return _registry_status(view)
        if args.command == 'resume-enrolment':
            view = client.resume_enrolment(_line('Recovery phrase:'))
            _out({'enrolled': True, 'registry': view})
            return _registry_status(view)
        if args.command == 'devices':
            view = client.devices()
            _out(view)
            return _registry_status(view)
        if args.command == 'rotate':
            phrase = _line('Recovery phrase:') if client.rotation_requires_phrase else None
            return _rotation_status(client.rotate(phrase))
        if args.command == 'settle-rotation':
            return _rotation_status(client.settle_rotation())
        if args.command == 'recover':
            return _rotation_status(client.recover(_line('Recovery phrase:')))
        if args.command == 'save':
            text = args.text if args.text is not None else sys.stdin.read()
            _out(client.save_text(text, project_id=args.project_id))
        elif args.command == 'recall':
            _out(client.recall(args.query, top_k=args.top_k, cursor=args.cursor, project_id=args.project_id,
                               token_budget=args.token_budget, details=args.details))
        elif args.command == 'continue':
            _out(client.continue_(format=args.format, limit=args.limit, max_chars=args.max_chars, cursor=args.cursor,
                                  session_anchor=args.session, project_id=args.project_id, token_budget=args.token_budget))
        elif args.command == 'raw':
            _out(client.raw(args.record_ids, cursor=args.cursor, max_bytes=args.max_bytes, project_id=args.project_id))
        elif args.command == 'export-claude-code':
            import os
            import tempfile
            raw = ClaudeCodeImport(client, project_id=args.project_id).reconstruct(
                args.session_id, message_id=args.message_id, digest=args.digest)
            # Do not create or replace the destination until every original has passed integrity checks.
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix='.anamnesis-export-', delete=False) as stream:
                    temporary = Path(stream.name)
                    os.chmod(temporary, 0o600)
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, args.output)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            _out({'exported_bytes': len(raw), 'capture': 'original_conversation_jsonl', 'whole_file': False})
        elif args.command == 'import-claude-code':
            report = ClaudeCodeImport(client, project_id=args.project_id, retry_skipped=args.retry_skipped).run(args.path)
            _out(report.to_json())
        return 0
    finally:
        client.close()


def main(arguments=None, *, policy_loader=load_policy) -> int:
    try:
        return run(sys.argv[1:] if arguments is None else arguments, policy_loader=policy_loader)
    except AttestationRefused as refused:
        # The enclave is not the published one: nothing was sealed to it.
        _err('alarm', MemoryClientError(str(refused)))
        return 3
    except (CustodyError, PhraseError) as local:
        _err('local', MemoryClientError(str(local)))
        return 4
    except (CredentialAlarm, MemorySetAside) as alarm:
        _err('alarm', alarm)
        return 3
    except Refused as refused:
        _err('refused', refused)
        return 2
    except LocalStateError as local:
        _err('local', local)
        return 4
    except ServiceUnavailable as unavailable:
        _err('unavailable', unavailable)
        return 5
    except httpx.HTTPError as network:
        # The outcome is unknown: an interrupted rotation is settled with `settle-rotation`, an import is resumed
        # by running it again, a save is safe to repeat (records deduplicate).
        _err('unavailable', MemoryClientError('network_' + type(network).__name__))
        return 5
    except MemoryClientError as error:
        _err('error', error)
        return 2


def _err(kind: str, error: MemoryClientError) -> None:
    body = {kind: error.code}
    if error.retry_after is not None:
        body['retry_after'] = error.retry_after
    if error.detail is not None and error.code in ('rotation_pending', 'memory_limits_unavailable'):
        body['detail'] = error.detail
    if error.code == 'embedding_vector_invalid':
        body['message'] = 'this text could not be processed; it was not resent'
    print(json.dumps(body, sort_keys=True), file=sys.stderr, flush=True)


if __name__ == '__main__':
    sys.exit(main())
