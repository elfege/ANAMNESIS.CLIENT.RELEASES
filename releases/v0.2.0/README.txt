Anamnesis memory client

This client keeps your private memory keys on your own device. Your Anamnesis account access key is a separate private code. You do not create a memory secret on the website or paste it into an AI conversation.

Install a reviewed release

Use Python 3.12 or newer. Download the reviewed client wheel and SHA256SUMS from the independently published release-only repository. Verify that release's source revision and wheel SHA256 against its immutable release record. A checksum served beside a download by anamnesis.chat alone is not independent verification. Public independent publication is a release prerequisite; this document does not claim that repository already exists.

Linux/macOS terminal:
  python3 -m venv anamnesis-client
  anamnesis-client/bin/python -m pip install ./anamnesis_chat_client-0.2.0-py3-none-any.whl
  anamnesis-client/bin/anamnesis-memory release-info

Windows PowerShell:
  py -3.12 -m venv anamnesis-client
  .\anamnesis-client\Scripts\python.exe -m pip install .\anamnesis_chat_client-0.2.0-py3-none-any.whl
  .\anamnesis-client\Scripts\anamnesis-memory.exe release-info

The command examples below use anamnesis-memory; use its full path from the environment above. These are Python client instructions, not a claim of qualified native installers or every desktop keyring.

Connect your account

  anamnesis-memory connect --username YOUR_NAME

Paste the access key you already created when prompted. It needs Connect a device, Save new memories and Recall saved memories permissions (developer scope names: memory:enrol, memory:append, memory:read). The command reads the key privately from standard input; it never belongs in the command line, URL or chat. Connect uses https://anamnesis.chat and only the measurements built into this authenticated package. A changed runtime measurement is refused. Existing saved configuration and custody are never silently replaced.

For your first device only:
  anamnesis-memory enrol

Write down the 24-word recovery phrase offline. The client asks you to confirm it and never saves it. Keep it: a new device or lost local keys may need recovery. Do not re-enroll to troubleshoot existing memory. After an interrupted first enrollment use resume-enrolment with the same phrase. The website never generates or holds your device secret.

Save, recall and recover originals

  anamnesis-memory save "Remember the decision about the elephant logo."
  anamnesis-memory recall "Which logo did we choose?"
  anamnesis-memory continue
  anamnesis-memory raw RECORD_ID

The save answer contains record IDs. To save private or long text, pipe standard input instead of putting it in command history. The Python library also accepts client.save(raw_content=EXACT_TEXT, source=SOURCE); that is the same encrypted, metered content, not an unmetered upload.

Complete Claude Code conversation import:
  anamnesis-memory import-claude-code PATH_TO_SESSION.jsonl
  anamnesis-memory export-claude-code SESSION_ID restored-conversation.jsonl

Import reads the local JSONL directly, including original tool calls, tool results, thinking and metadata blocks. It preserves UTF-8 and line endings; large originals are fragmented and verified on reconstruction. Rerun the same import after an interruption: accepted fragments deduplicate. Changed records with the same UUID remain separate revisions. Compaction summaries, malformed lines and nonconversation process metadata are explicitly counted as exclusions. This is original-conversation capture, not a promise to reproduce every process-metadata line in a file.

Memory service availability and account usage limits still apply. A published client or qualified worker artifact alone does not activate the service. If the bundled record is qualification-only, connect refuses it until an independently published production client is installed. The installed release cannot learn replacement trust pins from the runtime.

Trust details

The package pins the AWS Nitro Enclaves root certificate by its DER SHA256 and verifies the signed attestation certificate chain, current timestamp, non-debug measurements and exact approved PCR0/PCR8 before sealing memory. The public AWS root certificate and exact worker/model/tokenizer record accompany the release. AWS reference: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

The application repository is private. The proposed public release-only repository must contain only this reviewed client source, wheel, public certificates and release metadata; no application repository history, private settings or customer content. Its creation and immutable publication remain separately governed. Do not interpret same-origin downloads as satisfying that independent gate.
