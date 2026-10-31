# Compact lossless evidence

Current canonical captures use `tools/verification/compact-value-graph.mjs`. Earlier interrupted and intermediate captures use `tools/verification/compact-evidence-codec.mjs`. Both are verification-only formats; the standalone application has no evidence-codec dependency.

## Current raw typed-value graph

The current `compact-typed-value-graph-v1` stream encodes raw authored values and canonical/Compact projections directly, without building recursively repeated tagged arrays or whole expanded JSON strings per prefix. It preserves the original `compactStable` value semantics: undefined, sparse holes, negative zero, nonfinite numbers, bigint, typed class/bytes, buffers, dates, ordered maps/sets and every sorted enumerable object field. Object prototypes alone and non-index array properties remain outside those original tagged semantics.

Complete canonical parity validates the independently decoded baseline graph nodes directly against the actual candidate's complete raw record in a separate real-source process. It is not digest-only equality and does not manufacture a candidate digest by copying the expected root. Source-local positive checks, DOM and deep checks may also compare equal root IDs in the same exact-content interning domain. Node keys include complete typed content and child IDs. `compact-typed-value-merkle-sha256-v1` is an explicitly labelled integrity digest, not the former expanded JSON SHA256.

`ValueGraphEncoder.encode(rawRecord)` returns `{frames, record}`. `new ValueGraphEncoder(comparisonGraph)` privately reuses an already-built exact `ValueGraph`; each encoder still emits every required definition from node0 and produces an independent stream. Before returning, a separate decoder consumes every frame and checks its nodes against the actual complete raw value. Previously verified value/node pairs may be reused only after proving the entire reachable plain-data container deeply immutable. Mutable branches, stateful built-ins and mutable descendants hidden behind frozen wrappers are read again. Failed captures roll back new definitions/proofs without removing preexisting comparison nodes; returned frames do not expose encoder-owned storage.

Compositional proof caches retain at most65536 entries and a separate cache retains at most32 fully proved immutable capture roots. Transactional overlays have the same bounded policy. These are speed caches, not limits on values, nodes, fields, cases, cursors or assertions: eviction recomputes the original data. Collection uses one complete independently decodable stream per case, not a new full authored dictionary every256operations.

`compareCompactValues` uses the same complete typed interning without computing unused portable Merkle digests. This boolean path still reads mutable input fully, including two references to the same mutable object; ordinary `ValueGraph` and encoded evidence retain their real digests.

Only one actual source fixture is resident in each data process. The baseline process retains every complete record and its own independent raw-value/positive checks; the candidate process consumes the complete immutable baseline stream and checks every expected node against its actual raw authored value or canonical/Compact prefix, with its own positive predicates. Both actual compilers independently reproduce the complete frozen cursor list before selection. The case/parent reports bind both source statuses, all nested artifacts, exact source assignments, complete stream tails and exact-once outcomes. Large cases run exclusively rather than alongside light fixtures on the measured16GBhost. A source-only pass or focused canary is not full parity acceptance.

Definition frames contain at most4096 nodes and target1048576 serialized JSON characters per group; one indivisible definition can exceed that target. Record frames bind an ordered record index, root and explicitly named graph digest. All frames bind their order, previous hash and complete serialized frame fields. Collection receipts independently bind frame byte counts/SHA256, record ownership, operation/cursor selectors, counts, final chain and complete compressed-stream bytes/SHA256. Node definitions are append-only and reference only existing nodes. The reader rejects invalid schemas/types/references, altered chains, malformed UTF-8/JSONL, incomplete final LF and compression errors.

```sh
bun tools/verification/compact-value-graph.mjs check --input=CASE.graph.jsonl.gz --expected-records=N --expected-last-sha256=HEX
bun tools/verification/compact-value-graph.mjs extract --input=CASE.graph.jsonl.gz --record-index=1 --field=baseline --out=baseline.tagged.json --expected-records=N --expected-last-sha256=HEX
bun tools/verification/compact-value-graph.mjs extract --input=CASE.graph.jsonl.gz --case-id=CASE --kind=prefix '--cursor={"eventIndex":3,"milestone":"complete"}' --field=projection --out=projection.tagged.json --expected-records=N --expected-last-sha256=HEX
```

Both graph commands require the exact per-case receipt values for `N` and `HEX`. Check and extraction validate the complete tail before success or output release; a valid surviving prefix is not a complete stream. Extraction creates a new file exclusively and streams the exact original `compactStable` tagged JSON for the selected raw record or top-level field, followed by one LF. It does not materialize the expanded selected tree. The integrated graph/carrier/original-report smoke passed 42/42 under pinned Bun 1.4.2, including typed equality, mutable rereads, eviction, rollback, corruption, selectors, complete tails, byte-exact single/bulk report restoration and no-overwrite/path controls. That focused smoke is not full-corpus acceptance.

## Standard compressed graph carrier

`readValueGraphFrames(filename, {compression})` and the graph CLI accept exactly `gzip` or `brotli`; gzip is the default. Brotli decoding uses the pinned runtime's strict native `DecompressionStream`, rejects unused compressed tails and stays backpressured. Native zlib's `bytesWritten` counter alone did not reject an ignored Brotli tail under Bun1.4.2; that failed control and its causal diagnostics are retained.

```sh
bun tools/verification/compact-evidence-carrier.mjs --input=CASE.graph.jsonl.gz --out=NEW_CARRIER_DIRECTORY
bun tools/verification/compact-value-graph.mjs check --input=NEW_CARRIER_DIRECTORY/evidence.jsonl.br --compression=brotli --expected-records=N --expected-last-sha256=HEX
bun tools/verification/compact-value-graph.mjs extract --input=NEW_CARRIER_DIRECTORY/evidence.jsonl.br --compression=brotli --record-index=1 --field=baseline --out=baseline.tagged.json --expected-records=N --expected-last-sha256=HEX
```

The permanent carrier producer streams all concatenated gzip members into standard Brotli, quality9/window24, without parsing JSON or transforming any record. It independently decodes both carriers and directly compares every original wire byte through both tails. It binds original/carrier/wire bytes and hashes plus unchanged producer, input and runtime identities. Only the exclusively promoted `encoding-proof.json` with status `ready` establishes transport readiness; a staged file or carrier alone is not ready. Invalid inputs leave failed evidence in their fresh private directory and never overwrite existing outputs. Complete graph validation remains a separate consumer check, not a property inferred from transport readiness.


## Shared original JSON reports

`tools/verification/compact-json-evidence.mjs` reuses the established `compact-evidence-structural-v1` wire format to share repeated ordinary report metadata. It does not discard fields, failures, observations or historical qualifiers. Every original report is independently decoded and reconstructed byte-for-byte, including indentation and outer whitespace. JSON that would require normalization, duplicate-key loss or invalid UTF-8 is rejected instead of rewritten.

The manifest declares each regular input file, its original report path and standard `none`/`gzip`/`brotli` input transport. The fresh output contains the complete append-only stream, `record-index.json`, an actual independent stored-stream consumer receipt and `encoding-proof.json`. The index binds every report's original bytes/SHA256 and its exact record selector. A standard Brotli carrier may subsequently hold the identical complete codec wire; its own transport proof binds every wire byte.

```sh
bun tools/verification/compact-json-evidence.mjs encode --manifest=REPORTS.json --out=NEW_REPORT_BUNDLE
bun tools/verification/compact-json-evidence.mjs restore --input=REPORTS.jsonl.br --compression=brotli --case-id=review/evidence/report.json --expected-records=N --expected-last-sha256=HEX --out=NEW_REPORT.json
bun tools/verification/compact-json-evidence.mjs restore-all --input=REPORTS.jsonl.br --compression=brotli --expected-records=N --expected-last-sha256=HEX --out=NEW_RESTORED_DIRECTORY
```

Take `N` and `HEX` from the bundle's record index/proof, not from a surviving prefix. Restore-all decodes once and checks every original report before publishing `reports/` and the final `restoration-proof.json`. Paths under `reports/` are the exact original report paths from the index. Individual extraction also waits for the complete tail. Invalid tails, duplicate report identities and traversal paths leave only explicitly failed private stages; existing files/directories are never overwritten. Standard unbundled `.json.gz`/`.json.br` reports remain ordinary original-byte streams, not this codec.

The current bundle carries734 complete original reports,678679555 original bytes, in the18181066-byte `review/evidence/shared-original-json-23/reports.dag.jsonl.br`. `review/evidence/REPORT-LOCATIONS.json` maps every former archive member, including `.json.gz`/`.json.br` aliases, to its exact case selector and restored uncompressed JSON path. Those aliases are not fabricated physical compressed files. The plain `record-index.json` binds original transport bytes/SHA256 as local provenance and original JSON bytes/SHA256 for independent inspection.

Both the stored734-record stream and its complete standard-Brotli wire passed independent consumption. All734 restored reports were then directly byte-compared with their independently decompressed original inputs. The frozen original parity authority and the mixed-format causal conclusion remain unchanged standalone files. No independent before/after record, failed attempt, slow observation, field or protocol operation is removed by sharing equal codec nodes.

## Historical preimage transport

`review/evidence/PREIMAGE-LOCATIONS.json` maps former optional diagnostic ZIP references to complete original member sets. One full snapshot is reconstructed from exact delivered-base files plus verbatim source/producer/manifest overlays and a verified byte-identical pinned rebuild. Five minimal snapshots use a standard solid TAR compressed with Brotli; every original source and emitted-HTML byte remains present. The generic exact-wire carrier does not interpret TAR as JSON.

Actual consumers restored all483original members,33711798bytes, and every result was directly compared to its original ZIP member. Original optional ZIP containers remain local with exact size/hash bindings, not silently discarded. Their absence as physical ZIP members is explicit; no original assertion, snapshot source version, failed native result or release condition is changed. The separately mandated frozen archives retain their exact original bytes. `reproduce.md` supplies the two real restoration commands.



## Shared JSON codec and historical tagged captures

The following producer and consumer describe earlier `compact-evidence-structural-v1` captures. Their `compact-tagged-lossless-v1` inputs, including tags for undefined, sparse arrays, typed data, dates and maps, remain ordinary nested JSON data. Keep this reader for those exact historical artifacts and unchanged regression tests; do not use it to interpret current raw graph frames.

The same codec also carries the ordinary original-JSON envelopes above. This does not change the historical tagged inputs or their decoder, and it does not turn raw typed-value graph frames into this format.

## Producer and consumer

```js
import {EvidenceEncoder, EvidenceDecoder} from '../../tools/verification/compact-evidence-codec.mjs';
const encoder = new EvidenceEncoder();
const decoder = new EvidenceDecoder();
const chunk = encoder.encode(record);
const originalValue = decoder.decode(JSON.parse(JSON.stringify(chunk)));
```

Use one encoder for the ordered authored and prefix record stream, and a fresh decoder for each replay. `encode(value)` returns one JSON-compatible append-only chunk. Every encode self-checks reconstructed UTF-8 bytes against the exact `JSON.stringify(value)` bytes, not just a hash. `decode(chunk)` consumes the next chunk and returns an independent value. Repeated input aliases are JSON values, not preserved object identity; decoded occurrences and later records never share mutable containers. Plain and null-prototype objects remain distinct. Object key order, prototype-sensitive own keys, Unicode, numeric types and negative zero are preserved.

Input must be finite JSON-compatible data. Raw undefined, bigint, nonfinite numbers, cycles, sparse arrays, symbols, accessors, nonenumerable fields, custom object prototypes and extra array properties are rejected rather than silently normalized. Represent non-JSON canonical values using the existing lossless tags before encoding.

## Wire format

A chunk has exactly these fields in this order:

- `format: "compact-evidence-structural-v1"`, `version: 1`.
- `index`: zero-based record index; `offset`: total node count before this chunk.
- `nodes`: new postorder node definitions only; node ID is `offset + position`.
- `root`: typed reference `[type, nodeId]` to this record's root.
- `jsonBytes`, `jsonSha256`: byte count and SHA-256 of the original UTF-8 JSON.
- `previous`: preceding chunk's `sha256`, or null for the first chunk.
- `sha256`: SHA-256 of `JSON.stringify` of all preceding fields in the order above, excluding `sha256` itself.

Node definitions are `["z"]` (null), `["b", boolean]`, `["s", string]`, `["n", canonicalNumberString]`, `["a", childReferences]`, or `["o", entries]` / `["p", entries]` for plain / null-prototype objects. A number string is `String(number)`, except negative zero is `"-0"`. Object entries are ordered `[stringKeyReference, valueReference]` pairs. All child references are typed and strictly backward; roots may also reference older records. Duplicate keys, noncanonical numeric-key ordering, invalid types, dangling/forward references, order/offset errors and hash/byte-count mismatches fail closed. A rejected chunk does not advance decoder state.

The encoder interns serialized typed child-reference signatures, not decoded snapshots. It traverses mutable inputs anew on every record; there is no cross-record object-identity cache. The decoder retains node definitions and reconstructs fresh containers only when requested. Pool memory grows with unique structures, not the number of full snapshots. Chunk hashes and final receipts are integrity bindings, not signatures or proof of producer trust.

## Offline gzip JSONL CLI

Write `JSON.stringify(chunk) + '\n'` to gzip JSONL in order. One gzip stream or concatenated gzip members are supported. No runtime packages or network access are required.

```sh
bun tools/verification/compact-evidence-codec.mjs check --input=critical-exact.dag.jsonl.gz
bun tools/verification/compact-evidence-codec.mjs extract --input=critical-exact.dag.jsonl.gz --record-index=17 --out=record.json
bun tools/verification/compact-evidence-codec.mjs extract --input=critical-exact.dag.jsonl.gz --case-id=CASE --kind=prefix '--cursor={"eventIndex":3,"milestone":"complete"}'
```

Record selectors require either a zero-based `--record-index` or exact top-level `--case-id` and `--kind`, with `--cursor` when necessary. Cursors have exactly `eventIndex` and `milestone`; selector key order is irrelevant. Ambiguous or absent matches fail. `--out` creates a new file exclusively; otherwise extraction writes the original JSON bytes plus one LF to stdout. No tag decoding or semantic transformation is performed.

`check` reports `records`, total original `jsonBytes` and `lastSha256`. Bind those values in the surrounding evidence receipt. Both commands accept `--expected-records=N` and `--expected-last-sha256=HEX` to verify the externally bound stream identity. This is necessary to detect removal of an entire valid final gzip member/chunk: an append-only stream alone cannot distinguish a valid prefix from an intended shorter stream.

Both commands stream gzip/UTF-8/JSONL and validate the complete tail before reporting success or releasing an extraction. Invalid UTF-8, gzip CRC/trailer errors, malformed JSON and a missing final LF fail. Checking hashes reconstructed JSON tokens without allocating decoded snapshots. Extraction only materializes selector fields and retains the selected record's JSON tokens, not the expanded corpus. Memory includes the structural pool, current encoded JSONL record and selected output when extracting; this is not random access.

For programmatic streaming, `decoder.check(chunk)` consumes and validates a record without returning a snapshot. After checking, `decoder.matches(chunk, selector)` selects the current record, and `decoder.json(chunk)` yields its exact JSON text tokens. Each chunk must be consumed once, by either `check` or `decode`. Encoder-internal `selfCheck(chunk, bytes)` additionally compares the reconstructed bytes directly.

## Ordinary original-byte reports

Unbundled original-byte `.json.gz` and `.json.br` files use standard gzip/Brotli, not DAG records. The final `review/evidence/EVIDENCE-ENCODINGS.json` binds physical standard-Brotli payloads to their original bytes/SHA256; current timing/profile gzip states also have exact encoded/decoded bindings in their transport/state proof. A former compressed JSON alias mapped by `REPORT-LOCATIONS.json` is a shared734-record selector, not a physical file for this decoder. Compression never parses, normalizes, drops fields or filters observation rows.

```sh
gzip -dc REPORT.json.gz > REPORT.json
bun --eval "import{brotliDecompressSync}from'node:zlib';const b=brotliDecompressSync(await Bun.file(process.argv[1]).bytes());await Bun.write(process.argv[2],b)" review/evidence/current-performance/resources-52/compact-mobile-performance-status.json.br restored-resource-report.json
sha256sum restored-resource-report.json
```

The current resource report's original bytes are25719066with SHA256 `38d1bab35a8b09b907214cc75df213397ef1e8619764b368b9e70eec29c09e15`; pinned Bun1.4.2 decoded and directly verified this transport during recovery. No runtime package or network is needed. The earlier62721212-byte flagged report with SHA256 `31816f1e000bc5ddf5b091867d268f16d7b34b69bc7ea601e30816040a20ed6d` remains preserved through the original-report locator, not a fabricated standalone compressed alias. `resource-evidence-encoding.json` retains the exact historical resource bindings; current reports/state payloads have their own supplied proof.

## Compact canonical handoff versus local raw forensics

The completed134160-operation phase does not make its multi-gigabyte raw outputs suitable for the LLM upload. `review/evidence/canonical-complete-16/slim-manifest.json` binds the exact review scope. The packet includes a labelled original-status projection, every original `joined-outcomes.jsonl` row with standard byte-preserving compression, and only the per-case critical carriers already selected.

The projection preserves every original top-level field. Each of its2080 `criticalExact.streams` entries retains only `path`, `caseId`, `bytes`, `sha256`, `records`, `frames` and `lastFrameSha256`. Full `recordProofs`, `frameBindings`, `operationIds`, `operationRecords` and other stream detail remain in the original170243329-byte status locally. The projection records that original's exact SHA256 and is explicitly not presented as the raw report.

The full original status, all2080graph value dumps, remaining canonical metadata and both complete verified forensic carriers stay local/on demand. `source/docs/compact-view/omitted-tracked-payloads.json` lists every omitted original file with bytes, SHA256 and reason, plus carrier custody. All source/test/control/frozen operation inputs remain selected for complete reproduction. A summary is never substituted for a claim that an omitted raw report is inspectable in the review ZIP.

