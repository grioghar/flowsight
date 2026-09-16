# API

Flowsight speaks JSON over HTTP. The document at **`/api/openapi.json`** is the
reference, and it is generated from the service's own route tables rather than
maintained beside them — it cannot describe an endpoint that no longer exists,
and an endpoint added without a description appears anyway, marked
undocumented, because a silent gap in an API reference is worse than a visible
one. A copy is committed here as `openapi.json`, but the running service is
authoritative.

A browsable reference is at **`/docs`** (Swagger UI, with try-it-out). It loads
Swagger UI from a CDN, and that page alone relaxes the service's
`default-src 'none'` policy far enough to fetch it. An appliance with no
outbound access is an ordinary case rather than an error, so the page renders
the same document itself when the script does not arrive; `/docs?local=1`
forces that path so it can be exercised deliberately.

## Reaching it

| From | Base |
|---|---|
| On the firewall | `http://127.0.0.1:8080/api/` |
| Through the OPNsense GUI | `/flowsight.php?api=` |

The service binds to loopback and ships **no authentication of its own**. Inside
OPNsense it is reached through `flowsight.php`, which the web GUI has already
authenticated, and which forwards only an explicit allow-list of endpoints.
Writes additionally require `allow_write` in the interface configuration.

That proxy is why every operation is reachable by POST even where a REST verb
fits better: it forwards only GET and POST, so a PUT-only operation would work
for direct callers and fail behind the GUI. `PUT` and `DELETE` are accepted by
the service as aliases.

## Shape

Reads return an object. Failures return one too, carrying an `error` field —
so a caller reads `.error` rather than branching on status alone, though the
status is set as well (400 for a rejected write, 404 for an unknown endpoint or
entry).

Writes that change a configuration document validate first, keep a timestamped
backup, then replace the file atomically, and return `{"ok": true, "note": ...}`
where `note` says what was reloaded as a result.

## Groups

- **System** — health, counters, installation checks, this document.
- **Traffic** — hosts, flows, applications, the layer-2 inventory, and the
  per-host report that joins all of them.
- **DNS** — resolver activity, the query log, and address naming.
- **Enrollment** — device identification, zone placement, and what enforcing
  would write.
- **Configuration** — CRUD over every configuration document.
- **Policy** — the declarative policy document and its compilation.
