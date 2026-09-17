# Telemetry backend

Flowsight ships telemetry over OTLP to a two-node Grafana/Mimir/Loki cluster
fronted by a floating address. Nothing here is Flowsight-specific — it is where
the metrics and events go.

| | |
|---|---|
| Ingest | `http://192.168.1.251:4318` (OTLP/HTTP, JSON) |
| Metrics | `http://192.168.1.251:9009/prometheus` |
| Logs | `http://192.168.1.251:3100` |

**Point clients at the VIP, never at a node.** A client addressed to one node
loses its telemetry when that node goes down, which is the failure the second
node exists to prevent.

## Shape

Two peers, each running minio, mimir, loki, otel-gateway and grafana under host
networking, on **separate physical hosts** — that part matters, because a second
container beside the first survives a service failure and not a host failure,
and host failure is the one that actually happens.

They are not two independent stores. MinIO runs distributed across four drives,
two per node, and Mimir and Loki cluster over memberlist with replication
factor 2. Each node's gateway writes to its own local Mimir and Loki, which then
replicate — so both nodes answer the same query with the same number, and a
node that was down has no gap to backfill when it returns.

Memberlist uses two rings on the shared host network: Mimir on 7946, Loki on
7948, each with its own `cluster_label` so they cannot join each other. Both
pin `advertise_addr` to the node's LAN address, because under host networking
the default choice is docker0's `172.17.0.1`, which the peer cannot reach.

## The floating address

keepalived, `virtual_router_id 51`. One node is MASTER at priority 150, the
other BACKUP at 100, so the address returns to the primary when it recovers.
Eligibility is gated on `check_stack.sh`, which requires the node's own OTLP and
Grafana ports to accept connections — a node whose stack has died stops
advertising and hands the address over, rather than holding it and blackholing
ingest.

Give the address the **same prefix length as the LAN**. It is easy to write
`/24` out of habit on a `192.168.1.x` address; if the network is a `/17`, that
is wrong, and it gets more wrong the moment a renumber starts handing clients
addresses outside the `/24`.

## The failure that looks like nothing

**Both nodes can sit in FAULT STATE indefinitely, with no one holding the VIP,
while both nodes are individually healthy.** Every service answers on its own
address, every health check passes when run by hand, and the VIP answers
nothing. keepalived does not climb out of FAULT on its own once the condition
clears.

It is entered when the health check flaps, which is what a host under memory
pressure does to the stack running on it. Restart keepalived on the master
first, then the backup.

Worth checking before anything else when telemetry silently stops:

```
ip -4 addr show dev eth0 | grep 251      # on each node - someone must have it
journalctl -u keepalived -n 20           # FAULT STATE is stated plainly
/etc/keepalived/check_stack.sh; echo $?  # 0 means eligible
```

A client pointed at a VIP nobody holds fails exactly like a dead backend, and
the nodes look fine from every other angle.
