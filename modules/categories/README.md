# flowsight-categories

Maps a category name to a domain list, so policy can say
`deny.categories: [gambling]` instead of enumerating domains.

```bash
flowsight-categories status            # what is cached, and how big
flowsight-categories update            # refresh all
flowsight-categories update crypto     # refresh one
```

## Why domain feeds and not nDPI categories

nDPI categorises **flows**, by IP and SNI. DNS blocking needs **domains**. They
are different problems, so this uses open per-category domain feeds rather than
nDPI's category ids.

## Size is the constraint

Some categories are enormous, and a per-view `local-zone` is not a resolver
blocklist:

| category | domains |
|---|---|
| crypto | ~1.3k |
| tracking | ~144k |
| phishing | ~190k |
| gambling | ~343k |
| adult / malware | millions |

`flowsight-policy` refuses any policy resolving to more than 200,000 domains
and says so, rather than compiling a view that would degrade DNS for the whole
network. For the very large categories the right mechanism is a resolver-wide
blocklist (Unbound's DNSBL module), not per-group views.

## Failure behaviour

- Compiles read **only from the on-disk cache** — a policy compile never
  depends on the network, so a feed outage cannot silently shrink enforcement.
- A feed that parses to zero domains is treated as a failed fetch and the
  existing cache is kept. That is nearly always an error page, and overwriting
  a good list with it would quietly disable blocking.
- A category with no cached feed is a hard error naming the fix command.
