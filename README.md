# trinity-templates

The agent-template registry for [Trinity](https://github.com/abilityai/trinity).

Trinity installs fetch [`registry.yaml`](registry.yaml) at runtime to decide which
GitHub repos appear as agent templates in the Library. **Editing `registry.yaml`
changes every install's catalog on its next fetch — no Trinity release required.**

## How an install resolves its catalog

```
admin-curated list (system_settings)  ->  THIS registry  ->  bundled floor (empty)
```

An install with an admin-curated list never consults this registry. Otherwise
this file is the source. Every failure mode — unreachable, malformed, oversized,
redirected — degrades to the (empty) bundled floor and leaves the catalog
standing; nothing here can break an install.

## Adding a template

Open a PR editing `registry.yaml`. Each entry:

```yaml
  - repo: Owner/repo-name          # REQUIRED, ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$
    display_name: "Short name"     # optional, <= 200 chars
    description: "One or two sentences."   # optional, <= 1000 chars
```

Top level is `version: 1` and a `templates:` list of at most 25 entries.

### Requirements for a listed repo

- **Public and anonymously cloneable** — Trinity's tokenless clone path is what
  lets a fresh install create the agent with no GitHub PAT.
- **Declares a valid `template.yaml`** at its root.
- **Useful, or gracefully degraded, with zero credentials.**
- Reviewed for public-repo hygiene: no secrets, PII, or internal references.

### What a registry entry cannot do

Only `repo`, `display_name` and `description` are read. An entry **cannot**
assert `fork_to_own`, `credentials`, `schedules`, `hidden` or `id` — those are
read exclusively from the listed repo's own `template.yaml`, which is the trust
boundary. Listing a repo is a recommendation, not a warranty: Trinity clones and
trusts that repo, so only list repos you control or have reviewed.

## Operators

To pin or disable the registry:

- `TEMPLATE_REGISTRY_URL` — point at your own registry file.
- `TEMPLATE_REGISTRY_ENABLED=false` — hard kill switch (air-gapped installs).
  No setting can re-enable it.

Live status is in **Settings → Template Registry** on your instance.
