# TODO - RiskPatch remediation roadmap (handoff file)

Read this whole file first. It is written so another agent can continue the work without the chat history.
Update the checkboxes and the **Progress log** at the bottom in the same commit as the work.

Related: `TODO-OVERVIEW-FINDING-WORKFLOW.md` (finding ownership/workflow metrics; belongs to Phase 2 below).

## Goal and hard limits

Focus: **validate → prioritise → ownership → planned remediation → verify**.

- Keep the existing UI design: left navigation, compact cards, filters, dense tables, severity chips, Executive/Technical tabs. Do **not** introduce a new visual language, kanban boards or new dashboards. Reuse existing CSS classes (`.panel`, `.hint`, `.note`, `.kc`, `.spill`, `.cov-*`) and add small rules next to them in `src/riskpatch/ui.py`.
- Keep screens simple and understandable to non-technical readers. Plain words, no jargon (e.g. say "target", not "TTL"), one short sentence beats a paragraph.
- Do not promise end-to-end patch deployment. RiskPatch is a vulnerability-intelligence and asset-risk console; no execution agent exists yet.
- Alert count is not patch work. One CVE/package affects many assets; one asset has many findings.
- **Freshness is not validity.** Stale = the evidence is old or inputs changed, not that findings are wrong. Never turn a finding into resolved/fixed because a refresh failed or a snapshot is missing; show `Unknown/unreachable`. Never silently drop stale findings from totals.
- Suggested stale copy: `Data stale - this is the last known finding, not a verified view of the asset's current state. Refresh inventory and correlation to confirm.` Do not write "all findings are invalid/stale".
- AI may summarise or suggest groupings; applicability, final score, assignment and status stay deterministic, traceable and correctable by an analyst.

Three product objects (do not blur them):

| Object | Meaning | Main user |
| --- | --- | --- |
| Finding | Evidence of a CVE on one component of one asset, from a snapshot + correlation rules | Analyst |
| Work item | Decision/action grouped by CVE + package + target fix; has owner and SLA | SOC, service owner |
| Campaign | Remediation plan for work items over a set of assets / change window | Platform/ops manager |

## How to work in this repo (operational notes)

- App: FastAPI + SQLite (WAL) in `src/riskpatch/`; UI is server-rendered HTML in `src/riskpatch/ui.py`; migrations are `src/riskpatch/migrations/NNNN_*.sql` (latest: `0020`). Next migration number: `0021`.
- Stack runs from `docker-compose.yml`: `api` (4 uvicorn workers, 4 CPUs/2g), `worker` (single scheduler, do not scale), `nginx` (TLS on 8443). Server: `https://<SERVER_IP>:8443`.
- **Standing authorisation from the owner:** after each fix/feature that works and passes tests, do rebuild → recreate → restart nginx → commit → push without asking again:
  ```
  docker compose build && docker compose up -d && docker compose restart nginx
  curl -sk https://localhost:8443/api/v1/ready          # expect schema_version = latest migration
  git add <only the files you changed> && git commit && git push
  ```
  Never commit `.kilo/` or `.tgrep/` (untracked tool dirs). End commit messages with the attribution line the harness gives you. Verify health and `docker compose logs --since 1m api worker | grep -ci "traceback\|locked"` is 0 after deploying.
- **Tests:** the host has no pytest. Run them inside the api container against a copy of the code (the container is recreated on every deploy, so redo this each time):
  ```
  CID=$(docker compose ps -q api)
  docker exec $CID mkdir -p /tmp/wk && docker cp src $CID:/tmp/wk/src && docker cp tests $CID:/tmp/wk/tests && docker cp pyproject.toml $CID:/tmp/wk/
  docker exec $CID sh -c 'cd /tmp && uv pip install --target /tmp/pt pytest'            # once per container
  docker exec $CID sh -c 'cd /tmp/wk && env -u RISKPATCH_BOOTSTRAP_ADMIN_USER -u RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD PYTHONPATH=/tmp/pt:/tmp/wk/src /app/.venv/bin/python -m pytest tests -q -p no:cacheprovider'
  ```
  **Baseline: 15 tests fail in the container** (missing `inventory/` fixtures and similar) and also failed before any of this work; anything beyond those 15 is a regression. Use a fresh `/tmp/wkN` dir per run (do not `rm -rf` in the container). Do not pass `-I` to python when you rely on `PYTHONPATH`.
- Test pattern: `tests/test_api.py` and `tests/test_freshness.py` have an `env` fixture (client, tokens, conn, settings); `_add_findings(conn, name, {level: n})` in `tests/test_api.py` seeds findings; `tests.helpers.session_for(client, conn, "viewer"|"operator"|"admin")` logs a UI session. A test with a hand-built legacy DB (`test_alert_workflow_migration_preserves_legacy_closed_records`) lists tables migrations touch; update it when a migration needs another table, and bump its expected version.
- The UI is English. Read-only users must not be pointed at buttons they do not have (check `c.who.has("operate")` / `"admin"`).

## Pitfalls already learned (do not repeat)

- **SQLite has one writer.** Keep write transactions short; never loop over thousands of rows with slow statements inside `tx()`. `search_index` is FTS5 with `UNINDEXED` kind/ref: delete by rowid via `search_map` (see `db.index_text`), never `DELETE ... WHERE kind=? AND ref=?` in a loop.
- **List queries need an index that matches their ORDER BY.** `WHERE workspace_id=? AND status=? ORDER BY id DESC LIMIT 100` on alerts sorted all 195k open alerts through a temp B-tree (about 0.6 s on the server; the live DB has no `sqlite_stat1`, so the planner guesses). Migration `0020` adds `(workspace_id, status, id)`. Check new list queries with `EXPLAIN QUERY PLAN`: `USE TEMP B-TREE FOR ORDER BY` on a large table is a bug.
- **Every list/count query on `findings` (130k+ rows, ~2 KB each) needs a covering index**, or a page costs seconds. Indexes live in migration `0014`. Check `EXPLAIN QUERY PLAN` for any new filter/sort. Do not `SELECT *` from `reports` (3.4 MB `content_json` per row) or load all findings into Python.
- Migrations on the production-size DB (3.5 GB) take 20–100 s (index builds); the API returns 503 "migrating" meanwhile. Say so before deploying a heavy one.
- Profile in the container on a **copy** of the DB, and never run two heavy jobs at once (it inflated early timings 100x). Production data right now: ~137k open findings, ~1M evidence rows, 205 assets.
- Correlation freshness: analysis only re-runs assets affected by changed CVEs; `freshness.mark_correlation_current` re-baselines the rest at the end of `run_analysis`. A stale inventory still wins.
- Rate limiting is per uvicorn worker (4 workers), not global.
- DB size: most of the file is reusable free pages, not growth (see Phase 1 hygiene for measurements). Reports hold a large `content_json`; retention keeps 3 per asset.

## Phase 1 - Trust (prerequisite for showing anything as current/verified)

- [x] Coverage "How to read this page" panel (status legend, plain words), horizontal layout.
- [x] One-sentence explanation + affected count under each stale/failed layer (`layer_why`).
- [x] Correlation no longer looks stale for assets a CVE change does not affect (`mark_correlation_current`).
- [x] Overview/asset-detail counts are real totals (asset detail used a page-size count).
- [x] Reword the "Risk of leaving it as is" box and the KPI card to the *last-known* wording above (stale ≠ wrong).
- [x] (shipped incl. per-server "Re-check now") **Stale assets drilldown** on Coverage: asset, last successful snapshot, target age, collector version, reason (inventory too old / re-check needed), open findings affected, link to asset; later a per-asset "queue refresh" for operators (collector-driven inventory cannot be refreshed server-side - say so).
- [x] (v1: Coverage guide note explains reporting vs monitored vs layer counts; denominators on Overview/Assets still open) Count definitions: next to each count show denominator and scope (e.g. `202 reporting / 202 monitored`, `205 inventory assets`, `N correlated findings`) and one line why they can differ.
- [x] (Assets: "Last snapshot"; Findings: "Last checked"; asset detail: "Last snapshot received" + "Findings last checked"; Coverage already splits feed/snapshot/correlation. Remaining: CVE Intel feed-update column) Separate timestamps everywhere "updated" appears: Last seen, Latest inventory snapshot, Correlation run, Intel feed update.
- [x] (Coverage risk box: total / confirmed / old data / KEV on old data / Unverified; Overview not yet) Split risk metrics: `Last-known open`, `Freshly confirmed`, `Stale evidence`, `Unverified` (do not drop stale from totals).
- [x] (`fresh_chip`: Fresh / Stale / Unverified / Refreshing / Refresh failed / Refresh queued, linking to Coverage; on Assets and Findings) Per-object freshness chip on Assets/Findings (`Fresh`, `Stale`, `Unverified`, `Refresh queued`, `Refresh failed`) linking to Coverage.
- [x] (Coverage "Servers needing attention": latest re-check state, time, retry count, error; per-server "Re-check now" for operators via `/ui/actions/coverage/refresh-asset`; collector-driven inventory says "Run the collector") Refresh observability: queued refresh, last attempt, last error per asset/layer on Coverage.
- [x] (v1 on Status: records received per source, new/updated/unchanged, sources that failed, change vs previous run; **still open:** count records a source returned but the system rejected, and parsed-vs-normalized per record - `cvesync.py` only counts `created/updated/unchanged/failed`) Feed provenance: per feed fetched / parsed / normalized / rejected and delta vs previous run (Status page).
- [x] CVE sync now queues one follow-up analysis (`jobs.queue_followup_analysis`) so correlation is not left stale until the next 3-hourly run.
- [x] WAL: worker runs `db.checkpoint_wal` every 15 min and `journal_size_limit` is 64 MiB (was a 248 MB WAL slowing reads).
- [x] Report retention (`jobs.prune_reports`, `REPORT_KEEP_PER_ASSET`, default 3): empties `content_json` of older reports (Markdown kept, newest per asset never touched); runs inside `prune()` after each CVE sync. **Today it prunes 0 rows** (433 reports, ~2 per asset). Measured sizes on 2026-11-11: file 5.7 GB of which **3.4 GB is free pages** (reusable, not growth); real data ~2.2 GB: search_index 1.0 GB (FTS), reports 444 MB, findings 419 MB, finding_evidence 187 MB. Reclaiming disk needs an offline `VACUUM` (rewrites the DB, blocks writers for minutes) - optional, not done.

## Phase 2 - Workflow

Data facts to know first (measured 2026-11-11): **no CVE in the catalog carries `patched_versions`** (0 of 8,872), so fixed versions are *derived* from NVD ranges: `match.derive_fixed_versions` takes `end_excluding` of the ranges that contain the installed version (`analysis.py` uses it when `patched_versions` is empty). 71% of open findings get one (linux, go, apache, python, openssl, php, nginx). It is the **upstream** version: for kernels and distro packages the real fix is the distro's backported package, so the UI labels it "(upstream version)". `findings.fixed_version` is NULL = not extracted yet, '' = no fix known. Both backfills run once at worker start (`jobs.backfill_fixed_versions`, `jobs.backfill_fixed_from_ranges`, marker `fixed_version_from_ranges_v1`). One package@version has a different fix per CVE (e.g. python 3.8.10 -> 3.10.0 / 3.10.20 / 3.13.10), so the effective upgrade target for a server is the highest fix among its CVEs. `work.py` is the service (queue computed live from open findings; a `work_items` row appears only after someone decides; key = CVE + ecosystem + package + installed version + upstream fix). Encoding note: the key is joined with `\x1f`; GET query params are decoded once by the framework, POST form values carry `quote()`d text and are `unquote`d once.

- [x] Asset ownership (migration `0015`; `asset_admin.set_ownership`, audited; `PATCH /api/v1/assets/{id}/ownership` needs operate; Assets filters owner/tier + "without an owner" note; Ownership panel on asset detail, editable by operators). Environment stays collector-reported (ingest overwrites it); owner/tier/service/window are never touched by ingest. Tier labels in `asset_admin.TIERS`; free-text maintenance window (no scheduler yet). **Bulk assign shipped** (`asset_admin.set_ownership_bulk`, `POST /ui/actions/assets/ownership-bulk`: ticked rows or "all N matching the current filter"; empty field = keep, so it can never blank data; one audit event lists the servers; operators see checkboxes, only admins see Delete; per-button confirm via `e.submitter` in the JS). **Open:** CSV import, owner directory/teams, tier/SLA settings page.
- [x] (shipped: `/ui/findings?group=cve|package|asset`, same filters, drill-down links to the flat list, new `component` filter; 0.6–0.8 s for CVE/package, 0.08 s for asset on 134k findings, no new index on purpose to keep analysis writes light. **Open:** the Work group key still needs the *recommended fixed version* (`min_safe_target` is only inside `verdict_json`; consider a column) and an index if grouped pages get slow; `low` and `unverified` share `level_rank` 1 so a group's label is taken from one of them) Findings group-by CVE / package / asset; keep the default flat table. Group key: CVE + package/ecosystem + installed version + recommended fixed version.
- [x] (`work.triage`: state, applicability, assignee, reason, actor, time, server count, latest snapshot ids per affected server; append-only `work_events`; "Verified" cannot be set by hand) Triage record: applicability (confirmed / potential / not applicable / unknown), confidence, decision, reason, actor, timestamp, source snapshot.
- [x] (`/ui/work` queue + `/ui/work/item` detail; views All / KEV / Needs validation / No fix known / My work; **open:** "Past SLA" view needs the SLA step; live count 2,346 items, 0.5 s) **Work** menu (after Alerts): grouped remediation queue, not one task per alert. Saved views: My work, KEV/external, Past SLA, Needs validation, No fix. States: New, Needs validation, Accepted, Scheduled, Mitigated, Verified, Deferred, Not applicable. `No vendor fix` when no verified fixed version (mitigation/exception, not a patch task).
- [x] (queue page: tick items, one decision + assignee + reason, max 200, per-item history + one audit event; **open:** an explicit scope preview step before applying, and "all matching this view") Bulk assign/triage only on groups, with scope preview and audit record.
- [x] (Alerts list has a "Work item" column linking each alert to its work item with the item's state; the item page shows its alert counts and links to `/ui/alerts?view=all&cve=...`; closing an alert never changes the item; **open:** optional "acknowledge alerts when the item is accepted") Alerts become an evidence/event stream linked to Work items; closing an alert is not "finding resolved".
- [x] (`risk.py`, version 1: severity 40/30/15/5 + KEV 25 + internet 10 + tier 10/5 + fix known 5 + age 3/5 − unverified 10, bands P1 80+ / P2 60+ / P3 35+ / P4; every point is shown as a reason in a tooltip, on the item page and in Settings) Risk score: transparent, versioned; components visible (`KEV + internet-facing + Tier 1`); inputs: KEV/exploit, exposure, asset tier, applicability/confidence, fix availability, age, freshness, compensating controls. Do not use CVSS alone.
- [x] (`sla.py`: per-band acknowledge hours + fix days in Settings, admin-only, validated and audited as `sla.update`; clock = earliest `first_seen` of the group, never reset; mitigated/verified/deferred/not-applicable pause it; **open:** verification target, per-tier overrides, deferral expiry via Exceptions) SLA: configurable in Settings (ack, remediation, verification targets differ); no reset on reassignment or severity change; pauses/exceptions carry actor, reason, expiry.
- [ ] Finding ownership/workflow metrics: see `TODO-OVERVIEW-FINDING-WORKFLOW.md`.
- [x] (3 cards: work past SLA, KEV work without an owner, work awaiting a decision; **open:** risky campaigns, which need Phase 3) Overview additions (cards link to filters): overdue KEV, stale evidence, work without owner, risky campaigns.

## Phase 3 - Remediation

- [x] **Campaigns** v1 (`campaigns.py`, migration 0019: `campaigns`, `campaign_items`, `campaign_targets`, `campaign_servers`, `campaign_events`; menu `/ui/campaigns`). Planned from the Work queue (tick items -> "Plan a campaign"): name, owner, change window, ticket ID, backout plan; planning marks items Scheduled; only New / Needs validation / Accepted / Scheduled items can be planned. Approval = a different admin than the author, needs a backout plan; editing the window or backout plan withdraws approval; Scheduled needs approval + backout + window; statuses Planned -> Scheduled -> In progress -> Completed / Cancelled (reason). Per-server **reported** status (Planned, Attempted, Updated, Failed, Unreachable, Excepted) vs **evidence**: an "Updated" server is Awaiting verification, Verified or Still affected strictly from newer analyzed snapshots (`work.server_evidence`). Change-list CSV (audited, login required). **Shipped since:** the worker (every 5 min, `campaigns.auto_progress`) promotes a campaign's work item to Verified once every server planned for it was reported Updated and a newer analyzed snapshot shows it clear, and completes the campaign when every server is Verified (actor `system:verification`; a failed or silent server keeps it open); overlapping open campaigns on the same servers are flagged on the campaign page (`campaigns.conflicts`, informational, never blocks; windows are compared by date, the per-server free-text maintenance window is not parsed). **Open:** ticket-system integration (the team uses none today, so only a free-text ID exists), mapping server status `Excepted` to an Exception record, campaign-level SLA, direct deployment (out of scope until approvals, staged rollout, health checks and recovery exist).
- [x] (`work.verification` / `verify_mitigated`, run by the worker every 5 min; migration 0017 stores the covered servers on each event. A server is clear only when its latest snapshot was collected **after** the mitigation was recorded, that snapshot is analyzed, and the group has no open finding on it; removed servers are set aside; silence is never proof; a fix that did not work shows "Still affected". Item page has a Verification panel; Mitigated pill has a tooltip. Mitigations recorded before 0017 have no server list and are never guessed - a person must re-record them. **Open:** a "Mitigated - awaiting verification" filter in the queue, and alerting when verification stays stuck for N days) `Mitigated` = operator-reported with evidence; `Verified` requires a new successful snapshot **and** fresh correlation showing the affected version gone. Show `Mitigated - awaiting fresh verification` while evidence is stale; never report that as verified/closed.
- [x] **Exceptions** menu (`/ui/exceptions`, migration 0018 `work_exceptions`): a Deferred decision now REQUIRES a reason and an expiry date (1-180 days) and may carry a compensating control; it creates an exception; changing the decision supersedes it; the worker (every 5 min) expires overdue ones and reopens the item as Needs validation (actor `system:exceptions`) **without resetting the SLA**; admins can revoke with a reason; views Active / Expiring within 30 days / Closed. **Open:** approver separate from requester, exceptions scoped to some servers only, expiry reminders/notifications, Not-applicable review dates.
- [ ] Reports: estate, owner/SLA, campaign verification, exception expiry, coverage freshness (keep per-asset reports).
- [ ] CVE Intel detail: affected asset count, affected package/version range, fix available/no fix, per-source evidence and timestamps (conflicts shown per source, `CVSS pending` shown as pending, not low), CWE, KEV date, related work. Keep intel record lifecycle (published/updated/rejected/withdrawn) separate from remediation workflow. No second catalog.
- [ ] v1 scope for campaigns: plan, change-list export, evidence, status, ticket integration. No direct deployment/auto-rollback.

## Phase 4 - Integrations

- [ ] Ticketing first. Then Ansible/AWX or a patch executor with approval, staged rollout, health checks, recovery. SBOM/image coverage after OS workloads are solid.
- Deferred until basic workflow is validated: supplier questionnaire, full GRC, predictive ML, automated rollback.

## Success metrics to support (build the data, then expose)

- % of assets/findings with *known* freshness (not just collectors online).
- Share of KEV with owner, triage decision and due date; stale/unknown reported separately.
- Time detection → acknowledgement → mitigation → verification; verification rate from fresh snapshots (not alerts closed).
- Work items per unique CVE/package/target fix (de-duplication).
- Feed records fetched/parsed/normalized/rejected and delta vs previous run.

## Menu plan (keep current menus and order; add **Remediation** group after Alerts only when Work is ready)

Overview (add overdue KEV / stale evidence / unowned work / risky campaigns) · Assets (owner, tier, env, service, window, freshness) · Findings (group-by + freshness/confidence badge) · Alerts (event stream) · **Work** · **Campaigns** · **Exceptions** · Reports · Coverage (asset-level stale list, queued refresh, last attempt/error, per-layer scope) · CVE Intel · AI Correlation / Skills (summaries only) · Status / Settings (SLA, tier, freshness targets, roles, integrations; mutations only for operator/admin).


## Backlog from review (2026-11-12)

- [ ] **Overview decision (waiting for the owner):** headline Open findings, plus a flow strip under it: new in period, closed in period, still open now (open and in assessment, not filtered by period), and past SLA. The "Remaining" card must count everything still unclosed, not only alerts created in the period, otherwise old backlog disappears when the window is short. Work items stay on the Work menu.
- [ ] **Alerts and Work feel slow (fixed in code, not yet measured on the server).** Alerts Open view: missing ordered index, fixed by migration `0020`. Work first load after cache expiry (about 1.5 s): cache TTL raised to 5 minutes, asset count added to the cache stamp. Still open: the cold computation itself (`work.groups`, about 1.5 s after any findings change). If it is still felt after the deploy, store the computed groups in a table written by the worker instead of per-process memory.
- [ ] **Asset deletion:** only permanent delete is built. Decide whether an archive mode is needed. Job history rows for a deleted asset are kept on purpose (they are not findings or alerts); confirm that is wanted.
- [ ] **Inline style attributes are blocked** by `style-src 'self'`. KPI card colours written as `style="--c:..."` across the app fall back to the default blue. Move them to `t-*` classes (as the Overview and Coverage cards already do) and audit `ui.py` for other `style="` attributes.
- [ ] **Stale tests:** `test_overview_shows_supported_kpis_and_finding_filters` and `test_overview_highest_cve_finding_level_tracks_open_findings` expect labels from an older Overview. `test_operator_brief_english_sections` calls `operator_brief(findings=...)`, which the current signature does not accept. Update or retire them; they are the three known failures.
- [ ] **Accounts:** API token expiry and rotation UI, a warning for tokens unused for a long time, and remove the duplicate `token.create` audit entry (`create_token` and `create_user_token` both write one).
- [ ] **Login rate limit is per uvicorn worker** (4 workers, so about 40 attempts per minute in practice). Move it to a shared store if this matters.
- [ ] **Database setup on <SERVER_IP>:** run `scripts/setup-db.sh` once after the deploy. Migration 0020 creates the alert index, and the script collects statistics, which the server has never had. Do not use `--recreate` there without a backup decision.
- [ ] **Test `scripts/setup-db.sh --recreate` end to end** on a throwaway volume. Only the copy-and-remove step was tested, on a dummy file.
- [ ] **Rename follow-ups (RiskPatch):** rename the database file and the `stackwatch-db` / `stackwatch-backups` volumes with a data migration (copy the file, verify `riskpatch db check`, keep the old file as a backup); update the AWX job templates and survey variables to `riskpatch_*`; remove the `STACKWATCH_*` fallback after every server has moved; decide whether `sw_` tokens should be reissued.
- [ ] **Deploy pending on <SERVER_IP>:** pull and rebuild for the assignee dropdowns, alert bulk actions, asset deletion, AI Skills fix, and Coverage Jobs/System move.
- [ ] **Laptop certificate:** `certs/cert.pem` in the working copy differs from the committed one. Decide whether a regenerated certificate should be committed or kept local.

## Security notes (read before touching UI auth or exports)

- **Anonymous visitors (guests) may only open the Overview (`/ui`).** `ui.user()` raises a 303 to `/ui/login` for any other path, form or download when there is no valid session; guests see a nav with only Overview and a Sign in button, no search. Decided by the owner on 2026-11-11. Real accounts have `Principal.kind == "user"`; guests have kind `"token"` and name `guest`. `login_required(c)` stays on the CSV exports as defence in depth. The Overview itself still shows estate-level numbers to guests.
- The API (`/api/v1`) is separate and always needs a bearer token.

## Progress log

Newest first. Add a line per shipped step: date, what, commit.

- 2026-11-13 - Renamed Stackwatch to RiskPatch: package, command, image, collector, Ansible variables, env vars (legacy names still read), brand on the sidebar, login page, title and favicon. Database file and volumes keep their names. See CHANGELOG.md.
- 2026-11-12 - Database setup: `scripts/setup-db.sh`, `riskpatch db check|analyze`, daily worker statistics, README section on setup and recreation. Indexes stay in migrations; statistics were never created anywhere before.
- 2026-11-12 - Alerts and Work speed: ordered alert index (migration 0020, Open view from about 230 ms to under 1 ms on a 214k-alert copy); Work cache TTL 5 min with asset count in its stamp. Not yet deployed to <SERVER_IP>.
- 2026-11-12 - Asset deletion (admins, audited, cascades to findings, alerts, reports, snapshots). Commit 8356f2a.
- 2026-11-12 - Alert Center: 100 per page, asset filter, bulk acknowledge and mark closed with one evidence note. Commits 6838bdb, 774e0ca.
- 2026-11-12 - AI Skills bulk actions moved out of an inline script blocked by CSP. Commit 0685900.
- 2026-11-12 - Assignee and owner dropdowns of registered accounts; table links no longer wrap. Commit f55d019.
- (date not recorded) - Username and password accounts with roles (viewer, operator, admin), Settings page, owned and purpose-tagged API tokens, `riskpatch user` CLI. Commits ac88ce1, 7f29f1f.
- (date not recorded) - Jobs and System menus merged into Coverage; schedules with Run now, Pause, and Delete. Coverage uses one page for scheduler, schedules, and jobs.
- 2026-11-12 - No ticketing system in use, so Phase 4 integrations are parked. Shipped instead: campaign auto-verify/auto-complete, schedule conflict warning, Overview card for deferrals ending within 14 days.
- 2026-11-12 - Campaigns v1 (plan, approval, status, per-server evidence, change-list CSV). Phase 3 is done except ticket integration; Phase 4 (integrations) not started.
- 2026-11-12 - Exceptions: deferrals need an expiry and reopen automatically (`work.expire_exceptions`, `work.revoke_exception`, migration 0018). Next: Campaigns.
- 2026-11-12 - Phase 3 started: automatic verification of mitigated work from fresh snapshots (`work.verify_mitigated`, migration 0017, commit 265de7c). Next: Exceptions (deferral with expiry), then Campaigns.
- 2026-11-12 - Alerts <-> Work linking (`work.for_findings`, `work.alert_counts`, `cve` filter on Alerts). Phase 2 is complete except SLA verification target and per-tier overrides.
- 2026-11-12 - Risk score + SLA + Overview work cards. Performance note: open findings grew to 218k and 4,421 work groups; `work.groups` is cached 60 s and validated by `_stamp` (work_items, SLA settings, `MAX(findings.updated_at)`) so every uvicorn worker sees decisions at once; the item page computes only its own group. A wide covering index on findings would make the cold computation (~1.3 s) faster but slows analysis writes - deliberately not added yet.
- 2026-11-11 - Work menu, work item detail, triage and bulk triage (`work.py`, `ui.py`, `tests/test_work.py`). Next in Phase 2: risk score + SLA, link Alerts to Work items, Overview cards (overdue KEV, unowned work).
- 2026-11-11 - Work foundation: migration 0016 (`findings.fixed_version`, `work_items`, `work_events`), fixed versions derived from NVD ranges and backfilled (95,653 of 134,603 findings), 2,346 work groups on current data.
- 2026-11-11 - Guests restricted to the Overview; all other UI pages need a login.
- 2026-11-11 - Findings CSV download (`/ui/findings/export.csv`: flat or grouped, same filters, streaming, audited as `findings.export`, login required, formula-safe via `csv_safe`). Alerts CSV now also requires login.
- 2026-11-11 - Findings group-by CVE / package / asset with a Flat/By switch.
- 2026-11-11 - Bulk assign ownership on Assets (selected rows or all matching the filter).
- 2026-11-11 - Phase 2 started: asset ownership (owner, tier, service, maintenance window) with audit, API, Assets filters and detail panel.
- 2026-11-11 - Status page "Intel feed runs" (`ui.feed_runs_panel`). Phase 1 is complete except: denominators/scope on Overview and Assets counts, per-record rejected counts in feed sync, and the CVE Intel feed-update column.
- 2026-11-11 - Freshness chips on Assets/Findings, clearer timestamp labels, per-server re-check + refresh status on Coverage (`freshness.asset_freshness`, `refresh_status`). Report retention shipped (prunes nothing yet).
- 2026-11-11 - Coverage risk box split into total / freshly confirmed / old data (`summary()` adds `findings_open_total`, `findings_confirmed`, `findings_old_data`); guide explains why counts differ.
- 2026-11-11 - Coverage "Servers needing attention" table (`freshness.attention_assets`); risk box reworded to last-known; CVE sync queues a follow-up analysis. Note: correlation entries stay stale until the next analysis finishes after a deploy (use "Run analysis").
- 2026-11-11 - Coverage: stale explanation panel, per-layer hints, correlation re-baseline, horizontal legend, aligned risk box. Perf: indexes (migration 0014), 4 workers, FTS `search_map` (0013), real totals on asset detail. See `git log`.
