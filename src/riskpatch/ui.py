"""Server-rendered, read-mostly web UI. Cookie session holds an API token; every POST carries a CSRF token."""
from __future__ import annotations

import html
import csv
import io
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, unquote

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse

from riskpatch import auth, llm
from riskpatch.api.app import LEVELS, dashboard_stats, fts_query, job_out, provider_out
from riskpatch.api.deps import RateLimiter, get_conn, principal_from
from riskpatch.auth import Principal
from riskpatch import freshness
from riskpatch import campaigns, risk, sla, work
from riskpatch.asset_admin import TIERS, delete_assets, set_ownership, set_ownership_bulk
from riskpatch.correlate import correlate
from riskpatch.db import (audit, connect, create_job_schedule, create_skill, delete_job_schedule, delete_skill,
                           get_job_schedule, get_skill, get_setting, list_active_skills, list_job_schedules, list_skills, now_iso, reset,
                           scheduler_enabled, set_job_schedule_enabled, set_job_schedule_last_run, set_setting, toggle_skill_active, tx, update_skill)
from riskpatch.jobs import enqueue
from riskpatch.textclip import best_summary, clip_list, operator_brief, product_from_key, _range_label

PAGE = 50
ALERT_PAGE = 100
LEVEL_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "unverified": "Unverified",
    # Indonesian legacy values in older DB rows
    "kritis": "Critical",
    "tinggi": "High",
    "sedang": "Medium",
    "rendah": "Low",
    "informasi": "Info",
}
STATUS_LABELS = {
    "success": "Success",
    "failed": "Failed",
    "partial": "Partial",
    "running": "Running",
    "queued": "Queued",
    "open": "Open",
    "resolved": "Resolved",
    "immediate": "Fix this week",
    "schedule": "Schedule within 30 days",
    "complete": "Complete inventory data",
    "document": "Document and monitor",
    "cve_sync": "CVE sync",
    "manual_cve_sync": "Manual CVE sync",
    "analysis": "Analysis",
    "manual_analysis": "Manual analysis",
    "freshness_refresh": "Coverage refresh",
    "verdict": "Verdict",
    "analyzed": "Analyzed",
    # Indonesian legacy values
    "segera": "Fix this week",
    "jadwalkan": "Schedule within 30 days",
    "lengkap": "Complete inventory data",
    "dokumentasi": "Document and monitor",
}
EMPTY_VALUES = {"", "unknown", "none", "null", "{}", "[]", "-"}
NAV = [
    ("/ui", "Overview"),
    ("/ui/assets", "Assets"),
    ("/ui/findings", "Findings"),
    ("/ui/alerts", "Alerts"),
    ("/ui/work", "Work"),
    ("/ui/exceptions", "Exceptions"),
    ("/ui/campaigns", "Campaigns"),
    ("/ui/reports", "Reports"),
    (freshness.COVERAGE_PAGE["path"], freshness.COVERAGE_PAGE["label"]),
    ("/ui/cves", "CVE Intel"),
    ("/ui/correlate", "AI Correlation"),
    ("/ui/skills", "AI Skills"),
    ("/ui/status", "Status"),
    ("/ui/settings", "Settings"),
]
CSS = """
:root{--bg:#08111f;--side:#091527;--panel:#0e1b2f;--panel2:#12233b;--line:#1d2f4b;--text:#e8eef8;--muted:#97a7be;--teal:#2ed3b7;--blue:#4d8df7;--link:#7cc7ff;--red:#ff7a7a;--orange:#fb923c;--amber:#f6bd4f;--green:#45dc9c;--slate:#64748b;--red-bg:rgba(255,122,122,.12);--amber-bg:rgba(246,189,79,.12);--green-bg:rgba(69,220,156,.14)}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:15px;line-height:1.45}
button,input,select,textarea{font-family:inherit;font-size:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:10px}
button,a.btn,a.ghost,a.primary{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 16px;cursor:pointer;font-weight:600;text-decoration:none;line-height:1.2}
button.primary,a.primary,.btn.primary{background:var(--blue);border-color:var(--blue);color:#06142b}
button.primary:hover,a.primary:hover,.btn.primary:hover{background:#6aa1fa;border-color:#6aa1fa;color:#06142b}
button.ghost,a.ghost,.btn.ghost{background:transparent;border-color:var(--line);color:var(--text)}
button.ghost:hover,a.ghost:hover,.btn.ghost:hover{background:#12233b;border-color:#2a4668;color:var(--text)}
button.danger,a.danger,.btn.danger,button.ghost.danger{background:#c8123f;border-color:#c8123f;color:#fff}
button.danger:hover,a.danger:hover,.btn.danger:hover,button.ghost.danger:hover{background:#e0214f;color:#fff}
select,input[type=text],input[type=search],input[type=number],input[type=password],textarea{background:var(--panel2);color:var(--text);border:1px solid var(--line)}
select option{background:#0e1b2f;color:#e8eef8}
input::placeholder,textarea::placeholder{color:#8091aa}
input[type=checkbox]{accent-color:var(--teal);width:16px;height:16px}
:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.app{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.side{background:var(--side);border-right:1px solid var(--line);padding:22px 16px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.brand{font-weight:700;letter-spacing:.04em;font-size:17px;padding:0 4px}
.brand b{color:var(--teal)}
.tag{color:var(--muted);font-size:11px;letter-spacing:.08em;margin-top:6px;padding:0 4px}
.nav{margin:26px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:2px;overflow:auto}
.nav li{list-style:none}
.nav a{display:block;padding:10px 14px;border-radius:10px;color:#c5d2e6;text-decoration:none}
.nav a:hover{background:#0f2036}
.nav a[aria-current="page"]{background:#15304f;color:var(--teal);font-weight:600}
.me{margin-top:auto;border-top:1px solid var(--line);padding-top:16px}
.me strong{display:block;font-size:13px;margin-bottom:10px}
.btn{border:1px solid var(--line);background:transparent;border-radius:10px;padding:9px 16px;cursor:pointer;font-weight:600;color:var(--text);transition:all .2s ease}
.btn:hover{background:#1a3556;border-color:#2a4668;box-shadow:0 2px 8px rgba(0,0,0,.15)}
.btn.primary{background:var(--blue);border-color:var(--blue);color:#06142b}
.btn.primary:hover{background:#6aa1fa;border-color:#6aa1fa}
.btn.ghost{background:transparent;border-color:var(--line);color:var(--text)}
.btn.ghost:hover{background:#12233b;border-color:#2a4668}
.btn.danger{background:#c8123f;border-color:#c8123f;color:#fff}
.btn.danger:hover{background:#e0214f;border-color:#e0214f}
.btn.success{background:#059669;border-color:#059669;color:#fff}
.btn.success:hover{background:#10b981;border-color:#10b981}
.main{min-width:0}
.top{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;padding:22px 36px;border-bottom:1px solid var(--line)}
.top h1{margin:0;font-size:32px;letter-spacing:-.01em}
.top .sub{color:var(--muted);margin-top:4px;font-size:14.5px}
.search{display:flex;gap:10px;align-items:center}
.search input{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:240px;height:40px}
.search button{height:40px;padding-top:0;padding-bottom:0}
.top-actions{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.top-actions .period-form{margin:0}
.top-actions .sel{gap:10px}
.top-actions .sel select{height:40px}
.search input::placeholder{color:#8091aa}
.content{padding:24px 36px 48px;display:flex;flex-direction:column;gap:22px}
.bar{display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between}
.seg{display:inline-flex;background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:3px;gap:2px}
.seg button{background:transparent;border:1px solid transparent;border-radius:8px;padding:8px 16px;cursor:pointer;color:var(--muted);font-weight:600;transition:all .2s ease}
.seg button:hover{color:var(--text)}
.seg button[aria-selected="true"]{background:#1a3556;color:var(--text);border:1px solid #2ed3b7}
.sel{display:inline-flex;align-items:center;gap:10px;color:var(--muted);font-size:13px}
.period-form{display:flex;align-items:center;margin:0}
.sel select{appearance:none;-webkit-appearance:none;background:var(--panel) url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'><path d='M1 1l5 5 5-5' fill='none' stroke='%2397a7be' stroke-width='2'/></svg>") no-repeat right 12px center;border:1px solid var(--line);border-radius:10px;padding:9px 36px 9px 14px;color:var(--text);font-weight:600;cursor:pointer;position:relative;z-index:100}
.sel select:hover{background-color:#12233b}
.sel select option{background:#0e1b2f;color:#e8eef8}
.sel{z-index:100}
.asof{color:var(--muted);font-size:13px}
.asof+.asof{border-left:1px solid var(--line);padding-left:14px}
.stackv{display:flex;flex-direction:column;gap:22px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px}
.panel h2{margin:0 0 4px;font-size:13px;letter-spacing:.14em;text-transform:uppercase;font-weight:700}
.panel .hint{color:var(--muted);font-size:13px;margin:0 0 16px}
.grid{display:grid;gap:16px}
.g6{grid-template-columns:repeat(6,minmax(0,1fr))}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.t-red{--c:var(--red)}.t-orange{--c:var(--orange)}.t-amber{--c:var(--amber)}.t-green{--c:var(--green)}.t-blue{--c:var(--blue)}
.mt-12{margin-top:12px}
.fcard{border-left:4px solid var(--red);padding:26px 30px 22px}
.fc-head{display:flex;justify-content:space-between;align-items:flex-end;gap:32px;flex-wrap:wrap}
.fc-kicker{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:700}
.fc-num{font-size:60px;font-weight:700;letter-spacing:-.02em;line-height:1;margin:10px 0 10px;color:var(--text)}
.fc-sub{color:var(--muted);font-size:14px}
.fc-sub b{color:var(--text);font-weight:600}
.fc-note{margin:0;max-width:44ch;color:var(--muted);font-size:13px;line-height:1.5;text-align:right}
.fc-flow{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));margin-top:26px;border-top:1px solid var(--line)}
.fc-stat{display:block;padding:18px 22px 4px;text-decoration:none;border-left:1px solid var(--line)}
.fc-stat:first-child{border-left:none;padding-left:0}
.fc-stat:hover .fc-val{text-decoration:underline;text-underline-offset:4px}
.fc-lab{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:600}
.fc-val{font-size:38px;font-weight:700;line-height:1.1;margin:8px 0 6px;color:var(--c)}
.fc-cap{font-size:13px;color:var(--muted);line-height:1.4}
.fc-bar{display:flex;height:6px;border-radius:999px;overflow:hidden;background:var(--panel2);margin-top:22px}
.fc-bar svg{display:block;width:100%;height:100%}
.fc-foot{margin-top:10px;font-size:13px;color:var(--muted)}
.kc.mini .num{font-size:32px;margin:10px 0 6px}
.g2{grid-template-columns:minmax(0,1.35fr) minmax(0,1fr)}
.g2e{grid-template-columns:repeat(2,minmax(0,1fr))}
.banner{display:grid;grid-template-columns:auto 1fr;gap:20px;align-items:center;border-left:6px solid var(--amber)}
.state{font-size:26px;font-weight:700;color:var(--amber);white-space:nowrap}
.banner p{margin:0;color:#d6e0f0;max-width:80ch}
.why{margin:10px 0 0;padding-left:18px;color:var(--muted);font-size:14px}
.why li{margin:2px 0}
.kc-link{text-decoration:none;color:inherit;display:block}
.kc-link:hover .kc{border-color:#2a4668;box-shadow:0 0 1px rgba(46,230,200,.12),0 2px 10px rgba(0,0,0,.18)}
.kc{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c,var(--blue));border-radius:16px;padding:20px 22px;min-height:150px;display:flex;flex-direction:column;transition:border-color .2s ease,box-shadow .2s ease}
.kc .lab{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.kc .num{font-size:44px;font-weight:700;letter-spacing:-.02em;line-height:1;margin:12px 0 8px}
.kc .num small{font-size:16px;font-weight:500;color:var(--muted);letter-spacing:0;margin-left:6px}
.kc .sub{color:var(--muted);font-size:14px}
.kc .sub b{color:var(--text);font-weight:600}
.chip{display:inline-flex;align-items:center;gap:6px;border-radius:99px;padding:3px 10px;font-size:12.5px;font-weight:600;white-space:nowrap}
.chip::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
.chip.bad{color:var(--red);background:var(--red-bg)}
.chip.bad::before{border-radius:2px}
.chip.warn{color:var(--amber);background:var(--amber-bg)}
.chip.warn::before{border-radius:0;clip-path:polygon(50% 0,100% 100%,0 100%)}
.chip.ok{color:var(--green);background:var(--green-bg)}
.pill{display:inline-block;background:var(--green-bg);color:var(--green);border-radius:99px;padding:2px 10px;font-weight:700;font-size:12.5px}
.sev{display:flex;flex-direction:column;gap:14px}
.sev .row{display:grid;grid-template-columns:92px 1fr 40px;gap:14px;align-items:center;font-size:14px}
.sev .row span:first-child{color:var(--muted)}
.sev .track{height:7px;border-radius:99px;background:#16294a;overflow:hidden}
.sev .fill{display:block;width:100%;height:100%}
.sev .cnt{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.actions{display:flex;flex-wrap:wrap;gap:12px}
.pipe{color:var(--muted);font-size:13.5px;margin:2px 0 0}
.t-per{color:inherit}
.legend{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-bottom:8px}
.legend i{display:inline-block;width:14px;height:4px;border-radius:2px;margin-right:6px;vertical-align:middle}
svg.chart{width:100%;height:auto;display:block}
.chart text{fill:#8ea0b9;font-size:11px;font-family:inherit}
.stk{display:flex;height:26px;border-radius:8px;overflow:hidden;gap:2px;margin:8px 0 12px}
.stk span{display:block;height:100%}
.keys{display:grid;gap:8px}
.keys div{display:flex;justify-content:space-between;gap:10px;font-size:14px}
.keys i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:8px}
.note{color:var(--muted);font-size:13px;margin:12px 0 0}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:#0b1829}
table{width:100%;border-collapse:collapse;font-size:14px}
th{font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);text-align:left;padding:12px 14px;border-bottom:1px solid var(--line);white-space:nowrap;background:#0d1d33}
td{padding:12px 14px;border-bottom:1px solid #162843;vertical-align:top}
tr:last-child td{border-bottom:0}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
a.lk{color:var(--link);text-decoration:none}a.lk:hover{text-decoration:underline}
.muted{color:var(--muted)}
.ai{display:inline-block;border:1px dashed #5f7aa3;border-radius:6px;padding:1px 7px;font-size:12px;color:#b9c9e2}
.prov{list-style:none;margin:0;padding:0}
.prov li{display:flex;justify-content:space-between;gap:14px;padding:13px 2px;border-bottom:1px solid #162843}
.prov li:last-child{border-bottom:0}
.prov .nm{display:flex;align-items:center;gap:12px}
.prov .dot{width:9px;height:9px;border-radius:50%;background:var(--teal)}
.prov .dot.late{background:var(--amber);border-radius:0;clip-path:polygon(50% 0,100% 100%,0 100%)}
.prov .st{color:var(--muted);font-size:14px;text-align:right}
.foot-note{color:var(--muted);font-size:12.5px;text-align:center;padding-top:6px}
.top .lede{color:var(--muted);margin:4px 0 0;font-size:14.5px}
.toolbar,.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
form.inline{display:inline}
.filters{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin:0 0 16px}
.filters .fl{display:flex;flex-direction:column;gap:6px;color:var(--muted);font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.filters input,.filters select,form.filters>input{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:9px 12px;color:var(--text);min-width:160px}
.filters button,form.filters>button,.login-card button{border:0;background:var(--blue);color:#06142b;border-radius:10px;padding:9px 16px;font-weight:700;cursor:pointer}
.filters button:hover,form.filters>button:hover,.login-card button:hover{background:#6aa1fa}
.table-wrap,.tw{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:#0b1829}
.badge{display:inline-flex;align-items:center;border-radius:99px;padding:2px 10px;font-size:12px;font-weight:700;letter-spacing:.02em}
.badge.critical,.badge.kritis{color:var(--red);background:var(--red-bg)}
.badge.high,.badge.tinggi{color:var(--orange);background:rgba(251,146,60,.14)}
.badge.medium,.badge.sedang{color:var(--amber);background:var(--amber-bg)}
.badge.low,.badge.rendah,.badge.success{color:var(--green);background:var(--green-bg)}
.badge.informational,.badge.informasi,.badge.unverified,.badge.failed{color:var(--muted);background:rgba(100,116,139,.18)}
.badge.kev{color:#06142b;background:var(--amber)}
.kpi-link{text-decoration:none;color:inherit}
.kpi{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:16px;padding:18px 20px;display:flex;flex-direction:column;min-height:120px}
.kpi.warn{border-left-color:var(--amber)}.kpi.bad{border-left-color:var(--red)}.kpi.ok{border-left-color:var(--green)}
.kpi-label{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.kpi b{font-size:36px;letter-spacing:-.02em;margin:8px 0 4px}
.kpi-hint{color:var(--muted);font-size:13px}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.fact{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.fact span{display:block;color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase}
.fact b{font-weight:600}
.pager{color:var(--muted);font-size:13px;display:flex;gap:12px;flex-wrap:wrap}
.pager a{color:var(--link);text-decoration:none}
.pager a:hover{text-decoration:underline}
a:not(.btn):not(.ghost):not(.primary):not(.nav a){color:var(--link)}
.content a:not(.btn):not(.ghost):not(.primary),td a,th a,.pager a{color:var(--link);text-decoration:none}
.content a:not(.btn):not(.ghost):not(.primary):hover,td a:hover,.pager a:hover{text-decoration:underline;color:#b7e0ff}
.nav a{color:#c5d2e6}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:12px 0}
.form-grid .full,.form-grid textarea{grid-column:1/-1}
.form-compact{margin-top:14px;background:transparent;border:0;padding:0}
.form-actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:14px}
.fl{display:flex;flex-direction:column;gap:6px;color:var(--muted);font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.fl input,.fl select,.fl textarea{text-transform:none;letter-spacing:0;font-size:15px;font-weight:500;padding:9px 12px;width:100%}
textarea{min-height:96px;resize:vertical}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:#12233b;border-radius:6px;padding:1px 6px}
.report-md h1,.report-md h2,.report-md h3{margin:12px 0 6px}
.report-md p,.report-md li{color:#d6e0f0}
.stale{color:var(--red)}
.login-body{min-height:100vh;display:grid;place-items:center;background:var(--bg)}
.login-card{width:min(420px,92vw);background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px}
.login-card .brand{letter-spacing:.04em;font-weight:700;font-size:18px}
.login-card .brand span,.login-card .brand b{color:var(--teal)}
.login-card .brand-sub,.login-card p{color:var(--muted)}
.login-card h1{margin:8px 0 12px;font-size:28px}
.login-card input{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:0 0 14px}
.login-card button{width:100%}
@media (max-width:1500px){.g6{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:1100px){.g4,.g3{grid-template-columns:repeat(2,minmax(0,1fr))}.g2,.g2e{grid-template-columns:1fr}.fc-flow{grid-template-columns:repeat(2,minmax(0,1fr))}.fc-stat:nth-child(odd){border-left:none;padding-left:0}.fc-note{text-align:left}}
@media (max-width:860px){.app{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;align-items:center;gap:14px;overflow-x:auto}.nav{flex-direction:row;margin:0}.me{display:none}.top,.content{padding-left:18px;padding-right:18px}.g6,.g4,.g3,.alert-grid{grid-template-columns:1fr}.banner{grid-template-columns:1fr}}
.close-evidence{margin-top:8px;max-width:280px}
.close-evidence summary{cursor:pointer;color:var(--amber);font-size:12px;font-weight:600}
.close-evidence textarea{width:100%;min-height:64px;box-sizing:border-box;margin:6px 0}
.seg a{display:inline-block;text-decoration:none;color:var(--muted);font-weight:600;border:1px solid transparent;border-radius:8px;padding:8px 16px}
.seg a:hover{color:var(--text)}
.seg a[aria-current="page"]{background:#1a3556;color:var(--text);border:1px solid #2ed3b7}
.spill{display:inline-flex;align-items:center;gap:8px;border:1px solid currentColor;border-radius:99px;padding:2px 10px;font-size:12px;font-weight:700;white-space:nowrap}
.spill i{width:8px;height:8px;border-radius:50%;background:currentColor;display:inline-block}
.st-success,.tr-built{color:var(--green)}
.st-running{color:#60a5fa}
.st-stale,.tr-detect{color:var(--amber)}
.st-failed,.tr-notbuilt{color:var(--red)}
.st-pending{color:#a3b1c6}
.tr-proposed{color:#60a5fa}
.t-slate{--c:var(--slate)}
.c-red{color:var(--red)}
.c-orange{color:var(--orange)}
.c-amber{color:var(--amber)}
.c-green{color:var(--green)}
.c-blue{color:var(--blue)}
.c-slate{color:#a3b1c6}
.cov-bar{display:block;border-radius:99px;overflow:hidden;margin-top:0}
.cov-layer{display:grid;grid-template-columns:minmax(200px,1.2fr) 130px minmax(200px,1fr);gap:16px;padding:16px 0;border-top:1px solid var(--line);align-items:center}
.cov-title{font-weight:600}
.cov-detail{font-size:14px;margin-top:4px}
.cov-meta{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-bottom:8px;flex-wrap:wrap}
.cov-age{font-weight:600}
.bulk{margin:0 0 14px}
.bulk h2{margin:0 0 4px;font-size:13px;letter-spacing:.14em;text-transform:uppercase;font-weight:700}
.filters .fl.chk{flex-direction:row;align-items:center;gap:8px;text-transform:none;letter-spacing:0;font-size:13px}
.badge.wk-slate{background:#1b2a3f;color:#a3b1c6}.badge.wk-amber{background:var(--amber-bg);color:var(--amber)}.badge.wk-blue{background:rgba(77,141,247,.14);color:var(--blue)}.badge.wk-green{background:var(--green-bg);color:var(--green)}
.cov-why{font-size:13px;margin-top:6px;color:var(--muted)}
.cov-why b{color:var(--text)}
.cov-guide p{margin:0 0 10px}
.cov-states{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px 18px;margin:12px 0 14px}
.cov-states>div{display:flex;flex-direction:column;align-items:flex-start;gap:6px;font-size:13px;color:var(--muted);line-height:1.35}
@media (max-width:1100px){.cov-states{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:640px){.cov-states{grid-template-columns:repeat(2,minmax(0,1fr))}}
.cov-dist{display:block;border-radius:8px;overflow:hidden}
.cov-legend{display:flex;flex-wrap:wrap;gap:14px 28px;margin-top:18px}
.cov-legendItem{display:flex;align-items:center;gap:10px}
.cov-count{font-size:20px;font-weight:700}
.cov-risk{display:grid;grid-template-columns:140px minmax(0,1fr);column-gap:20px;align-items:baseline;padding:14px 0;border-top:1px solid var(--line)}
.cov-risk-n{font-size:30px;line-height:1.1;font-variant-numeric:tabular-nums;white-space:nowrap}
@media (max-width:640px){.cov-risk{grid-template-columns:1fr;row-gap:4px}}
.bulk-bar{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;margin:0 0 14px}
.bulk-bar .bulk-note{flex:1 1 320px;min-width:0}
.bulk-bar .bulk-note input{width:100%}
td a.lk{white-space:nowrap}
.brand{display:flex;align-items:center;gap:8px}
.brand-mark{flex:0 0 auto}
.tagline{color:var(--teal);font-weight:600;letter-spacing:.03em;margin:2px 0 14px}
.scope-picker{border:0;padding:0;margin:0;display:flex;flex-direction:column;gap:8px;min-width:0}
.scope-picker legend{color:var(--muted);font-size:12px;letter-spacing:.06em;text-transform:uppercase;margin-bottom:6px;padding:0}
.scope-options{display:flex;flex-wrap:wrap;gap:8px}
.scope-options label{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:99px;padding:7px 14px;background:var(--panel2);color:var(--text);font-size:14px;font-weight:600;cursor:pointer;text-transform:none;letter-spacing:0}
.scope-options label:hover{border-color:#2a4668}
.scope-options input[type=checkbox]{width:auto;min-width:0;margin:0;accent-color:var(--teal)}
@media (max-width:860px){.cov-layer{grid-template-columns:1fr}}
"""
JS = """
document.addEventListener('submit',function(e){var m=(e.submitter&&e.submitter.getAttribute('data-confirm'))||e.target.getAttribute('data-confirm');if(m&&!window.confirm(m)){e.preventDefault();}});
document.addEventListener('change',function(e){if(e.target.matches('.period-select')&&e.target.form)e.target.form.requestSubmit();});
document.addEventListener('change',function(e){if(e.target.matches('input[data-select-all]')){document.querySelectorAll('input[name="alert_id"]:not([disabled])').forEach(function(b){b.checked=e.target.checked;});}});
document.addEventListener('click',function(e){
  var btn=e.target.closest('.seg [role="tab"]');
  if(!btn) return;
  var list=btn.closest('[role="tablist"]');
  if(!list) return;
  e.preventDefault();
  list.querySelectorAll('[role="tab"]').forEach(function(t){
    var on=t===btn;
    t.setAttribute('aria-selected',on?'true':'false');
    var panel=document.getElementById(t.getAttribute('aria-controls'));
    if(panel) panel.hidden=!on;
  });
});
document.addEventListener('change',function(e){if(e.target.id==='select-all'){document.querySelectorAll("input[name='skill_ids']").forEach(function(b){b.checked=e.target.checked;});}});
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('[data-bulk]');if(!b)return;e.preventDefault();var form=b.closest('form');var mode=b.getAttribute('data-bulk');var ids=Array.from(form.querySelectorAll("input[name='skill_ids']:checked")).map(function(x){return x.value;});if(!ids.length){alert('Select at least one skill');return;}if(mode==='delete'&&!confirm('Delete '+ids.length+' selected skill(s)?'))return;var f=document.createElement('form');f.method='POST';f.action=mode==='delete'?'/ui/actions/skill/bulk-delete':'/ui/actions/skill/bulk-toggle';var cs=document.createElement('input');cs.type='hidden';cs.name='csrf';cs.value=form.querySelector("input[name='csrf']").value;f.appendChild(cs);if(mode!=='delete'){var ac=document.createElement('input');ac.type='hidden';ac.name='active';ac.value=mode==='activate'?'1':'0';f.appendChild(ac);}ids.forEach(function(id){var h=document.createElement('input');h.type='hidden';h.name='skill_ids';h.value=id;f.appendChild(h);});document.body.appendChild(f);f.submit();});
"""


def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def fmt_n(v: Any) -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return "-" if v is None else str(v)


def fmt_dt(v: Any) -> str:
    if not v:
        return "-"
    raw = str(v)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        secs = int((datetime.now(timezone.utc) - dt).total_seconds())
        if secs < 90:
            rel = "just now"
        elif secs < 3600:
            rel = f"{secs // 60}m ago"
        elif secs < 86400:
            rel = f"{secs // 3600}h ago"
        elif secs < 7 * 86400:
            rel = f"{secs // 86400}d ago"
        else:
            rel = dt.strftime("%b %d")
        return f"{dt.strftime('%b %d, %H:%M')} UTC · {rel}"
    except ValueError:
        return raw


def label_of(value: str | None) -> str:
    if not value:
        return "-"
    return LEVEL_LABELS.get(value, STATUS_LABELS.get(value, value.replace("_", " ").title()))


def classified(v: Any, empty: str = "Not classified") -> str:
    if v is None:
        return empty
    s = str(v).strip()
    if s.lower() in EMPTY_VALUES:
        return empty
    return s


def actor_label(v: Any) -> str:
    s = classified(v, "system")
    return s[6:] if s.startswith("token:") else s


def en_text(v: Any) -> str:
    s = "" if v is None else str(v)
    for src, dst in (
        ("New CVE ", "New CVE "),
        ("Rollup raised informational → critical", "Rollup raised informational → critical"),
        ("Rollup raised from ", "Rollup raised from "),
        ("Provider failed: ", "Provider failed: "),
        ("from template, not from live traffic", "from template, not from live traffic"),
        ("Version ", "Version "),
        ("is in the affected range", "is in the affected range"),
        ("Actual risk is critical", "Actual risk is critical"),
        ("Unknown exposure treated as internet", "Unknown exposure treated as internet"),
        ("open network exposure and weak or unknown auth", "open network exposure and weak or unknown auth"),
        ("distro package ", "distro package "),
        ("vendor backport must be verified in the changelog", "vendor backport must be verified in the changelog"),
        ("from snapshot", "from snapshot"),
        ("from NVD", "from NVD"),
        # Indonesian legacy raises/lowers text in older DB rows
        ("exposure unknown diperlakukan sebagai internet", "unknown exposure treated as internet"),
        ("network, exposure terbuka, dan auth lemah atau tidak diketahui", "network, open exposure, and weak or unknown auth"),
        ("auth lemah atau tidak diketahui", "weak or unknown auth"),
        ("exposure terbuka", "open exposure"),
        ("masuk KEV", "in KEV"),
        ("dinaikkan satu level", "bumped one level"),
        ("dipangkas satu level", "lowered one level"),
        ):
        s = s.replace(src, dst)
    return s


def fmt_dur(v: Any) -> str:
    if v in (None, ""):
        return "-"
    try:
        sec = float(v)
    except (TypeError, ValueError):
        return str(v)
    if sec < 1:
        return "<1s"
    if sec < 60:
        return f"{int(sec)}s"
    if sec < 3600:
        return f"{int(sec // 60)}m {int(sec % 60)}s"
    return f"{int(sec // 3600)}h {int((sec % 3600) // 60)}m"


def summarize_counts(counts: Any) -> str:
    if not counts:
        return "-"
    if isinstance(counts, str):
        try:
            counts = json.loads(counts)
        except json.JSONDecodeError:
            return counts
    if not isinstance(counts, dict):
        return str(counts)
    parts = [f"{k.replace('_', ' ')} {fmt_n(v)}" for k, v in counts.items() if v not in (None, "", 0, "0")]
    return " · ".join(parts) or "No changes"


def fact(label: str, value: str) -> str:
    return f'<div class="fact"><span>{esc(label)}</span><b>{esc(value)}</b></div>'


def kev_cell(flag: Any) -> str:
    return '<span class="badge kev">KEV</span>' if flag else '<span class="muted">-</span>'


def _md_inline(text: str) -> str:
    out = esc(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)


def md_to_html(text: str) -> str:
    parts: list[str] = []
    ul = False

    def close_ul() -> None:
        nonlocal ul
        if ul:
            parts.append("</ul>")
            ul = False

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if line.startswith("# "):
            close_ul(); parts.append(f"<h1>{_md_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            close_ul(); parts.append(f"<h2>{_md_inline(line[3:])}</h2>")
        elif line.startswith("### "):
            close_ul(); parts.append(f"<h3>{_md_inline(line[4:])}</h3>")
        elif line.startswith("- "):
            if not ul:
                parts.append("<ul>"); ul = True
            parts.append(f"<li>{_md_inline(line[2:])}</li>")
        elif re.match(r"^\d+\. ", line):
            close_ul(); parts.append(f"<p>{_md_inline(line)}</p>")
        elif line:
            close_ul(); parts.append(f"<p>{_md_inline(line)}</p>")
        else:
            close_ul()
    close_ul()
    return '<div class="report-md">' + "".join(parts) + "</div>"


def badge(level: str | None) -> str:
    if not level:
        return '<span class="muted">-</span>'
    return f'<span class="badge {esc(level)}">{esc(label_of(level))}</span>'


def table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows) or f'<tr><td colspan="{len(headers)}" class="muted">No data</td></tr>'
    return f'<div class="table-wrap"><table><tr>{head}</tr>{body}</table></div>'


def kpi(label: str, value: Any, hint: str = "", tone: str = "", href: str = "") -> str:
    cls = f'kpi {tone}'.strip()
    inner = (f'<article class="{esc(cls)}"><span class="kpi-label">{esc(label)}</span>'
             f'<b>{esc(fmt_n(value))}</b><span class="kpi-hint">{esc(hint)}</span></article>')
    return f'<a class="kpi-link" href="{esc(href)}">{inner}</a>' if href else inner


class Ctx:
    def __init__(self, request: Request, who: Principal, conn: sqlite3.Connection):
        self.request, self.who, self.conn = request, who, conn
        self.token = request.cookies.get("rp_session", "")
        self.csrf = auth.csrf_for(self.token)

    def post_form(self, action: str, label: str, confirm: str, extra: str = "", cls: str = "") -> str:
        if not self.who.has("operate"):
            return ""
        base_class = "btn"
        if cls:
            base_class += f" {cls}"
        klass = f' class="{esc(base_class)}"'
        return (f'<form class="inline" method="post" action="{esc(action)}" data-confirm="{esc(confirm)}">'
                f'<input type="hidden" name="csrf" value="{self.csrf}">{extra}<button{klass}>{esc(label)}</button></form>')

    def page(self, title: str, body: str, refresh: bool = False, lede: str = "", actions: str = "") -> HTMLResponse:
        path = self.request.url.path.rstrip("/") or "/ui"
        guest = self.who.kind != "user"
        links = []
        for href, name in (NAV[:1] if guest else NAV):
            active = ' aria-current="page"' if path == href or (href != "/ui" and path.startswith(href)) else ""
            links.append(f'<li><a{active} href="{href}">{name}</a></li>')
        if self.who.has("admin") and not guest:
            active = ' aria-current="page"' if path.startswith("/ui/audit") else ""
            links.append(f'<li><a{active} href="/ui/audit">Audit</a></li>')
        nav = "".join(links)
        search = '<form class="search" method="get" action="/ui/search"><input name="q" placeholder="Search CVE, package, host" aria-label="Search CVE, package, host"><button class="btn primary" type="submit">Search</button></form>'
        logout = (f'<form method="post" action="/ui/logout"><input type="hidden" name="csrf" value="{self.csrf}">'
                  f'<button class="btn ghost" type="submit">Sign out</button></form>') if not guest else '<a class="btn primary" href="/ui/login">Sign in</a>'
        if guest:
            search = ""
        meta = '<meta http-equiv="refresh" content="10">' if refresh else ""
        sub = lede or "Vulnerability operations console"
        return HTMLResponse(
            f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} · RiskPatch</title>{meta}<link rel="icon" href="{FAVICON_HREF}"><link rel="stylesheet" href="/ui/static/app.css">'
            f'<script src="/ui/static/app.js" defer></script></head><body>'
            f'<div class="app">'
            f'<aside class="side"><div>'
            f'<div class="brand">{BRAND_MARK}<span>RISK<b>PATCH</b></span></div>'
            f'<div class="tag">PATCH Management Platform</div>'
            f'</div>'
            f'<ul class="nav">{nav}</ul>'
            f'<div class="me"><strong>{esc(actor_label(self.who.actor))}</strong>'
            f'{logout}</div></aside>'
            f'<div class="main">'
            f'<header class="top"><div><h1>{esc(title)}</h1><p class="lede">{esc(sub)}</p></div><div class="top-actions">{actions}{search}</div></header>'
            f'<main class="content">{body}</main></div></div></body></html>'
        )


BRAND_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><path d="M16 2 4 6.5v8.2c0 7.4 5 13.4 12 15.3 7-1.9 12-7.9 12-15.3V6.5Z" fill="#2ed3b7"/><path d="m10.5 16.2 3.8 3.8 7.2-7.4" fill="none" stroke="#070e1c" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
BRAND_MARK = BRAND_SVG.replace('<svg ', '<svg class="brand-mark" width="26" height="26" aria-hidden="true" ', 1)
FAVICON_HREF = "data:image/svg+xml," + quote(BRAND_SVG)


STATE_LABELS = {"success": "Success", "running": "Running", "stale": "Stale", "pending": "Pending", "failed": "Failed"}
STATE_HEX = {"success": "#34d399", "running": "#60a5fa", "stale": "#fbbf24", "pending": "#a3b1c6", "failed": "#f87171"}
JOB_STATE = {"queued": ("pending", "Queued"), "running": ("running", "Running"), "success": ("success", "Success"),
             "retry_wait": ("stale", "Retry scheduled"), "failed": ("failed", "Failed")}
TRIGGER_CLASS = {"Built": "tr-built", "Detect only": "tr-detect", "Not built": "tr-notbuilt", "Proposed": "tr-proposed"}
HEALTH_TONE = {"Healthy": "green", "Degraded": "amber", "Critical": "red"}


def state_pill(state: str, label: str | None = None) -> str:
    return f'<span class="spill st-{esc(state)}"><i aria-hidden="true"></i>{esc(label or STATE_LABELS.get(state, state))}</span>'


def fmt_age(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    s = int(seconds)
    if s >= 86400:
        return f"{s // 86400}d"
    if s >= 3600:
        return f"{s // 3600}h"
    if s >= 60:
        return f"{s // 60}m"
    return f"{s}s"


def ttl_label(ttl: int | None) -> str:
    if ttl is None:
        return "Follows its inputs"
    return f"{ttl // 3600}h" if ttl >= 3600 else fmt_age(ttl)


def fmt_utc(v: Any) -> str:
    dt = freshness.parse(str(v)) if v else None
    return dt.strftime("%b %d, %H:%M UTC") if dt else "-"


def cov_bar(pct: int, color: str, label: str) -> str:
    return (f'<svg class="cov-bar" viewBox="0 0 100 8" preserveAspectRatio="none" width="100%" height="8" role="img" aria-label="{esc(label)}">'
            f'<rect width="100" height="8" fill="#16294a"/><rect width="{pct}" height="8" fill="{color}"/></svg>')


def coverage_kpis(s: dict) -> str:
    health = s["health"]
    oldest = s["oldest"]
    ar = s["assets_reporting"]
    over = bool(oldest and oldest["ttl_seconds"] and oldest["age_seconds"] > oldest["ttl_seconds"])
    cards = [
        ("slate" if not health else HEALTH_TONE[health], "Cache health", esc(health or "No data yet"),
         f"{s['layers_within_ttl']} of {s['layers_total']} layers up to date" if health else "No cache entries recorded yet", "/ui/coverage?tab=tech"),
        ("red" if over else "blue", "Oldest cached data", esc(fmt_age(oldest["age_seconds"]) if oldest else "-"),
         f"{esc(oldest['layer'])} · target {esc(ttl_label(oldest['ttl_seconds']))}" if oldest else "No dated entries yet", "/ui/coverage?tab=tech"),
        ("blue", "Assets reporting", esc(f"{fmt_n(ar['reporting'])} / {fmt_n(ar['total'])}"), "Reporting in the last 24h", "/ui/assets"),
        ("orange", "Findings on stale data", fmt_n(s["findings_on_stale"]),
         "Last-known findings on servers whose data is old", "/ui/findings?status=open"),
    ]
    return '<section class="grid g4" aria-label="Coverage summary">' + "".join(
        f'<a href="{href}" class="kc-link"><article class="kc t-{tone}"><div class="lab">{label}</div>'
        f'<div class="num c-{tone}">{value}</div><div class="sub">{sub}</div></article></a>'
        for tone, label, value, sub, href in cards) + "</section>"


def layer_why(v: dict, can_refresh: bool = True) -> str:
    """One plain sentence under a layer that needs attention: what is wrong and what to do about it."""
    n, total, ttl = v["stale_entries"], v["entries"], ttl_label(v["ttl_seconds"])
    fix = "Refresh all re-runs the check." if can_refresh else "An operator can re-run the check."
    if v["state"] == "failed":
        return "<b>Refresh failed</b> after several tries. Open Technical detail to see the error."
    if v["state"] != "stale":
        return ""
    if v["kind"] == "inventory":
        return (f"<b>{fmt_n(n)} of {fmt_n(total)} servers</b> have not sent a snapshot in the last {esc(ttl)}. "
                "Run the collector on them; refreshing from this page cannot do this.")
    if v["kind"] == "correlation":
        return (f"<b>{fmt_n(n)} of {fmt_n(total)} servers</b> need a re-check: their inventory or CVE data changed since the findings were last confirmed. "
                + fix)
    return f"<b>Older than {esc(ttl)}.</b> " + ("Refresh all fetches new data now." if can_refresh else "An operator can fetch new data now.")


FINDING_GROUPS = {"cve": "By CVE", "package": "By package", "asset": "By asset"}
WORK_VIEWS = {"all": "All", "kev": "KEV", "needs_validation": "Needs validation", "no_fix": "No fix known", "mine": "My work", "past_sla": "Past SLA"}
BAND_CLASS = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
WORK_TONE = {"new": "slate", "needs_validation": "amber", "accepted": "blue", "scheduled": "blue", "mitigated": "green", "verified": "green",
             "deferred": "slate", "not_applicable": "slate"}


def band_chip(x: dict) -> str:
    """Priority band and score; hovering shows exactly which reasons add up to it."""
    return f'<span class="badge {BAND_CLASS.get(x["band"], "low")}" title="{esc(x["why"])}">{esc(x["band"])} · {x["score"]}</span>'


def due_cell(x: dict) -> str:
    when = esc(fmt_dt(x["fix_due"].isoformat(timespec="seconds").replace("+00:00", "Z")))
    if x["paused"]:
        return f'<span class="muted">Paused ({esc(work.STATE_LABELS.get(x["state"], x["state"]))})</span>'
    flag = ' <span class="badge critical">Overdue</span>' if x["fix_overdue"] else ""
    if x["ack_overdue"] and not x["fix_overdue"]:
        flag = ' <span class="badge medium">Needs a decision</span>'
    return when + flag


CAMPAIGN_TONE = {"planned": "slate", "scheduled": "blue", "in_progress": "amber", "completed": "green", "cancelled": "slate"}
PROGRESS_TONE = {"Verified": "wk-green", "Awaiting verification": "wk-amber", "Still affected": "critical", "Failed": "critical", "Unreachable": "medium",
                 "Updated": "wk-blue", "Attempted": "wk-blue", "Planned": "wk-slate", "Excepted": "wk-slate", "Server removed": "wk-slate"}


def campaign_pill(status: str) -> str:
    return f'<span class="badge wk-{CAMPAIGN_TONE.get(status, "slate")}">{esc(campaigns.STATUS_LABELS.get(status, status))}</span>'


WORK_HINTS = {"mitigated": "Reported by a person. It becomes Verified when fresh snapshots confirm every covered server is clear.",
              "verified": "Confirmed by evidence: fresh, analyzed snapshots no longer show this CVE on this package version."}


def work_pill(state: str) -> str:
    hint = f' title="{esc(WORK_HINTS[state])}"' if state in WORK_HINTS else ""
    return f'<span class="badge wk-{WORK_TONE.get(state, "slate")}"{hint}>{esc(work.STATE_LABELS.get(state, state))}</span>'


def csv_safe(value: Any) -> str:
    """CSV cell text; a leading = + - @ tab or CR would be run as a formula by Excel, so it is neutralised with a quote."""
    cell = "" if value is None else str(value)
    return "'" + cell if cell.startswith(("=", "+", "-", "@", "\t", "\r")) else cell


def findings_where(ws: int, severity: str = "", cve_id: str = "", asset_id: str = "", exposure: str = "", status: str = "open",
                   confidence: str = "", kev: str = "", updated_since: str = "", q: str = "", component: str = "") -> tuple[str, list]:
    """WHERE clause (alias f) shared by the Findings list, its grouped views and the CSV download, so all three always agree."""
    where, params = ["f.workspace_id=?"], [ws]
    for col, val in (("level", severity), ("cve_id", cve_id.upper()), ("asset_id", asset_id), ("exposure", exposure), ("status", status),
                     ("confidence", confidence), ("component_name", component)):
        if val:
            where.append(f"f.{col}=?"); params.append(val)
    if kev.lower() in {"true", "1", "yes"}:
        where.append("f.kev=1")
    if kev.lower() in {"false", "0", "no"}:
        where.append("f.kev=0")
    if updated_since and status == "resolved":
        where.append("f.updated_at>=?"); params.append(updated_since)
    if q:
        try:
            where.append("CAST(f.id AS TEXT) IN (SELECT ref FROM search_index WHERE kind='finding' AND search_index MATCH ?)"); params.append(fts_query(q))
        except HTTPException:
            pass
    return " AND ".join(where), params


def findings_group_sql(group: str) -> tuple[str, str, str]:
    """(GROUP BY expression, select list, order by) for a grouped Findings view."""
    if group == "cve":
        return ("f.cve_id", "f.cve_id AS k, COUNT(DISTINCT f.asset_pk) assets, COUNT(*) n, MAX(f.level_rank) r, f.level lvl, f.cvss_score cvss, f.kev kev, '' extra",
                "r DESC, kev DESC, assets DESC, k")
    if group == "package":
        return ("f.component_name, f.component_version, f.ecosystem",
                "f.component_name || ' ' || f.component_version AS k, COUNT(DISTINCT f.asset_pk) assets, COUNT(DISTINCT f.cve_id) n, MAX(f.level_rank) r, "
                "f.level lvl, MAX(f.kev) kev, f.component_name extra", "r DESC, kev DESC, assets DESC, k")
    return ("f.asset_pk", "f.asset_id AS k, 1 assets, COUNT(*) n, MAX(f.level_rank) r, f.level lvl, "
            "SUM(CASE WHEN f.level='critical' THEN 1 ELSE 0 END) cvss, SUM(f.kev) kev, '' extra", "r DESC, cvss DESC, kev DESC, n DESC")


def findings_view_switch(group: str, keep: dict, total: int = 0) -> str:
    """Flat / By CVE / By package / By asset, keeping the current filters, plus the CSV download of the current view."""
    def link(key: str, label: str) -> str:
        qs = "&amp;".join(f"{k}={quote(str(v))}" for k, v in {**keep, "group": key}.items() if v not in (None, ""))
        cur = ' aria-current="page"' if group == key else ""
        return f'<a href="/ui/findings?{qs}"{cur}>{esc(label)}</a>'
    items = "".join(link(k, v) for k, v in {"": "Flat list", **FINDING_GROUPS}.items())
    qs = "&amp;".join(f"{k}={quote(str(v))}" for k, v in {**keep, "group": group}.items() if v not in (None, ""))
    unit = {"": "finding", "cve": "CVE", "package": "package", "asset": "server"}[group]
    download = (f'<a class="btn ghost" href="/ui/findings/export.csv?{qs}" title="Downloads every row that matches the current filters, not only this page. '
                f'Opens in Excel.">Download CSV · {fmt_n(total)} {unit}{"" if total == 1 else "s"}</a>')
    return f'<div class="bar"><nav class="seg" aria-label="Group findings">{items}</nav>{download}</div>'


def asset_filter(ws: int, q: str = "", owner: str = "", tier: str = "") -> tuple[str, list]:
    """WHERE clause (alias a) shared by the Assets list and the bulk actions, so 'all matching' means exactly what the list shows."""
    where, params = "a.workspace_id=?", [ws]
    if q:
        where += " AND (a.asset_id LIKE ? OR a.hostname LIKE ?)"; params += [f"%{q}%"] * 2
    if owner == "none":
        where += " AND a.owner=''"
    elif owner:
        where += " AND a.owner LIKE ?"; params.append(f"%{owner}%")
    if tier == "none":
        where += " AND a.business_tier=''"
    elif tier in TIERS:
        where += " AND a.business_tier=?"; params.append(tier)
    return where, params


def owner_cell(row: sqlite3.Row | dict) -> str:
    """Owner and business tier in one compact cell; an empty owner is shown as Unassigned, never guessed."""
    owner = (row["owner"] or "").strip()
    tier = TIERS.get(row["business_tier"] or "", "")
    name = esc(owner) if owner else '<span class="muted">Unassigned</span>'
    return name + (f' <span class="pill">{esc(tier)}</span>' if tier else "")


def refresh_note(r: dict | None) -> str:
    """Plain sentence about the latest re-check attempt for a server, or empty if none was requested."""
    if not r:
        return ""
    at = esc(fmt_utc(r["at"]))
    if r["state"] == "queued":
        return f"Re-check queued · {at}"
    if r["state"] == "running":
        return "Re-check running now"
    if r["state"] == "retry_wait":
        return f"Re-check failed, retrying (try {fmt_n(r['retries'])}) · {at}"
    if r["state"] == "failed":
        return f"Last re-check failed · {at}" + (f" · {esc(r['error'])}" if r["error"] else "")
    return f"Last re-check finished · {at}"


FRESH_LABELS = {"success": "Fresh", "stale": "Stale", "pending": "Unverified", "running": "Refreshing", "failed": "Refresh failed"}


def fresh_chip(state: str, queued: bool = False) -> str:
    """Small freshness pill that links to Coverage. A queued/retrying refresh is shown as such."""
    pill = state_pill("running", "Refresh queued") if queued else state_pill(state, FRESH_LABELS.get(state, state))
    return f'<a class="lk" href="/ui/coverage" title="Data freshness of this server. Open Coverage for details.">{pill}</a>'


def feed_runs_panel(jobs: list[sqlite3.Row]) -> str:
    """Recent CVE feed runs: what each source returned, what was stored, and the change from the run before."""
    runs = []
    for j in jobs:
        try:
            counts, prov = json.loads(j["counts_json"] or "{}"), json.loads(j["provider_status_json"] or "{}")
        except ValueError:
            counts, prov = {}, {}
        runs.append({"finished": j["finished_at"], "status": j["status"], "counts": counts, "prov": prov,
                     "received": sum(int(v.get("records") or 0) for v in prov.values() if isinstance(v, dict)),
                     "failed": [k for k, v in prov.items() if isinstance(v, dict) and not v.get("ok", True)]})
    rows = []
    for i, r in enumerate(runs[:8]):  # the 9th run is only read to compute the change shown on the 8th
        older = runs[i + 1]["received"] if i + 1 < len(runs) else None
        delta = "-" if older is None else f"{r['received'] - older:+,}"
        rec = lambda name: fmt_n((r["prov"].get(name) or {}).get("records", 0))  # noqa: E731
        c = r["counts"]
        rows.append([esc(fmt_dt(r["finished"])), badge(r["status"]), rec("kev"), rec("nvd"), rec("osv"), fmt_n(r["received"]), delta,
                     fmt_n(c.get("created", 0)), fmt_n(c.get("updated", 0)), fmt_n(c.get("unchanged", 0)),
                     esc(", ".join(r["failed"]) or "-")])
    body = table(["Finished", "Result", "KEV", "NVD", "OSV", "Received", "Change vs previous", "New", "Updated", "Unchanged", "Sources that failed"], rows)
    return ('<section class="panel"><h2>Intel feed runs</h2>'
            '<p class="hint">What each source returned in recent CVE syncs, what was stored, and how the volume changed from the run before. '
            'Records a source returned but the system rejected are not counted individually yet.</p>' + body + "</section>")


def coverage_attention(rows: list[dict], total: int, can_refresh: bool = True, c: "Ctx | None" = None) -> str:
    """Which servers hold the stale data, so the layers above can be acted on."""
    head = '<section class="panel"><h2>Servers needing attention</h2>'
    if not rows:
        return head + '<p class="hint">Every server’s data is up to date.</p></section>'
    def action(r: dict) -> str:
        if r["inventory_problem"]:
            return '<span class="muted">Run the collector</span>'
        form = c.post_form("/ui/actions/coverage/refresh-asset", "Re-check now", f"Queue a re-check of the findings for {r['asset_id']}?",
                           f'<input type="hidden" name="asset_id" value="{esc(r["asset_id"])}">') if c else ""
        return form or '<span class="muted">An operator can re-check</span>'

    body = table(["Server", "Why", "Last snapshot", "Target", "Collector", "Open findings", "Next step"], [
        [f'<a class="lk" href="/ui/assets/{quote(r["asset_id"])}">{esc(r["asset_id"])}</a>',
         esc(r["why"]) + (f'<div class="muted cov-detail">Last error: {esc(r["error"])}</div>' if r["error"] else "")
         + (f'<div class="muted cov-detail">{refresh_note(r.get("refresh"))}</div>' if r.get("refresh") else ""),
         esc(fmt_utc(r["last_snapshot"])) if r["inventory_problem"] else "-",
         esc(ttl_label(r["target_seconds"])) if r["inventory_problem"] else "-",
         esc(classified(r["collector_version"], "-")), fmt_n(r["open_findings"]), action(r)] for r in rows])
    shown = f"Showing {fmt_n(len(rows))} of {fmt_n(total)}. " if total > len(rows) else ""
    fix = ("Run the collector on these servers to send a new snapshot." if any(r["inventory_problem"] for r in rows)
           else ("Refresh all re-runs the check." if can_refresh else "An operator can re-run the check."))
    return (head + f'<p class="hint">{shown}Their findings stay listed as last known until a fresh check confirms them. {esc(fix)}</p>' + body + "</section>")


def coverage_guide(can_refresh: bool = True) -> str:
    states = [
        ("success", "Up to date. Nothing to do."),
        ("stale", "Getting old, or changed since the last check. Not an error."),
        ("running", "Refreshing right now."),
        ("pending", "Waiting for its first data."),
        ("failed", "Refresh failed after retries. Needs attention."),
    ]
    rows = "".join(f"<div>{state_pill(k)}<span>{esc(t)}</span></div>" for k, t in states)
    return ('<section class="panel cov-guide"><h2>How to read this page</h2>'
            '<p class="hint">Each row below is one kind of data. Its colour tells you whether you can trust today’s numbers.</p>'
            f'<div class="cov-states">{rows}</div>'
            '<p class="note"><b>Why numbers can differ:</b> <i>reporting</i> counts servers that sent a snapshot in the last 24h, <i>monitored</i> counts every registered server, '
            'and each layer below counts its own entries (usually one per server).</p>'
            '<p class="note"><b>Cache health</b> sums it up: Healthy = everything is up to date · Degraded = something is stale · Critical = a refresh failed. '
            'Stale servers: run the collector on them. Stale results: '
            + ('press <b>Refresh all</b> (top right).' if can_refresh else 'ask an operator to refresh them.') + '</p></section>')


def coverage_layers(s: dict, can_refresh: bool = True) -> str:
    rows = []
    for v in s["layers"]:
        if v["kind"] == "feed":
            detail = f"{v['entries']} sources" if v["entries"] else "No data yet"
        elif v["kind"] == "index":
            detail = f"{fmt_n(v['record_count'])} indexed records" if v["entries"] else "No data yet"
        elif v["kind"] == "inventory":
            detail = f"{v['entries']} assets · {fmt_n(v['record_count'])} components" if v["entries"] else "No data yet"
        else:
            detail = f"{v['entries']} assets · {fmt_n(v['record_count'])} open findings" if v["entries"] else "No data yet"
        age, ttl = v["age_seconds"], v["ttl_seconds"]
        if age is None:
            age_label, pct = "No data yet", 0
        elif ttl:
            age_label, pct = f"{fmt_age(age)} / {ttl_label(ttl)}", min(100, round(100 * age / ttl))
        else:
            age_label, pct = f"{fmt_age(age)} · follows inputs", 0
        refreshed = f"Refreshed {fmt_utc(v['refreshed_at'])}" if v["refreshed_at"] else "Never refreshed"
        bar = cov_bar(pct, STATE_HEX[v["state"]], f"{v['name']}: {age_label}, {STATE_LABELS[v['state']]}")
        rows.append(
            f'<div class="cov-layer"><div><div class="cov-title">{esc(v["name"])}</div>'
            f'<div class="muted cov-detail">{esc(detail)}</div>'
            + (f'<div class="cov-why">{layer_why(v, can_refresh)}</div>' if layer_why(v, can_refresh) else "") + '</div>'
            f'<div>{state_pill(v["state"])}</div>'
            f'<div><div class="cov-meta"><span class="muted">{esc(refreshed)}</span>'
            f'<span class="st-{v["state"]} cov-age">{esc(age_label)}</span></div>{bar}</div></div>')
    return ('<section class="panel"><h2>Cache layers</h2>'
            '<p class="hint">The bar shows how old the data is compared with how old it is allowed to get (the target). A full bar means it is stale.</p>'
            + "".join(rows) + "</section>")


def coverage_exec(s: dict) -> str:
    dist = s["distribution"]
    total = sum(dist.values())
    if total:
        x, segs = 0, []
        for k, n in dist.items():
            if n:
                segs.append(f'<rect x="{x}" y="0" width="{n}" height="14" fill="{STATE_HEX[k]}"/>')
                x += n
        aria = ", ".join(f"{n} {STATE_LABELS[k].lower()}" for k, n in dist.items() if n)
        bar = (f'<svg class="cov-dist" viewBox="0 0 {total} 14" preserveAspectRatio="none" width="100%" height="14" role="img" '
               f'aria-label="Cache entries: {esc(aria)}"><rect width="{total}" height="14" fill="#16294a"/>{"".join(segs)}</svg>')
        legend = "".join(f'<div class="cov-legendItem">{state_pill(k)}<span class="cov-count st-{k}">{n}</span></div>' for k, n in dist.items())
        legend = f'<div class="cov-legend">{legend}</div>'
    else:
        bar, legend = '<p class="note">No cache entries yet. The worker records them on its next sweep.</p>', ""
    distribution = ('<section class="panel"><h2>State distribution</h2><p class="hint">Every cache entry is in exactly one state.</p>'
                    f'{bar}{legend}<p class="note">Lifecycle: pending → running → success → stale → refresh. A failed refresh becomes failed after retries are exhausted.</p></section>')
    risks = [
        (s["findings_open_total"], "blue", "open findings in total. This is the last known state of every server."),
        (s["findings_confirmed"], "green", "were confirmed by fresh data (the server’s inventory and re-check are both up to date)."),
        (s["findings_old_data"], "orange", "sit on servers whose data is old, so they are not a verified view of the server today. Refresh to confirm."),
        (s["kev_on_stale"], "amber", "known-exploited (KEV) findings are on servers with old data. They stay listed as risk until a fresh check confirms whether they are still there or fixed."),
        (s["unverified"], "slate", "findings are Unverified: the package match is not confirmed yet. A fresh inventory is the first step to settle them."),
    ]
    risk = ('<section class="panel"><h2>Risk of leaving it as is</h2><p class="hint">Stale means last known, not wrong. Nothing here is counted as fixed just because it is old. Counts can overlap: Unverified findings may be on fresh or old servers.</p>'
            + "".join(f'<div class="cov-risk"><b class="cov-risk-n c-{c}">{fmt_n(n)}</b><div>{esc(t)}</div></div>' for n, c, t in risks)
            + "</section>")
    targets = table(["Layer", "Freshness target", "Refreshed by", "Marked stale when"],
                    [[esc(v["name"]), esc(ttl_label(v["ttl_seconds"])), esc(v["refreshed_by"]), esc(v["stale_when"])] for v in s["layers"]])
    return (f'<section class="grid g2">{distribution}{risk}</section>'
            '<section class="panel"><h2>Freshness targets</h2><p class="hint">How long each layer may go without a refresh, what refreshes it, and what marks it stale. Values come from configuration.</p>'
            f'{targets}</section>')


def coverage_tech(jobs: list[dict], triggers: list[dict], gaps: list[dict]) -> str:
    rows = []
    for j in jobs:
        key, label = JOB_STATE[j["state"]]
        state = state_pill(key, label + (" · dead-lettered" if j["dead_lettered"] else ""))
        progress = f"{fmt_n(j['progress_done'])} / {fmt_n(j['progress_total'])}" if j["progress_total"] else "n/a"
        start, end = freshness.parse(j["started_at"]), freshness.parse(j["finished_at"])
        duration = "-"
        if start and end:
            secs = max(0, int((end - start).total_seconds()))
            duration = f"{secs // 60:02d}:{secs % 60:02d}"
        job_link = f'<a class="lk" href="/ui/jobs/{j["job_id"]}">#{j["job_id"]}</a>' if j["job_id"] else "-"
        rows.append([job_link, esc(s_layer_name(j["layer_key"])), esc(j["target"]), state, esc(progress),
                     esc(fmt_utc(j["started_at"])), esc(duration), esc(f"{j['retries']} / {j['max_retries']}")])
    jobs_panel = ('<section class="panel"><h2>Coverage refresh runs</h2><p class="hint">Refreshes queued for cache layers. Progress shows only when a run reports a total.</p>'
                  + table(["Job", "Layer", "Target", "State", "Progress", "Started (UTC)", "Duration", "Retries"], rows)
                  + '</section>')
    trigger_rows = [[esc(t["name"]), esc(t["scope"]), f'<span class="spill {TRIGGER_CLASS.get(t["status"], "")}"><i aria-hidden="true"></i>{esc(t["status"])}</span>']
                    for t in triggers]
    triggers_panel = ('<section class="panel"><h2>Invalidation triggers</h2><p class="hint">What makes a cache entry stale, and whether anything acts on it today.</p>'
                      + table(["Trigger", "Scope", "Status"], trigger_rows) + "</section>")
    gap_rows = "".join(
        f'<div class="cov-risk"><span class="badge {"critical" if g["priority"] == "P1" else "medium"}">{esc(g["priority"])}</span>'
        f'<div><div class="cov-title">{esc(g["title"])}</div><div class="muted cov-detail">{esc(g["note"])}</div></div></div>'
        for g in gaps) or '<p class="note">No open gaps in the capability registry.</p>'
    gaps_panel = ('<section class="panel"><h2>Gaps and next steps</h2><p class="hint">Ordered by priority. Only capabilities that are not shipped and tested are listed.</p>'
                  f'{gap_rows}</section>')
    return jobs_panel + f'<section class="grid g2">{triggers_panel}{gaps_panel}</section>'


def s_layer_name(key: str) -> str:
    layer = freshness.LAYER_BY_KEY.get(key)
    return layer.name if layer else key


TRIGGER_LABELS = {"schedule": "Scheduled", "ui": "Manual (UI)", "api": "Manual (API)", "manual": "Manual", "retry": "Retry", "ttl": "Cache TTL expiry"}
INTERVAL_PRESETS = ((900, "Every 15 minutes"), (3600, "Every hour"), (21600, "Every 6 hours"), (43200, "Every 12 hours"), (86400, "Every 24 hours"))
SCHEDULE_JOB_TYPES = ("cve_sync", "analysis", "report_export")


def fmt_interval(seconds: int) -> str:
    s = int(seconds)
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if s >= size and s % size == 0:
            n = s // size
            return f"Every {n} {unit}{'s' if n > 1 else ''}"
    return f"Every {s} seconds"


def coverage_scheduler(enabled: bool, schedules: int, total: int, active: int, failed: int, is_admin: bool, csrf: str) -> str:
    state = state_pill("success", "Running") if enabled else state_pill("failed", "Stopped")
    if is_admin:
        action = "/ui/actions/system-config/disable" if enabled else "/ui/actions/system-config/enable"
        label = "Pause all schedules" if enabled else "Resume all schedules"
        toggle = (f'<form class="inline" method="post" action="{action}" data-confirm="Change the scheduler state for every schedule?">'
                  f'<input type="hidden" name="csrf" value="{esc(csrf)}"><button class="ghost">{label}</button></form>')
    else:
        toggle = '<span class="muted">Admin scope is required to pause or resume schedules.</span>'
    facts = (fact("Registered schedules", fmt_n(schedules)) + fact("Total jobs", fmt_n(total))
             + fact("Queued or running", fmt_n(active)) + fact("Failed", fmt_n(failed)))
    return ('<section class="panel"><h2>Background scheduler</h2>'
            '<p class="hint">The worker enqueues scheduled jobs and runs queued jobs. Pausing stops scheduled runs; manual runs still start.</p>'
            f'<div class="toolbar">{state}{toggle}</div><div class="facts">{facts}</div></section>')


def coverage_schedules(schedules: list, is_admin: bool, csrf: str) -> str:
    rows = []
    for s in schedules:
        on = bool(s["enabled"])
        status = state_pill("success", "Active") if on else state_pill("pending", "Paused")
        if is_admin:
            sid, name, token = s["id"], esc(s["name"]), esc(csrf)
            actions = (
                f'<form class="inline" method="post" action="/ui/actions/job-schedule/{sid}/toggle" data-confirm="{"Pause" if on else "Resume"} schedule {name}?">'
                f'<input type="hidden" name="csrf" value="{token}"><button class="ghost">{"Pause" if on else "Resume"}</button></form> '
                f'<form class="inline" method="post" action="/ui/actions/job-schedule/{sid}/run" data-confirm="Run {name} now?">'
                f'<input type="hidden" name="csrf" value="{token}"><button class="ghost">Run now</button></form> '
                f'<form class="inline" method="post" action="/ui/actions/job-schedule/{sid}/delete" data-confirm="Delete schedule {name}?">'
                f'<input type="hidden" name="csrf" value="{token}"><button class="ghost danger">Delete</button></form>')
        else:
            actions = '<span class="muted">Admin scope required</span>'
        rows.append([esc(s["name"]), esc(label_of(s["job_type"])), esc(fmt_interval(s["interval_seconds"])), status,
                     esc(fmt_utc(s["last_run_at"])), actions])
    add = ""
    if is_admin:
        types = "".join(f'<option value="{t}">{esc(label_of(t))}</option>' for t in SCHEDULE_JOB_TYPES)
        presets = "".join(f'<option value="{sec}"{" selected" if sec == 3600 else ""}>{esc(text)}</option>' for sec, text in INTERVAL_PRESETS)
        add = (f'<form class="filters" method="post" action="/ui/actions/job-schedule/create"><input type="hidden" name="csrf" value="{esc(csrf)}">'
               '<label class="fl"><span>Name</span><input name="name" maxlength="80" placeholder="e.g. Daily CVE sync" required></label>'
               f'<label class="fl"><span>Job type</span><select name="job_type">{types}</select></label>'
               f'<label class="fl"><span>Interval</span><select name="interval_seconds">{presets}</select></label>'
               '<button>Add schedule</button></form>')
    return ('<section class="panel"><h2>Schedules</h2>'
            '<p class="hint">Jobs the worker enqueues automatically. Pausing a schedule keeps its history; deleting it does not delete past jobs.</p>'
            f'{add}{table(["Name", "Job type", "Interval", "Status", "Last run (UTC)", "Actions"], rows)}</section>')


def user_options(conn: sqlite3.Connection, ws: int, selected: str, blank: str) -> str:
    """Options for an assignee or owner dropdown: active registered users only, plus the current value if it is not one of them."""
    names = [r[0] for r in conn.execute("SELECT username FROM users WHERE workspace_id=? AND disabled_at IS NULL ORDER BY username", (ws,))]
    out = [f'<option value=""{"" if selected else " selected"}>{esc(blank)}</option>']
    if selected and selected not in names:
        out.append(f'<option value="{esc(selected)}" selected>{esc(selected)} (not a registered user)</option>')
    out += [f'<option value="{esc(n)}"{" selected" if n == selected else ""}>{esc(n)}</option>' for n in names]
    return "".join(out)


def registered_error(conn: sqlite3.Connection, ws: int, value: str | None) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if conn.execute("SELECT 1 FROM users WHERE workspace_id=? AND username=? AND disabled_at IS NULL", (ws, value)).fetchone():
        return None
    return f"Choose a registered user. '{value}' is not an active account."


def build_ui() -> APIRouter:
    r = APIRouter(include_in_schema=False)
    login_limiter = RateLimiter(10)

    @r.get("/")
    def root() -> RedirectResponse:
        return RedirectResponse("/ui", status_code=303)

    @r.get("/ui/static/app.css")
    def css() -> Response:
        return Response(CSS, media_type="text/css", headers={"Cache-Control": "public, max-age=300"})

    @r.get("/ui/static/app.js")
    def js() -> Response:
        return Response(JS, media_type="text/javascript", headers={"Cache-Control": "public, max-age=300"})

    @r.get("/ui/login", response_class=HTMLResponse)
    def login_page(error: str = "") -> HTMLResponse:
        msg = f'<p class="stale">{esc(error)}</p>' if error else '<p>Sign in with your RiskPatch account.</p>'
        return HTMLResponse(
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Sign in · RiskPatch</title><link rel="icon" href="{FAVICON_HREF}"><link rel="stylesheet" href="/ui/static/app.css"></head>'
            f'<body class="login-body"><div class="login-card"><div class="brand">{BRAND_MARK}<span>RISK<b>PATCH</b></span></div>'
            f'<p class="brand-sub">PATCH Management Platform</p>'
            f'<p class="tagline">Identify. Prioritize. Remediate.</p><h1>Sign in</h1>{msg}'
            '<form method="post" action="/ui/login">'
            '<input name="username" autocomplete="username" required placeholder="Username" maxlength="64">'
            '<input type="password" name="password" autocomplete="current-password" required placeholder="Password">'
            "<button>Sign in</button></form></div></body></html>"
        )

    @r.post("/ui/login")
    def login(request: Request, username: str = Form(""), password: str = Form(""), conn: sqlite3.Connection = Depends(get_conn)):
        client = request.client.host if request.client else "-"
        if not login_limiter.allow(client):
            page = login_page("Too many sign-in attempts. Wait a minute and try again.")
            page.status_code = 429
            return page
        row = auth.authenticate_password(conn, username, password) if username.strip() and password else None
        if row is None:
            with tx(conn):
                audit(conn, "anonymous", "user.login_failed", username.strip()[:64] or "-", {"client": client})
            page = login_page("Invalid username or password.")
            page.status_code = 401
            return page
        secret = auth.create_session(conn, row["id"])
        with tx(conn):
            audit(conn, f"user:{row['username']}", "user.login", row["username"], {"client": client})
        resp = RedirectResponse("/ui", status_code=303)
        resp.set_cookie("rp_session", secret, httponly=True, samesite="strict", secure=False, max_age=auth.SESSION_HOURS * 3600, path="/")
        return resp

    def user(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> Ctx:
        who = principal_from(request, conn, cookie=True)
        if who is None or not who.has("read"):
            # Anonymous visitors may only look at the Overview; every other page, form and download needs a signed-in account.
            if (request.url.path.rstrip("/") or "/ui") != "/ui":
                raise HTTPException(303, headers={"Location": "/ui/login"})
            who = Principal(token_id=0, name="guest", workspace_id=1, scopes=frozenset({"read"}))
        return Ctx(request, who, conn)

    def login_required(c: Ctx) -> RedirectResponse | None:
        """Data downloads need a signed-in account. Anonymous visitors are browsed as read-only 'guest', which must not be able to bulk-export."""
        return None if c.who.kind == "user" else RedirectResponse("/ui/login", status_code=303)

    def check_csrf(c: Ctx, token: str, scope: str = "operate") -> None:
        if not c.who.has(scope) or token != c.csrf:
            raise HTTPException(403, "CSRF or scope invalid")

    @r.post("/ui/logout")
    def logout(csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf, "read")
        if c.who.kind == "user":
            auth.delete_session(c.conn, c.token)
        resp = RedirectResponse("/ui/login", status_code=303)
        resp.delete_cookie("rp_session", path="/")
        return resp

    @r.get("/ui")
    def dashboard(period: str = "30d", c: Ctx = Depends(user)):
        period_labels = {
            "24h": "24 hours", "7d": "7 days", "30d": "30 days",
            "3m": "3 months", "6m": "6 months", "1y": "1 year", "all": "all time",
        }
        period = period if period in period_labels else "30d"
        s = dashboard_stats(c.conn, c.who.workspace_id, c.request.app.state.settings, alert_period=period)
        period_label = period_labels[period]
        by = s["findings_by_level"]
        total = max(int(s["findings_open"]) or 0, 1)
        highest = s.get("highest_level")
        sev_rows = []
        for lvl in LEVELS:
            n = int(by.get(lvl, 0) or 0)
            pct = round(100 * n / total, 1) if s["findings_open"] else 0
            color = {"critical":"#ff7a7a","high":"#fb923c","medium":"#f6bd4f","low":"#45dc9c","informational":"#64748b","unverified":"#64748b"}.get(lvl,"#97a7be")
            sev_rows.append(
                f'<div class="row"><span>{esc(label_of(lvl))}</span>'
                f'<div class="track"><svg class="fill" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect width="{pct}" height="8" fill="{color}"/></svg></div>'
                f'<a class="cnt lk" href="/ui/findings?status=open&amp;severity={quote(lvl)}" aria-label="View {n} open {esc(label_of(lvl))} findings">{n}</a></div>'
            )
        sev = '<div class="sev">\n' + "".join(sev_rows) + "\n</div>"
        top = c.conn.execute(
            "SELECT asset_id, MAX(level_rank) r, level lvl, COUNT(*) n, SUM(CASE WHEN level='critical' THEN 1 ELSE 0 END) crit "
            "FROM findings WHERE workspace_id=? AND status='open' GROUP BY asset_pk ORDER BY r DESC, crit DESC, n DESC LIMIT 6",
            (c.who.workspace_id,),
        ).fetchall()
        toptable = (
            f'<div class="tw"><table>'
            f'<thead><tr><th>Asset</th><th>Highest</th><th class="n">Critical</th><th class="n">Open</th></tr></thead>'
            f'<tbody>'
            + "".join(
                f'<tr><td><a class="lk" href="/ui/assets/{quote(x["asset_id"])}">{esc(x["asset_id"])}</a></td>'
                f'<td><strong>{esc(label_of(x["lvl"]))}</strong></td>'
                f'<td class="n"><a class="lk" href="/ui/findings?status=open&amp;severity=critical&amp;asset_id={quote(x["asset_id"])}">{x["crit"]}</a></td>'
                f'<td class="n"><a class="lk" href="/ui/findings?status=open&amp;asset_id={quote(x["asset_id"])}">{x["n"]}</a></td></tr>'
                for x in top
            )
            + '</tbody></table></div>'
        )
        job_rows = []
        for t, j in s["last_successful_jobs"].items():
            if j:
                job_rows.append(
                    f'<tr><td>{esc(label_of(t))}</td>'
                    f'<td><span class="pill">{badge(j["status"])}</span></td>'
                    f'<td>{esc(fmt_dt(j["finished_at"]))}</td>'
                    f'<td>{esc(en_text(j["error"]) or "-")}</td></tr>'
                )
            else:
                job_rows.append(
                    f'<tr><td>{esc(label_of(t))}</td>'
                    f'<td><span class="pill">-</span></td><td>-</td><td>-</td></tr>'
                )
        jobs_table = (
            f'<div class="tw"><table>'
            f'<thead><tr><th>Pipeline</th><th>Status</th><th>Finished</th><th>Error</th></tr></thead>'
            f'<tbody>{"".join(job_rows)}</tbody></table></div>'
        )
        prov_rows = []
        for p in s.get("providers") or []:
            cls = "late" if p.get("stale") else ""
            state = "STALE" if p.get("stale") else "Fresh"
            prov_rows.append(
                f'<li><span class="nm"><span class="dot {cls}"></span>{esc(p["provider"])}</span>'
                f'<span class="st">{esc(state)} · {esc(fmt_dt(p.get("last_success_at")) if p.get("last_success_at") else "never")}</span></li>'
            )
        providers_list = (
            f'<ul class="prov">{"".join(prov_rows) or "<li class=muted>No providers yet</li>"}</ul>'
        )
        actions = (
            '<div class="toolbar">'
            + c.post_form("/ui/actions/cve-sync", "Sync CVE feed", "Run CVE sync now?")
            + c.post_form("/ui/actions/analyze", "Run analysis", "Run analysis for all assets?")
            + c.post_form("/ui/actions/correlate", "AI correlation", "Send summary of open findings to LLM gateway for correlation? Verdicts will not be changed.", cls="ghost")
            + (c.post_form("/ui/actions/reset", "Reset to clean slate", "DELETE ALL DATA (assets, findings, CVEs, alerts, jobs, reports, audit). Cannot be undone. Schema and tokens are kept.", cls="danger") if c.who.has("admin") else "")
            + "</div>"
        )
        latest = s.get("latest_snapshot_received")
        last_successful_pipeline = max(
            ((t, j) for t, j in (s.get("last_successful_jobs") or {}).items() if j and j.get("finished_at")),
            key=lambda pair: pair[1]["finished_at"],
            default=None,
        )
        pipeline_note = (
            f'Last successful {esc(label_of(last_successful_pipeline[0]).lower())} run: {esc(fmt_dt(last_successful_pipeline[1]["finished_at"]))}.'
            if last_successful_pipeline else "No successful pipeline run recorded yet."
        )
        window_qs = f'since={quote(s["alerts_period_since"])}&amp;until={quote(s["alerts_period_until"])}'
        open_alerts_url = f'/ui/alerts?view=open&amp;{window_qs}'
        assessment_alerts_url = f'/ui/alerts?view=assessment&amp;{window_qs}'
        closed_alerts_url = f'/ui/alerts?view=closed&amp;{window_qs}'
        remaining_alerts_url = f'/ui/alerts?view=remaining&amp;{window_qs}'
        cards_row1 = (
            f'<a href="/ui/assets" class="kc-link"><article class="kc t-blue"><div class="lab">Assets monitored</div><div class="num">{fmt_n(s["assets"])}</div><div class="sub">{fmt_n(s["assets_reporting_24h"])} reporting in the last 24h</div></article></a>'
            f'<a href="/ui/findings?status=open&amp;kev=true" class="kc-link"><article class="kc t-amber"><div class="lab">Open KEV findings</div><div class="num">{fmt_n(s["kev_findings"])}</div><div class="sub">Known exploited, not resolved</div></article></a>'
            f'<a href="/ui/cves" class="kc-link"><article class="kc t-blue"><div class="lab">CVE catalog</div><div class="num">{fmt_n(s["cves"])}</div><div class="sub">Indexed records</div></article></a>'
        )
        active_alerts = s["open_alerts"] + s["alerts_in_assessment"]
        open_share = round(100 * s["open_alerts"] / active_alerts, 2) if active_alerts else 0
        findings_card = (
            f'<section class="panel fcard">'
            f'<div class="fc-head">'
            f'<div><div class="fc-kicker">Open findings</div>'
            f'<div class="fc-num">{fmt_n(s["findings_open_period"])}</div>'
            f'<div class="fc-sub">Highest: <b>{esc(label_of(highest) or "-")}</b></div></div>'
            f'<p class="fc-note">Alerts map one-to-one to findings. All counts cover items created in the selected period ({period_label}); '
            f'Remaining is open plus in assessment.</p>'
            f'</div>'
            f'<div class="fc-flow">'
            f'<a href="{open_alerts_url}" class="fc-stat t-orange"><div class="fc-lab">Open alerts</div><div class="fc-val">{fmt_n(s["open_alerts"])}</div><div class="fc-cap">Awaiting operator action</div></a>'
            f'<a href="{assessment_alerts_url}" class="fc-stat t-blue"><div class="fc-lab">In assessment</div><div class="fc-val">{fmt_n(s["alerts_in_assessment"])}</div><div class="fc-cap">Acknowledged, being assessed</div></a>'
            f'<a href="{closed_alerts_url}" class="fc-stat t-green"><div class="fc-lab">Closed · {period_label}</div><div class="fc-val">{fmt_n(s["alerts_closed_period"])}</div><div class="fc-cap">Created in period, now closed</div></a>'
            f'<a href="{remaining_alerts_url}" class="fc-stat t-amber"><div class="fc-lab">Remaining · {period_label}</div><div class="fc-val">{fmt_n(s["alerts_remaining_period"])}</div><div class="fc-cap">Created in period, not yet closed</div></a>'
            f'</div>'
            f'<div class="fc-bar" role="img" aria-label="Open alerts {fmt_n(s["open_alerts"])}, in assessment {fmt_n(s["alerts_in_assessment"])}">'
            f'<svg viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true"><rect width="{open_share}" height="6" fill="#fb923c"/><rect x="{open_share}" width="{round(100 - open_share, 2)}" height="6" fill="#4d8df7"/></svg></div>'
            f'<div class="fc-foot">Open alerts + In assessment = {fmt_n(active_alerts)}'
            f'{", matching" if active_alerts == s["findings_open_period"] else ", NOT matching"} {fmt_n(s["findings_open_period"])} open findings</div>'
            f'</section>'
        )
        wsum = work.summary(c.conn, c.who.workspace_id)
        work_cards = (
            '<section class="grid g4" aria-label="Work needing attention">'
            f'<a href="/ui/work?view=past_sla" class="kc-link"><article class="kc t-red"><div class="lab">Work past its SLA</div><div class="num">{fmt_n(wsum["past_sla"])}</div>'
            f'<div class="sub">Remediation target missed · {fmt_n(wsum["p1"])} top-priority items open</div></article></a>'
            f'<a href="/ui/work?view=kev" class="kc-link"><article class="kc t-amber"><div class="lab">Known-exploited work without an owner</div><div class="num">{fmt_n(wsum["kev_unassigned"])}</div>'
            '<div class="sub">KEV items nobody is assigned to</div></article></a>'
            f'<a href="/ui/work" class="kc-link"><article class="kc t-blue"><div class="lab">Work awaiting a decision</div><div class="num">{fmt_n(wsum["undecided"])}</div>'
            f'<div class="sub">Of {fmt_n(wsum["items"])} work items, none triaged yet</div></article></a>'
            f'<a href="/ui/exceptions?view=soon" class="kc-link"><article class="kc t-orange"><div class="lab">Deferrals ending soon</div><div class="num">{fmt_n(wsum["deferrals_soon"])}</div>'
            '<div class="sub">Within 14 days, then the work reopens</div></article></a></section>')
        period_control = (
            f'<form class="period-form" action="/ui" method="get"><label class="sel"><span>Alert period</span>'
            f'<select class="period-select" name="period" aria-label="Alert period">'
            f'<option value="24h"{" selected" if period == "24h" else ""}>Last 24 hours</option>'
            f'<option value="7d"{" selected" if period == "7d" else ""}>Last 7 days</option>'
            f'<option value="30d"{" selected" if period == "30d" else ""}>Last 30 days</option>'
            f'<option value="3m"{" selected" if period == "3m" else ""}>Last 3 months</option>'
            f'<option value="6m"{" selected" if period == "6m" else ""}>Last 6 months</option>'
            f'<option value="1y"{" selected" if period == "1y" else ""}>Last 1 year</option>'
            f'<option value="all"{" selected" if period == "all" else ""}>All time</option>'
            f'</select></label></form>'
        )
        body = (
            f'<div class="bar">'
            f'<div class="seg" role="tablist" aria-label="View">'
            f'<button role="tab" id="tab-exec" aria-selected="true" aria-controls="view-exec" type="button">Executive summary</button>'
            f'<button role="tab" id="tab-tech" aria-selected="false" aria-controls="view-tech" type="button">Technical detail</button>'
            f'</div>'
            f'<span class="asof">Latest snapshot: {esc(fmt_dt(latest)) if latest else "never"}</span>'
            f'</div>'
            f'<div id="view-exec" role="tabpanel" aria-labelledby="tab-exec" class="stackv">'
            f'<section class="grid g3" aria-label="Current security posture">{cards_row1}</section>'
            f'{findings_card}'
            f'{work_cards}'
            f'<section class="grid g2">'
            f'<section class="panel"><h2>Severity mix</h2>'
            f'<p class="hint">Open findings by severity. Current state; does not change with the time range.</p>'
            f'{sev}</section>'
            f'<section class="panel"><h2>High-risk assets</h2>'
            f'<p class="hint">Top 6 by highest open severity, then most critical findings.</p>{toptable}'
            f'</section>'
            f'</section>'
            f'<p class="foot-note">KEV = Known Exploited Vulnerability</p>'
            f'</div>'
            f'<div id="view-tech" role="tabpanel" aria-labelledby="tab-tech" class="stackv" hidden>'
            f'<section>'
            f'{actions}'
            f'<p class="pipe">{pipeline_note} KEV = Known Exploited Vulnerability.</p>'
            f'</section>'
            f'<section class="panel">'
            f'<h2>Threat-intelligence source health</h2>'
            f'<p class="hint">Freshness of vulnerability intelligence feeds used by analysis.</p>'
            f'{providers_list}'
            f'</section>'
            f'<section class="grid g2e">'
            f'<section class="panel"><h2>Last successful jobs</h2>'
            f'<p class="hint">Most recent successful run of each pipeline.</p>{jobs_table}</section>'
            f'<section class="panel"><h2>Intel providers</h2>'
            f'<p class="hint">Freshness of the vulnerability intelligence feeds.</p>{providers_list}</section>'
            f'</section>'
            f'</div>'
        )

        return c.page("Operations overview", body, lede="Live posture across assets, findings, and threat intel", actions=period_control)

    def pager(c: Ctx, path: str, params: dict, offset: int, total: int, size: int = PAGE) -> str:
        def link(off: int, label: str) -> str:
            q = "&".join(f"{k}={quote(str(v))}" for k, v in {**params, "offset": off}.items() if v not in (None, ""))
            return f'<a href="{path}?{q}">{label}</a>'
        parts = [f"{total} results"]
        if offset > 0:
            parts.append(link(max(0, offset - size), "Previous"))
        if offset + size < total:
            parts.append(link(offset + size, "Next"))
        return '<div class="pager">' + " · ".join(parts) + "</div>"

    @r.get("/ui/assets")
    def assets(q: str = "", owner: str = "", tier: str = "", offset: int = 0, notice: str = "", error: str = "", c: Ctx = Depends(user)):
        where, params = asset_filter(c.who.workspace_id, q, owner, tier)
        unowned = c.conn.execute("SELECT COUNT(*) FROM assets WHERE workspace_id=? AND owner=''", (c.who.workspace_id,)).fetchone()[0]
        total = c.conn.execute(f"SELECT COUNT(*) FROM assets a WHERE {where}", params).fetchone()[0]
        rows = c.conn.execute(
            f"SELECT a.*, (SELECT COUNT(*) FROM findings f WHERE f.asset_pk=a.id AND f.status='open') n, (SELECT level FROM findings f WHERE f.asset_pk=a.id AND f.status='open' ORDER BY level_rank DESC LIMIT 1) lvl "
            f"FROM assets a WHERE {where} ORDER BY a.last_seen DESC LIMIT ? OFFSET ?", params + [PAGE, max(0, offset)]).fetchall()
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (
            f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        tier_opts = "".join(f'<option value="{k}"{" selected" if tier == k else ""}>{esc(v)}</option>' for k, v in {**TIERS, "none": "Not set"}.items())
        body = flash + (f'<form class="filters" method="get"><label class="fl"><span>Asset or host</span><input name="q" value="{esc(q)}" placeholder="local-laptop, hostname"></label>'
                        f'<label class="fl"><span>Owner</span><input name="owner" value="{esc(owner)}" placeholder="name, team, or none"></label>'
                        f'<label class="fl"><span>Tier</span><select name="tier"><option value="">All</option>{tier_opts}</select></label><button>Filter</button></form>')
        if unowned:
            body += (f'<p class="note"><a href="/ui/assets?owner=none">{fmt_n(unowned)} server{"s" if unowned != 1 else ""} without an owner</a>. '
                     'Work cannot be assigned to a team until a server has one.</p>')
        def disp(val): return esc(classified(val))
        headers = ["Asset", "Owner / tier", "OS", "Kernel", "Collector", "Last snapshot", "Snapshot", "Findings", "Highest", "Data"]
        chips = freshness.asset_freshness(c.conn, c.who.workspace_id, [x["asset_id"] for x in rows])
        cells = [[f'<a href="/ui/assets/{quote(x["asset_id"])}">{esc(x["asset_id"])}</a>',
                  owner_cell(x),
                  esc(classified(f"{x['os_name'] or ''} {x['os_version'] or ''}".strip())),
                  disp(x["kernel"]),
                  esc(classified(x["collector_version"], "-")), esc(fmt_dt(x["last_seen"])), esc(classified(x["latest_snapshot_id"], "-")), str(x["n"]), badge(x["lvl"]), fresh_chip(*chips.get(x["asset_id"], ("pending", False)))] for x in rows]
        is_admin = c.who.kind == "user" and c.who.has("admin")
        if c.who.has("operate") and c.who.kind == "user":
            cells = [[f'<input type="checkbox" name="asset_id" value="{esc(x["asset_id"])}" aria-label="Select {esc(x["asset_id"])}">'] + row for x, row in zip(rows, cells)]
            tier_pick = "".join(f'<option value="{k}">{esc(v)}</option>' for k, v in TIERS.items())
            bulk = (
                '<div class="bulk"><h2>Set ownership for selected servers</h2>'
                '<p class="hint">Tick servers below, fill in what should change, and apply. Empty fields are left as they are.</p>'
                '<div class="filters">'
                f'<label class="fl"><span>Owner</span><select name="owner">{user_options(c.conn, c.who.workspace_id, "", "Leave owner unchanged")}</select></label>'
                f'<label class="fl"><span>Business tier</span><select name="business_tier"><option value="">Keep</option>{tier_pick}</select></label>'
                '<label class="fl"><span>Service</span><input name="service" maxlength="120"></label>'
                '<label class="fl"><span>Maintenance window</span><input name="maintenance_window" maxlength="120" placeholder="e.g. Sun 02:00-04:00 WIB"></label>'
                f'<label class="fl chk"><input type="checkbox" name="apply_filter" value="1"> <span>All {fmt_n(total)} server{"s" if total != 1 else ""} matching the current filter</span></label>'
                f'<input type="hidden" name="f_q" value="{esc(q)}"><input type="hidden" name="f_owner" value="{esc(owner)}"><input type="hidden" name="f_tier" value="{esc(tier)}">'
                f'<button class="btn" formaction="/ui/actions/assets/ownership-bulk" data-confirm="Apply the filled-in fields to the selected servers, or to all {fmt_n(total)} matching servers if that box is ticked? Empty fields are left unchanged.">Apply</button>'
                + ('<button class="ghost danger" formaction="/ui/actions/assets/delete" data-confirm="Permanently delete the selected assets and all their findings, alerts, reports, and snapshots? This cannot be undone.">Delete selected</button>' if is_admin else "")
                + '</div></div>')
            body += f'<form method="post"><input type="hidden" name="csrf" value="{esc(c.csrf)}">{bulk}' + table([""] + headers, cells) + "</form>"
        else:
            body += table(headers, cells)
        return c.page("Assets", body + pager(c, "/ui/assets", {"q": q, "owner": owner, "tier": tier}, offset, total), lede="Asset inventory, ownership and collector freshness")

    def findings_grouped(c: Ctx, group: str, clause: str, params: list, keep: dict, offset: int):
        """One row per CVE, package or asset instead of one per CVE x asset x component. Same filters as the flat list."""
        key, select, order = findings_group_sql(group)
        headers = {"cve": ["CVE", "Highest level", "CVSS", "KEV", "Servers", "Findings"], "package": ["Package", "Highest level", "KEV", "Servers", "CVEs"],
                   "asset": ["Server", "Owner / tier", "Highest level", "Critical", "KEV", "Data", "Findings"]}[group]
        total = c.conn.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM findings f WHERE {clause} GROUP BY {key})", params).fetchone()[0]
        rows = c.conn.execute(f"SELECT {select} FROM findings f WHERE {clause} GROUP BY {key} ORDER BY {order} LIMIT ? OFFSET ?",
                              params + [PAGE, max(0, offset)]).fetchall()
        flt = lambda **extra: "&amp;".join(f"{k}={quote(str(v))}" for k, v in {**{x: keep[x] for x in ("status", "severity", "exposure", "confidence", "kev")}, **extra}.items() if v not in (None, ""))  # noqa: E731
        cells: list[list[str]] = []
        if group == "cve":
            for x in rows:
                cells.append([f'<a class="lk" href="/ui/findings?{flt(cve_id=x["k"])}">{esc(x["k"])}</a>', badge(x["lvl"]), classified(x["cvss"], "Pending"),
                              kev_cell(x["kev"]), fmt_n(x["assets"]), fmt_n(x["n"])])
        elif group == "package":
            for x in rows:
                cells.append([f'<a class="lk" href="/ui/findings?{flt(component=x["extra"])}">{esc(x["k"])}</a>', badge(x["lvl"]), kev_cell(x["kev"]),
                              fmt_n(x["assets"]), fmt_n(x["n"])])
        else:
            owners = {r["asset_id"]: r for r in c.conn.execute(
                f"SELECT asset_id, owner, business_tier FROM assets WHERE workspace_id=? AND asset_id IN ({','.join('?' * len(rows)) or 'NULL'})",
                [c.who.workspace_id, *[x["k"] for x in rows]])}
            chips = freshness.asset_freshness(c.conn, c.who.workspace_id, [x["k"] for x in rows])
            for x in rows:
                cells.append([f'<a class="lk" href="/ui/findings?{flt(asset_id=x["k"])}">{esc(x["k"])}</a>', owner_cell(owners[x["k"]]) if x["k"] in owners else "-",
                              badge(x["lvl"]), fmt_n(x["cvss"]), fmt_n(x["kev"] or 0), fresh_chip(*chips.get(x["k"], ("pending", False))), fmt_n(x["n"])])
        view_switch = findings_view_switch(group, keep, total)
        label = {"cve": "CVEs", "package": "packages", "asset": "servers"}[group]
        note = (f'<p class="note">{fmt_n(total)} {label} · each row groups all matching findings. Click a name to see the individual findings. '
                'Filters from the flat list still apply; the level shown is the highest in the group.</p>')
        return c.page("Findings", view_switch + note + table(headers, cells) + pager(c, "/ui/findings", {**keep, "group": group}, offset, total),
                      lede="Prioritized open risk across the estate")

    def sla_panel(c: Ctx) -> str:
        targets = sla.load(c.conn)
        editable = c.who.has("admin")
        rows = []
        for band, minimum, name in risk.BANDS:
            ack, fix = targets[band]
            if editable:
                cells = [f'<input name="{band.lower()}_ack" type="number" min="1" max="{sla.LIMITS["ack_hours"][1]}" value="{ack}" aria-label="{band} acknowledge hours">',
                         f'<input name="{band.lower()}_fix" type="number" min="1" max="{sla.LIMITS["fix_days"][1]}" value="{fix}" aria-label="{band} fix days">']
            else:
                cells = [f"{ack} hours", f"{fix} days"]
            rows.append([f'<span class="badge {BAND_CLASS[band]}">{band}</span> {esc(name)}', f"{minimum}+ points", *cells])
        head = ["Priority", "Score", "Acknowledge within" + (" (hours)" if editable else ""), "Fix within" + (" (days)" if editable else "")]
        grid = table(head, rows)
        if editable:
            grid = (f'<form method="post" action="/ui/actions/settings/sla"><input type="hidden" name="csrf" value="{esc(c.csrf)}">{grid}'
                    '<div class="toolbar"><button class="btn">Save SLA targets</button></div></form>')
        points = " · ".join([f"{risk.LEVEL_LABELS[k]} {v:+d}" for k, v in risk.LEVEL_POINTS.items() if k in ("critical", "high", "medium", "low")]
                            + [f"Known exploited {risk.KEV_POINTS:+d}", f"Internet-facing {risk.INTERNET_POINTS:+d}", f"Tier 1 {risk.TIER_POINTS['tier1']:+d}",
                               f"Tier 2 {risk.TIER_POINTS['tier2']:+d}", f"Fix is known {risk.FIX_POINTS:+d}", "Open 30+ days +3", "Open 90+ days +5", f"Package match not confirmed {risk.ALL_UNVERIFIED_PENALTY:+d}"])
        return ('<section class="panel"><h2>Priority and SLA</h2>'
                '<p class="hint">Work items get a priority from a visible points score (not CVSS alone). The SLA clock starts when the item was first detected and never restarts when it is reassigned or its severity changes. '
                'Mitigated, verified, deferred and not-applicable items are not counted as overdue.</p>'
                + grid + f'<p class="note"><b>Score (version {risk.RISK_VERSION}, maximum 100):</b> {esc(points)}.</p></section>')

    @r.post("/ui/actions/settings/sla")
    def act_settings_sla(csrf: str = Form(""), p1_ack: str = Form(""), p1_fix: str = Form(""), p2_ack: str = Form(""), p2_fix: str = Form(""),
                         p3_ack: str = Form(""), p3_fix: str = Form(""), p4_ack: str = Form(""), p4_fix: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf, "admin")
        raw = {"P1": (p1_ack, p1_fix), "P2": (p2_ack, p2_fix), "P3": (p3_ack, p3_fix), "P4": (p4_ack, p4_fix)}
        try:
            targets = {b: (int(a), int(f)) for b, (a, f) in raw.items()}
            changed = sla.save(c.conn, c.who.workspace_id, c.who.actor, targets)
        except ValueError as exc:
            msg = str(exc) if "must" in str(exc) or "cannot" in str(exc) else "Enter whole numbers in every field."
            return RedirectResponse(f"/ui/settings?error={quote(msg)}", status_code=303)
        work.invalidate_summary()
        return RedirectResponse(f"/ui/settings?notice={quote('SLA targets saved.' if changed else 'No change.')}", status_code=303)

    def work_state_options(selected: str = "") -> str:
        return "".join(f'<option value="{k}"{" selected" if k == selected else ""}>{esc(v)}</option>' for k, v in work.STATE_LABELS.items() if k in work.SETTABLE_STATES)

    @r.get("/ui/work")
    def work_queue(view: str = "all", state: str = "", offset: int = 0, notice: str = "", error: str = "", c: Ctx = Depends(user)):
        view = view if view in WORK_VIEWS else "all"
        rows, total = work.queue(c.conn, c.who.workspace_id, view, state, c.who.name, PAGE, offset)
        tabs = "".join(f'<a href="/ui/work?view={k}"{" aria-current=\"page\"" if view == k and not state else ""}>{esc(v)}</a>' for k, v in WORK_VIEWS.items())
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        can = c.who.has("operate") and c.who.kind == "user"
        headers = ["Priority", "CVE", "Package", "Upstream fix", "Level", "KEV", "Servers", "State", "Assignee", "Fix due"]
        cells = []
        for x in rows:
            key = work.Key(x["cve_id"], x["ecosystem"], x["component_name"], x["component_version"], x["fixed"])
            row = [band_chip(x), f'<a class="lk" href="/ui/work/item?k={quote(key.encode())}">{esc(x["cve_id"])}</a>', esc(f'{x["component_name"]} {x["component_version"]}'),
                   esc(x["fixed"]) if x["fixed"] else '<span class="muted">No fix known</span>', badge(x["lvl"]), kev_cell(1 if x["kev"] else 0),
                   fmt_n(x["servers"]), work_pill(x["state"]), esc(x["assignee"]) if x["assignee"] else '<span class="muted">Unassigned</span>', due_cell(x)]
            cells.append(([f'<input type="checkbox" name="k" value="{esc(quote(key.encode()))}" aria-label="Select {esc(x["cve_id"])}">'] + row) if can else row)
        bulk = ""
        if can:
            bulk = ('<div class="bulk"><h2>Decide for the selected items</h2>'
                    '<p class="hint">Tick items below, choose the decision, and apply. Each item keeps its own history. Verified cannot be set by hand.</p><div class="filters">'
                    f'<label class="fl"><span>Decision</span><select name="state">{work_state_options("needs_validation")}</select></label>'
                    f'<label class="fl"><span>Assignee</span><select name="assignee">{user_options(c.conn, c.who.workspace_id, "", "No assignee")}</select></label>'
                    '<label class="fl"><span>Reason (required for Deferred, Not applicable, Mitigated)</span><input name="note" maxlength="1000"></label>'
                    f'<label class="fl"><span>Deferred until (Deferred only)</span><input name="expires_on" type="date"></label>'
                    f'<label class="fl"><span>Compensating control (Deferred only)</span><input name="control" maxlength="{work.CONTROL_MAX}"></label>'
                    '<button class="btn" formaction="/ui/actions/work/bulk" data-confirm="Apply this decision to every selected item? Each item records it in its history.">Apply</button></div></div>'
                    '<div class="bulk"><h2>Plan a campaign from the selected items</h2>'
                    '<p class="hint">A campaign groups the selected items into one remediation plan with an owner, a change window, a ticket and a backout plan. Planning it marks the items Scheduled. '
                    'It tracks the work; it does not deploy anything.</p><div class="filters">'
                    '<label class="fl"><span>Campaign name</span><input name="name" maxlength="120" placeholder="e.g. Q4 OpenSSL upgrade"></label>'
                    f'<label class="fl"><span>Owner</span><select name="owner">{user_options(c.conn, c.who.workspace_id, "", "No owner")}</select></label>'
                    '<label class="fl"><span>Window starts</span><input name="window_start" type="date"></label>'
                    '<label class="fl"><span>Window ends</span><input name="window_end" type="date"></label>'
                    '<label class="fl"><span>Change / ticket ID</span><input name="ticket_id" maxlength="120"></label>'
                    '<label class="fl"><span>Backout plan (needed to approve)</span><input name="backout_plan" maxlength="1000"></label>'
                    '<button class="btn" formaction="/ui/actions/campaigns/create">Plan campaign</button></div></div>')
        table_html = table(([""] if can else []) + headers, cells)
        body = (flash + f'<div class="bar"><nav class="seg" aria-label="Work views">{tabs}</nav></div>'
                f'<p class="note">{fmt_n(total)} work item{"" if total == 1 else "s"}, highest priority first (hover a priority for the reasons; the rules are in Settings). One item is one CVE on one package version with its recommended fix, across all servers; '
                'it is not one task per alert. “Upstream fix” is the version the CVE data names; for kernels and distro packages use the vendor’s patched package.</p>')
        body += (f'<form method="post"><input type="hidden" name="csrf" value="{esc(c.csrf)}">{bulk}{table_html}</form>' if can else table_html)
        return c.page("Work", body + pager(c, "/ui/work", {"view": view, "state": state}, offset, total), lede="Decisions to make and actions to take, grouped by CVE and package")

    @r.get("/ui/work/item")
    def work_item(k: str = "", notice: str = "", error: str = "", c: Ctx = Depends(user)):
        try:
            key = work.Key.decode(k)  # a query parameter: the framework has already percent-decoded it
        except ValueError:
            raise HTTPException(404, "Work item not found")
        ws = c.who.workspace_id
        affected = work.servers(c.conn, ws, key)
        saved = work.item(c.conn, ws, key)
        if not affected and saved is None:
            raise HTTPException(404, "Work item not found")
        top = max(affected, key=lambda r: (r["level"] != "unverified", r["cvss_score"] or 0), default=None)
        state = saved["state"] if saved else "new"
        chips = freshness.asset_freshness(c.conn, ws, [r["asset_id"] for r in affected])
        scored = next(iter(work.groups(c.conn, ws, key=key)), None)  # only this item, not every group
        prio = (f'<div class="fact"><span>Priority</span><b>{band_chip(scored)} {esc(risk.BAND_NAMES[scored["band"]])}</b></div>'
                f'<div class="fact"><span>Acknowledge by</span><b>{esc(fmt_dt(scored["ack_due"].isoformat(timespec="seconds").replace("+00:00", "Z")))}</b></div>'
                f'<div class="fact"><span>Fix by</span><b>{due_cell(scored)}</b></div>') if scored else ""
        al = work.alert_counts(c.conn, ws, key)
        alerts_line = (f'<p class="note">Alerts for this item: {fmt_n(al.get("open", 0))} open · {fmt_n(al.get("acknowledged", 0))} in assessment · {fmt_n(al.get("closed", 0))} closed. '
                       f'<a class="lk" href="/ui/alerts?view=all&amp;cve={quote(key.cve_id)}">See them in Alerts</a>. Closing alerts does not change this item; record the decision here.</p>') if al else ""
        why = (f'<p class="note"><b>Why this priority:</b> {esc(scored["why"])} (score version {risk.RISK_VERSION}). '
               'The due dates count from the first detection and do not restart when the item is reassigned or its severity changes.</p>') if scored else ""
        facts = (f'<div class="fact"><span>CVE</span><b><a class="lk" href="/ui/cves/{quote(key.cve_id)}">{esc(key.cve_id)}</a></b></div>{prio}'
                 + fact("Package", f"{key.component_name} {key.component_version} ({key.ecosystem})")
                 + fact("Upstream fix", key.fixed_version or "No fix known") + fact("Servers affected", fmt_n(len(affected)))
                 + fact("State", work.STATE_LABELS.get(state, state)) + fact("Applicability", work.APPLICABILITY_LABELS.get(saved["applicability"], "Unknown") if saved else "Unknown")
                 + fact("Assignee", (saved["assignee"] if saved else "") or "Unassigned"))
        active_exc = c.conn.execute("SELECT * FROM work_exceptions WHERE work_item_id=? AND status='active'", (saved["id"],)).fetchone() if saved else None
        exc_line = (f'<p class="note"><b>Deferred until {esc(active_exc["expires_on"])}</b> by {esc(actor_label(active_exc["requested_by"]))}. '
                    + (f'Compensating control: {esc(active_exc["compensating_control"])}. ' if active_exc["compensating_control"] else "<b>No compensating control recorded.</b> ")
                    + 'When the date passes the item returns to the queue and its SLA is not reset. <a class="lk" href="/ui/exceptions">All exceptions</a></p>') if active_exc else ""
        decided = (f'<p class="note">Last decision: {esc(saved["decision"])} by {esc(saved["updated_by"])} on {esc(fmt_dt(saved["updated_at"]))}'
                   + (f' - {esc(saved["reason"])}' if saved["reason"] else "") + ".</p>") if saved else '<p class="note">No decision recorded yet, so this item is New.</p>'
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        form = ""
        if c.who.has("operate") and c.who.kind == "user":
            applic = "".join(f'<option value="{a}"{" selected" if saved and saved["applicability"] == a else ""}>{esc(v)}</option>' for a, v in work.APPLICABILITY_LABELS.items())
            form = (f'<form class="filters" method="post" action="/ui/actions/work/triage"><input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="k" value="{esc(quote(key.encode()))}">'
                    f'<label class="fl"><span>Decision</span><select name="state">{work_state_options(state if state in work.SETTABLE_STATES else "needs_validation")}</select></label>'
                    f'<label class="fl"><span>Applicability</span><select name="applicability">{applic}</select></label>'
                    f'<label class="fl"><span>Assignee</span><select name="assignee">{user_options(c.conn, c.who.workspace_id, (saved["assignee"] or "") if saved else "", "No assignee")}</select></label>'
                    '<label class="fl"><span>Reason (required for Deferred, Not applicable, Mitigated)</span><input name="note" maxlength="1000"></label>'
                    f'<label class="fl"><span>Deferred until (required for Deferred, up to {work.MAX_DEFER_DAYS} days)</span><input name="expires_on" type="date"></label>'
                    f'<label class="fl"><span>Compensating control (what protects it meanwhile)</span><input name="control" maxlength="{work.CONTROL_MAX}"></label>'
                    '<button class="btn">Save decision</button></form>'
                    '<p class="note">The decision is recorded with your name, the time, the number of servers and the snapshots it was based on. '
                    'Verified is set only from a fresh snapshot (not built yet).</p>')
        srv = table(["Server", "Owner / tier", "Level", "Exposure", "Confidence", "Data", "Snapshot"], [
            [f'<a class="lk" href="/ui/assets/{quote(r["asset_id"])}">{esc(r["asset_id"])}</a>', owner_cell(r), badge(r["level"]), esc(classified(r["exposure"])), esc(r["confidence"]),
             fresh_chip(*chips.get(r["asset_id"], ("pending", False))), f'<a class="lk" href="/ui/snapshots/{r["latest_snapshot_id"]}">#{r["latest_snapshot_id"]}</a>' if r["latest_snapshot_id"] else "-"]
            for r in affected])
        verify_panel = ""
        if saved and saved["state"] in ("mitigated", "verified"):
            mit = work.latest_mitigation(c.conn, saved["id"])
            covered = json.loads(mit["servers"] or "[]") if mit else []
            if not covered:
                verify_panel = ('<section class="panel"><h2>Verification</h2><p class="hint">This mitigation was recorded before servers were tracked, so it cannot be verified '
                                'automatically. Record it again to start verification.</p></section>')
            else:
                res = work.verification(c.conn, ws, key, mit["at"], covered)
                headline = (f'Verified: all {fmt_n(res["total"])} covered server(s) were re-checked after the fix and are clear.' if saved["state"] == "verified"
                            else f'{fmt_n(res["clear"])} of {fmt_n(res["total"])} covered server(s) confirmed clear · {fmt_n(res["waiting"])} waiting for a fresh snapshot or analysis'
                                 + (f' · <b>{fmt_n(res["affected"])} still affected</b>' if res["affected"] else "") + ".")
                shown = sorted(res["servers"], key=lambda r: ({"affected": 0, "waiting": 1, "clear": 2, "removed": 3}[r["status"]], r["asset_id"]))
                vt = table(["Server", "Evidence", "Latest snapshot", "Collected"], [
                    [f'<a class="lk" href="/ui/assets/{quote(r["asset_id"])}">{esc(r["asset_id"])}</a>',
                     {"clear": '<span class="badge wk-green">', "affected": '<span class="badge critical">', "waiting": '<span class="badge wk-amber">', "removed": '<span class="badge wk-slate">'}[r["status"]] + esc(r["label"]) + "</span>",
                     f'<a class="lk" href="/ui/snapshots/{r["snapshot_id"]}">#{r["snapshot_id"]}</a>' if r["snapshot_id"] else "-", esc(fmt_dt(r["collected_at"])) if r["collected_at"] else "-"]
                    for r in shown[:100]])
                more = f'<p class="note">Showing 100 of {fmt_n(len(shown))} servers, problems first.</p>' if len(shown) > 100 else ""
                verify_panel = (f'<section class="panel"><h2>Verification</h2><p class="hint">Mitigated was recorded {esc(fmt_dt(mit["at"]))}. Nothing is assumed from silence: '
                                f'a server counts as clear only after it sends a newer snapshot, that snapshot is analyzed, and the finding is gone.</p><p>{headline}</p>{vt}{more}</section>')
        events = work.history(c.conn, saved["id"]) if saved else []
        hist = table(["When", "Who", "Change", "Applicability", "Assignee", "Servers", "Reason"], [
            [esc(fmt_dt(e["at"])), esc(actor_label(e["actor"])), f'{esc(work.STATE_LABELS.get(e["from_state"], e["from_state"]))} → {esc(work.STATE_LABELS.get(e["to_state"], e["to_state"]))}',
             esc(work.APPLICABILITY_LABELS.get(e["applicability"], e["applicability"])), esc(e["assignee"] or "-"), fmt_n(e["server_count"]), esc(e["note"] or "-")] for e in events])
        body = (flash + f'<section class="panel"><h2>Decision</h2><div class="facts">{facts}</div>{why}{alerts_line}{decided}{exc_line}{form}</section>'
                f'{verify_panel}<section class="panel"><h2>Affected servers</h2><p class="hint">Open findings for this exact CVE, package version and fix.</p>{srv}</section>'
                f'<section class="panel"><h2>History</h2><p class="hint">Every decision, newest first. Nothing here is ever edited or deleted.</p>{hist}</section>')
        return c.page(f"{key.cve_id} · {key.component_name} {key.component_version}", body, lede="Work item")

    @r.post("/ui/actions/campaigns/create")
    def act_campaign_create(k: list[str] = Form([]), name: str = Form(""), owner: str = Form(""), window_start: str = Form(""), window_end: str = Form(""),
                            ticket_id: str = Form(""), backout_plan: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if (problem := registered_error(c.conn, c.who.workspace_id, owner)):
            return RedirectResponse(f"/ui/work?error={quote(problem)}", status_code=303)
        try:
            cid = campaigns.create(c.conn, c.who.workspace_id, c.who.actor, name, [work.Key.decode(unquote(x)) for x in k], owner, window_start, window_end, ticket_id, backout_plan)
        except ValueError as exc:
            return RedirectResponse(f"/ui/work?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/campaigns/{cid}?notice={quote('Campaign planned. Add a backout plan and get it approved before scheduling.')}", status_code=303)

    @r.get("/ui/campaigns")
    def campaigns_page(status: str = "", c: Ctx = Depends(user)):
        rows = campaigns.list_campaigns(c.conn, c.who.workspace_id, status)
        tabs = "".join(f'<a href="/ui/campaigns{("?status=" + k) if k else ""}"{" aria-current=\"page\"" if status == k else ""}>{esc(v)}</a>'
                       for k, v in {"": "All", **campaigns.STATUS_LABELS}.items())
        body_rows = [[f'<a class="lk" href="/ui/campaigns/{x["id"]}">{esc(x["name"])}</a>', campaign_pill(x["status"]), esc(x["owner"]) or '<span class="muted">Unassigned</span>',
                      (esc(x["window_start"]) + " → " + esc(x["window_end"])) if x["window_start"] else '<span class="muted">Not set</span>',
                      esc(x["ticket_id"]) or '<span class="muted">-</span>', fmt_n(x["item_count"]), fmt_n(x["server_count"]),
                      f'{fmt_n(x["reported_count"])} of {fmt_n(x["server_count"])}',
                      f'Approved by {esc(actor_label(x["approved_by"]))}' if x["approved_by"] else '<span class="muted">Awaiting approval</span>'] for x in rows]
        body = (f'<div class="bar"><nav class="seg" aria-label="Campaign status">{tabs}</nav></div>'
                '<p class="note">A campaign is a remediation plan: which work items, which servers, who owns it, when, under which change ticket and with what backout plan. '
                'Create one from the Work queue. Campaigns plan and track; they do not deploy anything.</p>'
                + table(["Campaign", "Status", "Owner", "Window", "Ticket", "Work items", "Servers", "Reported", "Approval"], body_rows))
        return c.page("Campaigns", body, lede="Planned remediation, tracked with evidence")

    @r.get("/ui/campaigns/{cid}/change-list.csv")
    def campaign_change_list(cid: int, c: Ctx = Depends(user)):
        if (redirect := login_required(c)) is not None:
            return redirect
        try:
            camp = campaigns.get(c.conn, c.who.workspace_id, cid)
        except LookupError:
            raise HTTPException(404, "Campaign not found")
        rows = campaigns.change_list(c.conn, c.who.workspace_id, cid)
        with tx(c.conn):
            audit(c.conn, c.who.actor, "campaign.export", f"campaign #{cid}", {"rows": len(rows)}, c.who.workspace_id)
        head = ["server", "owner", "tier", "server_window", "campaign", "ticket", "window_start", "window_end", "cve", "package", "ecosystem", "installed_version",
                "upstream_fix", "reported_status", "progress", "note"]
        buf = io.StringIO(newline="")
        w = csv.writer(buf)
        w.writerow(head)
        for r in rows:
            w.writerow([csv_safe(r[h]) for h in head])
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="riskpatch-campaign-{camp["id"]}-{stamp}.csv"', "Cache-Control": "no-store"})

    @r.get("/ui/campaigns/{cid}")
    def campaign_detail(cid: int, notice: str = "", error: str = "", c: Ctx = Depends(user)):
        ws = c.who.workspace_id
        try:
            camp = campaigns.get(c.conn, ws, cid)
        except LookupError:
            raise HTTPException(404, "Campaign not found")
        prog = campaigns.progress(c.conn, ws, cid)
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        operate = c.who.has("operate") and c.who.kind == "user"
        approval = (f'Approved by {esc(actor_label(camp["approved_by"]))} on {esc(fmt_dt(camp["approved_at"]))}' if camp["approved_by"] else "Awaiting approval")
        facts = (fact("Status", campaigns.STATUS_LABELS[camp["status"]]) + fact("Owner", camp["owner"] or "Unassigned")
                 + fact("Change window", f'{camp["window_start"]} → {camp["window_end"]}' if camp["window_start"] else "Not set") + fact("Change / ticket ID", camp["ticket_id"] or "-")
                 + f'<div class="fact"><span>Approval</span><b>{approval}</b></div>' + fact("Created by", actor_label(camp["created_by"])))
        summary = " ".join(f'<span class="badge {PROGRESS_TONE.get(lbl, "wk-slate")}">{esc(lbl)} · {fmt_n(n)}</span>' for lbl, n in sorted(prog["counts"].items(), key=lambda kv: -kv[1]))
        plan = (f'<p class="note"><b>Backout plan:</b> {esc(camp["backout_plan"]) or "<b>None yet - required before approval.</b>"}</p>'
                + (f'<p class="note"><b>Notes:</b> {esc(camp["notes"])}</p>' if camp["notes"] else ""))
        actions = ""
        if operate:
            nxt = [st for st in ("scheduled", "in_progress", "completed", "planned") if st in campaigns.NEXT[camp["status"]]]
            for st in nxt:
                label = {"scheduled": "Schedule", "in_progress": "Start", "completed": "Mark completed", "planned": "Back to planned"}[st]
                actions += (f'<form class="inline" method="post" action="/ui/actions/campaigns/{cid}/status" data-confirm="{esc(label)} this campaign?">'
                            f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="status" value="{st}"><button class="btn">{esc(label)}</button></form>')
            if camp["status"] in ("planned", "scheduled", "in_progress"):
                actions += (f'<form class="inline" method="post" action="/ui/actions/campaigns/{cid}/status" data-confirm="Cancel this campaign?">'
                            f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="status" value="cancelled">'
                            '<input name="note" placeholder="Reason to cancel" maxlength="1000" required aria-label="Reason to cancel"><button class="btn ghost danger">Cancel campaign</button></form>')
        if c.who.kind == "user" and c.who.has("admin") and camp["status"] in campaigns.EDITABLE and not camp["approved_by"]:
            actions += (f'<form class="inline" method="post" action="/ui/actions/campaigns/{cid}/approve" data-confirm="Approve this plan? You are confirming the window and the backout plan.">'
                        f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><button class="btn">Approve</button></form>')
        edit = ""
        if operate and camp["status"] in campaigns.EDITABLE:
            edit = (f'<form class="filters" method="post" action="/ui/actions/campaigns/{cid}/edit"><input type="hidden" name="csrf" value="{esc(c.csrf)}">'
                    f'<label class="fl"><span>Owner</span><select name="owner">{user_options(c.conn, c.who.workspace_id, camp["owner"] or "", "No owner")}</select></label>'
                    f'<label class="fl"><span>Window starts</span><input name="window_start" type="date" value="{esc(camp["window_start"])}"></label>'
                    f'<label class="fl"><span>Window ends</span><input name="window_end" type="date" value="{esc(camp["window_end"])}"></label>'
                    f'<label class="fl"><span>Change / ticket ID</span><input name="ticket_id" value="{esc(camp["ticket_id"])}" maxlength="120"></label>'
                    f'<label class="fl"><span>Backout plan</span><input name="backout_plan" value="{esc(camp["backout_plan"])}" maxlength="1000"></label>'
                    f'<label class="fl"><span>Notes</span><input name="notes" value="{esc(camp["notes"])}" maxlength="1000"></label>'
                    '<button class="btn ghost">Save changes</button></form>'
                    '<p class="note">Changing the window or the backout plan of an approved campaign withdraws the approval.</p>')
        item_rows = [[f'<a class="lk" href="/ui/work/item?k={quote(i["key"].encode())}">{esc(i["cve_id"])}</a>', esc(f'{i["component_name"]} {i["component_version"]}'),
                      esc(i["fixed_version"]) if i["fixed_version"] else '<span class="muted">No fix known</span>', fmt_n(i["server_count"]), work_pill(i["state"])] for i in campaigns.items(c.conn, cid)]
        can_report = operate and camp["status"] in ("scheduled", "in_progress")
        srv_rows = []
        for r in prog["servers"]:
            cells = [f'<a class="lk" href="/ui/assets/{quote(r["asset_id"])}">{esc(r["asset_id"])}</a>', esc(r["owner"]) or '<span class="muted">Unassigned</span>',
                     esc(r["window"]) or "-", fmt_n(r["items"]),
                     f'<span class="badge {PROGRESS_TONE.get(r["label"], "wk-slate")}">{esc(r["label"])}</span>' + (f'<div class="muted cov-detail">{esc(r["note"])}</div>' if r["note"] else "")]
            srv_rows.append(([f'<input type="checkbox" name="asset_id" value="{esc(r["asset_id"])}" aria-label="Select {esc(r["asset_id"])}">'] + cells) if can_report else cells)
        srv_head = (["" ] if can_report else []) + ["Server", "Owner", "Maintenance window", "Items", "Progress"]
        srv_table = table(srv_head, srv_rows)
        if can_report:
            opts = "".join(f'<option value="{k}">{esc(v)}</option>' for k, v in campaigns.REPORTED_LABELS.items() if k != "planned")
            srv_table = (f'<form method="post" action="/ui/actions/campaigns/{cid}/report"><input type="hidden" name="csrf" value="{esc(c.csrf)}"><div class="bulk"><div class="filters">'
                         f'<label class="fl"><span>Report on selected servers</span><select name="status">{opts}</select></label>'
                         '<label class="fl"><span>Note (required for Failed, Unreachable, Excepted)</span><input name="note" maxlength="1000"></label>'
                         '<button class="btn">Record</button></div><p class="hint">What you report is recorded as reported. “Verified” appears only when a newer analyzed snapshot shows the CVE gone.</p></div>' + srv_table + "</form>")
        clash = campaigns.conflicts(c.conn, ws, cid)
        conflict_panel = ('<section class="panel"><h2>Schedule conflicts</h2><p class="hint">These servers are also planned in another open campaign with an overlapping change window. '
                          'Nothing is blocked; agree the order with the other owner.</p>'
                          + table(["Campaign", "Status", "Window", "Shared servers"], [
                              [f'<a class="lk" href="/ui/campaigns/{x["id"]}">{esc(x["name"])}</a>', campaign_pill(x["status"]), esc(x["window"]),
                               esc(", ".join(x["servers"][:8])) + (f" and {len(x['servers']) - 8} more" if len(x["servers"]) > 8 else "")] for x in clash]) + "</section>") if clash else ""
        hist = table(["When", "Who", "What", "Detail"], [[esc(fmt_dt(e["at"])), esc(actor_label(e["actor"])), esc(e["action"]), esc(e["detail"] or "-")] for e in campaigns.history(c.conn, cid)])
        body = (flash + f'<section class="panel"><h2>{esc(camp["name"])}</h2><div class="facts">{facts}</div>{plan}<div class="toolbar">{actions}</div>{edit}</section>'
                f'<section class="panel"><h2>Progress</h2><p class="hint">{fmt_n(prog["verified"])} of {fmt_n(prog["total"])} servers verified by fresh snapshots.</p><p>{summary}</p>'
                f'<div class="toolbar"><a class="btn ghost" href="/ui/campaigns/{cid}/change-list.csv" title="One row per server and CVE, ready for a change ticket. Opens in Excel.">Download change list (CSV)</a></div></section>'
                f'{conflict_panel}<section class="panel"><h2>Work items</h2>{table(["CVE", "Package", "Upstream fix", "Servers", "State"], item_rows)}</section>'
                f'<section class="panel"><h2>Servers</h2>{srv_table}</section>'
                f'<section class="panel"><h2>History</h2><p class="hint">Every change to this campaign, newest first.</p>{hist}</section>')
        return c.page(camp["name"], body, lede="Campaign")

    @r.post("/ui/actions/campaigns/{cid}/approve")
    def act_campaign_approve(cid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf, "admin")
        try:
            campaigns.approve(c.conn, c.who.workspace_id, cid, c.who.actor)
        except LookupError:
            raise HTTPException(404, "Campaign not found")
        except ValueError as exc:
            return RedirectResponse(f"/ui/campaigns/{cid}?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/campaigns/{cid}?notice={quote('Approved.')}", status_code=303)

    @r.post("/ui/actions/campaigns/{cid}/status")
    def act_campaign_status(cid: int, status: str = Form(""), note: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        try:
            campaigns.set_status(c.conn, c.who.workspace_id, cid, c.who.actor, status, note)
        except LookupError:
            raise HTTPException(404, "Campaign not found")
        except ValueError as exc:
            return RedirectResponse(f"/ui/campaigns/{cid}?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/campaigns/{cid}?notice={quote('Status updated.')}", status_code=303)

    @r.post("/ui/actions/campaigns/{cid}/report")
    def act_campaign_report(cid: int, asset_id: list[str] = Form([]), status: str = Form(""), note: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        try:
            n = campaigns.report_servers(c.conn, c.who.workspace_id, cid, c.who.actor, asset_id, status, note)
        except LookupError:
            raise HTTPException(404, "Campaign not found")
        except ValueError as exc:
            return RedirectResponse(f"/ui/campaigns/{cid}?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/campaigns/{cid}?notice={quote(f'Recorded for {n} server(s).')}", status_code=303)

    @r.post("/ui/actions/campaigns/{cid}/edit")
    def act_campaign_edit(cid: int, owner: str = Form(None), window_start: str = Form(None), window_end: str = Form(None), ticket_id: str = Form(None),
                          backout_plan: str = Form(None), notes: str = Form(None), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if (problem := registered_error(c.conn, c.who.workspace_id, owner)):
            return RedirectResponse(f"/ui/campaigns/{cid}?error={quote(problem)}", status_code=303)
        try:
            changed = campaigns.update_details(c.conn, c.who.workspace_id, cid, c.who.actor, owner=owner, window_start=window_start, window_end=window_end,
                                               ticket_id=ticket_id, backout_plan=backout_plan, notes=notes)
        except LookupError:
            raise HTTPException(404, "Campaign not found")
        except ValueError as exc:
            return RedirectResponse(f"/ui/campaigns/{cid}?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/campaigns/{cid}?notice={quote('Saved.' if changed else 'No change.')}", status_code=303)

    @r.get("/ui/exceptions")
    def exceptions_page(view: str = "active", notice: str = "", error: str = "", c: Ctx = Depends(user)):
        view = view if view in ("active", "soon", "closed") else "active"
        rows = work.exceptions(c.conn, c.who.workspace_id, view)
        labels = {"active": "Active", "soon": "Expiring within 30 days", "closed": "Expired, revoked or replaced"}
        tabs = "".join(f'<a href="/ui/exceptions?view={k}"{" aria-current=\"page\"" if view == k else ""}>{esc(v)}</a>' for k, v in labels.items())
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        is_admin = c.who.kind == "user" and c.who.has("admin")
        headers = ["Work item", "Servers", "Reason", "Compensating control", "Requested by", "Expires", "Status"] + (["Action"] if is_admin and view != "closed" else [])
        body_rows = []
        for e in rows:
            left = e["days_left"]
            when = esc(e["expires_on"]) + (f' <span class="muted">({left} day{"" if left == 1 else "s"} left)</span>' if e["status"] == "active" and left >= 0 else "")
            if e["status"] == "active" and left <= 14:
                when += ' <span class="badge medium">Soon</span>'
            status = esc({"active": "Active", "expired": "Expired", "revoked": "Revoked", "superseded": "Replaced"}[e["status"]])
            if e["status"] != "active":
                status += f'<div class="muted cov-detail">{esc(fmt_dt(e["closed_at"]))} · {esc(e["closed_note"])}</div>'
            row = [f'<a class="lk" href="/ui/work/item?k={quote(e["key"].encode())}">{esc(e["cve_id"])}</a><div class="muted cov-detail">{esc(e["component_name"])} {esc(e["component_version"])}</div>',
                   fmt_n(e["server_count"]), esc(e["reason"]), esc(e["compensating_control"]) if e["compensating_control"] else '<span class="muted">None recorded</span>',
                   esc(actor_label(e["requested_by"])), when, status]
            if is_admin and view != "closed":
                row.append(f'<form class="inline" method="post" action="/ui/actions/exceptions/revoke" data-confirm="Revoke this exception? The item returns to Needs validation.">'
                           f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="exception_id" value="{e["id"]}">'
                           '<input name="note" placeholder="Reason" maxlength="1000" required aria-label="Reason to revoke"><button class="btn ghost">Revoke</button></form>')
            body_rows.append(row)
        body = (flash + f'<div class="bar"><nav class="seg" aria-label="Exception views">{tabs}</nav></div>'
                f'<p class="note">{fmt_n(len(rows))} exception{"" if len(rows) == 1 else "s"}. A deferral is an exception to fixing something: it needs a reason and an expiry date '
                f'(at most {work.MAX_DEFER_DAYS} days). When the date passes the work item reopens automatically and its SLA is not reset.</p>' + table(headers, body_rows))
        return c.page("Exceptions", body, lede="Deferred fixes with a reason, a compensating control and an expiry date")

    @r.post("/ui/actions/exceptions/revoke")
    def act_exception_revoke(exception_id: int = Form(0), note: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf, "admin")
        try:
            work.revoke_exception(c.conn, c.who.workspace_id, exception_id, c.who.actor, note)
        except LookupError:
            return RedirectResponse(f"/ui/exceptions?error={quote('That exception is no longer active.')}", status_code=303)
        except ValueError as exc:
            return RedirectResponse(f"/ui/exceptions?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/exceptions?notice={quote('Exception revoked; the item is back in the queue.')}", status_code=303)

    @r.post("/ui/actions/work/triage")
    def act_work_triage(k: str = Form(""), state: str = Form(""), applicability: str = Form("unknown"), assignee: str = Form(""), note: str = Form(""),
                        expires_on: str = Form(""), control: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if (problem := registered_error(c.conn, c.who.workspace_id, assignee)):
            return RedirectResponse(f"/ui/work?error={quote(problem)}", status_code=303)
        try:
            key = work.Key.decode(unquote(k))
            result = work.triage(c.conn, c.who.workspace_id, key, c.who.actor, state, applicability, assignee, note, expires_on, control)
        except LookupError:
            raise HTTPException(404, "Work item not found")
        except ValueError as exc:
            return RedirectResponse(f"/ui/work/item?k={k}&error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/ui/work/item?k={k}&notice={quote('Decision saved for ' + str(result['servers']) + ' server(s).')}", status_code=303)

    @r.post("/ui/actions/work/bulk")
    def act_work_bulk(k: list[str] = Form([]), state: str = Form(""), assignee: str = Form(""), note: str = Form(""), expires_on: str = Form(""), control: str = Form(""),
                      csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if (problem := registered_error(c.conn, c.who.workspace_id, assignee)):
            return RedirectResponse(f"/ui/work?error={quote(problem)}", status_code=303)
        try:
            keys = [work.Key.decode(unquote(x)) for x in k]
            result = work.triage_bulk(c.conn, c.who.workspace_id, keys, c.who.actor, state, "unknown", assignee, note, expires_on, control)
        except ValueError as exc:
            return RedirectResponse(f"/ui/work?error={quote(str(exc))}", status_code=303)
        msg = f"Updated {result['updated']} work item(s) covering {result['servers']} server(s)." + (f" Skipped {result['skipped']} with no open findings." if result["skipped"] else "")
        return RedirectResponse(f"/ui/work?notice={quote(msg)}", status_code=303)

    def ownership_panel(c: Ctx, a: sqlite3.Row) -> str:
        facts = (fact("Owner", a["owner"] or "Unassigned") + fact("Business tier", TIERS.get(a["business_tier"], "Not set"))
                 + fact("Service", a["service"] or "-") + fact("Maintenance window", a["maintenance_window"] or "-")
                 + fact("Environment (reported by collector)", classified(a["environment"])))
        who_changed = (f'<p class="note">Last changed {esc(fmt_dt(a["ownership_updated_at"]))} by {esc(a["ownership_updated_by"] or "-")}.</p>' if a["ownership_updated_at"] else "")
        form = ""
        if c.who.has("operate"):
            opts = "".join(f'<option value="{k}"{" selected" if a["business_tier"] == k else ""}>{esc(v)}</option>' for k, v in TIERS.items())
            form = (f'<form class="filters" method="post" action="/ui/actions/assets/ownership">'
                    f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="asset_id" value="{esc(a["asset_id"])}">'
                    f'<label class="fl"><span>Owner</span><select name="owner">{user_options(c.conn, c.who.workspace_id, a["owner"] or "", "No owner")}</select></label>'
                    f'<label class="fl"><span>Business tier</span><select name="business_tier"><option value="">Not set</option>{opts}</select></label>'
                    f'<label class="fl"><span>Service</span><input name="service" value="{esc(a["service"])}" maxlength="120" placeholder="e.g. Patient portal"></label>'
                    f'<label class="fl"><span>Maintenance window</span><input name="maintenance_window" value="{esc(a["maintenance_window"])}" maxlength="120" placeholder="e.g. Sun 02:00-04:00 WIB"></label>'
                    f'<button class="btn">Save</button></form>'
                    '<p class="note">Tier 1 = business critical, Tier 2 = important, Tier 3 = standard. These fields are set by people; collector runs never change them.</p>')
        return f'<section class="panel"><h2>Ownership</h2><div class="facts">{facts}</div>{who_changed}{form}</section>'

    @r.post("/ui/actions/assets/ownership-bulk")
    def act_assets_ownership_bulk(asset_id: list[str] = Form([]), apply_filter: str = Form(""), f_q: str = Form(""), f_owner: str = Form(""),
                                  f_tier: str = Form(""), owner: str = Form(""), business_tier: str = Form(""), service: str = Form(""),
                                  maintenance_window: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if (problem := registered_error(c.conn, c.who.workspace_id, owner)):
            return RedirectResponse(f"/ui/assets?error={quote(problem)}", status_code=303)
        if apply_filter:  # every server the list shows for this filter, not just the visible page
            where, params = asset_filter(c.who.workspace_id, f_q, f_owner, f_tier)
            asset_id = [r[0] for r in c.conn.execute(f"SELECT a.asset_id FROM assets a WHERE {where}", params)]
        try:
            result = set_ownership_bulk(c.conn, c.who.workspace_id, asset_id, c.who.actor, owner=owner, business_tier=business_tier,
                                        service=service, maintenance_window=maintenance_window)
        except (ValueError, LookupError) as exc:
            return RedirectResponse(f"/ui/assets?error={quote(str(exc))}", status_code=303)
        message = f"Updated {result['changed']} of {result['matched']} server(s)." + (" The rest already had these values." if result["changed"] < result["matched"] else "")
        return RedirectResponse(f"/ui/assets?notice={quote(message)}", status_code=303)

    @r.post("/ui/actions/assets/ownership")
    def act_asset_ownership(asset_id: str = Form(""), owner: str = Form(""), business_tier: str = Form(""), service: str = Form(""),
                            maintenance_window: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if (problem := registered_error(c.conn, c.who.workspace_id, owner)):
            return RedirectResponse(f"/ui/assets/{quote(asset_id)}?error={quote(problem)}", status_code=303)
        try:
            changed = set_ownership(c.conn, c.who.workspace_id, asset_id, c.who.actor, owner=owner, business_tier=business_tier,
                                    service=service, maintenance_window=maintenance_window)
        except LookupError:
            raise HTTPException(404, "Asset not found")
        except ValueError as exc:
            return RedirectResponse(f"/ui/assets/{quote(asset_id)}?error={quote(str(exc))}", status_code=303)
        note = "Ownership saved." if changed else "No change."
        return RedirectResponse(f"/ui/assets/{quote(asset_id)}?notice={quote(note)}", status_code=303)

    @r.post("/ui/actions/assets/delete")
    def act_delete_assets(asset_id: list[str] = Form([]), csrf: str = Form(""), c: Ctx = Depends(user)):
        if c.who.kind != "user" or not c.who.has("admin"):
            raise HTTPException(403, "admin role required")
        check_csrf(c, csrf, "admin")
        try:
            result = delete_assets(c.conn, c.who.workspace_id, asset_id, c.who.actor)
        except (ValueError, LookupError, RuntimeError) as exc:
            return RedirectResponse(f"/ui/assets?error={quote(str(exc))}", status_code=303)
        removed = sum(result["rows"].values())
        message = f"Deleted {len(result['assets'])} asset(s) and {removed} related rows."
        return RedirectResponse(f"/ui/assets?notice={quote(message)}", status_code=303)

    @r.get("/ui/assets/{asset_id}")
    def asset_detail(asset_id: str, notice: str = "", error: str = "", c: Ctx = Depends(user)):
        a = c.conn.execute("SELECT * FROM assets WHERE workspace_id=? AND asset_id=?", (c.who.workspace_id, asset_id)).fetchone()
        if a is None:
            raise HTTPException(404, "Asset not found")
        snaps = c.conn.execute("SELECT * FROM snapshots WHERE asset_pk=? ORDER BY collected_at DESC LIMIT 20", (a["id"],)).fetchall()
        fnd = c.conn.execute("SELECT * FROM findings WHERE asset_pk=? AND status='open' ORDER BY level_rank DESC, cvss_score DESC LIMIT 50", (a["id"],)).fetchall()
        open_total = c.conn.execute("SELECT COUNT(*) FROM findings WHERE asset_pk=? AND status='open'", (a["id"],)).fetchone()[0]
        checked_at = c.conn.execute("SELECT MAX(generated_at) FROM reports WHERE asset_pk=?", (a["id"],)).fetchone()[0]
        action = '<div class="toolbar">' + c.post_form(f"/ui/actions/refresh/{quote(asset_id)}", "Re-analyze snapshot", f"Re-analyze {asset_id} from latest snapshot? Agents will not be re-run; run Ansible for fresh collection.")
        action += c.post_form("/ui/actions/correlate", "AI correlation", f"Send finding summary for {asset_id} to LLM gateway?", f'<input type="hidden" name="asset_id" value="{esc(asset_id)}">', "ghost")
        if c.who.kind == "user" and c.who.has("admin"):
            action += (
                f'<form class="inline" method="post" action="/ui/actions/assets/delete" data-confirm="Permanently delete {esc(asset_id)} and all its findings, alerts, reports, and snapshots? This cannot be undone.">'
                f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="asset_id" value="{esc(asset_id)}">'
                '<button class="ghost danger">Delete asset</button></form>')
        action += "</div>"
        override = json.loads(a["metadata_override"] or "{}")
        facts = (
            fact("Hostname", classified(a["hostname"]))
            + fact("Kernel", classified(a["kernel"]))
            + fact("OS distro id", classified(a["os_id"]))
            + fact("Operating system", classified(f"{a['os_name'] or ''} {a['os_version'] or ''}".strip()))
            + fact("Collector", classified(a["collector_version"], "-"))
            + fact("Last snapshot received", fmt_dt(a["last_seen"]))
            + fact("Findings last checked", fmt_dt(checked_at) if checked_at else "-")
            + fact("Open findings", fmt_n(open_total))
        )
        extra = ""
        meta = f'<section class="panel"><h2>Asset context</h2><div class="facts">{facts}</div>{extra}{action}</section>' + ownership_panel(c, a)
        sn = table(["Snapshot", "Collected", "Status", "Collection issues", "Collector"],
                   [[f'<a href="/ui/snapshots/{s["id"]}">#{s["id"]}</a>', esc(fmt_dt(s["collected_at"])), esc(label_of(s["analysis_status"])),
                     "Clean" if not s["error_count"] else f'{s["error_count"]} issue(s)', esc(s["collector_version"])] for s in snaps])
        def min_safe_cell(finding: sqlite3.Row) -> str:
            v = json.loads(finding["verdict_json"] or "{}")
            target = v.get("min_safe_target")
            if target:
                return f'{esc(target)} <span class="muted">(upstream version)</span>'
            os_id = a["os_id"] or "this OS"
            return f'no fixed version in intel feeds - stay on vendor-supported release for {esc(os_id)}'

        def action_cell(finding: sqlite3.Row) -> str:
            act = finding["action"] or "-"
            return esc(act.replace("_", " ").title())

        ft = table(
            ["CVE", "Level", "Min safe target", "Action"],
            [[
                f'<a href="/ui/findings/{f["id"]}">{esc(f["cve_id"])}</a>',
                badge(f["level"]),
                min_safe_cell(f),
                action_cell(f)
            ] for f in fnd]
        )
        more = f'<p class="note">Showing {fmt_n(len(fnd))} of {fmt_n(open_total)} open findings, highest severity first. <a href="/ui/findings?status=open&amp;asset_id={quote(asset_id)}">View all {fmt_n(open_total)} findings for this asset</a>. KEV = Known Exploited Vulnerability.</p>'
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (
            f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        return c.page(asset_id, f'{flash}{meta}<section class="panel"><h2>Snapshot timeline</h2>{sn}</section><section class="panel"><h2>Open findings</h2>{more}{ft}</section>',
                      lede=f'{classified(a["hostname"])} · {fmt_n(open_total)} open findings')

    @r.get("/ui/snapshots/{sid}")
    def snapshot_detail(sid: int, c: Ctx = Depends(user)):
        from riskpatch.ingest import snapshot_diff

        s = c.conn.execute("SELECT * FROM snapshots WHERE id=? AND workspace_id=?", (sid, c.who.workspace_id)).fetchone()
        if s is None:
            raise HTTPException(404, "Snapshot not found")
        def payload(snapshot_id: int):
            row = c.conn.execute("SELECT payload_json FROM snapshot_facts WHERE snapshot_id=?", (snapshot_id,)).fetchone()
            return json.loads(row["payload_json"]) if row and row["payload_json"] else None
        prev = c.conn.execute("SELECT id FROM snapshots WHERE asset_pk=? AND collected_at < ? ORDER BY collected_at DESC LIMIT 1", (s["asset_pk"], s["collected_at"])).fetchone()
        diff = snapshot_diff(payload(prev["id"]) if prev else None, payload(sid) or {}) if prev else None
        comps = table(["Type", "Name", "Version", "Ecosystem", "Distro package"], [[esc(x["kind"]), esc(x["name"]), esc(x["version"]), esc(x["ecosystem"]), esc(x["distro_package"])]
                                                                       for x in c.conn.execute("SELECT * FROM components WHERE snapshot_id=?", (sid,))])
        changes = "<p class='muted'>No previous snapshot.</p>" if diff is None else (
            f"<p>Added {len(diff['added'])}, removed {len(diff['removed'])}, changed {len(diff['changed'])}</p>"
            + table(["Change", "From", "To"], [[esc(i["item"]), esc(i["from"]), esc(i["to"])] for i in diff["changed"]]
                    + [[esc("+ " + i), "", ""] for i in diff["added"][:100]] + [[esc("- " + i), "", ""] for i in diff["removed"][:100]]))
        return c.page(
            f"Snapshot #{sid}",
            f'<section class="panel"><p>{esc(fmt_dt(s["collected_at"]))} · {esc(s["analysis_status"])} · hash {esc(s["payload_hash"][:16])}</p></section>'
            f'<section class="panel"><h2>Changes</h2>{changes}</section><section class="panel"><h2>Identified components</h2>{comps}</section>',
            lede=str(s["asset_id"]),
        )

    @r.get("/ui/findings")
    def findings(severity: str = "", cve_id: str = "", asset_id: str = "", exposure: str = "", status: str = "open", confidence: str = "", kev: str = "", updated_since: str = "", q: str = "", component: str = "", group: str = "", offset: int = 0, c: Ctx = Depends(user)):
        group = group if group in FINDING_GROUPS else ""
        clause, params = findings_where(c.who.workspace_id, severity, cve_id, asset_id, exposure, status, confidence, kev, updated_since, q, component)
        keep = dict(severity=severity, cve_id=cve_id, asset_id=asset_id, exposure=exposure, status=status, confidence=confidence, kev=kev,
                    updated_since=updated_since, q=q, component=component)
        if group:
            return findings_grouped(c, group, clause, params, keep, offset)
        total = c.conn.execute(f"SELECT COUNT(*) FROM findings f WHERE {clause}", params).fetchone()[0]
        view_switch = findings_view_switch(group, keep, total)
        rows = c.conn.execute(f"SELECT f.* FROM findings f WHERE {clause} ORDER BY level_rank DESC, cvss_score DESC, id LIMIT ? OFFSET ?", params + [PAGE, max(0, offset)]).fetchall()
        def opts(name: str, title: str, values: list[str], cur: str) -> str:
            return (f'<label class="fl"><span>{esc(title)}</span><select name="{name}"><option value="">All</option>'
                    + "".join(f'<option value="{esc(v)}"{ " selected" if v == cur else ""}>{esc(label_of(v) if v in LEVEL_LABELS or v in STATUS_LABELS else v)}</option>' for v in values) + "</select></label>")
        form = ('<form class="filters" method="get">' + opts("severity", "Severity", LEVELS, severity) + opts("exposure", "Exposure", ["internet", "internal", "vpn", "localhost", "unknown"], exposure)
                + opts("status", "Status", ["open", "resolved"], status) + opts("confidence", "Confidence", ["high", "medium", "low"], confidence)
                + opts("kev", "KEV", ["true"], kev)
                + (f'<input type="hidden" name="updated_since" value="{esc(updated_since)}">' if updated_since else "")
                + (f'<input type="hidden" name="component" value="{esc(component)}">' if component else "")
                + f'<label class="fl"><span>CVE</span><input name="cve_id" value="{esc(cve_id)}" placeholder="CVE-..."></label>'
                f'<label class="fl"><span>Asset</span><input name="asset_id" value="{esc(asset_id)}" placeholder="Asset"></label>'
                f'<label class="fl"><span>Evidence</span><input name="q" value="{esc(q)}" placeholder="Keyword"></label><button>Filter</button></form>')
        chips = freshness.asset_freshness(c.conn, c.who.workspace_id, [f["asset_id"] for f in rows])
        body = view_switch + form + table(["CVE", "Asset", "Component", "Level", "CVSS", "KEV", "Exposure", "Confidence", "Last checked", "Data"],
                            [[f'<a href="/ui/findings/{f["id"]}">{esc(f["cve_id"])}</a>', f'<a href="/ui/assets/{quote(f["asset_id"])}">{esc(f["asset_id"])}</a>', esc(f"{f['component_name']} {f['component_version']}"), badge(f["level"]),
                              classified(f["cvss_score"], "Pending"), kev_cell(f["kev"]), esc(classified(f["exposure"])), esc(f["confidence"]), esc(fmt_dt(f["updated_at"])),
                              fresh_chip(*chips.get(f["asset_id"], ("pending", False)))] for f in rows])
        return c.page("Findings", body + pager(c, "/ui/findings", keep, offset, total), lede="Prioritized open risk across the estate")

    @r.get("/ui/findings/export.csv")
    def export_findings_csv(severity: str = "", cve_id: str = "", asset_id: str = "", exposure: str = "", status: str = "open", confidence: str = "",
                            kev: str = "", updated_since: str = "", q: str = "", component: str = "", group: str = "", c: Ctx = Depends(user)):
        """Streams every row matching the filters (flat or grouped) as CSV. Uses its own connection because the response outlives the request scope."""
        if (redirect := login_required(c)) is not None:
            return redirect
        group = group if group in FINDING_GROUPS else ""
        ws = c.who.workspace_id
        clause, params = findings_where(ws, severity, cve_id, asset_id, exposure, status, confidence, kev, updated_since, q, component)
        filters = {k: v for k, v in dict(severity=severity, cve_id=cve_id, asset_id=asset_id, exposure=exposure, status=status, confidence=confidence, kev=kev,
                                         updated_since=updated_since, q=q, component=component, group=group).items() if v}
        evidence = {a: FRESH_LABELS.get(st, st) for a, (st, _q) in freshness.asset_freshness(
            c.conn, ws, [r[0] for r in c.conn.execute("SELECT asset_id FROM assets WHERE workspace_id=?", (ws,))]).items()}
        total = (c.conn.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM findings f WHERE {clause} GROUP BY {findings_group_sql(group)[0]})", params).fetchone()[0]
                 if group else c.conn.execute(f"SELECT COUNT(*) FROM findings f WHERE {clause}", params).fetchone()[0])
        with tx(c.conn):
            audit(c.conn, c.who.actor, "findings.export", group or "flat", {"filters": filters, "rows": total}, ws)
        db_path = c.request.app.state.settings.db_path
        owners = {r["asset_id"]: r for r in c.conn.execute("SELECT asset_id, owner, business_tier, service FROM assets WHERE workspace_id=?", (ws,))}

        def rows_iter():
            conn = connect(db_path)
            try:
                if group:
                    key, select, order = findings_group_sql(group)
                    cur = conn.execute(f"SELECT {select} FROM findings f WHERE {clause} GROUP BY {key} ORDER BY {order}", params)
                    if group == "cve":
                        yield ["cve_id", "highest_level", "cvss", "kev", "servers", "findings"]
                        conv = lambda x: [x["k"], x["lvl"], x["cvss"], "yes" if x["kev"] else "no", x["assets"], x["n"]]  # noqa: E731
                    elif group == "package":
                        yield ["package", "highest_level", "kev", "servers", "cves"]
                        conv = lambda x: [x["k"], x["lvl"], "yes" if x["kev"] else "no", x["assets"], x["n"]]  # noqa: E731
                    else:
                        yield ["server", "owner", "business_tier", "highest_level", "critical", "kev", "evidence", "findings"]
                        conv = lambda x: [x["k"], (owners.get(x["k"]) or {"owner": ""})["owner"], TIERS.get((owners.get(x["k"]) or {"business_tier": ""})["business_tier"], ""),  # noqa: E731
                                          x["lvl"], x["cvss"], x["kev"] or 0, evidence.get(x["k"], "Unverified"), x["n"]]
                else:
                    cur = conn.execute(
                        f"SELECT f.cve_id, f.asset_id, f.component_name, f.component_version, f.ecosystem, f.level, f.cvss_score, f.kev, f.exposure, f.confidence, f.action, "
                        f"f.status, json_extract(f.verdict_json, '$.min_safe_target') AS fix, f.first_seen, f.last_seen, f.updated_at FROM findings f WHERE {clause} "
                        f"ORDER BY f.level_rank DESC, f.cvss_score DESC, f.id", params)
                    yield ["cve_id", "server", "owner", "business_tier", "service", "package", "installed_version", "ecosystem", "level", "cvss", "kev", "exposure",
                           "confidence", "action", "status", "fixed_version", "first_seen", "last_seen", "last_checked", "evidence"]
                    def conv(x):
                        o = owners.get(x["asset_id"])
                        return [x["cve_id"], x["asset_id"], o["owner"] if o else "", TIERS.get(o["business_tier"], "") if o else "", o["service"] if o else "",
                                x["component_name"], x["component_version"], x["ecosystem"], x["level"], x["cvss_score"], "yes" if x["kev"] else "no", x["exposure"],
                                x["confidence"], x["action"], x["status"], x["fix"] or "", x["first_seen"], x["last_seen"], x["updated_at"],
                                evidence.get(x["asset_id"], "Unverified")]
                while batch := cur.fetchmany(2000):
                    for x in batch:
                        yield conv(x)
            finally:
                conn.close()

        def body():
            buf = io.StringIO(newline="")
            writer = csv.writer(buf)
            first = True
            for row in rows_iter():
                writer.writerow([csv_safe(v) for v in row])
                if first or buf.tell() > 64 * 1024:
                    chunk = buf.getvalue()
                    buf.seek(0); buf.truncate(0)
                    yield ("\ufeff" + chunk) if first else chunk
                    first = False
            if buf.tell():
                yield buf.getvalue()

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        name = f"riskpatch-findings{'-by-' + group if group else ''}-{stamp}.csv"
        return StreamingResponse(body(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})

    @r.get("/ui/findings/{fid}")
    def finding_detail(fid: int, c: Ctx = Depends(user)):
        f = c.conn.execute("SELECT * FROM findings WHERE id=? AND workspace_id=?", (fid, c.who.workspace_id)).fetchone()
        if f is None:
            raise HTTPException(404, "Finding not found")
        v = json.loads(f["verdict_json"])
        ev = table(["Type", "Detail"], [[esc(e["kind"].replace("_", " ")), f"<code>{esc(en_text(e['detail']))}</code>"] for e in c.conn.execute("SELECT kind, detail FROM finding_evidence WHERE finding_id=? ORDER BY id", (fid,))])
        facts = (
            fact("Action", label_of(f["action"]))
            + fact("Confidence", classified(f["confidence"], "-"))
            + fact("Status", label_of(f["status"]))
            + fact("CVSS", classified(f["cvss_score"], "Pending"))
            + fact("KEV", "Known exploited" if f["kev"] else "Not in KEV")
            + fact("Reachability", classified(en_text(f["reachability"])))
        )
        head = (f'<section class="panel"><p>{badge(f["level"])} <a href="/ui/assets/{quote(f["asset_id"])}">{esc(f["asset_id"])}</a> · {esc(f["component_name"])} {esc(f["component_version"])} · '
                f'<a href="/ui/cves/{quote(f["cve_id"])}">{esc(f["cve_id"])}</a> · Rule set {esc(f["ruleset_version"])}</p>'
                f'<div class="facts">{facts}</div>'
                f'<p>{esc(en_text(f["one_line"]))}</p><p>Raises: {esc(en_text(", ".join(v.get("raises", [])) or "-"))}<br>Lowers: {esc(en_text(", ".join(v.get("lowers", [])) or "-"))}</p>'
                f'<p>Patched: {esc(", ".join(v.get("patched_versions", [])) or "-")}</p><p>{esc(en_text(v.get("summary")))}</p>')
        if v.get("narrative"):
            head += f'<p><i>Narrative ({esc(v.get("narrative_source"))}; does not change level):</i> {esc(en_text(v["narrative"]))}</p>'
        head += "</section>"
        return c.page(f"{f['cve_id']}", head + '<section class="panel"><h2>Evidence &amp; provenance</h2>' + ev + "</section>", lede=str(f["asset_id"]))

    @r.get("/ui/reports")
    def reports(offset: int = 0, c: Ctx = Depends(user)):
        total = c.conn.execute("SELECT COUNT(*) FROM reports WHERE workspace_id=?", (c.who.workspace_id,)).fetchone()[0]
        rows = c.conn.execute("SELECT id, asset_id, generated_at, highest, stale FROM reports WHERE workspace_id=? ORDER BY id DESC LIMIT ? OFFSET ?", (c.who.workspace_id, PAGE, max(0, offset))).fetchall()
        body = table(["Report", "Asset", "Generated", "Highest", "Stale", "Download"], [[f'<a href="/ui/reports/{x["id"]}">#{x["id"]}</a>', esc(x["asset_id"]), esc(fmt_dt(x["generated_at"])), badge(x["highest"]), "yes" if x["stale"] else "-",
                                                                                       f'<a href="/ui/reports/{x["id"]}/download">Markdown</a>'] for x in rows])
        return c.page("Reports", body + pager(c, "/ui/reports", {}, offset, total), lede="Generated posture reports")

    @r.get("/ui/reports/{rid}")
    def report_detail(rid: int, c: Ctx = Depends(user)):
        x = c.conn.execute("SELECT asset_id, generated_at, highest, content_md FROM reports WHERE id=? AND workspace_id=?", (rid, c.who.workspace_id)).fetchone()
        if x is None:
            raise HTTPException(404, "Report not found")
        dl = f'<p class="note"><a href="/ui/reports/{rid}/download">Download Markdown (.md)</a></p>'
        return c.page(f"Report #{rid}", f'<section class="panel"><p>{esc(fmt_dt(x["generated_at"]))} · {badge(x["highest"])}</p>{dl}{md_to_html(x["content_md"] or "")}</section>', lede=str(x["asset_id"]))

    @r.get("/ui/reports/{rid}/download")
    def report_download(rid: int, c: Ctx = Depends(user)):
        x = c.conn.execute("SELECT asset_id, content_md FROM reports WHERE id=? AND workspace_id=?", (rid, c.who.workspace_id)).fetchone()
        if x is None:
            raise HTTPException(404, "Report not found")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(x["asset_id"] or "asset")).strip("-") or "asset"
        filename = f"riskpatch-{safe}-{rid}.md"
        return Response(
            x["content_md"] or "",
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @r.get("/ui/jobs")
    def jobs_moved(offset: int = 0):
        return RedirectResponse(f"/ui/coverage?tab=tech&offset={max(0, offset)}", status_code=303)

    @r.get("/ui/jobs/{jid}")
    def job_detail(jid: int, c: Ctx = Depends(user)):
        row = c.conn.execute("SELECT * FROM jobs WHERE id=? AND workspace_id=?", (jid, c.who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "Job not found")
        j = job_out(row)
        ev = table(["Time", "Level", "Message"], [[esc(fmt_dt(e["at"])), esc(e["level"]), esc(en_text(e["message"]))] for e in c.conn.execute("SELECT * FROM job_events WHERE job_id=? ORDER BY id", (jid,))])
        return c.page(
            f"Job #{jid}",
            f'<section class="panel"><p>{badge(j["status"])} · Rule set {esc(j["ruleset_version"])} · Version {esc(j["app_version"])}</p>'
            f'<pre>{esc(json.dumps({"scope": j["scope"], "counts": j["counts"], "providers": j["provider_status"]}, indent=2))}</pre></section>'
            f'<section class="panel"><h2>Events</h2>{ev}</section>',
            refresh=j["status"] in {"queued", "running"},
            lede=label_of(j["type"]),
        )

    @r.get("/ui/cves")
    def cves(q: str = "", offset: int = 0, c: Ctx = Depends(user)):
        settings = c.request.app.state.settings
        provs = table(["Provider", "Last success", "Last attempt", "Health", "Error", "Records"],
                      [[esc(p["provider"]), esc(fmt_dt(p["last_success_at"])), esc(fmt_dt(p["last_attempt_at"])), '<span class="stale">STALE</span>' if p["stale"] else "Fresh",
                        esc(classified(en_text(p["last_error"]), "-")), fmt_n(p["records_last_run"])]
                       for p in (provider_out(x, settings.cve_sync_interval * 3) for x in c.conn.execute("SELECT * FROM provider_status ORDER BY provider"))])
        where, params = "1=1", []
        if q:
            try:
                where, params = "cve_id IN (SELECT ref FROM search_index WHERE kind='cve' AND search_index MATCH ?)", [fts_query(q)]
            except HTTPException:
                pass
        total = c.conn.execute(f"SELECT COUNT(*) FROM cves WHERE {where}", params).fetchone()[0]
        rows = c.conn.execute(f"SELECT * FROM cves WHERE {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?", params + [PAGE, max(0, offset)]).fetchall()
        feed = table(["CVE", "CVSS", "KEV", "Rev", "Source", "Updated", "Summary"], [[f'<a href="/ui/cves/{quote(x["cve_id"])}">{esc(x["cve_id"])}</a>', classified(x["cvss_score"], "Pending"), kev_cell(x["kev"]), str(x["revision"]),
                                                                                        esc(x["primary_source"]), esc(fmt_dt(x["updated_at"])), esc(clip_list(x["summary"] or "-"))] for x in rows])
        actions = '<div class="toolbar">' + c.post_form("/ui/actions/cve-sync", "Sync CVE", "Run CVE sync now?") + "</div>"
        return c.page("CVE intel", f'{actions}<section class="panel"><h2>Providers</h2>{provs}</section><section class="panel"><h2>Latest CVEs</h2><form class="filters" method="get"><input name="q" value="{esc(q)}" placeholder="Search CVE"><button>Search</button></form>{feed}'
                      + pager(c, "/ui/cves", {"q": q}, offset, total) + "</section>", lede="Feed health and catalog")

    @r.get("/ui/cves/{cve_id}")
    def cve_detail(cve_id: str, c: Ctx = Depends(user)):
        x = c.conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id.upper(),)).fetchone()
        if x is None:
            raise HTTPException(404, "CVE not found")
        src_rows = list(c.conn.execute("SELECT * FROM cve_sources WHERE cve_id=?", (x["cve_id"],)))
        src = table(["Source", "URL", "Fetched"], [[esc(s["source"]), esc(s["url"]), esc(fmt_dt(s["fetched_at"]))] for s in src_rows])
        fnd = list(c.conn.execute("""
            SELECT f.*, a.os_name, a.os_version
            FROM findings f
            JOIN assets a ON a.id = f.asset_pk
            WHERE f.cve_id=? AND f.workspace_id=? AND f.status='open'
            ORDER BY f.level_rank DESC, f.asset_id
        """, (x["cve_id"], c.who.workspace_id)))

        def verdict_cell(finding: sqlite3.Row) -> str:
            v = json.loads(finding["verdict_json"] or "{}")
            verdict = v.get("verdict")
            if verdict == "affected":
                return '<span class="badge critical">Affected</span>'
            if verdict == "not_affected":
                return '<span class="badge low">Not affected</span>'
            return '<span class="badge informational">Unknown</span>'

        def min_safe_cell(finding: sqlite3.Row) -> str:
            v = json.loads(finding["verdict_json"] or "{}")
            target = v.get("min_safe_target")
            if target:
                return f'{esc(target)} <span class="muted">(upstream version)</span>'
            os_id = finding["os_id"] or "this OS"
            return f'no fixed version in intel feeds - stay on vendor-supported release for {esc(os_id)}'

        summary = best_summary(x["summary"], *(s["raw_json"] for s in src_rows))
        products = []
        for row in c.conn.execute("SELECT match_key, ranges_json FROM cve_affected WHERE cve_id=? ORDER BY match_key", (x["cve_id"],)):
            ranges = json.loads(row["ranges_json"] or "[]")
            span = ", ".join(_range_label(r) for r in ranges[:6])
            products.append(f"{product_from_key(row['match_key'])}" + (f" ({span})" if span else ""))
        cwe = json.loads(x["cwe"] or "[]")
        patched = json.loads(x["patched_versions"] or "[]")
        affected_assets = []
        for f in fnd:
            v = json.loads(f["verdict_json"] or "{}")
            affected_assets.append({
                "asset": f["asset_id"],
                "component": f["component_name"],
                "version": f["component_version"],
                "level": f["level"],
                "min_safe_target": v.get("min_safe_target") or "",
                "observed_os": f"{f['os_name'] or ''} {f['os_version'] or ''}".strip() or None,
            })
        observed_os = affected_assets[0]["observed_os"] if affected_assets else None
        brief = operator_brief(
            cve_id=x["cve_id"],
            summary=summary,
            cvss_score=x["cvss_score"],
            cvss_severity=x["cvss_severity"],
            attack_vector=x["attack_vector"],
            kev=bool(x["kev"]),
            cwe=cwe if isinstance(cwe, list) else [],
            patched_versions=patched if isinstance(patched, list) else [],
            products=products,
            affected_assets=affected_assets,
            observed_os=observed_os,
            distro_package=None,
        )
        def ul(items: list[str]) -> str:
            return "<ul>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ul>"
        aff_rows = "".join(
            f"<tr><td>{esc(a['asset'])}</td><td>{esc(a['component'])} {esc(a['version'])}</td>"
            f"<td>{badge(a['level'])}</td><td>{esc(a['min_safe_target']) or '-'}</td><td>{esc(fmt_dt(f['updated_at']))}</td></tr>"
            for a, f in zip(affected_assets, fnd)
        )
        aff_table = (
            f'<table><tr><th>Asset</th><th>Component / version</th><th>Level</th><th>Min safe target</th><th>Updated</th></tr>{aff_rows or "<tr><td colspan=5 class=muted>No affected open findings on collected assets</td></tr>"}</table>'
        )
        body = (
            f'<section class="panel"><p>CVSS {esc(classified(x["cvss_score"], "Pending"))} {esc(x["cvss_severity"] or "")} · '
            f'KEV {"yes" if x["kev"] else "no"} · Revision {x["revision"]}</p>'
            f'<h2>Description</h2><p>{esc(summary)}</p></section>'
            f'<section class="panel"><h2>What is affected</h2>{ul(brief["affected"])}'
            f'<h3>Affected assets on this workspace</h3>{aff_table}</section>'
            f'<section class="panel"><h2>Mitigation (until patched)</h2>{ul(brief["mitigation"])}</section>'
            f'<section class="panel"><h2>Corrective action</h2>{ul(brief["corrective"])}</section>'
            f'<section class="panel"><h2>Preventive action</h2>{ul(brief["preventive"])}</section>'
            f'<section class="panel"><h2>Provenance</h2>{src}</section>'
        )
        return c.page(x["cve_id"], body, lede="Operator briefing from catalog facts - not an exploit guide")

    @r.get("/ui/alerts/export.csv")
    def export_alerts_csv(c: Ctx = Depends(user)):
        if (redirect := login_required(c)) is not None:
            return redirect
        rows = c.conn.execute(
            "SELECT id, status, asset_id, kind, message, created_at, acknowledged_at, acknowledged_by, closed_at, closed_by, resolution_note "
            "FROM alerts WHERE workspace_id=? ORDER BY id DESC",
            (c.who.workspace_id,),
        ).fetchall()
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["id", "status", "asset_id", "kind", "message", "created_at", "acknowledged_at", "acknowledged_by", "closed_at", "closed_by", "resolution_note"])
        for row in rows:
            writer.writerow([csv_safe(value) for value in row])
        return Response(
            "\ufeff" + stream.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="riskpatch-alerts.csv"'},
        )

    @r.get("/ui/alerts")
    def alerts(view: str = "open", since: str = "", until: str = "", asset: str = "", cve: str = "", offset: int = 0, notice: str = "", c: Ctx = Depends(user)):
        view = view if view in {"open", "assessment", "closed", "remaining", "all"} else "open"
        ws = c.who.workspace_id
        now = datetime.now(timezone.utc)
        closed_until = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        closed_since_30d = (now - timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z")
        open_n = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='open'", (ws,)).fetchone()[0]
        assessment_n = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='acknowledged'", (ws,)).fetchone()[0]
        closed_n = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='closed'", (ws,)).fetchone()[0]
        closed_30d = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='closed' AND closed_at>=? AND closed_at<=?", (ws, closed_since_30d, closed_until)).fetchone()[0]
        remaining_30d = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status IN ('open','acknowledged') AND created_at>=? AND created_at<=?", (ws, closed_since_30d, closed_until)).fetchone()[0]
        window_since = since or closed_since_30d
        window_until = until or closed_until
        window_label = "selected window" if since else "30 days"
        window_closed = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='closed' AND created_at>=? AND created_at<=?", (ws, window_since, window_until)).fetchone()[0]
        window_remaining = c.conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status IN ('open','acknowledged') AND created_at>=? AND created_at<=?", (ws, window_since, window_until)).fetchone()[0]
        total_n = open_n + assessment_n + closed_n
        where = "workspace_id=?"
        params: list = [ws]
        if view in {"open", "assessment", "closed"}:
            status = {"open": "open", "assessment": "acknowledged", "closed": "closed"}[view]
            where += " AND status=?"
            params.append(status)
        if view == "remaining":
            where += " AND status IN ('open','acknowledged')"
        if since:
            where += " AND created_at>=?"
            params.append(since)
        if until:
            where += " AND created_at<=?"
            params.append(until)
        if asset:
            where += " AND asset_id=?"
            params.append(asset)
        if cve:  # alerts raised for one CVE (used by the link on a work item)
            where += " AND finding_id IN (SELECT id FROM findings WHERE cve_id=?)"
            params.append(cve.upper())
        total = c.conn.execute(f"SELECT COUNT(*) FROM alerts WHERE {where}", params).fetchall()[0][0]
        rows = c.conn.execute(f"SELECT * FROM alerts WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?", params + [ALERT_PAGE, max(0, offset)]).fetchall()
        asset_ids = [r[0] for r in c.conn.execute("SELECT DISTINCT asset_id FROM alerts WHERE workspace_id=? AND asset_id IS NOT NULL ORDER BY asset_id", (ws,))]
        facts = (fact("Total", fmt_n(total_n)) + fact("Open", fmt_n(open_n))
                 + fact("In assessment", fmt_n(assessment_n)) + fact("Closed", fmt_n(closed_n))
                 + fact(f"Closed · {window_label}", fmt_n(window_closed))
                 + fact(f"Remaining created · {window_label}", fmt_n(window_remaining)))
        tabs = (
            f'<p class="note"><a href="/ui/alerts?view=open">Open {fmt_n(open_n)}</a> · '
            f'<a href="/ui/alerts?view=assessment">In assessment {fmt_n(assessment_n)}</a> · '
            f'<a href="/ui/alerts?view=closed">Closed {fmt_n(closed_n)}</a> · '
            f'<a href="/ui/alerts?view=closed&amp;since={quote(closed_since_30d)}&amp;until={quote(closed_until)}">Closed last 30 days {fmt_n(closed_30d)}</a> · '
            f'<a href="/ui/alerts?view=remaining&amp;since={quote(closed_since_30d)}&amp;until={quote(closed_until)}">Remaining created last 30 days {fmt_n(remaining_30d)}</a> · '
            f'<a href="/ui/alerts?view=all">All {fmt_n(total_n)}</a></p>'
            '<p class="note">Acknowledge means the alert is being assessed. Close it only after it is clear/patched, and record the remediation evidence. Alert status does not change vulnerability findings.</p>'
        )

        def status_cell(a) -> str:
            if a["status"] == "open":
                btn = c.post_form(f"/ui/actions/ack/{a['id']}", "Acknowledge", "Move this alert to In assessment?", cls="warn")
                return '<span class="badge high">Open</span> ' + (btn or '<span class="muted">read-only</span>')
            if a["status"] == "acknowledged":
                close_form = (
                    f'<details class="close-evidence"><summary>Mark closed (patched / clear)</summary>'
                    f'<form method="post" action="/ui/actions/close/{a["id"]}">'
                    f'<input type="hidden" name="csrf" value="{c.csrf}">'
                    f'<label class="fl"><span>Patch or clear evidence (required)</span>'
                    f'<textarea name="resolution_note" minlength="3" maxlength="1000" required placeholder="Patch version, validation, or reason this alert is clear"></textarea></label>'
                    f'<button class="btn success" type="submit">Confirm closed</button></form></details>'
                    if c.who.has("operate") else '<span class="muted">read-only</span>'
                )
                return (f'<span class="badge warn">In assessment</span> <span class="muted">{esc(actor_label(a["acknowledged_by"]))} · {esc(fmt_dt(a["acknowledged_at"]))}</span>'
                        f'{close_form}')
            evidence = esc(a["resolution_note"] or "Legacy closed record; no closure evidence was captured.")
            return (f'<span class="badge success">Closed</span> <span class="muted">{esc(actor_label(a["closed_by"]))} · {esc(fmt_dt(a["closed_at"]))}</span>'
                    f'<div class="muted">Evidence: {evidence}</div>')

        export_link = '<a class="btn ghost" href="/ui/alerts/export.csv">Download all CSV</a>'
        flash = f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else ""
        asset_options = "".join(f'<option value="{esc(a)}"{" selected" if a == asset else ""}>{esc(a)}</option>' for a in asset_ids)
        clear = f'<a href="/ui/alerts?view={esc(view)}">Clear filter</a>' if (asset or cve) else ""
        filter_form = (f'<form class="filters" method="get" action="/ui/alerts"><input type="hidden" name="view" value="{esc(view)}">'
                       + (f'<input type="hidden" name="cve" value="{esc(cve)}">' if cve else "") +
                       f'<label class="fl"><span>Asset</span><select name="asset"><option value="">All assets</option>{asset_options}</select></label>'
                       f'<button>Filter</button> {clear}</form>')
        can_ack = c.who.has("operate")
        bulk = ""
        if can_ack:
            bulk = (f'<form id="alert-bulk" class="bulk-bar" method="post" action="/ui/actions/alerts/bulk" data-confirm="Apply this action to the selected alerts?">'
                    f'<input type="hidden" name="csrf" value="{esc(c.csrf)}">'
                    '<label class="fl"><span>Action for selected</span><select name="action">'
                    '<option value="acknowledge">Acknowledge (open to in assessment)</option>'
                    '<option value="close">Mark closed (in assessment to closed)</option></select></label>'
                    '<label class="fl bulk-note"><span>Patch or clear evidence (required to mark closed)</span>'
                    '<input name="resolution_note" maxlength="1000" placeholder="e.g. Patched to 2.4.1 and verified"></label>'
                    '<button class="warn">Apply to selected</button>'
                    '<label class="muted"><input type="checkbox" data-select-all> Select all actionable alerts on this page</label>'
                    '<span class="muted">Closed alerts cannot be selected. Each action applies only to alerts in the matching status.</span></form>')
        head = ["Time", "Asset", "Type", "Message", "Work item", "Status"]
        cells = []
        linked = work.for_findings(c.conn, ws, [a["finding_id"] for a in rows if a["finding_id"]])

        def work_cell(a) -> str:
            hit = linked.get(a["finding_id"]) if a["finding_id"] else None
            if not hit:
                return '<span class="muted">-</span>'
            key, state = hit
            return f'<a class="lk" href="/ui/work/item?k={quote(key.encode())}" title="Open the work item this alert belongs to">{work_pill(state)}</a>'

        for a in rows:
            row = [esc(fmt_dt(a["created_at"])), f'<a href="/ui/assets/{quote(a["asset_id"])}">{esc(a["asset_id"])}</a>' if a["asset_id"] else "-",
                   esc(label_of(a["kind"])), esc(en_text(a["message"])), work_cell(a), status_cell(a)]
            if can_ack:
                disabled = " disabled" if a["status"] == "closed" else ""
                row = [f'<input type="checkbox" form="alert-bulk" name="alert_id" value="{a["id"]}" aria-label="Select alert {a["id"]}"{disabled}>'] + row
            cells.append(row)
        if can_ack:
            head = [""] + head
        page_nav = pager(c, "/ui/alerts", {"view": view, "since": since, "until": until, "asset": asset, "cve": cve}, offset, total, size=ALERT_PAGE)
        body = (
            flash
            + f'<section class="panel"><h2>Alert workload</h2><div class="facts">{facts}</div>{tabs}'
            f'<div class="toolbar">{export_link}</div></section>'
            + f'<section class="panel">{filter_form}{bulk}{table(head, cells)}{page_nav}</section>'
        )
        return c.page("Alert center", body, lede=f"{fmt_n(open_n)} open · {fmt_n(assessment_n)} in assessment · {fmt_n(closed_n)} closed · {fmt_n(total_n)} total")

    @r.get("/ui/search")
    def search(q: str = "", c: Ctx = Depends(user)):
        if not q.strip():
            return c.page("Search", "<p class='muted'>Enter a search keyword.</p>")
        try:
            hits = c.conn.execute("SELECT kind, ref, title, snippet(search_index, 3, '[', ']', '…', 12) s FROM search_index WHERE search_index MATCH ? ORDER BY rank LIMIT 50", (fts_query(q),)).fetchall()
        except HTTPException:
            hits = []
        def href(kind: str, ref: str) -> str:
            return {"cve": f"/ui/cves/{quote(ref)}", "asset": f"/ui/assets/{quote(ref)}", "finding": f"/ui/findings/{quote(ref)}"}.get(kind, "/ui")
        return c.page(f"Search: {q}", table(["Type", "Result", "Snippet"], [[esc(h["kind"]), f'<a href="{href(h["kind"], h["ref"])}">{esc(h["title"])}</a>', esc(h["s"])] for h in hits]))

    @r.get(freshness.COVERAGE_PAGE["path"])
    def coverage(tab: str = "exec", queued: int = 0, existing: int = 0, skipped: int = 0, offset: int = 0, c: Ctx = Depends(user)):
        ws = c.who.workspace_id
        now = freshness.utc_now()
        freshness.sweep(c.conn, ws, now)
        s = freshness.summary(c.conn, ws, now)
        refresh_runs = freshness.list_jobs(c.conn, ws, 25, None)
        triggers = list(freshness.TRIGGERS)
        gaps = sorted((g for g in freshness.CAPABILITIES if not (g["shipped"] and g["tested"])), key=lambda g: g["priority"])
        tab = tab if tab in {"exec", "tech"} else "exec"
        jobs_total = c.conn.execute("SELECT COUNT(*) FROM jobs WHERE workspace_id=?", (ws,)).fetchone()[0]
        job_rows = [job_out(x) for x in c.conn.execute(
            "SELECT * FROM jobs WHERE workspace_id=? ORDER BY id DESC LIMIT ? OFFSET ?", (ws, PAGE, max(0, offset)))]
        active = (any(j["state"] in {"queued", "running", "retry_wait"} for j in refresh_runs)
                  or any(j["status"] in {"queued", "running"} for j in job_rows))
        latest = s["latest_inventory"]
        latest_text = f"Latest inventory: {fmt_utc(latest['collected_at'])}"
        if latest["age_seconds"] is not None:
            latest_text += f" · {fmt_age(latest['age_seconds'])} old"
        if latest["stale"]:
            latest_text += " · over TTL"
        cur_exec = ' aria-current="page"' if tab == "exec" else ""
        cur_tech = ' aria-current="page"' if tab == "tech" else ""
        tabs = (f'<nav class="seg" aria-label="View">'
                f'<a href="/ui/coverage?tab=exec"{cur_exec}>Executive summary</a>'
                f'<a href="/ui/coverage?tab=tech"{cur_tech}>Technical detail</a></nav>')
        notice = ""
        if queued or existing or skipped:
            notice = (f'<section class="panel"><p>Refresh requested: {fmt_n(queued)} queued, {fmt_n(existing)} already queued, '
                      f'{fmt_n(skipped)} skipped (collector-driven layers run on the host).</p></section>')
        read_note = "" if c.who.has("operate") else '<p class="note">Read-only: operator scope is required to queue refreshes.</p>'
        head = f'<div class="bar">{tabs}<span class="asof">{esc(latest_text)}</span></div>{notice}{read_note}'
        if tab == "exec":
            view = coverage_exec(s)
        else:
            schedules = list_job_schedules(c.conn)
            is_admin = c.who.has("admin")
            scheduler = coverage_scheduler(
                scheduler_enabled(c.conn), len(schedules), jobs_total,
                c.conn.execute("SELECT COUNT(*) FROM jobs WHERE workspace_id=? AND status IN ('queued','running')", (ws,)).fetchone()[0],
                c.conn.execute("SELECT COUNT(*) FROM jobs WHERE workspace_id=? AND status='failed'", (ws,)).fetchone()[0],
                is_admin, c.csrf)
            buttons = (c.post_form("/ui/actions/cve-sync", "Sync CVE now", "Run CVE sync now?")
                       + c.post_form("/ui/actions/analyze", "Run analysis", "Run analysis for all assets?"))
            jobs_table = table(["Job", "Type", "Status", "Trigger", "Queued", "Duration", "Results", "Error"], [
                [f'<a class="lk" href="/ui/jobs/{j["id"]}">#{j["id"]}</a>', esc(label_of(j["type"])), badge(j["status"]),
                 esc(TRIGGER_LABELS.get(j["trigger_source"], label_of(j["trigger_source"]))), esc(fmt_dt(j["queued_at"])), esc(fmt_dur(j["duration_seconds"])),
                 esc(summarize_counts(j["counts"])), esc(classified(en_text(j["error"]), "-"))] for j in job_rows])
            jobs_panel = (f'<section class="panel"><h2>Background jobs</h2>'
                          '<p class="hint">Every job the worker has queued or run: scheduled, manual, and coverage refreshes.</p>'
                          f'<div class="toolbar">{buttons}</div>{jobs_table}{pager(c, "/ui/coverage", {"tab": "tech"}, offset, jobs_total)}</section>')
            view = scheduler + coverage_schedules(schedules, is_admin, c.csrf) + jobs_panel + coverage_tech(refresh_runs, triggers, gaps)
        can_refresh = c.who.has("operate")
        attention, attention_total = freshness.attention_assets(c.conn, ws)
        body = f'{head}{coverage_kpis(s)}{coverage_guide(can_refresh)}{coverage_layers(s, can_refresh)}{coverage_attention(attention, attention_total, can_refresh, c)}{view}'
        actions = (c.post_form("/ui/actions/coverage/invalidate", "Invalidate stale", "Queue a refresh for every stale entry?")
                   + c.post_form("/ui/actions/coverage/refresh", "Refresh all", "Queue a refresh for every refreshable layer?"))
        return c.page(freshness.COVERAGE_PAGE["title"], body, refresh=active, lede=freshness.COVERAGE_PAGE["subtitle"],
                      actions=f'<div class="toolbar">{actions}</div>')

    def _coverage_redirect(results: list[dict]) -> RedirectResponse:
        queued = sum(1 for x in results if x["status"] == "queued")
        existing = sum(1 for x in results if x["status"] == "already_queued")
        skipped = sum(1 for x in results if x["status"] == "skipped")
        return RedirectResponse(f"/ui/coverage?queued={queued}&existing={existing}&skipped={skipped}", status_code=303)

    @r.post("/ui/actions/coverage/refresh")
    def act_coverage_refresh(csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        return _coverage_redirect(freshness.request_refresh(c.conn, c.who.workspace_id, c.who.actor))

    @r.post("/ui/actions/coverage/refresh-asset")
    def act_coverage_refresh_asset(asset_id: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        if c.conn.execute("SELECT 1 FROM assets WHERE workspace_id=? AND asset_id=?", (c.who.workspace_id, asset_id)).fetchone() is None:
            raise HTTPException(404, "Asset not found")
        return _coverage_redirect(freshness.request_refresh(c.conn, c.who.workspace_id, c.who.actor, layer="correlation", asset_id=asset_id))

    @r.post("/ui/actions/coverage/invalidate")
    def act_coverage_invalidate(csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        return _coverage_redirect(freshness.invalidate_stale(c.conn, c.who.workspace_id, c.who.actor, freshness.utc_now()))

    @r.get("/ui/settings")
    def settings_page(notice: str = "", error: str = "", c: Ctx = Depends(user)):
        if c.who.kind != "user":
            return c.page("Settings", '<section class="panel"><h2>Sign in required</h2><p>Sign in with your own account to manage settings.</p></section>',
                          lede="Accounts, roles, and API tokens")
        me = auth.find_user(c.conn, c.who.name)
        flash = (f'<section class="panel"><p>{esc(notice)}</p></section>' if notice else "") + (
            f'<section class="panel"><p class="stale">{esc(error)}</p></section>' if error else "")
        account = (
            '<section class="panel"><h2>My account</h2>'
            + '<div class="facts">' + fact("Username", me["username"]) + fact("Role", label_of(me["role"])) + fact("Last sign-in", fmt_utc(me["last_login_at"])) + "</div>"
            + '<h3>Change password</h3>'
            + f'<form class="filters" method="post" action="/ui/actions/account/password"><input type="hidden" name="csrf" value="{esc(c.csrf)}">'
            + '<label class="fl"><span>Current password</span><input type="password" name="current_password" autocomplete="current-password" required></label>'
            + '<label class="fl"><span>New password</span><input type="password" name="new_password" autocomplete="new-password" minlength="12" required></label>'
            + '<label class="fl"><span>Confirm new password</span><input type="password" name="confirm" autocomplete="new-password" minlength="12" required></label>'
            + '<button>Change password</button></form>'
            + '<p class="note">Changing your password signs out your other sessions. Passwords must be at least 12 characters.</p></section>')
        admin = ""
        if c.who.has("admin"):
            users = c.conn.execute(
                """SELECT u.*, (SELECT COUNT(*) FROM api_tokens t WHERE t.owner_user_id=u.id AND t.revoked_at IS NULL) AS tokens
                   FROM users u WHERE u.workspace_id=? ORDER BY u.username""", (c.who.workspace_id,)).fetchall()
            user_rows = []
            for u in users:
                uid, name = u["id"], esc(u["username"])
                is_me = u["id"] == me["id"]
                roles = "".join(f'<option value="{r}"{" selected" if r == u["role"] else ""}>{esc(label_of(r))}</option>' for r in auth.ROLES)
                role_form = (f'<form class="inline" method="post" action="/ui/actions/users/{uid}/role" data-confirm="Change the role of {name}?">'
                             f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><select name="role" aria-label="Role for {name}">{roles}</select>'
                             '<button class="ghost">Save</button></form>') if not is_me else esc(label_of(u["role"]))
                status = state_pill("pending", "Disabled") if u["disabled_at"] else state_pill("success", "Active")
                if is_me:
                    actions = '<span class="muted">This is you</span>'
                else:
                    verb = "Enable" if u["disabled_at"] else "Disable"
                    actions = (f'<form class="inline" method="post" action="/ui/actions/users/{uid}/status" data-confirm="{verb} {name}?">'
                               f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="action" value="{verb.lower()}">'
                               f'<button class="ghost">{verb}</button></form> '
                               f'<form class="inline" method="post" action="/ui/actions/users/{uid}/password" data-confirm="Reset password for {name}? Their sessions will be signed out.">'
                               f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="password" name="new_password" minlength="12" placeholder="New password" aria-label="New password for {name}" required>'
                               '<button class="ghost">Reset password</button></form>')
                user_rows.append([name, role_form, status, esc(fmt_utc(u["last_login_at"])), esc(str(u["tokens"])), actions])
            role_options = "".join(f'<option value="{r}">{esc(label_of(r))}</option>' for r in auth.ROLES)
            create_user = (
                f'<form class="filters" method="post" action="/ui/actions/users/create"><input type="hidden" name="csrf" value="{esc(c.csrf)}">'
                '<label class="fl"><span>Username</span><input name="username" pattern="[A-Za-z0-9._-]{3,64}" maxlength="64" required></label>'
                f'<label class="fl"><span>Role</span><select name="role">{role_options}</select></label>'
                '<label class="fl"><span>Initial password</span><input type="password" name="password" minlength="12" required></label>'
                '<button>Create user</button></form>')
            admin += ('<section class="panel"><h2>Users</h2>'
                      '<p class="hint">Viewer: read only. Operator: also runs sync, analysis, alert actions, and coverage refreshes. Admin: also manages users, API tokens, and schedules.</p>'
                      f'{create_user}{table(["Username", "Role", "Status", "Last sign-in (UTC)", "Active API tokens", "Actions"], user_rows)}</section>')

            tokens = c.conn.execute(
                """SELECT t.*, u.username AS owner FROM api_tokens t LEFT JOIN users u ON u.id=t.owner_user_id
                   WHERE t.workspace_id=? ORDER BY t.id DESC""", (c.who.workspace_id,)).fetchall()
            now = now_iso()
            token_rows = []
            for t in tokens:
                if t["revoked_at"]:
                    status = state_pill("failed", "Revoked")
                elif t["expires_at"] and t["expires_at"] <= now:
                    status = state_pill("pending", "Expired")
                else:
                    status = state_pill("success", "Active")
                revoke = ""
                if not t["revoked_at"]:
                    revoke = (f'<form class="inline" method="post" action="/ui/actions/tokens/{t["id"]}/revoke" data-confirm="Revoke token {esc(t["name"])}? Collectors using it will stop working.">'
                              f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><button class="ghost danger">Revoke</button></form>')
                token_rows.append([esc(t["name"]), esc(t["owner"] or "No owner (created before accounts)"), esc(t["purpose"] or "-"),
                                   esc(t["scopes"].replace(",", ", ")), esc(fmt_utc(t["created_at"])), esc(fmt_utc(t["last_used_at"])), status, revoke or "-"])
            scope_boxes = "".join(f'<label><input type="checkbox" name="scopes" value="{s}"{" checked" if s == "read" else ""}> {s}</label>'
                                  for s in auth.SCOPES)
            create_token = (
                f'<form class="filters" method="post" action="/ui/actions/tokens/create"><input type="hidden" name="csrf" value="{esc(c.csrf)}">'
                '<label class="fl"><span>Name</span><input name="name" pattern="[A-Za-z0-9._-]{1,64}" maxlength="64" required placeholder="e.g. awx-prod"></label>'
                '<label class="fl"><span>Purpose</span><input name="purpose" maxlength="200" placeholder="e.g. AWX collector for prod hosts"></label>'
                f'<fieldset class="scope-picker"><legend>Scopes</legend><div class="scope-options">{scope_boxes}</div></fieldset>'
                '<button>Create token</button></form>'
                '<p class="note">The token value is shown once, right after creation. RiskPatch stores only a hash.</p>')
            admin += ('<section class="panel"><h2>API tokens</h2>'
                      '<p class="hint">Tokens used by collectors and integrations. Each token shows its owner, purpose, and scopes. Values are never shown again.</p>'
                      f'{create_token}{table(["Name", "Owner", "Purpose", "Scopes", "Created (UTC)", "Last used (UTC)", "Status", "Action"], token_rows)}</section>')
        body = flash + account + sla_panel(c) + admin
        return c.page("Settings", body, lede="Your account and, for administrators, users and API tokens")

    def _settings_redirect(message: str, error: bool = False) -> RedirectResponse:
        key = "error" if error else "notice"
        return RedirectResponse(f"/ui/settings?{key}={quote(message)}", status_code=303)

    def _require_user(c: Ctx) -> None:
        if c.who.kind != "user":
            raise HTTPException(403, "sign in with an account")

    def _require_admin(c: Ctx, csrf: str) -> None:
        if c.who.kind != "user" or not c.who.has("admin"):
            raise HTTPException(403, "admin role required")
        check_csrf(c, csrf, "admin")

    def _target_user(c: Ctx, uid: int):
        row = c.conn.execute("SELECT * FROM users WHERE id=? AND workspace_id=?", (uid, c.who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "User not found")
        return row

    @r.post("/ui/actions/account/password")
    def act_change_password(current_password: str = Form(""), new_password: str = Form(""), confirm: str = Form(""),
                            csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_user(c)
        check_csrf(c, csrf, "read")
        me = auth.find_user(c.conn, c.who.name)
        if not auth.verify_password(current_password, me["password_hash"]):
            return _settings_redirect("Current password is incorrect.", error=True)
        if new_password != confirm:
            return _settings_redirect("New passwords do not match.", error=True)
        try:
            auth.set_password(c.conn, me["id"], new_password, c.who.actor, keep_secret=c.token)
        except ValueError as exc:
            return _settings_redirect(str(exc), error=True)
        return _settings_redirect("Password changed. Your other sessions were signed out.")

    @r.post("/ui/actions/users/create")
    def act_create_user(username: str = Form(""), role: str = Form(""), password: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_admin(c, csrf)
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", username):
            return _settings_redirect("Username must be 3 to 64 characters: letters, digits, dot, dash, or underscore.", error=True)
        if role not in auth.ROLES:
            return _settings_redirect("Unknown role.", error=True)
        try:
            auth.create_user(c.conn, username, password, role, c.who.actor, c.who.workspace_id)
        except ValueError as exc:
            return _settings_redirect(str(exc), error=True)
        except sqlite3.IntegrityError:
            return _settings_redirect("That username already exists.", error=True)
        return _settings_redirect(f"User {username} created.")

    @r.post("/ui/actions/users/{uid}/role")
    def act_user_role(uid: int, role: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_admin(c, csrf)
        target = _target_user(c, uid)
        if role not in auth.ROLES:
            return _settings_redirect("Unknown role.", error=True)
        me = auth.find_user(c.conn, c.who.name)
        if target["id"] == me["id"]:
            return _settings_redirect("You cannot change your own role.", error=True)
        if target["role"] == "admin" and role != "admin" and not target["disabled_at"] and auth.active_admin_count(c.conn) <= 1:
            return _settings_redirect("Cannot remove the last active admin.", error=True)
        auth.set_user_role(c.conn, uid, role, c.who.actor)
        return _settings_redirect(f"Role for {target['username']} set to {label_of(role)}.")

    @r.post("/ui/actions/users/{uid}/status")
    def act_user_status(uid: int, action: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_admin(c, csrf)
        target = _target_user(c, uid)
        me = auth.find_user(c.conn, c.who.name)
        if target["id"] == me["id"]:
            return _settings_redirect("You cannot disable your own account.", error=True)
        if action not in {"enable", "disable"}:
            return _settings_redirect("Unknown action.", error=True)
        disable = action == "disable"
        if disable and target["role"] == "admin" and not target["disabled_at"] and auth.active_admin_count(c.conn) <= 1:
            return _settings_redirect("Cannot disable the last active admin.", error=True)
        auth.set_user_disabled(c.conn, uid, disable, c.who.actor)
        return _settings_redirect(f"{target['username']} {'disabled' if disable else 'enabled'}.")

    @r.post("/ui/actions/users/{uid}/password")
    def act_user_password(uid: int, new_password: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_admin(c, csrf)
        target = _target_user(c, uid)
        me = auth.find_user(c.conn, c.who.name)
        if target["id"] == me["id"]:
            return _settings_redirect("Use My account to change your own password.", error=True)
        try:
            auth.set_password(c.conn, uid, new_password, c.who.actor)
        except ValueError as exc:
            return _settings_redirect(str(exc), error=True)
        return _settings_redirect(f"Password reset for {target['username']}. Their sessions were signed out.")

    @r.post("/ui/actions/tokens/create")
    def act_create_token(name: str = Form(""), purpose: str = Form(""), scopes: list[str] = Form([]), csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_admin(c, csrf)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            return _settings_redirect("Token name: 1 to 64 letters, digits, dot, dash, or underscore.", error=True)
        chosen = sorted({s for s in scopes if s in auth.SCOPES})
        if not chosen:
            return _settings_redirect("Choose at least one scope.", error=True)
        me = auth.find_user(c.conn, c.who.name)
        try:
            token = auth.create_user_token(c.conn, name, chosen, me["id"], purpose.strip()[:200], c.who.actor, c.who.workspace_id)
        except sqlite3.IntegrityError:
            return _settings_redirect("A token with that name already exists.", error=True)
        body = (f'<section class="panel"><h2>Token created: {esc(name)}</h2>'
                '<p class="stale">Copy this value now. It is shown only once and cannot be retrieved later.</p>'
                f'<pre>{esc(token)}</pre>'
                f'<p>Scopes: {esc(", ".join(chosen))}</p>'
                '<p><a href="/ui/settings">Back to settings</a></p></section>')
        return c.page("Token created", body, lede="Shown once")

    @r.post("/ui/actions/tokens/{tid}/revoke")
    def act_revoke_token(tid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        _require_admin(c, csrf)
        row = c.conn.execute("SELECT * FROM api_tokens WHERE id=? AND workspace_id=?", (tid, c.who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "Token not found")
        if row["revoked_at"]:
            return _settings_redirect("Token is already revoked.", error=True)
        with tx(c.conn):
            c.conn.execute("UPDATE api_tokens SET revoked_at=? WHERE id=?", (now_iso(), tid))
            audit(c.conn, c.who.actor, "token.revoke", row["name"], {"id": tid}, c.who.workspace_id)
        return _settings_redirect(f"Token {row['name']} revoked.")

    @r.get("/ui/status")
    def status(c: Ctx = Depends(user)):
        from riskpatch.config import APP_VERSION, RULESET_VERSION
        from riskpatch.db import schema_version

        facts = (
            fact("Application", APP_VERSION)
            + fact("Rule set", RULESET_VERSION)
            + fact("Database schema", f"v{schema_version(c.conn)}")
            + fact("Server time", fmt_dt(now_iso()))
        )
        feed_jobs = c.conn.execute(
            "SELECT finished_at, status, counts_json, provider_status_json FROM jobs WHERE workspace_id=? AND type IN ('cve_sync','manual_cve_sync') "
            "AND status IN ('success','partial','failed') ORDER BY id DESC LIMIT 9", (c.who.workspace_id,)).fetchall()
        return c.page("Status", f'<section class="panel"><h2>Runtime</h2><div class="facts">{facts}</div>'
                      f"<p class='note'>No secrets are displayed on this page.</p></section>" + feed_runs_panel(feed_jobs),
                      lede="Build, rules, database schema, and intel feed runs")

    @r.get("/ui/audit")
    def audit_page(c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        rows = c.conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200").fetchall()
        return c.page("Audit trail", table(["Time", "Actor", "Action", "Target", "Detail"], [[esc(fmt_dt(x["at"])), esc(actor_label(x["actor"])), esc(x["action"]), esc(classified(x["target"], "-")), esc(x["detail"])] for x in rows]), lede="Privileged actions and token lifecycle")

    def _trigger(c: Ctx, csrf: str, job_type: str, scope: dict) -> RedirectResponse:
        check_csrf(c, csrf)
        job_id, created = enqueue(c.conn, job_type, "ui", scope, c.who.workspace_id)
        with tx(c.conn):
            audit(c.conn, c.who.actor, "job.trigger", str(job_id), {"type": job_type, "scope": scope, "new": created, "via": "ui"}, c.who.workspace_id)
        return RedirectResponse(f"/ui/jobs/{job_id}", status_code=303)

    @r.post("/ui/actions/cve-sync")
    def act_sync(csrf: str = Form(""), c: Ctx = Depends(user)):
        return _trigger(c, csrf, "manual_cve_sync", {})

    @r.post("/ui/actions/analyze")
    def act_analyze(csrf: str = Form(""), c: Ctx = Depends(user)):
        return _trigger(c, csrf, "manual_analysis", {})

    @r.post("/ui/actions/refresh/{asset_id}")
    def act_refresh(asset_id: str, csrf: str = Form(""), c: Ctx = Depends(user)):
        if c.conn.execute("SELECT 1 FROM assets WHERE workspace_id=? AND asset_id=?", (c.who.workspace_id, asset_id)).fetchone() is None:
            raise HTTPException(404, "Asset not found")
        return _trigger(c, csrf, "manual_analysis", {"asset_id": asset_id})

    @r.get("/ui/correlate", response_class=HTMLResponse)
    def correlate_page(c: Ctx = Depends(user)):
        active_skills = list_active_skills(c.conn)
        assets = c.conn.execute(
            "SELECT id, asset_id, os_name, os_version FROM assets ORDER BY asset_id"
        ).fetchall()
        asset_options = "".join(
            f'<option value="{esc(a["asset_id"])}">{esc(a["asset_id"])} ({esc(a["os_name"] or "")} {esc(a["os_version"] or "")})</option>'
            for a in assets
        )
        skills_note = ""
        if active_skills:
            skills_note = f'<p class="note">{len(active_skills)} active skill(s) will be applied automatically. Manage them at <a href="/ui/skills">System &gt; Skills</a>.</p>'
        body = (
            f'<section class="panel"><h2>AI correlation</h2>'
            f'<p class="note">Send open findings to the LLM gateway for correlation. Level, action, and status are computed by fixed rules; the AI only narrates and suggests connections.</p>'
            f'{skills_note}'
            f'<form class="panel form-compact" method="post" action="/ui/actions/correlate">'
            f'<input type="hidden" name="csrf" value="{c.csrf}">'
            f'<div class="form-grid">'
            f'<label class="fl"><span>Asset</span><select name="asset_id"><option value="">all assets</option>{asset_options}</select></label>'
            f'<label class="fl"><span>Max findings</span><input name="max_findings" value="5" type="number" min="1" max="20"></label>'
            f'<label class="fl full"><span>Extra skills / context (optional)</span>'
            f'<textarea name="skills" rows="4" placeholder="Additional one-time context for this correlation run..."></textarea></label>'
            f'</div>'
            f'<div class="form-actions"><button class="primary">Run AI correlation</button></div>'
            f'</form>'
            f"</section>"
        )
        return c.page("AI correlation", body, lede="Correlate findings across assets with optional skills context")

    @r.post("/ui/actions/correlate")
    def act_correlate(csrf: str = Form(""), asset_id: str = Form(""), skills: str | None = Form(None), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        asset_id = asset_id.strip() or ""
        if asset_id and c.conn.execute("SELECT 1 FROM assets WHERE workspace_id=? AND asset_id=?", (c.who.workspace_id, asset_id)).fetchone() is None:
            raise HTTPException(404, "Asset not found")
        cfg = llm.load_config()
        with httpx.Client(timeout=cfg.timeout if cfg else 60) as client:
            res = correlate(c.conn, c.who.workspace_id, client, asset_id, skills=skills, include_active=True)
        with tx(c.conn):
            audit(c.conn, c.who.actor, "correlation.ai", asset_id, {"status": res["ai"]["status"], "via": "ui", "skills": bool(skills), "error": (res["ai"]["error"] or {}).get("code")}, c.who.workspace_id)
        ai = res["ai"]
        parts = [f'<p class="muted">{esc(res["disclaimer"])}</p>']
        if ai["error"]:
            parts.append(f'<p class="stale">AI {esc(ai["status"])}: {esc(ai["error"]["code"])} - {esc(ai["error"]["hint"])}</p>')
        if ai["narrative"]:
            parts.append(f'<section class="panel"><h2>AI narrative (model {esc(ai["model"])})</h2><p>{esc(ai["narrative"])}</p></section>')
        if ai["correlations"]:
            parts.append('<section class="panel"><h2>Correlations and evidence</h2>' + table(["Title", "Claim", "Evidence"], [[esc(x["title"]), esc(x["claim"]), esc(", ".join(x["evidence"]))] for x in ai["correlations"]]) + "</section>")
        if ai["uncertainty"]:
            parts.append('<section class="panel"><h2>Uncertainty</h2><ul>' + "".join(f"<li>{esc(u)}</li>" for u in ai["uncertainty"]) + "</ul></section>")
        det = res["deterministic"]
        parts.append('<section class="panel"><h2>Deterministic verdict (not modified by AI)</h2>' + table(["Ref", "Asset", "CVE", "Component", "Level", "Action", "Confidence"], [
            [esc(v["ref"]), esc(v["asset_id"]), esc(v["cve_id"]), esc(v["component"]), badge(v["level"]), label_of(v["action"]), esc(v["confidence"])] for v in det["verdicts"]]) + "</section>")
        if res["truncated"]:
            parts.append(f'<p class="muted">Truncated: {len(det["verdicts"])} of {res["open_findings_total"]} open findings.</p>')
        return c.page("AI correlation" + (f" ({asset_id})" if asset_id else ""), "".join(parts))

    @r.post("/ui/actions/ack/{aid}")
    def act_ack(aid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        with tx(c.conn):
            cur = c.conn.execute("UPDATE alerts SET status='acknowledged', acknowledged_at=?, acknowledged_by=? WHERE id=? AND workspace_id=? AND status='open'", (now_iso(), c.who.actor, aid, c.who.workspace_id))
            if cur.rowcount:
                audit(c.conn, c.who.actor, "alert.ack", str(aid), {"via": "ui", "status": "acknowledged"}, c.who.workspace_id)
        row = c.conn.execute("SELECT status FROM alerts WHERE id=? AND workspace_id=?", (aid, c.who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "alert not found")
        if row["status"] != "acknowledged":
            raise HTTPException(409, "alert cannot be acknowledged")
        return RedirectResponse("/ui/alerts?view=assessment", status_code=303)

    @r.post("/ui/actions/alerts/bulk")
    def act_bulk_alerts(alert_id: list[int] = Form([]), action: str = Form(""), resolution_note: str = Form(""),
                        csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)

        def back(message: str) -> RedirectResponse:
            return RedirectResponse(f"/ui/alerts?view=open&notice={quote(message)}", status_code=303)

        ids = sorted({i for i in alert_id if i > 0})
        if not ids:
            return back("No alerts selected.")
        if len(ids) > ALERT_PAGE:
            return back(f"Select at most {ALERT_PAGE} alerts at a time.")
        if action not in {"acknowledge", "close"}:
            return back("Choose an action: acknowledge or mark closed.")
        marks = ",".join("?" * len(ids))
        ws = c.who.workspace_id
        if action == "acknowledge":
            with tx(c.conn):
                targets = [r[0] for r in c.conn.execute(
                    f"SELECT id FROM alerts WHERE workspace_id=? AND status='open' AND id IN ({marks})", [ws, *ids])]
                if targets:
                    tm = ",".join("?" * len(targets))
                    c.conn.execute(f"UPDATE alerts SET status='acknowledged', acknowledged_at=?, acknowledged_by=? WHERE workspace_id=? AND id IN ({tm})",
                                   [now_iso(), c.who.actor, ws, *targets])
                    audit(c.conn, c.who.actor, "alert.ack", f"{len(targets)} alerts", {"via": "ui", "ids": targets, "status": "acknowledged"}, ws)
            skipped = len(ids) - len(targets)
            return back(f"Acknowledged {len(targets)} alert(s)." + (f" Skipped {skipped} that were not open." if skipped else ""))
        note = resolution_note.strip()
        if len(note) < 3:
            return back("Closing requires patch or clear evidence (at least 3 characters).")
        if len(note) > 1000:
            return back("Closure evidence is limited to 1000 characters.")
        with tx(c.conn):
            targets = [r[0] for r in c.conn.execute(
                f"SELECT id FROM alerts WHERE workspace_id=? AND status='acknowledged' AND id IN ({marks})", [ws, *ids])]
            if targets:
                tm = ",".join("?" * len(targets))
                c.conn.execute(f"UPDATE alerts SET status='closed', closed_at=?, closed_by=?, resolution_note=? WHERE workspace_id=? AND id IN ({tm})",
                               [now_iso(), c.who.actor, note, ws, *targets])
                audit(c.conn, c.who.actor, "alert.close", f"{len(targets)} alerts", {"via": "ui", "ids": targets, "resolution_note": note}, ws)
        skipped = len(ids) - len(targets)
        return back(f"Closed {len(targets)} alert(s)." + (f" Skipped {skipped} not in assessment; acknowledge them first." if skipped else ""))

    @r.post("/ui/actions/close/{aid}")
    def act_close(aid: int, resolution_note: str = Form(""), csrf: str = Form(""), c: Ctx = Depends(user)):
        check_csrf(c, csrf)
        note = resolution_note.strip()
        if len(note) < 3:
            raise HTTPException(400, "closure requires patch/clear evidence (at least 3 characters)")
        if len(note) > 1000:
            raise HTTPException(400, "closure evidence is limited to 1000 characters")
        with tx(c.conn):
            cur = c.conn.execute(
                "UPDATE alerts SET status='closed', closed_at=?, closed_by=?, resolution_note=? WHERE id=? AND workspace_id=? AND status='acknowledged'",
                (now_iso(), c.who.actor, note, aid, c.who.workspace_id),
            )
            if cur.rowcount:
                audit(c.conn, c.who.actor, "alert.close", str(aid), {"via": "ui", "resolution_note": note}, c.who.workspace_id)
        row = c.conn.execute("SELECT status FROM alerts WHERE id=? AND workspace_id=?", (aid, c.who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "alert not found")
        if row["status"] != "closed":
            raise HTTPException(409, "alert must be acknowledged before it can be closed")
        return RedirectResponse("/ui/alerts?view=closed", status_code=303)

    @r.get("/ui/skills", response_class=HTMLResponse)
    def skills_page(c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        skills = list_skills(c.conn)
        rows = "".join(
            f"<tr>"
            f"<td><input type='checkbox' name='skill_ids' value='{s['id']}'></td>"
            f"<td>{esc(s['name'])}</td>"
            f"<td>{esc((s['content'] or '')[:100])}{'…' if (s['content'] or '') and len(s['content']) > 100 else ''}</td>"
            f"<td><span class='badge {'success' if s['active'] else 'failed'}'>{'Active' if s['active'] else 'Inactive'}</span></td>"
            f"<td>"
            f'<a class="ghost" href="/ui/actions/skill/{s["id"]}/edit" title="Edit">✎</a> '
            f'<form class="inline" method="post" action="/ui/actions/skill/{s["id"]}/toggle" data-confirm="Toggle skill {esc(s["name"])}?">'
            f'<input type="hidden" name="csrf" value="{c.csrf}"><button class="ghost">{"Deactivate" if s["active"] else "Activate"}</button></form> '
            f'<form class="inline" method="post" action="/ui/actions/skill/{s["id"]}/delete" data-confirm="Delete skill {esc(s["name"])}?">'
            f'<input type="hidden" name="csrf" value="{c.csrf}"><button class="ghost danger">Delete</button></form>'
            f"</td></tr>"
            for s in skills
        )
        body = (
            f'<section class="panel"><h2>AI skills / context</h2>'
            f'<p class="note">Reusable context snippets sent to the LLM during AI correlation and report generation. Only <b>Active</b> skills are applied automatically.</p>'
            f'<form class="panel form-compact" method="post" action="/ui/actions/skill/create">'
            f'<input type="hidden" name="csrf" value="{c.csrf}">'
            f'<div class="form-grid">'
            f'<label class="fl"><span>Name</span><input name="name" placeholder="e.g. Production patch policy" required></label>'
            f'<label class="fl full"><span>Content</span><textarea name="content" rows="4" placeholder="e.g. Asset A2 is production-critical; patch window is Sundays; node must stay LTS-compatible" required></textarea></label>'
            f'</div>'
            f'<div class="form-actions"><button class="primary">Save skill</button></div>'
            f'</form>'
            f'<form class="panel form-compact" method="post" action="/ui/actions/skill/bulk-toggle">'
            f'<input type="hidden" name="csrf" value="{c.csrf}">'
            f'<input type="hidden" name="active" value="1">'
            f'<table><tr><th><input type="checkbox" id="select-all"></th><th>Name</th><th>Preview</th><th>Status</th><th>Action</th></tr>'
            f'{rows or "<tr><td colspan=5 class=muted>No skills yet</td></tr>"}</table>'
            f'<div class="form-actions mt-12">'
            f'<button type="button" class="ghost" data-bulk="activate">Activate selected</button> '
            f'<button type="button" class="ghost" data-bulk="deactivate">Deactivate selected</button> '
            f'<button type="button" class="ghost danger" data-bulk="delete">Delete selected</button>'
            f'</div></form>'
        )
        return c.page("AI skills", body, lede="Manage reusable context snippets for AI correlation and reports")

    @r.get("/ui/actions/skill/{sid}/edit", response_class=HTMLResponse)
    def skill_edit_page(sid: int, c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        s = get_skill(c.conn, sid)
        if s is None:
            raise HTTPException(404, "Skill not found")
        body = (
            f'<section class="panel"><h2>Edit skill</h2>'
            f'<form class="panel form-compact" method="post" action="/ui/actions/skill/{sid}/update">'
            f'<input type="hidden" name="csrf" value="{c.csrf}">'
            f'<input type="hidden" name="id" value="{s["id"]}">'
            f'<label class="fl"><span>Name</span><input name="name" value="{esc(s["name"])}" required></label>'
            f'<label class="fl full"><span>Content</span><textarea name="content" rows="4" required>{esc(s["content"] or "")}</textarea></label>'
            f'<label class="fl"><span>Active</span><select name="active"><option value="1' + (' selected' if s["active"] else '') + '">Yes</option><option value="0' + (' selected' if not s["active"] else '') + '">No</option></select></label>'
            f'<div class="form-actions"><button class="primary">Update skill</button> <a class="ghost" href="/ui/skills">Cancel</a></div>'
            f'</form></section>'
        )
        return c.page("Edit skill", body, lede="Edit an existing AI skill / context snippet")

    @r.post("/ui/actions/skill/create")
    def act_skill_create(csrf: str = Form(""), name: str = Form(""), content: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf)
        name = name.strip()
        content = content.strip()
        if not name or not content:
            raise HTTPException(400, "Name and content are required")
        create_skill(c.conn, name, content, active=True)
        return RedirectResponse("/ui/skills", status_code=303)

    @r.post("/ui/actions/skill/{sid}/update")
    def act_skill_update(sid: int, csrf: str = Form(""), name: str = Form(""), content: str = Form(""), active: str = Form("1"), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf)
        name = name.strip()
        content = content.strip()
        if not name or not content:
            raise HTTPException(400, "Name and content are required")
        update_skill(c.conn, sid, name, content, active == "1")
        return RedirectResponse("/ui/skills", status_code=303)

    @r.post("/ui/actions/skill/{sid}/toggle")
    def act_skill_toggle(sid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf)
        s = get_skill(c.conn, sid)
        if s is None:
            raise HTTPException(404, "Skill not found")
        toggle_skill_active(c.conn, sid, not bool(s["active"]))
        return RedirectResponse("/ui/skills", status_code=303)

    @r.post("/ui/actions/skill/bulk-toggle")
    def act_skill_bulk_toggle(csrf: str = Form(""), active: str = Form("1"), skill_ids: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf)
        ids = [int(x) for x in skill_ids.split(",") if x.strip()]
        for sid in ids:
            toggle_skill_active(c.conn, sid, active == "1")
        return RedirectResponse("/ui/skills", status_code=303)

    @r.post("/ui/actions/skill/bulk-delete")
    def act_skill_bulk_delete(csrf: str = Form(""), skill_ids: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf)
        ids = [int(x) for x in skill_ids.split(",") if x.strip()]
        for sid in ids:
            delete_skill(c.conn, sid)
        return RedirectResponse("/ui/skills", status_code=303)

    @r.post("/ui/actions/skill/{sid}/delete")
    def act_skill_delete(sid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf)
        delete_skill(c.conn, sid)
        return RedirectResponse("/ui/skills", status_code=303)

    @r.post("/ui/actions/reset")
    def act_reset(csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        counts = reset(c.conn)
        with tx(c.conn):
            audit(c.conn, c.who.actor, "ui.reset", "all", {"counts": counts}, c.who.workspace_id)
        return RedirectResponse("/ui", status_code=303)

    @r.get("/ui/system")
    def system_moved():
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    @r.post("/ui/actions/system-config/enable")
    def act_system_enable(csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        set_setting(c.conn, "worker_enabled", "1")
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    @r.post("/ui/actions/system-config/disable")
    def act_system_disable(csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        set_setting(c.conn, "worker_enabled", "0")
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    @r.post("/ui/actions/job-schedule/create")
    def act_schedule_create(
        csrf: str = Form(""),
        name: str = Form(""),
        job_type: str = Form(""),
        interval_seconds: str = Form(""),
        c: Ctx = Depends(user),
    ):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        name = name.strip()
        job_type = job_type.strip()
        iv = (interval_seconds or "").strip()
        if not name or not job_type or not iv.isdigit() or int(iv) < 60:
            raise HTTPException(400, "Invalid input: name, type, and interval (minimum 60 seconds) are required")
        if job_type not in {"cve_sync", "analysis", "manual_cve_sync", "manual_analysis", "report_export"}:
            raise HTTPException(400, "Job type unknown")
        create_job_schedule(c.conn, name, job_type, int(iv), enabled=True)
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    @r.post("/ui/actions/job-schedule/{sid}/toggle")
    def act_schedule_toggle(sid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        s = get_job_schedule(c.conn, sid)
        if s is None:
            raise HTTPException(404, "Schedule not found")
        set_job_schedule_enabled(c.conn, sid, not bool(s["enabled"]))
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    @r.post("/ui/actions/job-schedule/{sid}/run")
    def act_schedule_run(sid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        s = get_job_schedule(c.conn, sid)
        if s is None:
            raise HTTPException(404, "Schedule not found")
        from riskpatch.jobs import enqueue
        enqueue(c.conn, s["job_type"], "ui", {}, c.who.workspace_id,
                dedupe_key=f"manual:{sid}:{now_iso()}")
        set_job_schedule_last_run(c.conn, sid, now_iso())
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    @r.post("/ui/actions/job-schedule/{sid}/delete")
    def act_schedule_delete(sid: int, csrf: str = Form(""), c: Ctx = Depends(user)):
        if not c.who.has("admin"):
            raise HTTPException(403, "admin scope required")
        check_csrf(c, csrf, "admin")
        delete_job_schedule(c.conn, sid)
        return RedirectResponse("/ui/coverage?tab=tech", status_code=303)

    return r
