"""Regenerates 'Neo — Remediation Layer' (page 3 of 3) as HTML for headless rendering.

Paths A and B and the headers reproduce the original diagram; Path C is redesigned so the
compensating controls travel the ServiceNow change path: CAB approval, then a person implements.
"""
import html
import sys

if len(sys.argv) < 2:
    sys.exit("usage: python remediation_layer.py OUT.html [INTER.woff2]")
OUT = sys.argv[1]
FONT = sys.argv[2] if len(sys.argv) > 2 else None   # optional; falls back to the system sans-serif

# Palette sampled from the original PNG.
TEAL, TEAL_BG = "#01A88D", "#DDF3EE"
SLATE, SLATE_BG = "#3F5873", "#EBF0F6"
RED = "#DD344C"
DARK = "#232F3E"
ORANGE = "#ED7100"
MAGENTA = "#C925D1"
GREEN = "#7AA116"
BLUE_DEEP = "#0B6E8A"
ARROW = "#4A5361"
GRAY = "#5B6570"
CARD_BORDER = "#D3D9DF"

els, lines = [], []


def esc(s):
    return html.escape(s, quote=False)


def rich(s):
    """**bold** markup -> html"""
    out, parts = "", esc(s).split("**")
    for i, p in enumerate(parts):
        out += f"<b>{p}</b>" if i % 2 else p
    return out


def box(x, y, w, h, cls="", style="", inner=""):
    els.append(f'<div class="b {cls}" style="left:{x}px;top:{y}px;width:{w}px;height:{h}px;{style}">{inner}</div>')


def text(x, y, s, size=12, color=GRAY, weight=400, w=None, align="left", lh=None, extra="", raw=False):
    width = f"width:{w}px;" if w else "white-space:nowrap;"
    lhs = f"line-height:{lh}px;" if lh else ""
    els.append(f'<div class="t" style="left:{x}px;top:{y}px;{width}font-size:{size}px;color:{color};'
               f'font-weight:{weight};text-align:{align};{lhs}{extra}">{s if raw else rich(s)}</div>')


def icon(x, y, label, color, w=36, h=36, size=10):
    els.append(f'<div class="ic" style="left:{x}px;top:{y}px;width:{w}px;height:{h}px;background:{color};'
               f'font-size:{size}px">{esc(label)}</div>')


def card(x, y, w, h, ic, ic_color, title, body, border=CARD_BORDER, bw=1, bg="#fff", ic_size=10,
         ic_w=36, ic_h=36):
    box(x, y, w, h, style=f"border:{bw}px solid {border};background:{bg};border-radius:8px")
    ix = x + 12
    if ic:
        icon(ix, y + (h - ic_h) // 2, ic, ic_color, ic_w, ic_h, ic_size)
        tx = ix + ic_w + (8 if ic_w < 36 else 11)
    else:
        tx = x + 14
    ty = y + (h - (19 + 18 * len(body))) // 2
    text(tx, ty, title, 14, "#1B2430", 700)
    for i, line in enumerate(body):
        text(tx, ty + 21 + 18 * i, line, 13, "#5A6470")


def vline(x, y1, y2, color=ARROW, head=True):
    lines.append(f'<line x1="{x}" y1="{y1}" x2="{x}" y2="{y2 - (7 if head else 0)}" stroke="{color}" stroke-width="2"/>')
    if head:
        lines.append(f'<polygon points="{x-5},{y2-8} {x+5},{y2-8} {x},{y2}" fill="{color}"/>')


def hline(y, x1, x2, color=ARROW, head=True):
    lines.append(f'<line x1="{x1}" y1="{y}" x2="{x2 - (7 if head else 0)}" y2="{y}" stroke="{color}" stroke-width="2"/>')
    if head:
        lines.append(f'<polygon points="{x2-8},{y-5} {x2-8},{y+5} {x2},{y}" fill="{color}"/>')


def arrow(x, y1, y2, label="", color=ARROW, label_color=GRAY):
    vline(x, y1, y2, color)
    if label:
        text(x + 12, (y1 + y2) // 2 - 8, label, 13, label_color)


# ---------------------------------------------------------------- header
text(64, 47, "Neo — Remediation Layer", 30, DARK, 700)
box(470, 54, 118, 26, style=f"border:1px solid {RED};border-radius:13px;background:#fff")
text(470, 59, "TARGET DESIGN", 11.5, RED, 700, w=118, align="center")
text(64, 94, "Page 3 of 3 · three kinds of fix, three delivery paths · the model proposes, humans approve, "
             "people or code execute, the scanner verifies", 15, "#6B7280")
for i, (col, lab, desc) in enumerate([(SLATE, "Deterministic", "code, rules, queues"),
                                      (TEAL, "Judgment", "LLM agents over MCP"),
                                      (RED, "Human gate", "approval required")]):
    y = 57 + 28 * i
    box(1440, y - 8, 15, 15, style=f"border:2px solid {col};border-radius:3px;background:#fff")
    text(1466, y - 9, f"**{lab}** — {desc}", 13, "#2B3440")

# ---------------------------------------------------------------- top row
box(64, 170, 299, 79, style=f"border:2px solid {TEAL};background:{TEAL_BG};border-radius:8px")
text(80, 192, "← Layer 2: Neo agent", 14, "#1B2430", 700)
text(80, 211, "remediation_plan · fixed_version", 13, "#0A7F6B")
hline(210, 363, 645, TEAL)
text(380, 186, "proposed fix", 13, TEAL)

box(645, 170, 518, 79, style=f"border:2px solid {SLATE};background:{SLATE_BG};border-radius:8px")
icon(657, 197, "RULE", "#545B64", 28, 26, 8.5)
text(692, 185, "**Deterministic router (code)** · fix type from scanner data", 13, "#3A4452")
text(692, 202, "dependency / image / IaC → A · host OS or installed software with", 13, "#3A4452")
text(692, 218, "fixed_version → B · no fixed_version → C", 13, "#3A4452")

box(1478, 170, 257, 79, style=f"border:2px solid {SLATE};background:{SLATE_BG};border-radius:8px")
text(1494, 192, "Layer 1: where findings close", 14, "#1B2430", 700)
text(1494, 211, "re-scan · close-out rule", 13, "#5A6470")

lines.append(f'<line x1="904" y1="249" x2="904" y2="275" stroke="{ARROW}" stroke-width="2"/>')
lines.append(f'<line x1="324" y1="275" x2="1480" y2="275" stroke="{ARROW}" stroke-width="2"/>')
for cx in (324, 904, 1480):
    vline(cx, 275, 300)

# ---------------------------------------------------------------- panels
PANEL_TOP, PANEL_BOT = 300, 1360
box(64, PANEL_TOP, 519, PANEL_BOT - PANEL_TOP, style=f"border:2px solid {DARK};background:#F7F9F9;border-radius:6px")
text(80, 312, "Path A · Code & images → GitHub MCP server", 13, "#2E3E4E", 700)
box(625, PANEL_TOP, 558, PANEL_BOT - PANEL_TOP, style=f"border:2px solid {SLATE};background:#F4F7FA;border-radius:6px")
text(641, 312, "Path B · Servers → ServiceNow change → update managers", 13, "#2F4A66", 700)
box(1225, PANEL_TOP, 510, PANEL_BOT - PANEL_TOP, style=f"border:2px solid #B0640A;background:#FFF8F0;border-radius:6px")
text(1241, 312, "Path C · No vendor patch yet → risk exception → ServiceNow change", 13, "#8A4B08", 700)

# ---------------------------------------------------------------- Path A
AX, AW, AC = 88, 471, 324
card(AX, 350, AW, 95, "AI", TEAL, "Neo agent drafts the fix",
     ["bumps the package to fixed_version in pom.xml,", "requirements.txt,",
      "package.json, a Dockerfile base image or a Terraform AMI"], border="#7FD0C2")
arrow(AC, 445, 487, "Neo finding ID in PR body")
card(AX, 487, AW, 110, "GH", "#1F2430", "GitHub MCP server",
     ["create_branch · push_files · create_pull_request", "fine-grained token · repo allowlist",
      "no merge permission"], border="#111", bw=2)
arrow(AC, 597, 638)
card(AX, 638, AW, 79, "CI", SLATE, "GitHub Actions CI", ["build · unit tests · dependency re-scan"])
arrow(AC, 717, 759, "PR ready for review")
card(AX, 759, AW, 94, "HUM", RED, "Code-owner review",
     ["CODEOWNERS approve and merge", "branch protection: the agent cannot merge"], border=RED, bw=2)
arrow(AC, 853, 894)
card(AX, 894, AW, 79, "CD", SLATE, "CD pipeline", ["rebuild image · redeploy service"])
box(AX, 1014, AW, 179, style="border:1.5px dashed #AEB6BE;border-radius:8px;background:#fff")
text(104, 1028, "Why the GitHub MCP server", 13.5, "#1B2430", 700)
for i, l in enumerate(["• A maintained, standard tool surface instead of custom REST code",
                       "• Token scope and repo allowlist limit what the agent can touch",
                       "• Each PR links back to the finding ID — an auditable record"]):
    text(104, 1049 + 18 * i, l, 13, "#3A4452")

# ---------------------------------------------------------------- Path B
BX, BW, BC = 649, 511, 904
card(BX, 350, BW, 95, "AI", TEAL, "Neo agent drafts the change",
     ["instance IDs · patch (KB or package @ fixed_version)", "maintenance window · test evidence"], border="#7FD0C2")
arrow(BC, 445, 487)
card(BX, 487, BW, 94, "CHG", SLATE, "ServiceNow change request",
     ["created via ServiceNow MCP / Table API", "CIs from the CMDB · change risk set from the tier"])
arrow(BC, 581, 622, "rollback plan attached")
card(BX, 622, BW, 119, None, None, "Rollback steps (written into the change)",
     ["1 · EBS snapshot / VM checkpoint before patching", "2 · uninstall the KB, or yum / dnf history undo",
      "3 · restore the snapshot if the health check fails"])
arrow(BC, 741, 782)
card(BX, 782, BW, 95, "HUM", RED, "CAB approval",
     ["normal change → CAB · P1 → emergency CAB", "low-risk patch groups → pre-approved standard change"], border=RED, bw=2)
arrow(BC, 877, 918, "approved → Implement", RED, RED)
card(BX, 918, BW, 95, "λ", ORANGE, "Patch executor (code, no model)",
     ["runs only if: state = Implement · inside the window · host", "on the approved CI list · re-checked after the snapshot"],
     ic_size=19)
arrow(BC, 1013, 1054, "exact instance IDs")
card(BX, 1054, BW, 95, "UPD", SLATE, "Update managers",
     ["AWS SSM Patch Manager · Azure Update Manager", "GCP VM Manager · WSUS / MECM · Red Hat Satellite"])
arrow(BC, 1149, 1190, "vendor repos · yum / apt / WSUS")
card(BX, 1190, BW, 95, "λ", ORANGE, "Post-patch health check (code)",
     ["healthy → DEPLOYED · change closes after a clean re-scan", "unhealthy → roll back · change closed unsuccessful"], ic_size=19)

# ---------------------------------------------------------------- Path C (redesigned)
CX, CW, CC = 1249, 462, 1480
CH, GAP = 80, 28
y = 350
# (icon, colour, title, body lines, card style, label on the arrow AFTER this card)
rows = [
    ("AI", TEAL, "Neo agent composes the controls",
     ["no vendor fix yet · picks controls from the catalog", "previews score and tier · proposes the tag to set"],
     dict(border="#7FD0C2"), "proposal · before / after score"),
    ("HUM", RED, "Risk owner approves",
     ["time-limited exception · named owner", "expiry capped by tier"], dict(border=RED, bw=2), "approved exception ID"),
    ("CHG", SLATE, "ServiceNow change request",
     ["implementation: apply the controls · set the tag", "rollback plan · CIs from the CMDB · exception ID"], {},
     "rollback plan attached"),
    ("HUM", RED, "CAB approval",
     ["normal change → CAB · P1 → emergency CAB", "the agent cannot approve"], dict(border=RED, bw=2),
     "approved → Implement"),
    ("HUM", RED, "Manual implementation (no executor)",
     ["change implementer applies the controls and sets the tag", "records evidence · closes the change"], {},
     "controls in place"),
    ("CTX", SLATE, "Layer 1 rescores",
     ["tag lists control IDs · code computes the weight", "exposure factor drops · tier may fall (KEV + public: P1)"], {},
     "exception runs until expiry"),
    ("λ", ORANGE, "Expiry watch (code)",
     ["vendor fix appears on a scan → re-route to A or B", "exception expires → finding reopens"], {}, ""),
]
for i, (ic, col, title, body, kw, after) in enumerate(rows):
    card(CX, y, CW, CH, ic, col, title, body, ic_size=19 if ic == "λ" else 10, **kw)
    if i < len(rows) - 1:
        hot = after.startswith("approved →")
        arrow(CC, y + CH, y + CH + GAP, after, RED if hot else ARROW, RED if hot else GRAY)
    y += CH + GAP
gy = y - GAP + 20
box(CX, gy, CW, 190, style="border:1px solid #BFD3EA;border-radius:8px;background:#F1F7FD")
text(CX + 14, gy + 12, "Governed AI Autonomy", 13.5, "#17479E", 700)
gov = [
    "**Controlled** — routing, patch execution and close-out are code; the agent never patches a server, "
    "merges a PR or approves a change.",
    "**Observable** — every finding carries its PR, change or exception ID.",
    "**Evaluable** — closure needs scan evidence; SLA met or missed is recorded per finding.",
    "**Auditable** — PR review history, change record with CAB approval, exception with expiry.",
]
text(CX + 14, gy + 34, "<br>".join(rich(g) for g in gov), 12.5, "#2B3440", w=CW - 28, lh=17, raw=True)

# ---------------------------------------------------------------- exits to Layer 1
arrow(324, PANEL_BOT, 1420, "deployed")
arrow(904, PANEL_BOT, 1420, "patched")
arrow(1480, PANEL_BOT, 1420, "controls implemented")

box(64, 1420, 1671, 199, style=f"border:2px solid {GREEN};background:{SLATE_BG};border-radius:6px")
text(80, 1431, "Back in Layer 1 · deterministic verification — a finding closes on scan evidence, not on “job succeeded”",
     13, "#5C7F12", 700)
BY, BH = 1477, 103
card(98, BY, 319, BH, "SCN", SLATE, "Targeted re-scan",
     ["trigger_scan for the fixed resources", "plus the next scheduled scan"])
hline(1528, 417, 479)
card(479, BY, 378, BH, "RULE", "#545B64", "Close-out rule (code)",
     ["absent on re-scan → **REMEDIATED**", "still present after the window → reopen + escalate"],
     border=SLATE, bw=2, bg=SLATE_BG, ic_size=8, ic_w=27, ic_h=24)
hline(1528, 857, 919)
card(919, BY, 318, BH, "DDB", MAGENTA, "Findings updated",
     ["status · remediated_at", "evidence: scan_id · PR / CHG number"], border=BLUE_DEEP, bw=2, bg="#E6F3F7")
hline(1528, 1237, 1299)
card(1299, BY, 398, BH, "SLA", SLATE, "Posture and SLA",
     ["risk summary drops · SLA met or missed", "next posture briefing reflects the fix"])

page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
{f"@font-face {{ font-family: Inter; src: url('{FONT}') format('woff2'); font-weight: 400 700; }}" if FONT else ""}
html,body {{ margin:0; background:#fff; }}
body {{ width:1800px; height:1680px; position:relative; font-family: Inter, 'Segoe UI', sans-serif; overflow:hidden; }}
.b {{ position:absolute; box-sizing:border-box; }}
.t {{ position:absolute; line-height:1.2; }}
.t b {{ font-weight:700; color:#1B2430; }}
.ic {{ position:absolute; border-radius:6px; color:#fff; font-weight:700; display:flex; align-items:center; justify-content:center; }}
svg {{ position:absolute; left:0; top:0; }}
</style></head><body>
{''.join(els)}
<svg width="1800" height="1680">{''.join(lines)}</svg>
</body></html>"""
open(OUT, "w", encoding="utf-8").write(page)
