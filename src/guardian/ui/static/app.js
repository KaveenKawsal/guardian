// Guardian review console. Every value from the API is attacker-controlled text (package
// names, advisories, commit messages, Jira comments): it is only ever written with
// textContent / setAttribute on elements created here. Nothing is parsed as HTML.
"use strict";

(() => {
  const LIVE_POLL_MS = 2500;
  const IDLE_POLL_MS = 10000;
  const LIST_POLL_MS = 5000;
  const TOKEN_KEY = "guardian-ui-token";

  const PRIORITY_NAMES = { P1: "Critical", P2: "High", P3: "Medium", P4: "Low" };
  const STATUS_WORDS = {
    PROPOSED: "Proposed",
    AWAITING_DECISION: "Waiting for your decision",
    APPROVED: "Approved, queued to apply",
    MODIFICATION_REQUESTED: "Change requested, queued to apply",
    APPLYING: "Applying in an isolated branch",
    VALIDATING: "Building and testing in the sandbox",
    VERIFIED: "Verified",
    VALIDATION_FAILED: "Validation failed, back to review",
    DECLINED: "Declined",
    CLOSED: "Closed",
  };
  const STATUS_TONE = {
    AWAITING_DECISION: "gate",
    APPROVED: "live",
    MODIFICATION_REQUESTED: "live",
    APPLYING: "live",
    VALIDATING: "live",
    VERIFIED: "go",
    VALIDATION_FAILED: "stop",
    DECLINED: "stop",
  };
  const REASONS = [
    ["accepted_risk", "Accepted risk (needs an expiry date)"],
    ["false_positive", "False positive"],
    ["wont_fix", "Won't fix"],
    ["duplicate", "Duplicate"],
  ];
  const FACTOR_NAMES = {
    severity: "Severity",
    exposure: "Exposure",
    exploitability: "Exploitability",
    reachability: "Reachability",
    fix: "Fix availability",
  };

  const state = {
    token: null,
    cases: [],
    selected: null,
    detail: null,
    detailJson: "",
    lastCurrent: null,
    chosenCandidate: null,
    timer: null,
    health: null,
    audit: null,
    view: "cases",
    arch: null,
    archJson: "",
    archSelected: null,
    codebase: null,
    codebaseRun: null,
  };

  // --- DOM helpers (text only) -----------------------------------------------------------

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") el.className = value;
        else if (key === "text") el.textContent = String(value);
        else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
        else if (key === "dataset") Object.assign(el.dataset, value);
        else el.setAttribute(key, value === true ? "" : String(value));
      }
    }
    append(el, children);
    return el;
  }

  function append(el, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  function safeLink(url, label) {
    // Only http(s) links; anything else (javascript:, data:) is shown as plain text.
    let parsed = null;
    try {
      parsed = new URL(String(url));
    } catch {
      parsed = null;
    }
    if (!parsed || (parsed.protocol !== "https:" && parsed.protocol !== "http:")) {
      return h("span", { class: "code", text: label || String(url) });
    }
    return h("a", { href: parsed.href, target: "_blank", rel: "noopener noreferrer", text: label || parsed.href });
  }

  function code(text) {
    return h("code", { text });
  }

  function when(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function num(value, digits = 1) {
    return typeof value === "number" ? value.toFixed(digits) : "unknown";
  }

  function toast(text) {
    const el = document.getElementById("toast");
    el.textContent = text;
    el.classList.add("show");
    window.clearTimeout(toast.timer);
    toast.timer = window.setTimeout(() => el.classList.remove("show"), 5000);
  }

  // --- token and API -----------------------------------------------------------------------

  function loadToken() {
    const params = new URLSearchParams(window.location.search);
    const fromUrl = params.get("token");
    if (fromUrl) {
      try {
        window.sessionStorage.setItem(TOKEN_KEY, fromUrl);
      } catch {
        /* storage blocked: keep it in memory only */
      }
      // Drop the token from the address bar and history.
      window.history.replaceState(null, "", window.location.pathname + window.location.hash);
      return fromUrl;
    }
    try {
      return window.sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  }

  async function api(path, options = {}) {
    const headers = { "X-Guardian-Token": state.token || "" };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      cache: "no-store",
      credentials: "omit",
    });
    let data = null;
    try {
      data = await response.json();
    } catch {
      data = { error: `Unexpected response (${response.status}).` };
    }
    return { status: response.status, ok: response.ok, data };
  }

  // --- header, banner ------------------------------------------------------------------------

  function renderTop() {
    const el = document.getElementById("top-status");
    const parts = [];
    if (state.health) {
      parts.push(h("span", { text: state.health.jira_configured ? "Jira configured" : "Jira not configured" }));
    }
    if (state.audit) {
      parts.push(
        state.audit.ok
          ? h("span", { class: "ok", text: `Audit chain intact (${state.audit.events} events)` })
          : h("span", { class: "bad", text: "Audit chain broken" }),
      );
    }
    el.replaceChildren(...parts);

    const banner = document.getElementById("banner");
    const jira = state.health && state.health.jira_configured;
    banner.textContent =
      (jira
        ? "Use this console when Jira is unavailable. "
        : "Jira is not configured on this machine. ") +
      'Decisions you record here are stored locally with channel "cli", checked against ' +
      "GUARDIAN_CLI_APPROVERS, parsed by the same /guardian grammar as Jira comments, and " +
      "written to the audit trail.";
  }

  // --- case list -------------------------------------------------------------------------------

  function renderList() {
    const root = document.getElementById("case-list");
    if (!state.cases.length) {
      root.replaceChildren(h("p", { class: "quiet", text: "No cases yet." }));
      return;
    }
    const groups = new Map();
    for (const c of state.cases) {
      if (!groups.has(c.priority)) groups.set(c.priority, []);
      groups.get(c.priority).push(c);
    }
    const sections = [];
    for (const [priority, cases] of [...groups.entries()].sort()) {
      const items = cases.map((c) => {
        const li = h("li", {
          class: "case-item" + (c.jira_key ? " has-jira" : ""),
          "aria-current": c.id === state.selected ? "true" : "false",
        });
        li.append(
          h(
            "button",
            { class: "case-button", type: "button", onclick: () => select(c.id) },
            h("span", { class: "case-title", text: c.title }),
            h(
              "span",
              { class: "case-meta" },
              h("span", { class: "chip", dataset: { tone: STATUS_TONE[c.status] || "" }, text: statusWords(c) }),
            ),
          ),
        );
        if (c.jira_key) {
          li.append(c.jira_url ? safeLink(c.jira_url, c.jira_key) : h("span", { text: c.jira_key }));
          li.lastChild.classList.add("case-jira");
        }
        return li;
      });
      sections.push(
        h(
          "section",
          { class: "group" },
          h("h3", { text: PRIORITY_NAMES[priority] || priority }),
          h("ul", { class: "case-items" }, items),
        ),
      );
    }
    root.replaceChildren(...sections);
  }

  function statusWords(c) {
    if (c.decision_pending && c.status === "AWAITING_DECISION") return "Decision recorded, moving on";
    return STATUS_WORDS[c.status] || c.status;
  }

  function renderEmpty() {
    document.getElementById("case-detail").replaceChildren(
      h(
        "div",
        { class: "empty" },
        h("h2", { text: "No remediation cases yet" }),
        h("p", { text: "Scan a repository, then create cases from its prioritized findings:" }),
        h("span", { class: "command", text: "guardian scan <path>" }),
        h("span", { class: "command", text: "guardian remediate latest" }),
        h("p", { class: "quiet", text: "This page refreshes on its own; new cases appear on the left." }),
      ),
    );
  }

  // --- route map ---------------------------------------------------------------------------------

  function renderRoute(detail) {
    const journey = detail.journey;
    const ol = h("ol", { class: "route", "aria-label": "Where this case is in the remediation flow" });
    const keys = journey.stations.map((s) => s.key);
    const current = journey.stations.find((s) => s.state === "current" || s.state === "failed");
    for (const station of journey.stations) {
      const li = h("li", {
        class: "station",
        dataset: { key: station.key, state: station.state },
        "aria-current": station === current ? "step" : null,
      });
      li.append(h("span", { class: "dot", "aria-hidden": "true" }));
      li.append(h("span", { class: "station-name", text: station.label }));
      if (station.state === "current") li.append(h("span", { class: "station-now", text: "Now" }));
      else if (station.state === "failed") li.append(h("span", { class: "station-now", text: "Failed here" }));
      else if (station.state === "skipped") li.append(h("span", { class: "station-when", text: "Not run" }));
      if (station.at && station.state !== "pending" && station.state !== "skipped") {
        li.append(h("span", { class: "station-when", text: when(station.at) }));
      }
      if (station.note && station.state !== "pending") {
        li.append(h("span", { class: "station-note", text: station.note }));
      }
      if (current && station === current && state.lastCurrent && state.lastCurrent !== `${detail.case.id}:${station.key}:${station.state}`) {
        li.classList.add("arrived");
      }
      ol.append(li);
    }
    state.lastCurrent = current ? `${detail.case.id}:${current.key}:${current.state}` : null;

    const decisionCol = keys.indexOf("decision") + 1;
    if (journey.branch) {
      const b = journey.branch;
      const accepted = b.reason === "ACCEPTED_RISK";
      const title = accepted
        ? `Risk accepted${b.until ? ` until ${b.until}` : ""}`
        : `Declined: ${(b.reason || "no reason").toLowerCase().replace(/_/g, " ")}`;
      const spur = h(
        "li",
        { class: "spur" },
        h("span", { class: "spur-text" }, h("strong", { text: title }), b.justification ? b.justification : "No change applied."),
      );
      const span = 2;
      spur.style.gridColumn = `${decisionCol} / span ${span}`;
      spur.style.marginLeft = `calc(${50 / span}% - 3px)`;
      ol.append(spur);
    }
    if (journey.loop_back) {
      const failedIndex = journey.stations.findIndex((s) => s.state === "failed");
      const end = failedIndex >= 0 ? failedIndex + 1 : keys.indexOf("verified") + 1;
      const span = Math.max(end - decisionCol + 1, 2);
      const attempts = journey.failed_attempts;
      const loop = h(
        "li",
        { class: "loop" },
        h("strong", { text: "Back to review" }),
        attempts > 0 ? ` after ${attempts} failed attempt${attempts === 1 ? "" : "s"}` : "",
      );
      loop.style.gridColumn = `${decisionCol} / span ${span}`;
      loop.style.marginLeft = `calc(${50 / span}% - 3px)`;
      loop.style.marginRight = `calc(${50 / span}% - 3px)`;
      ol.append(loop);
    }

    const wrap = h("div", { class: "route-wrap" }, ol);
    if (journey.notes && journey.notes.length) {
      wrap.append(h("div", { class: "route-notes" }, journey.notes.map((n) => h("p", { text: n }))));
    }
    return wrap;
  }

  // --- sections ----------------------------------------------------------------------------------

  function section(title, tag, ...body) {
    return h(
      "section",
      { class: "section" },
      h("div", { class: "section-head" }, h("h2", { text: title }), tag || null),
      body,
    );
  }

  function verifiedTag() {
    return h("span", { class: "tag verified", text: "Verified" });
  }

  function facts(pairs) {
    const dl = h("dl", { class: "facts" });
    for (const [label, value] of pairs) {
      if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) continue;
      dl.append(h("dt", { text: label }), h("dd", {}, value instanceof Node ? value : String(value)));
    }
    return dl;
  }

  function renderFindings(detail) {
    const items = detail.findings.map((f) => {
      if (f.missing) {
        return h("div", { class: "finding" }, h("p", { class: "quiet", text: `Finding ${f.id} is not in the stored scan.` }));
      }
      const d = f.details || {};
      const pairs = [
        ["Severity", f.severity],
        ["Tool", f.tool],
      ];
      if (d.kind === "vulnerability") {
        pairs.push(
          ["Advisory", d.vulnerability_id],
          ["Also known as", (d.aliases || []).join(", ")],
          ["Package", code(`${d.package}${d.version ? "@" + d.version : ""}`)],
          ["Fixed in", (d.fixed_versions || []).join(", ")],
          ["CVSS", d.cvss_score],
          ["Summary", d.summary],
        );
      } else if (d.kind === "code") {
        pairs.push(["Rule", d.rule_id], ["Message", d.message]);
      } else if (d.kind === "change") {
        pairs.push(["Category", d.category], ["Commit", d.commit ? code(d.commit.slice(0, 12)) : null], ["Subject", d.subject]);
      }
      if (f.path) pairs.push(["Location", code(`${f.path}${f.start_line ? ":" + f.start_line : ""}`)]);
      const evidence = (f.evidence || []).map((e) => {
        const src = [e.tool, e.path ? `${e.path}${e.line ? ":" + e.line : ""}` : null, e.commit ? e.commit.slice(0, 12) : null]
          .filter(Boolean)
          .join(", ");
        return h("li", {}, e.summary, h("span", { class: "src" }, src, e.url ? " " : null, e.url ? safeLink(e.url, "source") : null));
      });
      return h(
        "div",
        { class: "finding" },
        h("h3", { text: f.title }),
        facts(pairs),
        evidence.length ? h("ul", { class: "evidence", "aria-label": "Evidence" }, evidence) : null,
      );
    });
    return section("Finding and evidence", verifiedTag(), items.length ? items : h("p", { class: "quiet", text: "No findings attached." }));
  }

  function renderRisk(detail) {
    if (!detail.risk.length) {
      return section("Risk factors", null, h("p", { class: "quiet", text: detail.risk_note || "No risk assessment." }));
    }
    const blocks = detail.risk.map((r) => {
      const rows = r.factors.map((f) =>
        h(
          "tr",
          {},
          h("td", { text: FACTOR_NAMES[f.name] || f.name }),
          h(
            "td",
            { class: "num" },
            typeof f.value === "number" ? h("span", { class: "meter", "aria-hidden": "true" }, meterFill(f.value)) : null,
            typeof f.value === "number" ? f.value.toFixed(2) : "unknown",
          ),
          h("td", { class: "num", text: f.weight.toFixed(2) }),
          h("td", { text: f.rationale }),
        ),
      );
      return h(
        "div",
        {},
        h("p", {}, h("strong", { text: `Score ${num(r.score)} (${r.priority}, ${r.confidence} confidence). ` }), r.summary),
        h(
          "div",
          { class: "table-scroll" },
          h(
            "table",
            {},
            h("thead", {}, h("tr", {}, h("th", { text: "Factor" }), h("th", { class: "num", text: "Value" }), h("th", { class: "num", text: "Weight" }), h("th", { text: "Basis" }))),
            h("tbody", {}, rows),
          ),
        ),
      );
    });
    return section("Risk factors", verifiedTag(), blocks);
  }

  function meterFill(value) {
    const span = h("span");
    span.style.width = `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
    return span;
  }

  function candidateTitle(c) {
    const target = c.target_package || c.component;
    const versions = c.from_version || c.to_version ? ` ${c.from_version || "?"} to ${c.to_version || "?"}` : "";
    return `${c.action_type.toLowerCase().replace(/_/g, " ")} ${target}${versions}`;
  }

  function renderCandidates(detail, canDecide) {
    if (!detail.candidates.length) {
      return section("Fix options", null, h("p", { class: "quiet", text: "Guardian found no fix options for this case." }));
    }
    const items = detail.candidates.map((c) => {
      const selected = state.chosenCandidate === c.id;
      const li = h("li", {
        class: "candidate" + (c.recommended ? " is-recommended" : "") + (selected ? " is-selected" : ""),
      });
      const head = h(
        "div",
        { class: "candidate-head" },
        h("span", { class: "candidate-title", text: candidateTitle(c) }),
        c.recommended ? h("span", { class: "tag recommended", text: "Recommended" }) : null,
      );
      if (canDecide) {
        const input = h("input", {
          type: "radio",
          name: "candidate",
          value: c.id,
          checked: selected,
          onchange: () => {
            state.chosenCandidate = c.id;
            renderDetail(true);
          },
        });
        head.append(h("label", { class: "pick" }, input, "Select"));
      }
      li.append(head);
      const verified = c.version_verified === true ? "confirmed in the registry" : c.version_verified === false ? "not confirmed (registry unreachable)" : null;
      li.append(
        facts([
          ["Candidate", code(c.id)],
          ["Semver jump", c.semver_jump],
          ["Risk reduction", typeof c.expected_risk_reduction === "number" ? `${c.expected_risk_reduction.toFixed(1)} points` : "unknown"],
          ["Target version", verified],
          ["Strategy", c.strategy],
          ["Rollback", c.rollback ? code(c.rollback) : null],
        ]),
      );
      if (c.compatibility_notes && c.compatibility_notes.length) {
        li.append(h("ul", { "aria-label": "Compatibility notes" }, c.compatibility_notes.map((n) => h("li", { text: n }))));
      }
      return li;
    });
    return section("Fix options", verifiedTag(), h("ul", { class: "candidates" }, items));
  }

  function renderPlan(detail) {
    const plan = detail.plan;
    if (!plan) return null;
    const inferred = plan.source === "inferred";
    const chosen = detail.candidates.find((c) => c.id === plan.chosen_candidate_id);
    const body = [
      h("p", {}, "Recommends ", code(plan.chosen_candidate_id), chosen ? ` (${candidateTitle(chosen)})` : "", "."),
      h("p", { class: inferred ? "rationale" : "", text: plan.rationale }),
      facts([
        ["Confidence", plan.confidence],
        ["Model", inferred ? [plan.llm_provider, plan.llm_model].filter(Boolean).join(" / ") : null],
        ["Notes", (plan.notes || []).join("; ")],
      ]),
    ];
    if (inferred) {
      return h(
        "section",
        { class: "section" },
        h(
          "div",
          { class: "inference" },
          h("div", { class: "section-head" }, h("h2", { text: "Guardian's assessment (AI inference)" }), h("span", { class: "tag inferred", text: "Inferred" })),
          h("p", { class: "small quiet", text: "An AI model picked from the fix options above and explained why. It cannot add options or decide for you." }),
          body,
        ),
      );
    }
    return section("Guardian's selection (deterministic rule)", verifiedTag(), h("div", { class: "deterministic" }, body));
  }

  function renderDecisions(detail) {
    if (!detail.decisions.length) return null;
    const rows = detail.decisions.map((d) => {
      let what = d.decision.toLowerCase();
      if (d.candidate_id) what += ` candidate ${d.candidate_id}`;
      if (d.modify) {
        const kind = Object.keys(d.modify).find((k) => d.modify[k] !== null && k !== "target");
        if (kind) what += ` ${kind}=${d.modify[kind]}`;
      }
      if (d.decline_reason) what += ` (${d.decline_reason.toLowerCase().replace(/_/g, " ")})`;
      if (d.risk_acceptance_expires) what += ` until ${d.risk_acceptance_expires}`;
      return h(
        "tr",
        {},
        h("td", { text: when(d.decided_at) }),
        h("td", { text: what }),
        h("td", { text: d.actor_display }),
        h("td", { text: d.channel }),
        h("td", { text: d.justification || "" }),
      );
    });
    return section(
      "Decisions",
      null,
      h(
        "div",
        { class: "table-scroll" },
        h(
          "table",
          {},
          h("thead", {}, h("tr", {}, ["When", "Decision", "By", "Channel", "Justification"].map((t) => h("th", { text: t })))),
          h("tbody", {}, rows),
        ),
      ),
    );
  }

  function renderValidations(detail) {
    if (!detail.validations.length) {
      return section("Build and test", null, h("p", { class: "quiet", text: "Runs after a fix is approved and applied in an isolated branch." }));
    }
    const runs = detail.validations
      .slice()
      .reverse()
      .map((run, i) => {
        const rows = run.steps.map((s) =>
          h(
            "tr",
            {},
            h("td", { text: s.name }),
            h("td", {}, h("span", { class: "step-status", dataset: { status: s.status }, text: s.status.replace(/_/g, " ") })),
            h("td", { class: "num", text: s.exit_code === null || s.exit_code === undefined ? "" : String(s.exit_code) }),
            h("td", { class: "num", text: `${Number(s.duration_seconds || 0).toFixed(1)} s` }),
            h(
              "td",
              {},
              s.known_conflict ? h("span", { class: "tag conflict", text: "Fix conflicts with intentional challenge code" }) : null,
              s.known_conflict && s.detail ? " " : null,
              s.detail || "",
            ),
          ),
        );
        const tests =
          run.tests_discovered === null || run.tests_discovered === undefined
            ? null
            : `${run.tests_passed ?? 0} passed, ${run.tests_failed ?? 0} failed of ${run.tests_discovered}`;
        return h(
          "div",
          {},
          h("h3", { text: i === 0 ? `Latest attempt, ${when(run.started_at)}` : `Earlier attempt, ${when(run.started_at)}` }),
          facts([
            ["Branch", code(run.branch)],
            ["Commit", run.commit_sha ? code(run.commit_sha.slice(0, 12)) : null],
            ["Sandbox", run.sandbox === "docker" ? "Docker (no network for build and test)" : run.sandbox === "none" ? "Unavailable, so results are unverified" : "Host (unsafe, explicitly requested)"],
            ["Tests", tests],
          ]),
          h(
            "div",
            { class: "table-scroll" },
            h(
              "table",
              {},
              h("thead", {}, h("tr", {}, h("th", { text: "Step" }), h("th", { text: "Result" }), h("th", { class: "num", text: "Exit" }), h("th", { class: "num", text: "Time" }), h("th", { text: "Detail" }))),
              h("tbody", {}, rows),
            ),
          ),
        );
      });
    return section("Build and test", h("span", { class: "tag verified", text: "Sandboxed" }), runs);
  }

  function listBlock(title, items, tone) {
    return h(
      "div",
      { class: tone || "" },
      h("h3", { text: `${title} (${items.length})` }),
      items.length ? h("ul", {}, items.map((t) => h("li", {}, code(t)))) : h("p", { class: "small quiet", text: "None" }),
    );
  }

  function renderVerification(detail) {
    if (!detail.verifications.length) {
      return section("Rescan, before and after", null, h("p", { class: "quiet", text: "Runs after build and test: Guardian rescans the fixed branch and compares it with the original scan." }));
    }
    const v = detail.verifications[detail.verifications.length - 1];
    const diff = v.sbom_diff || { added: [], removed: [], changed: [] };
    const changed = (diff.changed || []).map((c) => `${c.purl_base} ${c.from_version || "?"} to ${c.to_version || "?"}`);
    return section(
      "Rescan, before and after",
      verifiedTag(),
      h("p", { class: "verdict", dataset: { status: v.status }, text: v.status.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase()) }),
      h(
        "p",
        { class: "before-after" },
        h("span", { class: "label", text: "Risk before" }),
        num(v.risk_before),
        h("span", { "aria-hidden": "true", text: "→" }),
        h("span", { class: "label", text: "after" }),
        num(v.risk_after),
      ),
      facts([
        ["Confidence", v.confidence],
        ["Scans", `${(v.before_scan_id || "").slice(0, 12)} and ${(v.after_scan_id || "none").slice(0, 12)}`],
      ]),
      h(
        "div",
        { class: "lists" },
        listBlock("Findings resolved", v.target_findings_resolved || [], "go"),
        listBlock("Still present", v.findings_still_present || [], ""),
        listBlock("New findings", v.new_findings || [], (v.new_findings || []).length ? "stop" : ""),
      ),
      h(
        "div",
        { class: "lists" },
        listBlock("Components changed", changed, ""),
        listBlock("Components added", diff.added || [], ""),
        listBlock("Components removed", diff.removed || [], ""),
      ),
      (v.reasons || []).length ? h("ul", { "aria-label": "Reasons" }, v.reasons.map((r) => h("li", { text: r }))) : null,
    );
  }

  function renderAudit(detail) {
    const chain = state.audit
      ? state.audit.ok
        ? h("p", { class: "small" }, h("strong", { text: "Chain intact. " }), `All ${state.audit.events} events in the log match their hashes.`)
        : h("div", { class: "message error" }, h("strong", { text: "Chain broken. " }), h("ul", {}, state.audit.problems.map((p) => h("li", { text: p }))))
      : null;
    const rows = detail.audit
      .slice()
      .reverse()
      .map((e) =>
        h(
          "tr",
          {},
          h("td", { text: when(e.at) }),
          h("td", {}, code(e.event)),
          h("td", { text: e.actor }),
          h("td", {}, code(e.event_sha256.slice(0, 12))),
        ),
      );
    return section(
      "Audit trail",
      null,
      chain,
      h(
        "div",
        { class: "table-scroll" },
        h(
          "table",
          {},
          h("thead", {}, h("tr", {}, ["When", "Event", "Actor", "Hash"].map((t) => h("th", { text: t })))),
          h("tbody", {}, rows),
        ),
      ),
    );
  }

  // --- AI investigation (shared by the case detail and the codebase view) ---------------------

  const AGENT_NOTES = {
    dependency: "How the package enters the dependency tree and who uses it.",
    vulnerability: "Whether the advisory matters for how this repository uses the package. It cannot change severity, affected versions or the fix.",
    code: "Whether attacker input can reach the flagged line. It does not decide anything.",
    correlator: "Guardian's overall reading, weighed against the verified facts.",
    architect: "What each area of the repository is for.",
  };
  const LEVEL_WORDS = { likely: "Likely", possible: "Possible", unlikely: "Unlikely", unknown: "Unknown" };

  function refChips(refs) {
    if (!refs || !refs.length) return null;
    return h("span", { class: "refs" }, h("span", { class: "refs-label", text: "Evidence:" }), refs.map((r) => code(r)));
  }

  function claimItem(claim) {
    if (!claim) return null;
    return h("li", { class: "claim" }, h("span", { text: claim.text }), " ", refChips(claim.evidence_refs));
  }

  function claimList(title, claims) {
    if (!claims || !claims.length) return null;
    return h("div", { class: "claims" }, h("h4", { text: title }), h("ul", {}, claims.map(claimItem)));
  }

  function verifiedFacts(report) {
    const facts = report.verified_facts || [];
    if (!facts.length) return null;
    const dl = h("dl", { class: "facts" });
    for (const f of facts) {
      dl.append(h("dt", { text: f.label }), h("dd", {}, f.value, f.ref ? " " : null, f.ref ? code(f.ref) : null));
    }
    return h("div", { class: "verified-block" }, h("div", { class: "section-head" }, h("h3", { text: "Verified facts" }), verifiedTag()), dl);
  }

  function modelLine(report) {
    if (!report.provider) return null;
    const latency = typeof report.latency_seconds === "number" ? `, ${report.latency_seconds.toFixed(1)} s` : "";
    const repaired = report.status === "repaired" ? ", answer repaired once" : "";
    const dropped = report.dropped_claims ? `, ${report.dropped_claims} unsupported claim${report.dropped_claims === 1 ? "" : "s"} removed` : "";
    return h("p", { class: "model-line", text: `${report.provider} / ${report.model}${latency}${repaired}${dropped}` });
  }

  function assessmentBody(report) {
    const a = report.assessment;
    if (!a) return [];
    switch (report.agent) {
      case "dependency":
        return [
          h("p", { class: "verdict-line" }, "Production use: ", h("strong", { text: a.scope_assessment })),
          claimList("How it enters", [a.how_it_enters]),
          claimList("Why", a.scope_reasons),
          claimList("Blast radius", [a.blast_radius]),
        ];
      case "vulnerability":
        return [
          h("p", { class: "verdict-line" }, "Relevance here: ", h("strong", { class: `level level-${a.relevance}`, text: LEVEL_WORDS[a.relevance] || a.relevance })),
          claimList("Threat model", [a.threat_model]),
          claimList("Reasons", a.reasons),
          claimList("Prerequisites", a.prerequisites),
          a.open_questions && a.open_questions.length ? h("div", { class: "claims" }, h("h4", { text: "For a human to check" }), h("ul", {}, a.open_questions.map((q) => h("li", { text: q })))) : null,
        ];
      case "code":
        return [
          h(
            "p",
            { class: "verdict-line" },
            "Exploitability: ",
            h("strong", { class: `level level-${a.exploitability}`, text: LEVEL_WORDS[a.exploitability] || a.exploitability }),
            a.intentional_challenge_code ? h("span", { class: "tag conflict", text: "Looks like intentional challenge code" }) : null,
          ),
          claimList("What the code does", [a.narrative]),
          claimList("Attacker input path", a.input_path),
          claimList("Against exploitability", a.counter_evidence),
          a.intentional_reason ? claimList("Why it looks intentional", [a.intentional_reason]) : null,
        ];
      case "correlator":
        return [
          h("p", { class: "verdict-line" }, "Confidence: ", h("strong", { text: a.confidence })),
          claimList("Assessment", [a.assessment]),
          a.recommendation ? h("p", {}, h("strong", { text: "Suggested next step: " }), a.recommendation) : null,
          a.recommended_candidate_id ? h("p", { class: "small" }, "Points to fix option ", code(a.recommended_candidate_id), ". You still decide.") : null,
        ];
      default:
        return [claimList("Notes", a.notes)];
    }
  }

  function inferenceBlock(report, options = {}) {
    const title = options.title || `${report.agent_label} (AI inference)`;
    if (!report.assessment) {
      return h(
        "div",
        { class: "inference unavailable" },
        h("div", { class: "section-head" }, h("h3", { text: title }), h("span", { class: "tag inferred", text: "No AI output" })),
        h("p", { class: "small", text: `AI unavailable: ${report.reason || "no reason recorded"}. Only verified facts are shown.` }),
      );
    }
    return h(
      "div",
      { class: "inference" },
      h("div", { class: "section-head" }, h("h3", { text: title }), h("span", { class: "tag inferred", text: "Inferred" })),
      options.note === false ? null : h("p", { class: "small quiet", text: AGENT_NOTES[report.agent] || "" }),
      assessmentBody(report),
      modelLine(report),
    );
  }

  function renderInvestigation(detail) {
    const inv = detail.investigation;
    if (!inv || !inv.reports.length) {
      return section(
        "AI investigation",
        null,
        h("p", { class: "quiet", text: "No AI investigation of this case yet. Start one from the Architecture view, or run:" }),
        h("span", { class: "command", text: "guardian investigate latest" }),
      );
    }
    const byAgent = {};
    for (const r of inv.reports) byAgent[r.agent] = r;
    const facts = byAgent.correlator || byAgent.dependency || byAgent.vulnerability;
    const blocks = ["dependency", "vulnerability", "correlator"].filter((a) => byAgent[a]).map((a) => inferenceBlock(byAgent[a], a === "correlator" ? { title: "Guardian's assessment (AI inference)" } : {}));
    return section(
      "AI investigation",
      null,
      h("p", { class: "small quiet", text: `Run ${inv.run.id}, ${when(inv.run.finished_at || inv.run.started_at)}. Investigators explain verified evidence; every claim lists the evidence it cites. They never change severity, the fix options or your decision.` }),
      facts ? verifiedFacts(facts) : null,
      h("div", { class: "inference-stack" }, blocks),
    );
  }

  // --- investigation job (button and live progress) ------------------------------------------

  function renderJob(job, investigation) {
    const running = job && job.running;
    const button = h(
      "button",
      {
        class: "act primary run-ai",
        type: "button",
        disabled: running,
        onclick: startInvestigation,
      },
      running ? "AI investigation running…" : "Run AI investigation",
    );
    const parts = [button];
    if (running) {
      const finished = (job.events || []).filter((e) => e.event === "finished");
      const last = finished.slice(-5).reverse();
      parts.push(
        h("p", { class: "small", text: `${finished.length} steps finished so far.` }),
        h(
          "ol",
          { class: "job-events", "aria-label": "Latest steps" },
          last.map((e) => h("li", {}, h("strong", { text: AGENT_TITLES[e.agent] || NODE_TITLES[e.node] || e.node }), e.subject_id ? " " : null, e.subject_id ? code(e.subject_id.slice(0, 12)) : null, e.status ? ` ${e.status.replace(/_/g, " ")}` : null)),
        ),
      );
    } else if (job && job.error) {
      parts.push(h("p", { class: "message error", text: job.error }));
    } else if (investigation) {
      const calls = `${investigation.calls} LLM call${investigation.calls === 1 ? "" : "s"}`;
      const models = investigation.providers.length ? ` (${investigation.providers.join(", ")})` : "";
      parts.push(h("p", { class: "small quiet", text: `Last run ${when(investigation.finished_at)}: ${investigation.status}, ${calls}${models}.` }));
    } else {
      parts.push(h("p", { class: "small quiet", text: "No investigation of this scan yet." }));
    }
    return h("div", { class: "job" }, parts);
  }

  async function startInvestigation(event) {
    const button = event.currentTarget;
    button.disabled = true;
    const result = await api("/api/investigate", { method: "POST", body: { top: 5 } });
    if (result.status === 202) toast("AI investigation started.");
    else toast(result.data.error || `Could not start (${result.status}).`);
    await refreshView(true);
  }

  // --- architecture view -------------------------------------------------------------------------

  const SVG_NS = "http://www.w3.org/2000/svg";
  const AGENT_TITLES = { architect: "Repository Architect", dependency: "Dependency Investigator", vulnerability: "Vulnerability Investigator", code: "Code Investigator", correlator: "Evidence Correlator" };
  const NODE_TITLES = { load_scan: "Load scan", gather: "Gather", correlate: "Evidence Correlator", persist: "Store reports" };
  const STATUS_TEXT = {
    success: "Ran",
    failed: "Failed",
    partial: "Partly ran",
    skipped: "Skipped",
    not_run: "Not run",
    running: "Running",
    waiting: "Waiting for a person",
    ai_unavailable: "AI unavailable",
  };
  // Positions in a 1200 x 560 drawing: the detection line on top, the remediation line below.
  const LAYOUT = {
    profile: [70, 150],
    sbom: [205, 60],
    osv: [345, 60],
    semgrep: [345, 130],
    git: [345, 200],
    indexer: [345, 270],
    graph: [490, 165],
    risk: [615, 165],
    "agent-architect": [790, 62],
    "agent-dependency": [790, 130],
    "agent-vulnerability": [790, 198],
    "agent-code": [790, 266],
    "agent-correlator": [1000, 165],
    cases: [110, 460],
    decision: [320, 460],
    apply: [520, 460],
    sandbox: [710, 460],
    rescan: [890, 460],
    verdict: [1070, 460],
  };
  const TRUNK_Y = 370;

  function svg(tag, attrs, ...children) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "text") el.textContent = String(value);
      else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
      else el.setAttribute(key, String(value));
    }
    for (const child of children.flat(Infinity)) if (child) el.append(child);
    return el;
  }

  function edgePath(from, to) {
    const [x1, y1] = LAYOUT[from];
    const [x2, y2] = LAYOUT[to];
    if (y2 >= 400 && y1 < 400) {
      // Leave stations sideways first so the drop to the lower line never crosses a label.
      const out = from.startsWith("agent-") ? x1 : x1 + 62;
      return `M ${x1} ${y1} H ${out} V ${TRUNK_Y} H ${x2} V ${y2}`;
    }
    if (y1 === y2) return `M ${x1} ${y1} H ${x2}`;
    const mid = Math.round((x1 + x2) / 2);
    return `M ${x1} ${y1} H ${mid} V ${y2} H ${x2}`;
  }

  const PASSED = new Set(["success", "partial", "waiting", "running"]);

  function nodeGroup(node) {
    const [x, y] = LAYOUT[node.id] || [0, 0];
    const selected = state.archSelected === node.id;
    const g = svg("g", {
      class: `arch-node kind-${node.kind}${selected ? " is-selected" : ""}`,
      "data-status": node.status,
      tabindex: "0",
      role: "button",
      "aria-pressed": selected ? "true" : "false",
      "aria-label": `${node.label}: ${STATUS_TEXT[node.status] || node.status}. ${node.summary}`,
      onclick: () => selectNode(node.id),
      onkeydown: (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          selectNode(node.id);
        }
      },
    });
    if (node.kind === "ai") {
      g.append(
        svg("rect", { class: "ai-box", x: x - 82, y: y - 21, width: 164, height: 42, rx: 6, fill: "url(#arch-hatch)" }),
        svg("text", { class: "node-label", x, y: y - 2, "text-anchor": "middle", text: node.label.replace(" Investigator", "") }),
        svg("text", { class: "node-status", x, y: y + 14, "text-anchor": "middle", text: STATUS_TEXT[node.status] || node.status }),
      );
      return g;
    }
    if (node.kind === "human") {
      g.append(
        svg("circle", { class: "ring-outer", cx: x, cy: y, r: 26 }),
        svg("circle", { class: "ring-inner", cx: x, cy: y, r: 17 }),
      );
    } else {
      g.append(svg("circle", { class: "dot-mark", cx: x, cy: y, r: 13 }));
    }
    const below = node.kind === "human" ? 46 : 34;
    g.append(
      svg("text", { class: "node-label", x, y: y + below, "text-anchor": "middle", text: node.label }),
      svg("text", { class: "node-status", x, y: y + below + 16, "text-anchor": "middle", text: STATUS_TEXT[node.status] || node.status }),
    );
    return g;
  }

  function renderDiagram(data) {
    const nodes = new Map(data.nodes.map((n) => [n.id, n]));
    const root = svg("svg", {
      class: "arch-diagram",
      viewBox: "0 0 1200 560",
      role: "group",
      "aria-label": "Guardian's pipeline for the latest scan. Select a station for details.",
    });
    root.append(
      svg(
        "defs",
        {},
        svg(
          "pattern",
          { id: "arch-hatch", width: 8, height: 8, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
          svg("rect", { class: "hatch-bg", width: 8, height: 8 }),
          svg("line", { class: "hatch-line", x1: 0, y1: 0, x2: 0, y2: 8 }),
        ),
      ),
    );
    // Zones: the AI zone is drafted (dashed), like the assessment blocks.
    root.append(
      svg("text", { class: "lane-label", x: 24, y: 22, text: "Find and understand: deterministic tools establish the facts" }),
      svg("rect", { class: "ai-zone", x: 690, y: 30, width: 420, height: 292, rx: 10 }),
      svg("text", { class: "zone-label", x: 706, y: 312, text: "AI investigators: inference that cites verified evidence" }),
      svg("text", { class: "lane-label", x: 1176, y: 400, "text-anchor": "end", text: "Fix with a person in the loop" }),
    );
    for (const [from, to] of data.edges) {
      if (!LAYOUT[from] || !LAYOUT[to]) continue;
      const source = nodes.get(from);
      const passed = source && PASSED.has(source.status);
      root.append(svg("path", { class: `arch-edge${passed ? " passed" : ""}${to.startsWith("agent-") || from.startsWith("agent-") ? " ai-edge" : ""}`, d: edgePath(from, to) }));
    }
    for (const node of data.nodes) if (LAYOUT[node.id]) root.append(nodeGroup(node));
    return h("div", { class: "arch-scroll" }, root);
  }

  function selectNode(id) {
    state.archSelected = state.archSelected === id ? null : id;
    renderArchitecture();
    const el = document.querySelector(`.arch-node[aria-pressed="true"]`);
    if (el) el.focus();
  }

  function renderNodeDetail(data) {
    const node = data.nodes.find((n) => n.id === state.archSelected);
    if (!node) {
      return h("p", { class: "quiet node-hint", text: "Select a station to see what ran, how long it took and what it produced." });
    }
    const kindWords = {
      tool: "Deterministic tool: its output is a verified fact.",
      derived: "Deterministic step over the tools' output.",
      ai: "AI investigator: everything it writes is inference and must cite input evidence.",
      human: "The only step where a person acts. Guardian never approves on anyone's behalf.",
      remediation: "Deterministic remediation step, run only after a recorded human decision.",
    };
    const tag = node.kind === "ai" ? h("span", { class: "tag inferred", text: "Inferred" }) : node.kind === "human" ? h("span", { class: "tag gate", text: "Human" }) : verifiedTag();
    return h(
      "div",
      { class: `node-detail kind-${node.kind}` },
      h("div", { class: "section-head" }, h("h3", { text: node.label }), tag),
      h("p", { class: "small quiet", text: kindWords[node.kind] || "" }),
      h("p", {}, h("strong", { text: `${STATUS_TEXT[node.status] || node.status}. ` }), node.summary),
      facts(node.details.map(([k, v]) => [k, v])),
    );
  }

  function renderArchitecture() {
    const data = state.arch;
    const root = document.getElementById("architecture");
    if (!data) return;
    if (!data.scan) {
      root.replaceChildren(
        h("div", { class: "empty" }, h("h2", { text: "No scan yet" }), h("p", { text: "Scan a repository to see Guardian's pipeline run on it:" }), h("span", { class: "command", text: "guardian scan <path>" })),
      );
      return;
    }
    const legend = h(
      "ul",
      { class: "legend", "aria-label": "Legend" },
      h("li", { class: "lg-tool", text: "Deterministic step (verified facts)" }),
      h("li", { class: "lg-ai", text: "AI investigator (inference)" }),
      h("li", { class: "lg-human", text: "Human decision" }),
    );
    root.replaceChildren(
      h(
        "header",
        { class: "view-head" },
        h("div", {}, h("h2", { text: `How Guardian handled ${data.scan.repository}` }), h("p", { class: "quiet" }, "Latest scan ", code(data.scan.id.slice(0, 12)), `, ${when(data.scan.started_at)}, ${data.scan.status}.`)),
        renderJob(data.job, data.investigation),
      ),
      legend,
      renderDiagram(data),
      h("section", { class: "node-panel", "aria-live": "polite" }, renderNodeDetail(data)),
    );
  }

  // --- codebase view -----------------------------------------------------------------------------

  const KIND_WORDS = { prod: "Production", dev: "Development tooling", test: "Tests", "challenge-fixture": "Challenge snippets", unknown: "Unknown" };

  function renderModules(data) {
    const rows = data.modules.map((m) => {
      const ai = m.ai;
      const differs = ai && ai.kind !== m.path_classification;
      return h(
        "tr",
        {},
        h("td", {}, code(m.area)),
        h("td", { class: "num", text: String(m.files) }),
        h("td", {}, h("span", { class: "chip", dataset: { tone: m.path_classification === "prod" ? "live" : m.path_classification === "challenge-fixture" ? "fixture" : "" }, text: KIND_WORDS[m.path_classification] || m.path_classification })),
        h(
          "td",
          { class: "ai-cell" },
          ai ? [h("span", { text: ai.purpose }), differs ? h("span", { class: "small differs", text: ` Reads it as ${(KIND_WORDS[ai.kind] || ai.kind).toLowerCase()}.` }) : null] : h("span", { class: "quiet", text: "No AI reading" }),
        ),
      );
    });
    const architect = data.architect;
    return section(
      "Module map",
      null,
      h("p", { class: "small quiet", text: "Path classification comes from fixed path rules (verified). The purpose column is the Repository Architect's reading (AI inference, hatched)." }),
      h(
        "div",
        { class: "table-scroll" },
        h(
          "table",
          { class: "modules" },
          h("thead", {}, h("tr", {}, h("th", { text: "Area" }), h("th", { class: "num", text: "Files" }), h("th", {}, "Path rule ", verifiedTag()), h("th", { class: "ai-cell" }, "Purpose ", h("span", { class: "tag inferred", text: "Inferred" })))),
          h("tbody", {}, rows),
        ),
      ),
      architect && architect.assessment ? h("div", { class: "inference" }, h("div", { class: "section-head" }, h("h3", { text: "Repository Architect (AI inference)" })), claimList("Entry points that matter", architect.assessment.key_entry_points), claimList("Notes", architect.assessment.notes), modelLine(architect)) : null,
      architect && !architect.assessment ? h("p", { class: "small quiet", text: `Repository Architect: AI unavailable (${architect.reason || "no reason"}).` }) : null,
    );
  }

  function renderCodeFindings(data) {
    const items = data.code_findings.map((f) => {
      const inv = f.code_investigator;
      const a = inv && inv.assessment;
      const summary = h(
        "summary",
        {},
        h("span", { class: "cf-title", text: f.title }),
        h(
          "span",
          { class: "cf-meta" },
          h("span", { text: f.severity }),
          f.location ? code(f.location) : null,
          h("span", { class: "chip", dataset: { tone: f.path_classification === "challenge-fixture" ? "fixture" : f.path_classification === "prod" ? "live" : "" }, text: KIND_WORDS[f.path_classification] || f.path_classification }),
          f.risk ? h("span", { text: `${f.risk.priority}, risk ${num(f.risk.score)}` }) : null,
          a ? h("span", { class: "ai-flag", text: `AI: ${LEVEL_WORDS[a.exploitability] || a.exploitability}${a.intentional_challenge_code ? ", challenge code" : ""}` }) : null,
        ),
      );
      const body = [
        facts([
          ["Rule", f.rule_id ? code(f.rule_id) : null],
          ["Message", f.message],
          ["Risk", f.risk ? f.risk.summary : null],
          ["Finding", code(f.id)],
        ]),
      ];
      if (inv) body.push(inferenceBlock(inv));
      if (f.correlator && f.correlator.assessment) body.push(inferenceBlock(f.correlator, { title: "Guardian's assessment (AI inference)" }));
      if (!inv) body.push(h("p", { class: "small quiet", text: "Not investigated (outside the top findings of the last run)." }));
      return h("li", {}, h("details", { class: "code-finding" }, summary, h("div", { class: "cf-body" }, body)));
    });
    return section(
      `Code findings (${data.code_findings.length})`,
      verifiedTag(),
      h("p", { class: "small quiet", text: "Read only: decisions are made on remediation cases. Highest risk first." }),
      items.length ? h("ul", { class: "code-findings" }, items) : h("p", { class: "quiet", text: "Semgrep reported no code findings." }),
    );
  }

  function renderCodebase() {
    const data = state.codebase;
    const root = document.getElementById("codebase");
    if (!data) return;
    if (!data.scan) {
      root.replaceChildren(h("div", { class: "empty" }, h("h2", { text: "No scan yet" }), h("span", { class: "command", text: "guardian scan <path>" })));
      return;
    }
    const p = data.profile;
    const entryKinds = Object.entries(p.entry_points_by_kind || {}).map(([k, n]) => `${n} ${k.replace(/-/g, " ")}`).join(", ");
    root.replaceChildren(
      h(
        "header",
        { class: "view-head" },
        h("div", {}, h("h2", { text: data.scan.repository }), h("p", { class: "quiet" }, "Scan ", code(data.scan.id.slice(0, 12)), data.scan.git_commit ? [", commit ", code(data.scan.git_commit.slice(0, 12))] : null, `, ${when(data.scan.started_at)}.`)),
        renderJob(state.arch ? state.arch.job : { running: false, events: [] }, data.investigation),
      ),
      section(
        "Profile",
        verifiedTag(),
        facts([
          ["Languages", p.languages.map((l) => `${l.name} (${l.files})`).join(", ")],
          ["Ecosystems", p.ecosystems.map((e) => `${e.ecosystem}${e.frameworks.length ? ` (${e.frameworks.join(", ")})` : ""}`).join(", ")],
          ["Files", `${p.total_files} in the repository, ${p.indexed_files} indexed`],
          ["Entry points", `${p.entry_points}${entryKinds ? `: ${entryKinds}` : ""}`],
        ]),
      ),
      renderModules(data),
      renderCodeFindings(data),
    );
  }

  // --- views -------------------------------------------------------------------------------------

  function viewFromHash() {
    const hash = window.location.hash.slice(1);
    return hash === "architecture" || hash === "codebase" ? hash : "cases";
  }

  function showView(view) {
    state.view = view;
    for (const name of ["cases", "architecture", "codebase"]) {
      document.getElementById(`view-${name}`).hidden = name !== view;
      const tab = document.getElementById(`tab-${name}`);
      if (name === view) tab.setAttribute("aria-current", "page");
      else tab.removeAttribute("aria-current");
    }
    document.getElementById("banner").hidden = view !== "cases";
  }

  async function refreshView(force) {
    if (state.view === "architecture" || state.view === "codebase") {
      const arch = await api("/api/architecture");
      if (arch.ok) {
        const json = JSON.stringify(arch.data);
        if (force || json !== state.archJson) {
          state.archJson = json;
          state.arch = arch.data;
          if (state.view === "architecture") renderArchitecture();
        }
      }
      if (state.view === "codebase") {
        const running = state.arch && state.arch.job && state.arch.job.running;
        if (force || !state.codebase || running || state.codebaseRun !== (state.arch && state.arch.investigation && state.arch.investigation.id)) {
          const cb = await api("/api/codebase");
          if (cb.ok) {
            state.codebase = cb.data;
            state.codebaseRun = cb.data.investigation ? cb.data.investigation.id : null;
            renderCodebase();
          }
        }
      }
    }
  }

  // --- decision panel ------------------------------------------------------------------------------

  function tomorrow() {
    const d = new Date();
    d.setDate(d.getDate() + 1);
    return d.toISOString().slice(0, 10);
  }

  function renderDecide(detail) {
    const c = detail.case;
    const panel = h("aside", { class: "decide", "aria-labelledby": "decide-title" });
    panel.append(h("h2", { id: "decide-title", text: "Your decision" }));
    const message = h("div", { id: "decide-message", "aria-live": "polite" });

    if (c.decision_pending) {
      panel.append(h("p", { text: "Decision recorded. Guardian is moving the case on; this page follows along." }));
      return panel;
    }
    if (c.status === "VALIDATION_FAILED" || c.status === "VERIFIED") {
      panel.append(
        h("p", { text: c.status === "VERIFIED" ? "The fix is verified. You can run validation again if something changed." : "Validation failed. Run it again after fixing the cause, or wait for the case to return to review." }),
        h("button", { class: "act", type: "button", onclick: (ev) => submit(ev, { action: "revalidate" }) }, "Run validation again"),
        message,
      );
      return panel;
    }
    if (c.status !== "AWAITING_DECISION") {
      panel.append(h("p", { class: "quiet", text: `No decision needed now. ${STATUS_WORDS[c.status] || c.status}.` }));
      return panel;
    }

    panel.append(h("p", { class: "small quiet", text: `You are deciding as the local user. The case moves only after you choose.` }));
    const recommended = detail.candidates.find((x) => x.recommended);
    if (recommended) {
      panel.append(
        h("p", {}, "Recommended: ", h("strong", { text: candidateTitle(recommended) })),
        h("button", { class: "act primary", type: "button", onclick: (ev) => submit(ev, { action: "accept" }) }, "Accept recommended fix"),
      );
    }
    const chosen = detail.candidates.find((x) => x.id === state.chosenCandidate);
    if (chosen && !chosen.recommended) {
      panel.append(
        h("p", { class: "small" }, "Selected: ", h("strong", { text: candidateTitle(chosen) })),
        h("button", { class: "act" + (recommended ? "" : " primary"), type: "button", onclick: (ev) => submit(ev, { action: "accept", candidate_id: chosen.id }) }, "Accept selected fix"),
      );
    } else if (!recommended && detail.candidates.length) {
      panel.append(h("p", { class: "small quiet", text: "Select a fix option to accept it." }));
    }

    // Modify: a different version.
    const version = h("input", { id: "modify-version", name: "version", inputmode: "decimal", autocomplete: "off", placeholder: "e.g. 4.17.21", maxlength: "64" });
    panel.append(
      h(
        "fieldset",
        {},
        h("legend", { text: "Use a different version" }),
        h("label", { for: "modify-version", text: "Version (Guardian validates it before applying)" }),
        version,
        h("button", { class: "act", type: "button", onclick: (ev) => submit(ev, { action: "modify", version: version.value.trim() }) }, "Use this version"),
      ),
    );

    // Decline.
    const reason = h("select", { id: "decline-reason", name: "reason" }, REASONS.map(([value, label]) => h("option", { value, text: label })));
    const until = h("input", { id: "decline-until", name: "until", type: "date", min: tomorrow() });
    const why = h("textarea", { id: "decline-why", name: "justification", maxlength: "2000" });
    const untilHint = h("p", { class: "hint", id: "until-hint", text: "Required for accepted risk: the date the acceptance expires." });
    until.setAttribute("aria-describedby", "until-hint");
    panel.append(
      h(
        "fieldset",
        {},
        h("legend", { text: "Decline the fix" }),
        h("label", { for: "decline-reason", text: "Reason" }),
        reason,
        h("label", { for: "decline-until", text: "Accept the risk until" }),
        until,
        untilHint,
        h("label", { for: "decline-why", text: "Justification" }),
        why,
        h(
          "button",
          {
            class: "act danger",
            type: "button",
            onclick: (ev) => submit(ev, { action: "decline", decline_reason: reason.value, until: until.value || null, justification: why.value.trim() || null }),
          },
          "Decline and record reason",
        ),
      ),
      message,
    );
    return panel;
  }

  function showMessage(kind, text, grammar) {
    const el = document.getElementById("decide-message");
    if (!el) {
      toast(text);
      return;
    }
    el.className = `message ${kind}`;
    el.replaceChildren(h("span", { text }), grammar ? h("pre", { text: grammar }) : null);
  }

  async function submit(event, body) {
    const button = event.currentTarget;
    button.disabled = true;
    const result = await api(`/api/cases/${encodeURIComponent(state.selected)}/decision`, { method: "POST", body });
    button.disabled = false;
    if (result.status === 202) {
      toast(result.data.message || "Decision recorded.");
      state.chosenCandidate = null;
      await refreshDetail(true);
      await refreshList();
      return;
    }
    showMessage("error", result.data.error || `Request failed (${result.status}).`, result.data.grammar);
  }

  // --- detail -----------------------------------------------------------------------------------------

  function renderDetail(force) {
    const detail = state.detail;
    const root = document.getElementById("case-detail");
    if (!detail) return;
    const active = document.activeElement;
    if (!force && active && active.closest && active.closest(".decide") && detail.case.status === "AWAITING_DECISION") {
      return; // do not wipe a form the presenter is filling in
    }
    const c = detail.case;
    const canDecide = c.status === "AWAITING_DECISION" && !c.decision_pending;
    const head = h(
      "header",
      { class: "case-head" },
      h("h2", { text: c.title }),
      h(
        "div",
        { class: "meta" },
        h("span", { class: "chip", dataset: { tone: STATUS_TONE[c.status] || "" }, text: statusWords(c) }),
        h("span", { text: `${PRIORITY_NAMES[c.priority] || c.priority} priority (${c.priority})` }),
        h("span", {}, code(c.id)),
        c.jira_key ? (c.jira_url ? safeLink(c.jira_url, `Jira ${c.jira_key}`) : h("span", { text: `Jira ${c.jira_key}` })) : h("span", { text: "Not published to Jira" }),
      ),
    );
    const left = h(
      "div",
      {},
      renderFindings(detail),
      renderRisk(detail),
      renderCandidates(detail, canDecide),
      renderPlan(detail),
      renderInvestigation(detail),
      renderDecisions(detail),
    );
    const columns = h("div", { class: "columns" }, left, h("div", {}, renderDecide(detail)));
    root.replaceChildren(
      head,
      renderRoute(detail),
      columns,
      renderValidations(detail),
      renderVerification(detail),
      renderAudit(detail),
    );
  }

  async function refreshDetail(force) {
    if (!state.selected) return;
    const id = state.selected;
    const result = await api(`/api/cases/${encodeURIComponent(id)}`);
    if (id !== state.selected) return;
    if (!result.ok) {
      document.getElementById("case-detail").replaceChildren(h("p", { class: "message error", text: result.data.error || "Could not load the case." }));
      return;
    }
    const json = JSON.stringify(result.data);
    if (!force && json === state.detailJson) return;
    state.detailJson = json;
    state.detail = result.data;
    renderDetail(force);
  }

  async function refreshList() {
    const result = await api("/api/cases");
    if (!result.ok) {
      document.getElementById("case-list").replaceChildren(h("p", { class: "message error", text: result.data.error || "Could not load cases." }));
      return false;
    }
    state.cases = result.data.cases;
    if (!state.selected && state.cases.length) {
      const fromHash = window.location.hash.slice(1); // a case id, or a view name
      state.selected = state.cases.some((c) => c.id === fromHash) ? fromHash : state.cases[0].id;
    }
    renderList();
    if (!state.cases.length) renderEmpty();
    return true;
  }

  async function refreshMeta() {
    const [health, audit] = await Promise.all([api("/api/health"), api("/api/audit/verify")]);
    if (health.ok) state.health = health.data;
    if (audit.ok) state.audit = audit.data;
    renderTop();
  }

  function select(id) {
    if (id === state.selected) return;
    state.selected = id;
    state.detailJson = "";
    state.lastCurrent = null;
    state.chosenCandidate = null;
    window.history.replaceState(null, "", `#${id}`);
    renderList();
    refreshDetail(true).then(() => document.getElementById("detail").focus({ preventScroll: false }));
  }

  function schedule() {
    window.clearTimeout(state.timer);
    const caseLive = state.view === "cases" && state.detail && (state.detail.case.live || state.detail.journey.live);
    const jobLive = state.view !== "cases" && state.arch && state.arch.job && state.arch.job.running;
    state.timer = window.setTimeout(tick, caseLive || jobLive ? LIVE_POLL_MS : IDLE_POLL_MS);
  }

  let lastList = 0;
  async function tick() {
    try {
      if (Date.now() - lastList > LIST_POLL_MS) {
        lastList = Date.now();
        await refreshList();
        await refreshMeta();
      }
      if (state.view === "cases") await refreshDetail(false);
      else await refreshView(false);
    } finally {
      schedule();
    }
  }

  async function onHashChange() {
    const view = viewFromHash();
    if (view === state.view && view === "cases") return;
    showView(view);
    if (view === "cases") {
      await refreshDetail(true);
    } else {
      await refreshView(true);
      if (view === "codebase" && !state.codebase) renderCodebase();
    }
    schedule();
  }

  async function start() {
    state.token = loadToken();
    if (!state.token) {
      document.getElementById("case-list").replaceChildren();
      document.getElementById("case-detail").replaceChildren(
        h(
          "div",
          { class: "empty" },
          h("h2", { text: "Open the link printed by guardian ui" }),
          h("p", { text: "This console needs the session link from the terminal, which carries a one-time token. Run:" }),
          h("span", { class: "command", text: "guardian ui" }),
        ),
      );
      return;
    }
    showView(viewFromHash());
    window.addEventListener("hashchange", onHashChange);
    document.getElementById("skip-link").addEventListener("click", (ev) => {
      ev.preventDefault();
      const target = state.view === "cases" ? document.getElementById("detail") : document.getElementById(`view-${state.view}`);
      target.setAttribute("tabindex", "-1");
      target.focus();
    });
    await refreshMeta();
    const ok = await refreshList();
    lastList = Date.now();
    if (state.view !== "cases") await refreshView(true);
    else if (ok) await refreshDetail(true);
    schedule();
  }

  document.addEventListener("DOMContentLoaded", start);
})();
