// Standard — operations console. Opens on the product in production (RUN); construction (BUILD) is one section away.
// Reads /api/state; signs reviews in this browser (sign.js). Nothing here is a permission: the kernel decides.
import { envelope, forgetSigner, importKeyFile, loadSigner, saveSigner } from "/sign.js";

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (sha) => esc(String(sha || "").slice(0, 7));
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function ago(ms) {
  const s = Math.max(1, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return "à l'instant";
  if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`;
  return new Date(ms).toLocaleDateString("fr-FR", { day: "numeric", month: "short" });
}
const due = (ms) => new Date(ms).toLocaleDateString("fr-FR", { day: "numeric", month: "short" });

// ---- vocabulary: what people call things ----------------------------------------------------------------------------
const NAMES = {
  vulns: "Vulnérabilités connues", "deps-age": "Dépendances à jour", licenses: "Licences autorisées",
  secrets: "Aucun secret dans le code", sast: "Analyse de sécurité du code", ci: "Tests au vert",
  actions: "Actions CI épinglées", sbom: "Inventaire des composants", branch: "Protection de la branche principale",
  lineage: "Chaque changement est jugé", inventory: "Dépôt entièrement couvert", soa: "Déclaration d'applicabilité",
  isms: "Politique de sécurité", risk: "Analyse de risques", access: "Revue des accès", training: "Formation",
  hr: "Sécurité des ressources humaines", suppliers: "Registre des fournisseurs", incident: "Procédure d'incident",
  continuity: "Test de continuité", backup: "Restauration des sauvegardes", legal: "Obligations légales",
  audit: "Audit indépendant", physical: "Sécurité physique", crypto: "Politique cryptographique",
  resilience: "Tests de résilience", assets: "Inventaire des actifs", infra: "Socle d'infrastructure",
  monitoring: "Supervision", threat: "Veille sur les menaces",
};
const DOMAINS = [
  ["Sécurité du code", (r) => repo(r) && r.domain === "code"],
  ["Dépendances et chaîne logicielle", (r) => repo(r) && ["deps", "supply"].includes(r.domain)],
  ["Intégration continue", (r) => repo(r) && r.domain === "ci"],
  ["Gouvernance du code", (r) => repo(r) && ["settings", "main", "inventory"].includes(r.domain)],
  ["Organisation", (r) => r.resource.startsWith("org:")],
];
const repo = (r) => r.resource.startsWith("repo:");
const STATES = {
  held: "Tenue", gap: "Écart", escalated: "Escaladée", attest: "À attester", unmeasured: "Non mesurée", pending: "En mesure",
};
const WHO = { agent: "L'agent seul", review: "L'agent, puis une revue", people: "Une personne" };
const name = (id) => NAMES[id] || id;
const VALUES = { none: "aucun", current: "à jour", complete: "complète", green: "au vert", red: "en échec", all: "toutes",
  compliant: "conformes", "guard-only": "garde seule" };
function measure(r) {
  if (!r.measured) return r.state === "held" ? "prouvée" : r.state === "attest" ? "attestation attendue" : "en attente";
  if (r.measured.startsWith("uncovered")) return "aucun instrument ici";
  const found = /^found:(\d+)$/.exec(r.measured);
  return found ? `${found[1]} trouvé${found[1] === "1" ? "" : "s"}` : VALUES[r.measured] || r.measured;
}
function subject(s) {
  const m = /^(?:Standard: )?remediate (\S+)$/.exec(s);
  return m ? `Réparation : ${name(m[1])}` : s.replace(/^Standard: /, "");
}

// ---- routing --------------------------------------------------------------------------------------------------------
const ROUTES = {
  run: ["Run", "run"], compliance: ["Conformité", "run"], activity: ["Activité", "run"],
  contributions: ["Contributions", "build"], requests: ["Demandes", "build"],
  reviews: ["Revues", "both"], proofs: ["Preuves", "both"], settings: ["Réglages", "both"],
};
let state = null, signer = null;
const route = () => (location.hash.slice(2) in ROUTES ? location.hash.slice(2) : "run");
window.addEventListener("hashchange", () => render());

function pending() {
  return [...state.build.contributions.filter((c) => c.awaiting_review), ...state.run.repairs.filter((r) => r.awaiting_review)];
}

function frame() {
  const here = route(), reviews = pending().length;
  const link = (id) => `<a href="#/${id}" ${id === here ? 'aria-current="page"' : ""}><span>${ROUTES[id][0]}</span>${
    id === "reviews" && reviews ? `<span class="badge">${reviews}</span>` : ""}</a>`;
  $("#nav").innerHTML = `
    <div class="group">Exploitation</div>${link("run")}${link("compliance")}${link("activity")}
    <div class="group">Construction</div>${link("contributions")}${link("requests")}
    <div class="group">Gouvernance</div>${link("reviews")}${link("proofs")}${link("settings")}`;
  const others = state.products.length > 1;
  $("#product").innerHTML = `<div class="mark">${esc(state.product.slice(0, 1).toUpperCase())}</div><div>
    ${others ? `<select aria-label="Produit">${state.products.map((p) => `<option ${p === state.product ? "selected" : ""}>${esc(p)}</option>`).join("")}</select>`
      : `<b>${esc(state.product)}</b>`}<span>${state.assessment === "INDEPENDENT" ? "Évalué indépendamment" : "Démonstration"}</span></div>`;
  const env = ROUTES[here][1] === "build" ? `<span class="env build">Construction</span>` : `<span class="env run">Production</span>`;
  $("#top").innerHTML = `<span class="crumb"><b>${esc(state.product)}</b>  /  ${ROUTES[here][0]}</span>${env}
    <span class="spacer"></span><span class="sha" title="Commit en production">main ${short(state.main)}</span>`;
  $("#who").innerHTML = signer ? `Connecté pour signer en tant que <b>${esc(signer.identity)}</b>` : `Aucune clé de signature dans ce navigateur`;
}

// ---- data -----------------------------------------------------------------------------------------------------------
async function refresh() {
  try {
    const r = await fetch("/api/state", { cache: "no-store" });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || r.statusText);
    state = body;
    render();
  } catch (err) {
    $("#view").innerHTML = `<div class="note bad">Standard ne répond pas ou n'est pas qualifié sur ce serveur : ${esc(err.message)}. Rien n'est attesté ni autorisé tant que ce n'est pas rétabli.</div>`;
  }
}

function render() {
  if (!state) return;
  frame();
  const views = { run: runView, compliance, activity, contributions, requests, reviews, proofs, settings };
  $("#view").innerHTML = views[route()]();
  if (route() === "run") loadRun();
  if (route() === "settings") bindSettings();
  document.querySelectorAll("[data-review]").forEach((b) => b.addEventListener("click", () => openReview(b.dataset.review)));
}

// ---- RUN: the product in production -------------------------------------------------------------------------------
function counts() {
  const by = (s) => state.requirements.filter((r) => r.state === s).length;
  return { total: state.requirements.length, held: by("held"), gap: by("gap"), escalated: by("escalated"),
    attest: by("attest"), unmeasured: by("unmeasured") };
}

function map() {
  return `<div class="map">${DOMAINS.map(([label, test]) => {
    const rs = state.requirements.filter(test);
    if (!rs.length) return "";
    const held = rs.filter((r) => r.state === "held").length;
    return `<div class="dom">${label}</div>
      <div class="cells">${rs.map((r) => `<button class="cell ${r.state}" title="${esc(name(r.id))} : ${STATES[r.state]}" aria-label="${esc(name(r.id))} : ${STATES[r.state]}" data-req="${esc(r.id)}"></button>`).join("")}</div>
      <div class="tally">${held} sur ${rs.length}</div>`;
  }).join("")}</div>
  <div class="legend">${["held", "gap", "attest", "unmeasured", "escalated"].map((s) => `<span><i class="cell ${s}"></i>${STATES[s]}</span>`).join("")}</div>`;
}

function todo() {
  const items = [];
  for (const e of state.health.escalated) items.push(["alert", `${name(e.target)} a dépassé son échéance`, "Décision humaine requise", "#/compliance", "Voir"]);
  for (const p of pending()) items.push(["wait", p.kind === "contribution" ? `Relire la contribution de ${p.author}` : `Relire la réparation « ${name(p.target)} »`,
    "Tests au vert, aucun nouvel écart", null, "Relire", p.resource]);
  for (const a of state.run.abandoned) items.push(["alert", `L'agent n'a pas su réparer « ${name(a.target)} »`, "Son dossier explique pourquoi", "#/activity", "Voir"]);
  const attest = counts().attest;
  if (attest) items.push(["people", `${plural(attest, "exigence organisationnelle", "exigences organisationnelles")} à attester`, "Politiques, accès, continuité, fournisseurs", "#/compliance", "Voir"]);
  if (!items.length) return `<div class="clear">Rien ne vous attend. L'agent surveille et répare en continu.</div>`;
  return `<div class="todo">${items.map(([kind, what, sub, href, cta, review]) => `
    <div class="task"><i class="dot ${kind}"></i><div class="what"><b>${esc(what)}</b><span>${esc(sub)}</span></div>
      ${review ? `<button class="btn primary" data-review="${esc(review)}">${cta}</button>` : `<a class="btn" href="${href}">${cta}</a>`}</div>`).join("")}</div>`;
}

function feed(limit) {
  const rows = state.history.slice(0, limit).map((c) => {
    const agent = c.author === "standard-agent";
    return `<li><i class="dot ${agent ? "agent" : "people"}"></i><div><div class="t">${esc(subject(c.subject))}</div>
      <div class="s">${agent ? "Réparé automatiquement par l'agent" : `Intégré après revue, par ${esc(c.author)}`}</div></div>
      <time>${c.at > 946684800 ? ago(c.at * 1000) : ""}</time></li>`;
  });
  return `<ul class="feed">${rows.join("")}</ul>`;
}

function compliance() {
  const c = counts();
  return `<h1>Conformité</h1>
    <p class="lede">${c.held} exigences tenues sur ${c.total}, mesurées par des instruments indépendants. On peut durcir une exigence à tout moment ; l'assouplir demande deux personnes et une heure de délai.</p>
    ${map()}
    <section><h2>À traiter par vous</h2>${todo()}</section>
    ${requirementTables()}`;
}

// ---- Run: the product's APIs and what an engineer on call needs ------------------------------------------------
let runWindow = Number(localGet("window")) || 3600, runData = null;
function localGet(k) { try { return localStorage.getItem("standard." + k); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem("standard." + k, v); } catch { /* private mode */ } }
const WINDOWS = [[900, "15 min"], [3600, "1 h"], [86400, "24 h"], [604800, "7 j"]];
const nf = (v, d = 0) => v == null ? "—" : Number(v).toLocaleString("fr-FR", { minimumFractionDigits: d, maximumFractionDigits: d });
const pct = (v, d = 2) => v == null ? "—" : `${nf(v * 100, d)} %`;
const msf = (v) => v == null ? "—" : v >= 1000 ? `${nf(v / 1000, 2)} s` : `${nf(v, v < 10 ? 1 : 0)} ms`;
const ROUTE_STATE = { healthy: ["held", "Opérationnelle"], degraded: ["gap", "Dégradée"], failing: ["escalated", "En échec"], idle: ["pending", "Aucun trafic"] };

function spark(values, w = 120, h = 28) {
  const max = Math.max(...values, 0.0001), step = w / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(" ");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true"><polyline points="${pts}"/></svg>`;
}

function area(values) {
  const w = 1000, h = 140, max = Math.max(...values, 0.0001), step = w / Math.max(values.length - 1, 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * (h - 12)).toFixed(1)}`);
  return `<svg class="area" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Requêtes par seconde sur la période">
    <polygon points="0,${h} ${pts.join(" ")} ${w},${h}"/><polyline points="${pts.join(" ")}"/></svg>
    <div class="axis"><span>${WINDOWS.find(([s]) => s === runWindow)?.[1] || ""}</span><span>max ${nf(max, 1)} req/s</span><span>maintenant</span></div>`;
}

function runView() {
  return `<div class="runhead"><div><h1>Run</h1>
      <p class="lede">${esc(state.product)} en production, version <span class="sha">${short(state.main)}</span>.</p></div>
    <div class="seg" role="group" aria-label="Période">${WINDOWS.map(([s, l]) => `<button data-window="${s}" class="${s === runWindow ? "on" : ""}">${l}</button>`).join("")}</div></div>
    <div id="run"><p class="quiet">Chargement des métriques</p></div>`;
}

const KIND = {
  api: ["APIs", "API", "APIs"], worker: ["Workers et files", "worker", "workers"], job: ["Tâches planifiées", "tâche planifiée", "tâches planifiées"],
  database: ["Bases de données", "base de données", "bases de données"], dependency: ["Services externes", "service externe", "services externes"],
  process: ["Processus", "processus", "processus"],
};
const bytes = (v) => v == null ? "—" : v >= 1 << 30 ? `${nf(v / (1 << 30), 1)} Go` : `${nf(v / (1 << 20), 0)} Mo`;
const dur = (s) => s == null ? "—" : s < 120 ? `${nf(s, 0)} s` : s < 7200 ? `${nf(s / 60, 0)} min` : s < 172800 ? `${nf(s / 3600, 0)} h` : `${nf(s / 86400, 0)} j`;
const stateCell = (s) => `<td><span class="state ${ROUTE_STATE[s][0]}"><i></i>${ROUTE_STATE[s][1]}</span></td>`;

function table(cols, rows) {
  return `<table class="table api"><colgroup>${cols.map(([, w]) => `<col${w ? ` style="width:${w}px"` : ""}>`).join("")}</colgroup>
    <thead><tr>${cols.map(([h, , num]) => `<th class="${num ? "num" : ""}">${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

const SECTIONS = {
  api: (rs, d) => table([["État", 150], ["Méthode", 76], ["Route"], ["Trafic", 136], ["Req/s", 80, 1], ["Erreurs", 84, 1], ["p50", 78, 1], ["p95", 78, 1], ["p99", 78, 1], ["Dispo.", 92, 1]],
    rs.map((r) => `<tr class="${r.state === "idle" ? "idle" : ""}">${stateCell(r.state)}<td><span class="verb ${esc(r.operation.toLowerCase())}">${esc(r.operation)}</span></td>
      <td><span class="path">${esc(r.name)}</span>${r.observed && !r.declared && d.openapi ? `<div class="sub">absente d'openapi.json</div>` : ""}</td>
      <td>${r.observed ? spark(r.spark) : ""}</td><td class="num">${r.observed ? nf(r.rps, 2) : "—"}</td>
      <td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td><td class="num">${msf(r.p50)}</td>
      <td class="num">${msf(r.p95)}</td><td class="num">${msf(r.p99)}</td><td class="num">${pct(r.availability, 2)}</td></tr>`)),
  worker: (rs) => table([["État", 150], ["File"], ["Débit", 136], ["Messages/s", 96, 1], ["Échecs", 84, 1], ["p50", 78, 1], ["p95", 78, 1], ["En attente", 100, 1]],
    rs.map((r) => `<tr>${stateCell(r.state)}<td><span class="path">${esc(r.name)}</span><div class="sub">${esc(r.operation)}</div></td>
      <td>${spark(r.spark)}</td><td class="num">${nf(r.rps, 2)}</td><td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td>
      <td class="num">${msf(r.p50)}</td><td class="num">${msf(r.p95)}</td><td class="num ${r.backlog > 100 ? "bad" : ""}">${nf(r.backlog)}</td></tr>`)),
  job: (rs) => table([["État", 150], ["Tâche"], ["Dernier succès", 150, 1], ["Durée", 100, 1], ["Période", 100, 1], ["Dernière exécution", 160, 1]],
    rs.map((r) => `<tr>${stateCell(r.state)}<td><span class="path">${esc(r.name)}</span>${r.state === "degraded" ? `<div class="sub">en retard sur sa période</div>` : ""}</td>
      <td class="num">${r.last_success ? ago(r.last_success * 1000) : "jamais"}</td><td class="num">${r.duration == null ? "—" : msf(r.duration * 1000)}</td>
      <td class="num">${dur(r.period)}</td><td class="num ${r.ok === 0 ? "bad" : ""}">${r.ok === 0 ? "en échec" : r.ok === 1 ? "réussie" : "—"}</td></tr>`)),
  database: (rs) => table([["État", 150], ["Base"], ["Opération", 110], ["Trafic", 136], ["Op/s", 80, 1], ["Erreurs", 84, 1], ["p50", 78, 1], ["p95", 78, 1], ["p99", 78, 1]],
    rs.map((r) => `<tr>${stateCell(r.state)}<td><span class="path">${esc(r.name)}</span></td><td><span class="verb">${esc(r.operation)}</span></td>
      <td>${spark(r.spark)}</td><td class="num">${nf(r.rps, 2)}</td><td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td>
      <td class="num">${msf(r.p50)}</td><td class="num">${msf(r.p95)}</td><td class="num">${msf(r.p99)}</td></tr>`)),
  dependency: (rs) => table([["État", 150], ["Service"], ["Méthode", 76], ["Trafic", 136], ["Appels/s", 86, 1], ["Erreurs", 84, 1], ["p95", 78, 1], ["p99", 78, 1]],
    rs.map((r) => `<tr>${stateCell(r.state)}<td><span class="path">${esc(r.name)}</span></td><td><span class="verb ${esc(r.operation.toLowerCase())}">${esc(r.operation)}</span></td>
      <td>${spark(r.spark)}</td><td class="num">${nf(r.rps, 2)}</td><td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td>
      <td class="num">${msf(r.p95)}</td><td class="num">${msf(r.p99)}</td></tr>`)),
  process: (rs) => table([["État", 150], ["Processus"], ["CPU", 110, 1], ["Mémoire", 120, 1], ["Démarré depuis", 150, 1]],
    rs.map((r) => `<tr>${stateCell(r.state)}<td><span class="path">${esc(r.name)}</span></td><td class="num">${r.cpu == null ? "—" : pct(r.cpu, 1)}</td>
      <td class="num">${bytes(r.memory)}</td><td class="num">${dur(r.uptime)}</td></tr>`)),
};

async function loadRun() {
  try {
    const r = await fetch(`/api/run?window=${runWindow}`, { cache: "no-store" });
    runData = await r.json();
    if (!r.ok) throw new Error(runData.error);
  } catch (err) {
    $("#run").innerHTML = `<div class="note bad">Les métriques sont indisponibles : ${esc(err.message)}</div>`;
    return;
  }
  const d = runData, f = d.fleet, c = d.components;
  const total = c.api.reduce((acc, r) => r.spark.map((v, i) => (acc[i] || 0) + v), []);
  const budgetTone = f.budget == null ? "" : f.budget < 0 ? "bad" : f.budget < 0.25 ? "warn" : "";
  const down = d.targets.filter((t) => !t.up);
  const kpi = (label, value, sub, tone = "") => `<div class="kpi ${tone}"><div class="k">${label}</div><div class="v">${value}</div><div class="s">${sub}</div></div>`;
  const order = { failing: 0, degraded: 1, healthy: 2, idle: 3 };
  const kinds = Object.keys(KIND).filter((k) => c[k]?.length);
  const tile = (k) => {
    const rs = c[k], bad = rs.filter((r) => r.state === "failing").length, warn = rs.filter((r) => r.state === "degraded").length;
    const tone = bad ? "escalated" : warn ? "gap" : "held";
    const word = bad ? `${bad} en échec` : warn ? `${warn} ${warn > 1 ? "dégradés" : "dégradé"}` : "opérationnels";
    return `<a class="tile" href="#k-${k}"><span class="state ${tone}"><i></i></span><b>${rs.length}</b><span>${rs.length > 1 ? KIND[k][2] : KIND[k][1]}</span><em class="${tone}">${word}</em></a>`;
  };
  $("#run").innerHTML = `
    ${!d.targets.length ? `<div class="note warn">Aucune source de métriques n'est configurée. Ajoutez dans standard.toml : <span class="sha">[run] metrics = ["http://127.0.0.1:9000/metrics"]</span>.</div>` : ""}
    ${down.length ? `<div class="note bad">${plural(down.length, "source de métriques ne répond pas", "sources de métriques ne répondent pas")} : ${down.map((t) => esc(t.url)).join(", ")}.</div>` : ""}
    <div class="tiles">${kinds.map(tile).join("")}</div>
    <div class="kpis">
      ${kpi("Requêtes", `${nf(f.rps, 1)}<small>/s</small>`, `${nf(f.requests)} sur la période`)}
      ${kpi("Erreurs", pct(f.error_rate), "réponses 5xx", f.error_rate > 0.01 ? "bad" : "")}
      ${kpi("Latence p50", msf(f.p50), "médiane")}
      ${kpi("Latence p95", msf(f.p95), `p99 ${msf(f.p99)}`)}
      ${kpi("Disponibilité", pct(f.availability, 3), `objectif ${pct(d.slo, 1)}`, f.availability != null && f.availability < d.slo ? "bad" : "")}
      ${kpi("Budget d'erreur", f.budget == null ? "—" : f.budget < 0 ? "Épuisé" : pct(f.budget, 0),
        f.budget == null ? "pas de trafic" : f.budget < 0 ? `consommé à ${pct(1 - f.budget, 0)}` : "restant sur la période", budgetTone)}
    </div>
    ${c.api.length ? `<section class="chart"><h2>Trafic des APIs</h2>${area(total.length ? total : [0, 0])}</section>` : ""}
    ${kinds.map((k) => `<section id="k-${k}"><h2>${KIND[k][0]} <span class="quiet small">${c[k].length}${k === "api" && d.openapi ? ", déclarées dans openapi.json" : ""}</span></h2>
      ${SECTIONS[k]([...c[k]].sort((a, b) => order[a.state] - order[b.state] || (b.rps || 0) - (a.rps || 0)), d)}</section>`).join("")}
    <section class="cols">
      <div><h2>Mises en production</h2>${feed(6)}</div>
      <div><h2>Sources</h2><div class="rows">${d.targets.map((t) => `<div class="rowi"><div class="main"><span class="sha">${esc(t.url)}</span>
        <div class="facts">${fact(t.up ? "Répond" : `Ne répond pas : ${t.error}`, t.up ? "ok" : "bad")}${t.at ? fact(`dernière collecte ${ago(t.at * 1000)}`, "") : ""}</div></div></div>`).join("") || `<div class="rowi quiet">Aucune source</div>`}</div>
        <p class="small quiet" style="margin-top:12px">Les métriques sont des informations pour l'équipe : elles n'ouvrent aucun droit.</p></div>
    </section>`;
}

document.addEventListener("click", (e) => {
  const w = e.target.closest("[data-window]");
  if (w) { runWindow = Number(w.dataset.window); localSet("window", runWindow); render(); }
});

function activity() {
  const repairs = state.run.repairs;
  return `
    <h1>Activité</h1><p class="lede">Tout ce qui a atteint la branche principale, et ce que l'agent prépare.</p>
    ${repairs.length ? `<section><h2>Réparations de l'agent</h2><div class="rows">${repairs.map((p) => `
      <div class="rowi"><div class="main"><b>${esc(name(p.target))}</b> <span class="sha">${short(p.head)}</span>
        <div class="facts">${p.route === "recipe" ? fact("Reproduite à l'identique", p.facts.reproduced === "yes" ? "ok" : "")
          : fact(p.facts.review === "approved" ? "Revue approuvée" : "Revue requise", p.facts.review === "approved" ? "ok" : "wait")}
          ${fact(p.facts.tests === "green" ? "Tests au vert" : p.facts.tests ? "Tests en échec" : "Tests en cours", p.facts.tests === "green" ? "ok" : p.facts.tests ? "bad" : "")}
          ${p.submitted ? fact("Acceptée par la loi", "ok") : ""}</div></div>
        <button class="btn ${p.awaiting_review ? "primary" : ""}" data-review="${esc(p.resource)}">${p.awaiting_review ? "Relire" : "Détails"}</button></div>`).join("")}</div></section>` : ""}
    ${state.run.abandoned.length ? `<section><h2>Ce que l'agent n'a pas su réparer</h2>${state.run.abandoned.map((a) => `
      <div class="panel"><b>${esc(name(a.target))}</b><pre style="margin-top:12px">${esc(a.dossier)}</pre></div>`).join("")}</section>` : ""}
    <section><h2>Historique de production</h2>${feed(50)}</section>`;
}

function fact(text, tone) {
  return `<span class="fact ${tone}"><i></i>${esc(text)}</span>`;
}

function requirementTables() {
  return `${DOMAINS.map(([label, test]) => {
      const rs = state.requirements.filter(test);
      return rs.length ? `<section><h2>${label}</h2><table class="table req"><colgroup><col><col style="width:150px"><col style="width:190px"><col style="width:210px"></colgroup>
        <thead><tr><th>Exigence</th><th>État</th><th>Mesure</th><th>Réparée par</th></tr></thead><tbody>
      ${rs.map((r) => `<tr><td><div class="name">${esc(name(r.id))}</div><div class="sub">${esc(r.property)} = ${esc(r.expect)}</div>
        ${r.where.length && r.state === "gap" ? `<ul class="where">${r.where.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</td>
        <td><span class="state ${r.state}"><i></i>${STATES[r.state]}</span></td>
        <td class="sub">${esc(measure(r))}</td>
        <td class="sub">${WHO[r.who]}</td></tr>`).join("")}</tbody></table></section>` : "";
    }).join("")}`;
}

// ---- BUILD: the product being built -------------------------------------------------------------------------------
function contributions() {
  const cs = state.build.contributions;
  const status = (c) => c.landed ? fact("En production", "ok") : c.stale ? fact("La branche principale a avancé : à rebaser", "wait")
    : c.blocked.length ? fact("Bloquée par la loi", "bad") : c.awaiting_review ? fact("Attend une revue", "wait") : fact("Mesure en cours", "");
  return `<h1>Contributions</h1>
    <p class="lede">Le travail poussé par les développeurs. Il n'entre en production qu'avec les tests au vert, aucun nouvel écart et une revue signée.</p>
    <section>${cs.length ? `<div class="rows">${cs.map((c) => `
      <div class="rowi"><div class="main"><b>${esc(c.branch)}</b> <span class="quiet">par ${esc(c.author)}</span> <span class="sha">${short(c.head)}</span>
        <div class="facts">${status(c)}
          ${fact(c.facts.tests === "green" ? "Tests au vert" : c.facts.tests ? "Tests en échec" : "Tests en cours", c.facts.tests === "green" ? "ok" : c.facts.tests ? "bad" : "")}
          ${fact(c.facts.regressions === "none" ? "Aucun nouvel écart" : c.facts.regressions ? "Ouvre un nouvel écart" : "Écarts en cours", c.facts.regressions === "none" ? "ok" : c.facts.regressions ? "bad" : "")}</div>
        ${c.why.length ? `<ul class="where">${c.why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</div>
        ${c.landed ? "" : `<button class="btn ${c.awaiting_review ? "primary" : ""}" data-review="${esc(c.resource)}">${c.awaiting_review ? "Relire" : "Détails"}</button>`}</div>`).join("")}</div>`
      : `<div class="empty"><b>Aucune contribution</b>Poussez une branche à votre nom, par exemple <span class="sha">git push origin HEAD:refs/heads/vous/ma-branche</span>.</div>`}</section>`;
}

function requests() {
  return `<h1>Demandes</h1>
    <p class="lede">Décrivez une fonctionnalité et ses critères d'acceptation. Les critères deviennent des tests que vous validez avant que l'agent n'écrive le code ; il ne peut ensuite ni les modifier ni les contourner.</p>
    <section><div class="empty"><b>Bientôt disponible</b>Les demandes arrivent dans la prochaine version de Standard.</div></section>`;
}

// ---- governance -----------------------------------------------------------------------------------------------------
function reviews() {
  const items = pending();
  return `<h1>Revues</h1>
    <p class="lede">La loi a déjà vérifié les tests et l'absence de nouvel écart. Vous jugez le sens du changement. Votre signature porte sur ce commit exact : s'il change, il faut relire.</p>
    ${signer ? "" : `<div class="note warn" style="margin-top:24px">Pour signer, ajoutez votre clé dans Réglages.</div>`}
    <section>${items.length ? `<div class="rows">${items.map((i) => `
      <div class="rowi"><div class="main"><b>${i.kind === "contribution" ? esc(i.branch) : `Réparation : ${esc(name(i.target))}`}</b>
        <span class="quiet">${i.kind === "contribution" ? `par ${esc(i.author)}` : "par l'agent"}</span> <span class="sha">${short(i.head)}</span></div>
        <button class="btn primary" data-review="${esc(i.resource)}">Relire</button></div>`).join("")}</div>`
      : `<div class="empty"><b>Aucune revue en attente</b>Les contributions et réparations à relire apparaîtront ici.</div>`}</section>`;
}

function proofs() {
  const c = counts();
  return `<h1>Preuves</h1>
    <p class="lede">Chaque exigence tenue repose sur une observation signée par un instrument indépendant, inscrite dans un journal chaîné. C'est ce que vous remettez à un auditeur.</p>
    <section class="cols">
      <div class="panel"><h2>Journal</h2><p class="small quiet">Entrées : ${state.prefix.size}</p>
        <p class="small quiet">Tête : <span class="sha">${esc(state.prefix.head.slice(7, 23))}</span></p>
        <p class="small quiet">Loi : <span class="sha">${esc(state.law_digest.slice(7, 23))}</span></p>
        <p class="small quiet">${state.assessment === "INDEPENDENT" ? "Installation évaluée par un tiers indépendant." : "Installation auto-évaluée : ces preuves ne valent pas certification."}</p></div>
      <div class="panel"><h2>Couverture</h2><p class="small quiet">${c.held} exigences tenues sur ${c.total}, ${c.attest} attestations attendues, ${c.unmeasured} non mesurées sur cette installation.</p>
        <button class="btn" id="export">Télécharger le rapport</button></div>
    </section>`;
}

function settings() {
  const grants = state.signing.grants;
  return `<h1>Réglages</h1>
    <p class="lede">Votre clé de signature reste dans ce navigateur : elle y est importée sans pouvoir en sortir, et n'est jamais envoyée au serveur. Le navigateur fabrique lui-même ce qu'il signe.</p>
    <section class="panel">${signer
      ? `<div class="note ok">Ce navigateur signe en tant que <b>${esc(signer.identity)}</b>.</div><button class="btn danger" id="forget">Retirer la clé de ce navigateur</button>`
      : `<h2>Ajouter votre clé</h2>
        <label for="ident">Identité</label><input id="ident" type="text" value="${esc(grants.reviewer?.holder || "")}" autocomplete="off">
        <label for="keyfile">Fichier de clé</label><input id="keyfile" type="file">
        <p class="small quiet">Installation de démonstration : le fichier créé par la cérémonie. En production, une passkey sur votre appareil.</p>
        <button class="btn primary" id="import">Ajouter la clé</button> <span id="msg" class="small quiet"></span>`}</section>
    <section><h2>Rôles</h2><table class="table"><thead><tr><th>Rôle</th><th>Personne</th></tr></thead><tbody>
      ${Object.entries(grants).map(([k, g]) => `<tr><td>${k === "reviewer" ? "Relecteur" : k === "officer" ? "Responsable conformité" : esc(k)}</td><td>${esc(g.holder)}</td></tr>`).join("")}
    </tbody></table></section>`;
}

function bindSettings() {
  $("#forget")?.addEventListener("click", async () => { await forgetSigner(); signer = null; render(); });
  $("#import")?.addEventListener("click", async () => {
    const file = $("#keyfile").files[0], ident = $("#ident").value.trim();
    try {
      if (!file || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(ident)) throw new Error("indiquez une identité et un fichier de clé");
      const s = await importKeyFile(await file.text());
      await saveSigner(ident, s);
      signer = { identity: ident, ...s };
      render();
    } catch (err) { $("#msg").textContent = `La clé n'a pas été ajoutée : ${err.message}`; }
  });
}

document.addEventListener("click", (e) => {
  if (e.target.id === "export") {
    const report = { product: state.product, main: state.main, journal: state.prefix, law: state.law_digest,
      assessment: state.assessment, requirements: state.requirements, generated_at: new Date().toISOString() };
    const a = Object.assign(document.createElement("a"), { download: `standard-${state.product}-${state.main.slice(0, 7)}.json`,
      href: URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" })) });
    a.click();
  }
  const cell = e.target.closest("[data-req]");
  if (cell) location.hash = "#/compliance";
});

// ---- reviewing and signing -----------------------------------------------------------------------------------------
async function openReview(resource) {
  const item = [...state.build.contributions, ...state.run.repairs].find((i) => i.resource === resource);
  const head = resource.split("/").pop(), dlg = $("#dlg"), body = $("#dlgbody");
  body.innerHTML = `<p class="quiet">Chargement du dossier</p>`;
  dlg.showModal();
  let d;
  try {
    const r = await fetch(`/api/dossier/${head}`);
    d = await r.json();
    if (!r.ok) throw new Error(d.error);
  } catch (err) {
    body.innerHTML = `<div class="note bad">Le dossier est indisponible : ${esc(err.message)}</div><footer><button class="btn" id="close">Fermer</button></footer>`;
    $("#close").onclick = () => dlg.close();
    return;
  }
  const diff = esc(d.diff).split("\n").map((l) => /^\+(?!\+\+)/.test(l) ? `<span class="add">${l}</span>` : /^-(?!--)/.test(l) ? `<span class="del">${l}</span>` : l).join("\n");
  const grant = state.signing.grants.reviewer, can = Boolean(signer && item?.awaiting_review && grant);
  body.innerHTML = `
    <h2>${item?.kind === "contribution" ? esc(item.branch) : `Réparation : ${esc(name(item?.target))}`}</h2>
    <div class="quiet small">${item?.kind === "contribution" ? `par ${esc(item.author)}` : "par l'agent"}, commit <span class="sha">${short(head)}</span> sur <span class="sha">${short(resource.split("/").slice(-2)[0])}</span></div>
    <div class="facts">${fact(item?.facts.tests === "green" ? "Tests au vert" : "Tests non verts", item?.facts.tests === "green" ? "ok" : "bad")}
      ${item?.kind === "contribution" ? fact(item.facts.regressions === "none" ? "Aucun nouvel écart" : "Ouvre un nouvel écart", item.facts.regressions === "none" ? "ok" : "bad") : ""}</div>
    <h3>Description</h3><pre>${esc(d.message)}</pre>
    <h3>Changements</h3><pre>${diff}</pre>
    ${!signer ? `<div class="note warn" style="margin-top:18px">Ajoutez votre clé dans Réglages pour signer.</div>` : ""}
    ${signer && !item?.awaiting_review ? `<div class="note warn" style="margin-top:18px">Ce commit n'attend pas de revue : il est déjà signé, bloqué par la loi ou encore en mesure.</div>` : ""}
    <footer><span id="sigmsg" class="small quiet spacer"></span><button class="btn" id="close">Fermer</button>
      <button class="btn" id="changes" ${can ? "" : "disabled"}>Demander des changements</button>
      <button class="btn primary" id="approve" ${can ? "" : "disabled"}>Approuver</button></footer>`;
  $("#close").onclick = () => dlg.close();
  const sign = async (verdict) => {
    $("#sigmsg").textContent = "Signature dans ce navigateur";
    const statement = { id: `review-${crypto.randomUUID().replaceAll("-", "")}`, at: Math.max(Date.now(), state.signing.as_of + 1),
      author: signer.identity, under: grant.id, resource, property: "review", status: verdict, level: "real" };
    try {
      const env = await envelope(state.signing.domain, "observation", statement, signer);
      const r = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
      const out = await r.json();
      if (!r.ok) throw new Error(out.refused || out.error);
      $("#sigmsg").textContent = verdict === "approved" ? "Approuvé" : "Changements demandés";
      setTimeout(() => { dlg.close(); refresh(); }, 800);
    } catch (err) { $("#sigmsg").textContent = `Signature refusée par le noyau : ${err.message}`; }
  };
  if (can) { $("#approve").onclick = () => sign("approved"); $("#changes").onclick = () => sign("changes_requested"); }
}

// ---- start ----------------------------------------------------------------------------------------------------------
signer = await loadSigner().catch(() => null);
await refresh();
setInterval(() => { if (!$("#dlg").open && route() !== "settings") refresh(); }, 15000);
