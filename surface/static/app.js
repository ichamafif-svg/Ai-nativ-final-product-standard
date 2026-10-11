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
  "run-sources": "Métriques de production collectées", "run-slo": "Objectif de service tenu", "run-live": "main en production",
};
const DOMAINS = [
  ["Sécurité du code", (r) => repo(r) && r.domain === "code"],
  ["Dépendances et chaîne logicielle", (r) => repo(r) && ["deps", "supply"].includes(r.domain)],
  ["Intégration continue", (r) => repo(r) && r.domain === "ci"],
  ["Gouvernance du code", (r) => repo(r) && ["settings", "main", "inventory"].includes(r.domain)],
  ["Production", (r) => r.resource.startsWith("run:")],
  ["Organisation", (r) => r.resource.startsWith("org:")],
];
const repo = (r) => r.resource.startsWith("repo:");
const STATES = {
  held: "Tenue", gap: "Écart", escalated: "Escaladée", attest: "À attester", unmeasured: "Non mesurée", pending: "En mesure",
};
const WHO = { agent: "L'agent seul", review: "L'agent, puis une revue", people: "Une personne" };
const name = (id) => NAMES[id] || id;
const LEVEL = {
  autonomous: ["held", "Autonome", "L'agent répare seul"], supervised: ["gap", "Supervisée", "L'agent prépare, une personne signe"],
  human: ["attest", "Humaine", "Seules des personnes agissent"], observed: ["pending", "Observation", "Standard mesure, personne n'agit par lui"],
};
const RAISE = {
  autonomous: "Déjà au maximum : rien n'entre sans preuve indépendante, et cette preuve suffit.",
  supervised: "Une recette dont le résultat se recalcule à l'identique ferait passer ce type de correction en autonome.",
  human: "Un instrument qui mesure ce point dans le code ou la plateforme remplacerait l'attestation.",
  observed: "Une opération d'exploitation dans la loi (par exemple revenir à la version précédente), exécutée par la garde sous conditions mesurées.",
};
const levelTag = (lv) => `<span class="state ${LEVEL[lv][0]}"><i></i>${LEVEL[lv][1]}</span>`;
const VALUES = { met: "tenu", behind: "en retard", none: "aucun", current: "à jour", complete: "complète", green: "au vert", red: "en échec", all: "toutes",
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
  run: ["Run", "run"], alerts: ["Alertes", "run"], objectives: ["Objectifs et règles", "run"], autonomy: ["Autonomie", "run"], compliance: ["Conformité", "run"], activity: ["Activité", "run"],
  contributions: ["Contributions", "build"], requests: ["Demandes", "build"],
  reviews: ["Revues", "both"], proofs: ["Preuves", "both"], settings: ["Réglages", "both"],
};
let state = null, signer = null, alerting = null;
const route = () => (location.hash.slice(2) in ROUTES ? location.hash.slice(2) : "run");
window.addEventListener("hashchange", () => render());

function pending() {
  return [...state.build.contributions.filter((c) => c.awaiting_review), ...state.run.repairs.filter((r) => r.awaiting_review)];
}

function frame() {
  const here = route(), reviews = pending().length, untaken = alerting?.untaken || 0;
  const badge = (id) => id === "reviews" && reviews ? `<span class="badge">${reviews}</span>`
    : id === "alerts" && untaken ? `<span class="badge alarm">${untaken}</span>` : "";
  const link = (id) => `<a href="#/${id}" ${id === here ? 'aria-current="page"' : ""}><span>${ROUTES[id][0]}</span>${badge(id)}</a>`;
  document.title = untaken ? `(${untaken}) Standard` : "Standard";
  $("#nav").innerHTML = `
    <div class="group">Exploitation</div>${link("run")}${link("alerts")}${link("objectives")}${link("autonomy")}${link("compliance")}${link("activity")}
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
    const [r, a] = await Promise.all([fetch("/api/state", { cache: "no-store" }), fetch("/api/alerts", { cache: "no-store" })]);
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || r.statusText);
    state = body;
    alerting = a.ok ? await a.json() : null;
    render();
  } catch (err) {
    $("#view").innerHTML = `<div class="note bad">Standard ne répond pas ou n'est pas qualifié sur ce serveur : ${esc(err.message)}. Rien n'est attesté ni autorisé tant que ce n'est pas rétabli.</div>`;
  }
}

function render() {
  if (!state) return;
  frame();
  const views = { run: runView, alerts: alertsView, objectives: objectivesView, autonomy, compliance, activity, contributions, requests, reviews, proofs, settings };
  $("#view").innerHTML = banner() + views[route()]();
  if (route() === "run") loadRun();
  if (route() === "objectives") loadObjectives();
  if (route() === "settings") bindSettings();
  document.querySelectorAll("[data-review]").forEach((b) => b.addEventListener("click", () => openReview(b.dataset.review)));
  document.querySelectorAll("[data-ack]").forEach((b) => b.addEventListener("click", () => take(b)));
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

function autonomy() {
  const a = state.autonomy, c = a.count, n = a.total, share = (k) => Math.round((100 * c[k]) / Math.max(n, 1));
  const blocked = a.requirements.filter((r) => r.blocked).length;
  return `<h1>Autonomie</h1>
    <p class="lede">Ce que Standard fait sans personne, pour chaque élément, et pourquoi pas davantage. L'autonomie n'est jamais une confiance accordée à l'agent : elle existe seulement là où une preuve indépendante suffit.</p>
    <section class="autosum">
      <div class="panel"><h2>Code et conformité</h2>
        <div class="bar">${["autonomous", "supervised", "human"].map((k) => `<span class="seg-${k}" style="flex:${c[k]}" title="${LEVEL[k][1]} : ${c[k]}"></span>`).join("")}</div>
        <ul class="levels">${["autonomous", "supervised", "human"].map((k) => `<li>${levelTag(k)}<b>${c[k]} sur ${n}</b><span>${share(k)} %</span><p>${esc(a.levels[k])}</p></li>`).join("")}</ul>
        ${blocked ? `<p class="small quiet">${plural(blocked, "exigence n'est pas mesurée", "exigences ne sont pas mesurées")} sur cette installation : leur autonomie reste théorique tant qu'aucun instrument ne les couvre.</p>` : ""}
      </div>
      <div class="panel"><h2>Exploitation</h2>${levelTag("observed")}<p>${esc(a.runtime.why)}</p>
        <p class="small quiet">Pour aller plus loin : ${esc(RAISE.observed)}</p></div>
    </section>
    ${["autonomous", "supervised", "human"].map((lv) => {
      const rs = a.requirements.filter((r) => r.level === lv);
      return rs.length ? `<section class="lvl"><div class="lvlhead">${levelTag(lv)}<h2>${LEVEL[lv][2]}</h2><span class="quiet">${rs.length} sur ${n}</span></div>
        <div class="lvlbody"><div><h3>Pourquoi cette limite</h3><p>${esc(a.levels[lv])}</p><h3>Ce qui l'augmenterait</h3><p>${esc(RAISE[lv])}</p></div>
        <ul class="items">${rs.map((r) => `<li><b>${esc(name(r.id))}</b>${r.condition ? `<span class="cond">${esc(r.condition)}</span>` : ""}${r.blocked ? `<span class="cond bad">Non mesurée ici : autonomie théorique.</span>` : ""}</li>`).join("")}</ul></div></section>` : "";
    }).join("")}
    <section class="lvl"><div class="lvlhead">${levelTag("observed")}<h2>${LEVEL.observed[2]}</h2><span class="quiet">tous les composants en exploitation</span></div>
      <div class="lvlbody"><div><h3>Pourquoi cette limite</h3><p>${esc(a.runtime.why)}</p><h3>Ce qui l'augmenterait</h3><p>${esc(RAISE.observed)}</p></div>
      <ul class="items">${["APIs", "Workers et files", "Tâches planifiées", "Bases de données", "Services externes", "Processus"].map((k) => `<li><b>${k}</b></li>`).join("")}</ul></div></section>`;
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
const ROUTE_STATE = { healthy: ["held", "Opérationnel"], degraded: ["gap", "Dégradé"], failing: ["escalated", "En échec"], idle: ["pending", "Aucun trafic"] };

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
const pctx = (v) => pct(v, Math.min(3, Math.max(0, String(+(v * 100).toFixed(3)).split(".")[1]?.length || 0)));   // as set
function reason(w) {
  if (!w) return "";
  return {
    no_traffic: "aucune requête sur la période",
    error_rate: `${pct(w.value)} d'erreurs, seuil ${pctx(w.limit)}`,
    availability: `disponibilité ${pct(w.value, 2)}, objectif ${pctx(w.limit)}`,
    p99: `p99 ${msf(w.value)}, seuil ${msf(w.limit)}`,
    job_failed: "dernière exécution échouée",
    job_never: "jamais réussie",
    job_late: `aucun succès depuis ${dur(w.value)}, limite ${dur(w.limit)}`,
    burn: `budget consommé à ${nf(w.value, 1)}× son débit sur ${w.span}${w.budget != null ? `, ${w.budget < 0 ? "épuisé" : pct(w.budget, 0) + " restant"}` : ""}`,
  }[w.rule] || "";
}
const stateCell = (s, w) => `<td><span class="state ${ROUTE_STATE[s][0]}"><i></i>${ROUTE_STATE[s][1]}</span>${s !== "healthy" && w ? `<div class="sub">${esc(reason(w))}</div>` : ""}</td>`;

const CAP = { see: "Voit", alert: "Prévient", act: "Agit", prove: "Prouve" };
function frontierCell(r) {
  const why = runData.frontier_reasons;
  return `<td><div class="fr">${Object.keys(CAP).map((k) => `<span class="f ${r.frontier[k] ? "on" : ""}" title="${esc(r.frontier[k] ? why[k].yes : why[k].no)}">${CAP[k]}</span>`).join("")}</div></td>`;
}

function table(cols, rows) {
  return `<table class="table api"><colgroup>${cols.map(([, w]) => `<col${w ? ` style="width:${w}px"` : ""}>`).join("")}</colgroup>
    <thead><tr>${cols.map(([h, , num]) => `<th class="${num ? "num" : ""}">${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

const SECTIONS = {
  api: (rs, d) => table([["État", 132], ["Autonomie", 238], ["Route"], ["Trafic", 92], ["Req/s", 62, 1], ["Erreurs", 70, 1], ["p50", 64, 1], ["p95", 64, 1], ["p99", 64, 1], ["Dispo.", 78, 1]],
    rs.map((r) => `<tr class="${r.state === "idle" ? "idle" : ""}">${stateCell(r.state, r.why)}${frontierCell(r)}
      <td><span class="verb ${esc(r.operation.toLowerCase())}">${esc(r.operation)}</span> <span class="path">${esc(r.name)}</span>${r.observed && !r.declared && d.openapi ? `<div class="sub">absente d'openapi.json</div>` : ""}</td>
      <td>${r.observed ? spark(r.spark, 84) : ""}</td><td class="num">${r.observed ? nf(r.rps, 2) : "—"}</td>
      <td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td><td class="num">${msf(r.p50)}</td>
      <td class="num">${msf(r.p95)}</td><td class="num">${msf(r.p99)}</td><td class="num">${pct(r.availability, 2)}</td></tr>`)),
  worker: (rs) => table([["État", 132], ["Autonomie", 238], ["File"], ["Messages/s", 92, 1], ["Échecs", 76, 1], ["p50", 70, 1], ["p95", 70, 1], ["En attente", 92, 1]],
    rs.map((r) => `<tr>${stateCell(r.state, r.why)}${frontierCell(r)}<td><span class="path">${esc(r.name)}</span><div class="sub">${esc(r.operation)}</div></td>
      <td class="num">${nf(r.rps, 2)}</td><td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td>
      <td class="num">${msf(r.p50)}</td><td class="num">${msf(r.p95)}</td><td class="num ${r.backlog > 100 ? "bad" : ""}">${nf(r.backlog)}</td></tr>`)),
  job: (rs) => table([["État", 132], ["Autonomie", 238], ["Tâche"], ["Dernier succès", 120, 1], ["Durée", 80, 1], ["Période", 80, 1], ["Dernière exécution", 140, 1]],
    rs.map((r) => `<tr>${stateCell(r.state, r.why)}${frontierCell(r)}<td><span class="path">${esc(r.name)}</span></td>
      <td class="num">${r.last_success ? ago(r.last_success * 1000) : "jamais"}</td><td class="num">${r.duration == null ? "—" : msf(r.duration * 1000)}</td>
      <td class="num">${dur(r.period)}</td><td class="num ${r.ok === 0 ? "bad" : ""}">${r.ok === 0 ? "en échec" : r.ok === 1 ? "réussie" : "—"}</td></tr>`)),
  database: (rs) => table([["État", 132], ["Autonomie", 238], ["Base et opération"], ["Op/s", 70, 1], ["Erreurs", 76, 1], ["p50", 70, 1], ["p95", 70, 1], ["p99", 70, 1]],
    rs.map((r) => `<tr>${stateCell(r.state, r.why)}${frontierCell(r)}<td><span class="verb">${esc(r.operation)}</span> <span class="path">${esc(r.name)}</span></td>
      <td class="num">${nf(r.rps, 2)}</td><td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td>
      <td class="num">${msf(r.p50)}</td><td class="num">${msf(r.p95)}</td><td class="num">${msf(r.p99)}</td></tr>`)),
  dependency: (rs) => table([["État", 132], ["Autonomie", 238], ["Service"], ["Appels/s", 80, 1], ["Erreurs", 76, 1], ["p95", 70, 1], ["p99", 70, 1]],
    rs.map((r) => `<tr>${stateCell(r.state, r.why)}${frontierCell(r)}<td><span class="verb ${esc(r.operation.toLowerCase())}">${esc(r.operation)}</span> <span class="path">${esc(r.name)}</span></td>
      <td class="num">${nf(r.rps, 2)}</td><td class="num ${r.error_rate > 0.01 ? "bad" : ""}">${pct(r.error_rate)}</td>
      <td class="num">${msf(r.p95)}</td><td class="num">${msf(r.p99)}</td></tr>`)),
  process: (rs) => table([["État", 132], ["Autonomie", 238], ["Processus"], ["CPU", 90, 1], ["Mémoire", 100, 1], ["Démarré depuis", 130, 1]],
    rs.map((r) => `<tr>${stateCell(r.state, r.why)}${frontierCell(r)}<td><span class="path">${esc(r.name)}</span></td><td class="num">${r.cpu == null ? "—" : pct(r.cpu, 1)}</td>
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
    const word = bad ? `${bad} en échec` : warn ? `${warn} ${warn > 1 ? "dégradés" : "dégradé"}` : rs.length > 1 ? "opérationnels" : "opérationnel";
    const acts = rs.some((r) => r.frontier.act);
    return `<a class="tile" href="#k-${k}"><span class="state ${tone}"><i></i></span><b>${rs.length}</b><span>${rs.length > 1 ? KIND[k][2] : KIND[k][1]}</span><em class="${tone}">${word}</em>
      <small>${acts ? "voit et agit" : "voit, n'agit pas"}</small></a>`;
  };
  $("#run").innerHTML = `
    ${!d.targets.length ? `<div class="note warn">Aucune source de métriques n'est configurée. Ajoutez dans standard.toml : <span class="sha">[run] metrics = ["http://127.0.0.1:9000/metrics"]</span>.</div>` : ""}
    ${down.length ? `<div class="note bad">${plural(down.length, "source de métriques ne répond pas", "sources de métriques ne répondent pas")} : ${down.map((t) => esc(t.url)).join(", ")}.</div>` : ""}
    <div class="tiles">${kinds.map(tile).join("")}</div>
    <div class="defs">
      <p><span class="state held"><i></i>Opérationnel</span> moins de ${pctx(1 - d.rules.slo)} d'erreurs (objectif de disponibilité ${pctx(d.rules.slo)}) et p99 sous ${msf(d.rules.slow_p99_ms)}.</p>
      <p><span class="state gap"><i></i>Dégradé</span> disponibilité sous l'objectif, ou p99 au-dessus de ${msf(d.rules.slow_p99_ms)}. Pour une tâche planifiée : aucun succès depuis ${d.rules.late_periods} périodes.</p>
      <p><span class="state escalated"><i></i>En échec</span> ${pctx(d.rules.failing_error_rate)} d'erreurs ou plus. Pour une tâche planifiée : sa dernière exécution a échoué.</p>
      <p><span class="state pending"><i></i>Aucun trafic</span> aucune requête sur la période choisie.</p>
    </div>
    <section class="frontier"><h2>Frontière d'autonomie <span class="quiet small">ce que Standard fait seul pour ces ${d.frontier_total.of} composants</span></h2>
      <div class="caps">${Object.keys(CAP).map((k) => { const n = d.frontier_total[k], all = d.frontier_total.of, on = n === all && all > 0;
        return `<div class="cap ${on ? "on" : n ? "part" : "off"}"><div class="ck"><i></i>${CAP[k]}</div><div class="cv">${n} sur ${all}</div>
          <p>${esc(on || (n && k !== "prove") ? d.frontier_reasons[k].yes : n ? `${d.frontier_reasons[k].yes} Les processus et les services externes sont montrés, pas comptés dans ce fait.` : d.frontier_reasons[k].no)}</p></div>`; }).join("")}</div>
      ${d.uncovered.length ? `<div class="uncov"><h3>${d.live.configured ? `${plural(d.uncovered.length, "composant dégradé", "composants dégradés")} sur la période : une personne doit les prendre, sauf retour de version` : `${plural(d.uncovered.length, "écart n'est couvert", "écarts ne sont couverts")} par aucune autonomie : une personne doit les prendre`}</h3>
        ${d.uncovered.map((u) => `<div class="ucrow"><span class="state ${ROUTE_STATE[u.state]?.[0] || "pending"}"><i></i>${ROUTE_STATE[u.state]?.[1] || u.state}</span>
          <b>${esc([u.operation && u.kind !== "worker" ? u.operation : "", u.name].filter(Boolean).join(" "))}</b><span class="quiet">${esc(KIND[u.kind][1])}</span>
          <span class="why">${esc(u.seen ? reason(u.why) : "Standard ne le voit plus")}. ${u.seen ? `Signalé dans <a href="#/alerts">Alertes</a>. ${d.live.configured ? "Retour de version seulement s'il suit une mise en production." : "Standard n'agit pas."}` : "Rien ne garantit son état."}</span></div>`).join("")}</div>`
        : `<p class="small quiet">Aucun composant dégradé en ce moment. Si l'un se dégrade, il est signalé dans Alertes ; ${d.live.configured ? "Standard revient à la version précédente seulement si la dégradation suit une mise en production" : "Standard n'agit pas"}.</p>`}
      <a class="small" href="#/autonomy">Toute l'autonomie, code compris</a>
    </section>
    <div class="kpis">
      ${kpi("Requêtes", `${nf(f.rps, 1)}<small>/s</small>`, `${nf(f.requests)} sur la période`)}
      ${kpi("Erreurs", pct(f.error_rate), "réponses 5xx", f.error_rate > 0.01 ? "bad" : "")}
      ${kpi("Latence p50", msf(f.p50), "médiane")}
      ${kpi("Latence p95", msf(f.p95), `p99 ${msf(f.p99)}`)}
      ${kpi("Disponibilité", pct(f.availability, 3), `objectif ${pctx(d.slo)}`, f.availability != null && f.availability < d.slo ? "bad" : "")}
      ${kpi("Budget d'erreur", f.budget == null ? "—" : f.budget < 0 ? "Épuisé" : pct(f.budget, 0),
        f.budget == null ? "pas de trafic" : f.budget < 0 ? `consommé à ${pct(1 - f.budget, 0)}` : "restant sur la période", budgetTone)}
    </div>
    ${Object.keys(d.live.slos || {}).length ? `<section><h2>SLO <span class="quiet small">budget d'erreur sur la fenêtre de chaque SLO ; <a href="#/objectives">régler</a></span></h2><div class="slostrip">${Object.entries(d.live.slos).map(([id, e]) => `
      <div class="panel"><div class="slohead"><b>${esc(e.name)}</b>${e.fast ? `<span class="sev page">Page</span>` : e.slow ? `<span class="sev ticket">Ticket</span>` : ""}</div>
        <div class="small quiet">${pctx(e.target / 100)} sur ${e.window_d} j · conformité ${e.compliance == null ? "—" : pct(e.compliance, 3)}</div>${budgetBar(e.budget)}
        <div class="burns small">${Object.entries(e.burn || {}).map(([span, v]) => `<span>${fmtBurn(v)} ${span}</span>`).join("")}</div></div>`).join("")}</div></section>` : ""}
    ${c.api.length ? `<section class="chart"><h2>Trafic des APIs</h2>${area(total.length ? total : [0, 0])}</section>` : ""}
    ${kinds.map((k) => `<section id="k-${k}"><h2>${KIND[k][0]} <span class="quiet small">${c[k].length}${k === "api" && d.openapi ? ", déclarées dans openapi.json" : ""}</span></h2>
      ${SECTIONS[k]([...c[k]].sort((a, b) => order[a.state] - order[b.state] || (b.rps || 0) - (a.rps || 0)), d)}</section>`).join("")}
    ${liveSection(d.live)}
    <section class="cols">
      <div><h2>Branche principale</h2>${feed(6)}</div>
      <div><h2>Sources</h2><div class="rows">${d.targets.map((t) => `<div class="rowi"><div class="main"><span class="sha">${esc(t.url)}</span>
        <div class="facts">${fact(t.up ? "Répond" : `Ne répond pas : ${t.error}`, t.up ? "ok" : "bad")}${t.at ? fact(`dernière collecte ${ago(t.at * 1000)}`, "") : ""}</div></div></div>`).join("") || `<div class="rowi quiet">Aucune source</div>`}</div>
        <p class="small quiet" style="margin-top:12px">Les métriques sont des informations pour l'équipe : elles n'ouvrent aucun droit.</p></div>
    </section>`;
}

document.addEventListener("click", async (e) => {
  const m = e.target.closest("[data-silence]");
  if (m && alerting) {
    m.disabled = true;
    const id = "m-" + crypto.randomUUID().replaceAll("-", "").slice(0, 8), g = alerting.signing.engineer;
    try {
      for (const [k, v] of [["target_of", m.dataset.silence], ["reason", "silencée depuis Alertes"], ["until", String(Date.now() + 3_600_000)]]) {
        await signFact(alerting.signing.domain, Math.max(Date.now(), alerting.signing.as_of + 1), g, `run:policy/${id}/${k}`, "value", v);
      }
      m.textContent = "Silence signé : appliqué au prochain passage";
    } catch (err) { m.textContent = `Refusé : ${err.message}`; }
    return;
  }
  const d = e.target.closest("[data-decide]");
  if (d && runData) {
    d.disabled = true;
    const at = Math.max(Date.now(), state.signing.as_of + 1);
    try {
      await signFact(state.signing.domain, at, runData.live.grant, d.dataset.decide, d.dataset.prop, "yes");
      d.textContent = "Signé : la garde exécute au prochain passage";
    } catch (err) { d.textContent = `Refusé : ${err.message}`; }
    return;
  }
  const w = e.target.closest("[data-window]");
  if (w) { runWindow = Number(w.dataset.window); localSet("window", runWindow); render(); }
});

const SWITCH = { deploy: "Mise en production", rollback: "Retour à la version précédente", restart: "Redémarrage sans coupure",
  canary: "Canary démarré", abort: "Canary retiré" };
const LAG = { none: ["held", "main est en production"], behind: ["gap", "main n'est pas en production"] };
const DETAIL = {
  "main's head was rolled back: a new commit on main is needed": ["La version de main a été retirée par un retour arrière : il faut un nouveau commit sur main", "bad"],
  "no earlier release is known to have met the objective": ["Aucune version précédente n'a tenu l'objectif : pas de retour possible", "wait"],
};
function liveDetail(x) {
  const [k, ...rest] = x.split(": "), v = rest.join(": ");
  if (k === "live") return fact(`en production : ${v.slice(0, 7) || "aucune"}`, "");
  if (k === "main") return fact(`main : ${v.slice(0, 7)}`, "");
  if (k === "rolled_back") return v ? fact(`versions retirées : ${v.split(", ").map((s) => s.slice(0, 7)).join(", ")}`, "") : "";
  if (k === "canary") return "";
  if (k === "served") return v && v !== "None" ? fact(`version qui répond : ${v.slice(0, 7)}`, "") : fact("le produit ne dit pas quelle version répond", "wait");
  const RULES = [
    [/^migration not declared compatible: (.*)$/, (m) => [`Retour impossible : migration non déclarée compatible (${m[1]}). Une personne corrige en avant.`, "bad"]],
    [/^stepping back across a compatible migration is turned off$/, () => ["Retour à travers une migration compatible désactivé dans les règles", "wait"]],
    [/^automatic deployment is off/, () => ["Mise en production automatique désactivée : un ingénieur approuve", "wait"]],
    [/^automatic rollback is off/, () => ["Retour automatique désactivé : un ingénieur décide", "wait"]],
    [/^(\w{7})\w* never answered: (\w{7})\w* still serves$/, (m) => [`${m[1]} n'a jamais répondu : ${m[2]} sert toujours, retour automatique`, "bad"]],
    [/^automatic restart is off$/, () => ["Redémarrage automatique désactivé", ""]],
    [/^deployments are frozen$/, () => ["Mises en production gelées par un ingénieur", "wait"]],
    [/^outside the deployment window \((.*)\)$/, (m) => [`Hors de la fenêtre de mise en production (${m[1]})`, "wait"]],
    [/^error budget left ([\d.]+) % is under ([\d.]+) %: frozen$/, (m) => [`Budget d'erreur restant ${m[1]} % sous ${m[2]} % : mises en production gelées`, "wait"]],
    [/^the breach follows a switch/, () => ["La rupture suit une mise en production : redémarrer le même code ne la corrigerait pas", "wait"]],
    [/^(\d+) restarts in the last hour/, (m) => [`${m[1]} redémarrages dans l'heure : budget épuisé, une personne décide`, "bad"]],
  ];
  for (const [rx, f] of RULES) { const m = v.match(rx); if (m) { const [text, tone] = f(m); return fact(text, tone); } }
  const known = DETAIL[v] || (/^live for (\d+) min/.test(v) ? [`En production depuis ${v.match(/\d+/)[0]} min avant la rupture : le retour de version ne lui est pas attribué, une personne décide`, "wait"] : [v, ""]);
  return fact(known[0], known[1]);
}
function canaryText(v) {
  let m;
  if ((m = v.match(/^canary on (\d+) % of traffic: (\d+) requests so far$/))) return `${m[2]} requêtes reçues, en attente du minimum`;
  if ((m = v.match(/^canary baking: (\d+)\/(\d+) min, (\d+)\/(\d+) requests, no worse so far$/))) return `en essai : ${m[1]}/${m[2]} min, ${m[3]}/${m[4]} requêtes, pas pire jusqu'ici`;
  if ((m = v.match(/^canary fails ([\d.]+) points more/))) return `${m[1]} points d'erreurs de plus que la version en place : retrait`;
  if ((m = v.match(/^canary held (\d+) min on (\d+) requests/))) return `tenu ${m[1]} min sur ${m[2]} requêtes : promotion`;
  if (v.startsWith("main moved on")) return "main a avancé : le canary est retiré";
  return v;
}
function liveSection(live) {
  if (!live.configured) {
    return `<section><h2>Version en production</h2><div class="note warn">Aucune mise en production n'est confiée à Standard. Ajoutez dans standard.toml une section <span class="sha">[deploy] root = "run"</span> : Standard déploiera main et reviendra à la version précédente si l'objectif casse.</div></section>`;
  }
  const lag = LAG[live.lag] || ["pending", live.lag ? "non mesuré" : "pas encore mesuré"];
  const canary = live.canary ? `<div class="rowi"><div class="main"><span class="state gap"><i></i>Canary en cours</span> <span class="sha">${short(live.canary.release)}</span> sur ${live.canary.percent ?? "?"} % du trafic
      <div class="facts">${fact(`depuis ${ago(live.canary.since).replace("il y a ", "")}`, "")}${(live.details.find((x) => x.startsWith("canary: ")) || "").replace("canary: ", "") ? fact(canaryText((live.details.find((x) => x.startsWith("canary: ")) || "").slice(8)), "wait") : ""}</div></div></div>` : "";
  return `<section><h2>Version en production <span class="quiet small">faits signés par le scanner, bascules faites par le gardien</span></h2>
    <div class="rows">${canary}<div class="rowi"><div class="main"><span class="state ${lag[0]}"><i></i>${lag[1]}</span>
      <div class="facts">${live.slo ? fact(`objectif sur les 5 dernières minutes, signé : ${live.slo === "met" ? "tenu" : live.slo.startsWith("breached") ? "rompu" : "non mesuré"}`, live.slo === "met" ? "ok" : live.slo.startsWith("breached") ? "bad" : "wait") : ""}${live.details.map(liveDetail).filter(Boolean).join("")}</div></div></div>
    ${live.switches.map((s) => `<div class="rowi"><div class="main"><b>${SWITCH[s.op] || esc(s.op)}</b> ${s.op === "restart" ? `<span class="sha">${short(s.to)}</span>` : `<span class="sha">${short(s.from)}</span> → <span class="sha">${short(s.to)}</span>`}
      <div class="facts">${fact(ago(s.at), "")}${fact({ rollback: "sur une rupture de l'objectif", restart: "sur une rupture, même version", canary: `sur ${s.percent ?? "?"} % du trafic`, abort: "plus d'erreurs que la version en place" }[s.op] || "main jugée", ["deploy", "canary"].includes(s.op) ? "ok" : "wait")}</div></div></div>`).join("")
      || `<div class="rowi quiet">Aucune bascule pour l'instant</div>`}</div>
    ${liveActions(live)}</section>`;
}
function liveActions(live) {
  const can = Boolean(signer && live.grant && signer.identity === live.grant.holder), a = live.actions || {};
  const btn = (kind, label, resource, prop, tone) => resource
    ? `<button class="btn ${tone}" data-decide="${esc(resource)}" data-prop="${prop}" ${can ? "" : "disabled"}>${label}</button>` : "";
  const buttons = [btn("deploy", "Mettre main en production", a.deploy, "approved", "primary"),
    btn("rollback", "Revenir à la version précédente", a.rollback, "requested", ""),
    btn("restart", "Redémarrer sans coupure", a.restart, "requested", ""),
    live.canary ? btn("abort", "Retirer le canary", a.abort, "requested", "danger") : ""].join("");
  return `<div class="decide">${buttons}<span class="small quiet">${can
    ? "Chaque décision est une signature de ce navigateur ; la loi l'exécute par la garde, seulement si le fait du scanner la permet."
    : `Décisions réservées à ${esc(live.grant?.holder || "l'ingénieur habilité")}, avec sa clé dans ce navigateur.`}</span></div>`;
}

// ---- ALERTS: what is wrong now, and who took it -------------------------------------------------------------------
const ALERT_STATE = { failing: ["escalated", "En échec"], degraded: ["gap", "Dégradé"], escalated: ["escalated", "Échéance dépassée"],
  resolved: ["held", "Résolu"] };
function banner() {
  if (!alerting || !alerting.open || route() === "alerts") return "";
  const u = alerting.unattended;
  return `<a class="alarm-bar ${u ? "hot" : ""}" href="#/alerts"><i></i><b>${plural(alerting.open, "alerte ouverte", "alertes ouvertes")}</b>
    <span>${alerting.untaken ? `${alerting.untaken} sans personne pour la prendre${u ? `, dont ${u} depuis plus de ${alerting.ack_ms / 60000} min` : ""}` : "toutes prises en charge"}</span><em>Voir</em></a>`;
}
function alertsView() {
  if (!alerting) return `<h1>Alertes</h1><div class="note bad">Les alertes sont indisponibles.</div>`;
  const grant = alerting.signing.grant, can = Boolean(signer && grant && signer.identity === grant.holder);
  const engineer = Boolean(signer && alerting.signing.engineer && signer.identity === alerting.signing.engineer.holder);
  const what = (a) => a.kind === "slo" ? `SLO <b>${esc(a.name)}</b>` : a.kind === "obligation" ? `Écart réglementaire : ${esc(name(a.name.replace(/^target:/, "")))}`
    : a.kind === "source" ? `Source de métriques ${esc(a.name)}` : `${esc(KIND[a.kind]?.[1] || a.kind)} <b>${esc([a.operation, a.name].filter(Boolean).join(" "))}</b>`;
  const why = (a) => a.why?.rule === "overdue" ? `échéance du ${due(a.why.due)} dépassée` : a.why?.rule === "source_down" ? "ne répond pas" : reason(a.why);
  const row = (a) => {
    const s = ALERT_STATE[a.closed_at ? "resolved" : a.state] || ["pending", a.state];
    return `<div class="rowi"><div class="main">${a.closed_at ? "" : `<span class="sev ${a.severity}">${a.severity === "page" ? "Page" : "Ticket"}</span>`}<span class="state ${s[0]}"><i></i>${s[1]}</span> ${what(a)}
      <div class="facts">${fact(`depuis ${ago(a.opened_ms)}`, "")}${a.why ? fact(why(a), "") : ""}
        ${a.closed_at ? fact(`résolu ${ago(a.closed_at * 1000)}`, "ok") : ""}
        ${a.silenced ? fact(`silencée jusqu'à ${new Date(a.silenced.until).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}${a.silenced.reason ? ` : ${a.silenced.reason}` : ""}`, "")
          : a.taken ? fact("Prise en charge signée", "ok") : a.closed_at ? "" : fact(a.unattended ? "Personne ne l'a prise" : "En attente d'une personne", a.unattended ? "bad" : "wait")}</div></div>
      ${!a.closed_at && !a.silenced && engineer && a.subject ? `<button class="btn" data-silence="${esc(a.subject)}">Silencer 1 h</button>` : ""}
      ${!a.closed_at && !a.taken && !a.silenced ? `<button class="btn primary" data-ack="${esc(a.resource)}" ${can ? "" : "disabled"}>Prendre en charge</button>` : ""}</div>`;
  };
  const open = alerting.alerts.filter((a) => !a.closed_at), closed = alerting.alerts.filter((a) => a.closed_at);
  return `<h1>Alertes</h1><p class="lede">Ce qui se dégrade en production et les écarts dont l'échéance est passée. Prendre une alerte en charge
    est une signature faite dans ce navigateur et gardée dans le journal : c'est la preuve qu'une personne a été prévenue et a répondu.</p>
    ${!signer ? `<div class="note warn">Ajoutez votre clé dans Réglages pour prendre une alerte en charge.</div>`
      : !can ? `<div class="note warn">Seul ${esc(grant?.holder || "le détenteur du droit de revue")} peut prendre une alerte en charge ici.</div>` : ""}
    <section><h2>Ouvertes <span class="quiet small">${open.length}</span></h2><div class="rows">${open.map(row).join("") || `<div class="rowi quiet">Aucune alerte ouverte</div>`}</div></section>
    ${closed.length ? `<section><h2>Résolues ces dernières 24 h</h2><div class="rows">${closed.map(row).join("")}</div></section>` : ""}
    ${alerting.silenced ? `<p class="small quiet">${plural(alerting.silenced, "alerte silencée", "alertes silencées")} (maintenance) : hors du badge, les faits signés ne changent pas.</p>` : ""}
    <p class="small quiet">Page : à prendre maintenant (composant en échec, SLO qui brûle vite son budget, échéance dépassée). Ticket : à traiter dans la journée (dégradé, consommation lente).
      Une alerte s'ouvre quand un composant passe dégradé ou en échec sur les 5 dernières minutes, ou quand une source se tait ;
      elle se ferme quand il revient. Pas encore d'e-mail ni de messagerie : seulement cette page, le badge et le titre de l'onglet.</p>`;
}
async function take(button) {
  const grant = alerting.signing.grant;
  button.disabled = true;
  button.textContent = "Signature";
  const statement = { id: `ack-${crypto.randomUUID().replaceAll("-", "")}`, at: Math.max(Date.now(), alerting.signing.as_of + 1),
    author: signer.identity, under: grant.id, resource: button.dataset.ack, property: "ack", status: "taken", level: "real" };
  try {
    const env = await envelope(alerting.signing.domain, "observation", statement, signer);
    const r = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
    const out = await r.json();
    if (!r.ok) throw new Error(out.refused || out.error);
    refresh();
  } catch (err) {
    button.textContent = `Refusé : ${err.message}`;
  }
}

// ---- OBJECTIVES: what engineers set (D31) ---------------------------------------------------------------------------
async function signFact(domain, at, grant, resource, property, status) {
  const statement = { id: `set-${crypto.randomUUID().replaceAll("-", "")}`, at, author: signer.identity, under: grant.id,
    resource, property, status: String(status), level: "real" };
  const env = await envelope(domain, "observation", statement, signer);
  const r = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
  const out = await r.json();
  if (!r.ok) throw new Error(out.refused || out.error);
  return out;
}
const SETTINGS = {
  objective: ["Objectif de santé immédiate", "%", "Disponibilité minimale d'un composant sur la fenêtre de jugement ; en dessous, il est dégradé."],
  failing: ["Seuil « en échec »", "% d'erreurs", "Au-delà, un composant est en échec : c'est une rupture signée, qui peut déclencher un retour."],
  p99_ms: ["Latence p99 maximale", "ms", "Au-delà, le composant est dégradé."],
  window_s: ["Fenêtre de jugement", "s", "Durée sur laquelle le scanner juge l'état immédiat et le signe."],
  late_periods: ["Retard toléré d'une tâche planifiée", "périodes", "Sans succès depuis ce nombre de périodes : dégradée."],
  burn_fast: ["Alerte rapide (page)", "× le débit du budget", "Sonne quand la consommation sur 1 h ET sur 5 min dépasse ce multiple. 14,4 = 2 % d'un budget de 30 j en 1 h. Rompt l'objectif signé."],
  burn_slow: ["Alerte lente (ticket)", "× le débit du budget", "Sonne quand la consommation sur 6 h ET sur 30 min dépasse ce multiple. 6 = 5 % d'un budget de 30 j en 6 h."],
  rollback_horizon_min: ["Horizon du retour automatique", "min", "Une rupture plus tardive après une mise en production ne lui est plus attribuée."],
  restarts_per_hour: ["Redémarrages automatiques par heure", "max", "Au-delà, une personne décide."],
  freeze_below: ["Gel sur budget d'erreur", "% restant", "Sous ce reste de budget (sur le SLO le plus entamé), plus de mise en production automatique. 0 = jamais."],
  deploy_hours: ["Heures de mise en production", "HH-HH", "Plage horaire où une mise en production automatique peut commencer."],
  deploy_tz: ["Fuseau horaire", "", "Pour les jours et les heures ci-dessus."],
  canary_percent: ["Part du trafic en canary", "%", "Requêtes envoyées à la nouvelle version pendant l'essai (jamais /metrics)."],
  canary_bake_min: ["Durée d'essai minimale", "min", "Avant toute promotion, même si tout va bien."],
  canary_max_error_delta: ["Écart d'erreurs toléré", "points de %", "Taux d'erreurs du canary moins celui de la version en place ; au-delà, retrait immédiat."],
  canary_min_requests: ["Requêtes minimales", "requêtes", "Pas de promotion sur moins de requêtes que cela."],
  base_url: ["Adresse publique du produit", "", "Les sondes externes l'appellent de l'extérieur, comme un client."],
};
const TOGGLES = {
  auto_deploy: ["Mise en production automatique de main", "Sinon le scanner propose et un ingénieur approuve chaque mise en production."],
  auto_rollback: ["Retour automatique à la version précédente", "Sur une rupture juste après une mise en production, ou une version qui ne démarre pas."],
  auto_restart: ["Redémarrage automatique", "Sur une rupture qui ne suit pas une mise en production, dans la limite par heure."],
  compatible_migrations: ["Retour arrière à travers une migration compatible", "Seulement les migrations déclarées .compatible.sql (ajout seul) ; jamais à travers une autre."],
  freeze: ["Gel des mises en production", "Plus aucune mise en production automatique ; les retours arrière restent possibles."],
};
const TABS = [["slos", "SLO et budgets"], ["alerting", "Alertes"], ["release", "Mise en production"], ["health", "Santé immédiate"],
  ["components", "Composants"], ["probes", "Sondes"], ["silences", "Silences"], ["code", "Règles en code"], ["history", "Historique"]];
const DAYNAMES = { mon: "lun", tue: "mar", wed: "mer", thu: "jeu", fri: "ven", sat: "sam", sun: "dim" };
const ZONES = ["UTC", "Europe/Paris", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Asia/Tokyo", "Asia/Singapore"];
let settingsData = null, objTab = localGet("objtab") || "slos";
function objectivesView() {
  return `<h1>Objectifs et règles</h1><p class="lede">Ce que la production doit tenir, comment on est prévenu et ce que Standard a le droit d'y faire seul.
    Chaque réglage est une signature de votre navigateur, gardée au journal. <b>Plus strict : appliqué tout de suite. Plus souple : appliqué après le délai de la loi.</b></p>
    <div class="tabs" role="tablist">${TABS.map(([id, label]) => `<button role="tab" data-objtab="${id}" aria-selected="${id === objTab}">${label}</button>`).join("")}</div>
    <div id="obj"><p class="quiet">Chargement</p></div>`;
}
const fmtBurn = (v) => v == null ? "—" : `${nf(v, v < 100 ? 1 : 0)}×`;
function budgetBar(b) {
  if (b == null) return `<div class="bbar"><i style="width:0"></i></div><span class="small quiet">pas encore de données</span>`;
  const w = Math.max(0, Math.min(1, b)), tone = b < 0 ? "bad" : b < 0.25 ? "warn" : "ok";
  return `<div class="bbar ${tone}"><i style="width:${(w * 100).toFixed(1)}%"></i></div><span class="small ${tone}">${b < 0 ? `épuisé, dépassé de ${pct(-b, 0)}` : `${pct(b, 1)} restant`}</span>`;
}
async function loadObjectives() {
  try {
    const r = await fetch("/api/settings", { cache: "no-store" });
    settingsData = await r.json();
    if (!r.ok) throw new Error(settingsData.error);
  } catch (err) {
    $("#obj").innerHTML = `<div class="note bad">Les réglages sont indisponibles : ${esc(err.message)}</div>`;
    return;
  }
  const s = settingsData, p = s.policy;
  if (!p) { $("#obj").innerHTML = `<div class="note warn">L'opérateur n'a pas encore publié ses réglages : attendez un passage.</div>`; return; }
  const can = Boolean(signer && s.signing.grant && signer.identity === s.signing.grant.holder);
  const dis = can ? "" : "disabled";
  const value = (name, fallback) => name in p.effective ? p.effective[name] : fallback;
  const g = (k) => value(`global/${k}`, p.defaults[k]);
  const left = (at) => { const m = Math.ceil((at - Date.now()) / 60000); return m > 0 ? `dans ${m} min` : "au prochain passage du scanner"; };
  const comps = Object.fromEntries(s.components.map((c) => [c.id, [c.operation, c.name].filter(Boolean).join(" ")]));
  const VAL = { on: "activé", off: "désactivé" };
  const label = (name, v) => {
    const [scope, key] = name.split("/"), val = VAL[v] || String(v);
    if (scope === "global") return `${(SETTINGS[key] || TOGGLES[key] || [key === "strategy" ? "Stratégie" : key === "deploy_days" ? "Jours de mise en production" : key])[0]} : ${val}${SETTINGS[key]?.[1] && !SETTINGS[key][1].includes("HH") ? " " + SETTINGS[key][1] : ""}`;
    if (scope.startsWith("p-")) return v === "off" ? "Sonde retirée" : `Sonde ${val}`;
    if (scope.startsWith("s-")) return `SLO ${p.slos?.[scope]?.name || scope}, ${key} : ${val}`;
    if (scope.startsWith("m-")) return `Silence ${scope}, ${key} : ${key === "until" ? new Date(+v).toLocaleString("fr-FR") : val}`;
    const what = { objective: "objectif", p99_ms: "p99 max", counted: "compté dans l'objectif" }[key] || key;
    return `${comps[scope] || "Composant"}, ${what} : ${val}`;
  };
  const pend = (name) => p.pending[name] ? `<span class="fact wait"><i></i>${esc(label(name, p.pending[name].value))} : plus souple, appliqué ${left(p.pending[name].applies_at)}</span>` : "";
  const field = (key, scope = "global", fallback = p.defaults[key]) => {
    const name = `${scope}/${key}`, v = value(name, fallback), [lab, unit, help] = SETTINGS[key], b = p.bounds[key];
    const input = key === "deploy_tz"
      ? `<select data-set="${name}" ${dis}>${ZONES.map((z) => `<option ${z === v ? "selected" : ""}>${z}</option>`).join("")}</select>`
      : `<input class="num" type="${["base_url", "deploy_hours"].includes(key) ? "text" : "number"}" data-set="${name}" value="${esc(v ?? "")}" ${b && typeof b[0] === "number" ? `min="${b[0]}" max="${b[1]}" step="any"` : ""} ${dis}>`;
    return `<div class="set"><div class="sl"><b>${lab}</b><span class="small quiet">${help}</span></div>
      <div class="sv">${input}<span class="unit">${unit}</span><button class="btn" data-save="${name}" ${dis}>Enregistrer</button></div><div class="sp">${pend(name)}</div></div>`;
  };
  const toggle = (key) => {
    const name = `global/${key}`, on = g(key) === "on", [lab, help] = TOGGLES[key];
    return `<div class="set"><div class="sl"><b>${lab}</b><span class="small quiet">${help}</span></div>
      <div class="sv"><label class="switch"><input type="checkbox" data-toggle="${name}" ${on ? "checked" : ""} ${dis}><span></span></label>
      <span class="small">${on ? "Activé" : "Désactivé"}</span></div><div class="sp">${pend(name)}</div></div>`;
  };
  const selectorLabel = (sel) => sel === "counted" ? "composants comptés" : sel === "all" ? "tous les composants" : sel.startsWith("kind:") ? `type ${KIND[sel.slice(5)]?.[2] || sel.slice(5)}` : sel.split(",").map((c) => comps[c] || c).join(", ");
  const selectorInput = (id, sel) => `<select data-slo-sel="${id}" ${dis}>${["counted", "all", ...Object.keys(KIND).map((k) => `kind:${k}`), ...s.components.map((c) => c.id)].map((o) =>
    `<option value="${o}" ${o === sel ? "selected" : ""}>${esc(selectorLabel(o))}</option>`).join("")}</select>`;

  const tabs = {
    slos: () => {
      const defs = p.slos || {};
      const card = ([sid, d]) => {
        const e = s.slos[sid] || {};
        const alert = e.fast ? `<span class="state escalated"><i></i>Alerte rapide</span>` : e.slow ? `<span class="state gap"><i></i>Alerte lente</span>` : `<span class="state held"><i></i>Dans le budget</span>`;
        return `<div class="slo panel"><div class="slohead"><div><b>${esc(d.name)}</b><div class="small quiet">${d.sli === "latency" ? `latence : requêtes sous ${msf(d.threshold_ms)}` : "disponibilité : requêtes sans échec"}, ${esc(selectorLabel(d.selector))}, ${pctx(d.target / 100)} sur ${d.window_d} j glissants</div></div>${alert}</div>
          <div class="slogrid"><div><div class="k">Conformité</div><div class="v">${e.compliance == null ? "—" : pct(e.compliance, 3)}</div><div class="small quiet">${nf(e.events || 0)} évènements</div></div>
            <div class="wide"><div class="k">Budget d'erreur</div>${budgetBar(e.budget)}</div>
            <div class="wide"><div class="k">Consommation du budget</div><div class="burns">${Object.entries(e.burn || {}).map(([span, v]) => `<span><b>${fmtBurn(v)}</b> ${span}</span>`).join("")}</div>
              <div class="small quiet">seuils : rapide ${fmtBurn(g("burn_fast"))} (1 h et 5 min), lente ${fmtBurn(g("burn_slow"))} (6 h et 30 min)</div></div></div>
          <details><summary>Modifier</summary>${sloForm(sid, d)}</details></div>`;
      };
      return `${Object.entries(defs).map(card).join("")}
        <div class="panel"><h3>Nouveau SLO</h3>${sloForm("s-" + crypto.randomUUID().replaceAll("-", "").slice(0, 8), { name: "", sli: "latency", threshold_ms: 300, target: 99, window_d: 28, selector: "kind:api" }, true)}</div>
        <p class="small quiet">Un SLO compte des bons et des mauvais évènements sur une fenêtre glissante. Le budget d'erreur est la part de mauvais évènements que la cible autorise.
          Une alerte rapide rompt l'objectif signé (et peut déclencher un retour automatique) ; une alerte lente prévient sans rien déclencher.</p>`;
    },
    alerting: () => `<div class="panel sets">${field("burn_fast")}${field("burn_slow")}</div>
      <p class="small quiet">Règle multi-fenêtres : une fenêtre longue pour la significativité, une courte pour que l'alerte s'arrête vite quand la cause cesse.
        Un multiple de 1 consomme exactement le budget sur la fenêtre du SLO. Les alertes apparaissent dans Alertes (page = à prendre maintenant, ticket = à traiter dans la journée).</p>`,
    release: () => {
      const days = g("deploy_days").split(","), strategy = g("strategy");
      return `${s.configured ? "" : `<div class="note warn">Aucune mise en production n'est confiée à Standard (section [deploy]) : ces règles ne s'appliquent pas encore.</div>`}
      <h3>Stratégie</h3><div class="panel sets">
        <div class="set"><div class="sl"><b>Comment une nouvelle version arrive</b><span class="small quiet">Directe : bascule de tout le trafic après le contrôle de santé. Canary : d'abord une part du trafic, comparée à la version en place, puis promotion ou retrait.</span></div>
          <div class="sv"><div class="seg">${[["direct", "Directe"], ["canary", "Canary"]].map(([v, l]) => `<button data-strategy="${v}" aria-pressed="${v === strategy}" ${dis}>${l}</button>`).join("")}</div></div><div class="sp">${pend("global/strategy")}</div></div>
        ${strategy === "canary" ? ["canary_percent", "canary_bake_min", "canary_max_error_delta", "canary_min_requests"].map((k) => field(k)).join("") : ""}</div>
      <h3>Quand</h3><div class="panel sets">${toggle("freeze")}
        <div class="set"><div class="sl"><b>Jours de mise en production</b><span class="small quiet">Retirer un jour s'applique tout de suite ; en ajouter attend le délai.</span></div>
          <div class="sv"><div class="days">${Object.entries(DAYNAMES).map(([d, l]) => `<label><input type="checkbox" data-day="${d}" ${days.includes(d) ? "checked" : ""} ${dis}>${l}</label>`).join("")}</div>
          <button class="btn" id="savedays" ${dis}>Enregistrer</button></div><div class="sp">${pend("global/deploy_days")}</div></div>
        ${field("deploy_hours")}${field("deploy_tz")}${field("freeze_below")}</div>
      <h3>Autonomie</h3><div class="panel sets">${toggle("auto_deploy")}${toggle("auto_rollback")}${field("rollback_horizon_min")}${toggle("auto_restart")}${field("restarts_per_hour")}${toggle("compatible_migrations")}</div>`;
    },
    health: () => `<div class="panel sets">${["objective", "failing", "p99_ms", "window_s", "late_periods"].map((k) => field(k)).join("")}</div>
      <p class="small quiet">La santé immédiate juge chaque composant sur la fenêtre courte (Opérationnel, Dégradé, En échec). Un composant compté en échec rompt l'objectif signé ; dégradé, il prévient seulement.</p>`,
    components: () => `<div class="tablewrap"><table class="table api comps"><thead><tr><th>Composant</th><th>Dispo. (1 h)</th><th>p99 (1 h)</th><th>Objectif</th><th>p99 max</th><th>Compté</th><th></th></tr></thead>
      <tbody>${s.components.map((c) => {
        const o = value(`${c.id}/objective`, null), l = value(`${c.id}/p99_ms`, null), counted = value(`${c.id}/counted`, null);
        return `<tr><td><b>${esc(comps[c.id])}</b><div class="sub">${esc(KIND[c.kind]?.[1] || c.kind)} · <span class="sha">${c.id}</span></div></td>
          <td>${c.availability == null ? "—" : pct(c.availability, 2)}</td><td>${msf(c.p99)}</td>
          <td><input class="num sm" type="number" step="any" data-set="${c.id}/objective" value="${o ?? ""}" placeholder="${g("objective")}" ${dis}> %</td>
          <td><input class="num sm" type="number" step="any" data-set="${c.id}/p99_ms" value="${l ?? ""}" placeholder="${g("p99_ms")}" ${dis}> ms</td>
          <td><label class="switch"><input type="checkbox" data-toggle="${c.id}/counted" ${(counted ? counted === "on" : c.counted) ? "checked" : ""} ${dis}><span></span></label></td>
          <td><button class="btn" data-savecomp="${c.id}" ${dis}>Enregistrer</button>${pend(`${c.id}/objective`)}${pend(`${c.id}/p99_ms`)}${pend(`${c.id}/counted`)}</td></tr>`; }).join("")
        || `<tr><td colspan="7" class="quiet">Aucun composant mesuré</td></tr>`}</tbody></table></div>
      <p class="small quiet">Vide = la valeur globale. Décocher « Compté » : le composant reste montré et alerté, mais ne rompt plus l'objectif signé (utile pour un service externe).</p>`,
    probes: () => {
      const answers = Object.fromEntries((s.probes || []).map((x) => [x.id, x]));
      const probes = Object.entries(p.effective).filter(([k, v]) => k.endsWith("/spec") && v !== "off");
      return `<div class="panel sets">${field("base_url")}
        ${probes.map(([k, v]) => { const id = k.split("/")[0], a = answers[id];
          return `<div class="set"><div class="sl"><b class="sha">${esc(v)}</b><span class="small quiet">${a ? `dernière réponse ${a.last || "aucune"}, ${nf(a.errors)} échec(s) sur ${nf(a.count)}` : "pas encore appelée"}</span></div>
            <div class="sv"><button class="btn danger" data-probe-off="${id}" ${dis}>Retirer</button></div><div class="sp">${pend(k)}</div></div>`; }).join("")}
        <div class="set"><div class="sl"><b>Ajouter une sonde</b><span class="small quiet">Méthode, chemin, statut attendu. Elle compte comme un composant de type sonde.</span></div>
          <div class="sv"><select id="pm" ${dis}><option>GET</option><option>HEAD</option><option>POST</option></select>
          <input class="num" id="pp" type="text" value="/health" ${dis}><input class="num sm" id="ps" type="number" value="200" ${dis}>
          <button class="btn primary" id="padd" ${dis}>Ajouter</button></div><div class="sp"></div></div></div>`;
    },
    silences: () => {
      const active = Object.entries(p.silences || {});
      const targets = [["all", "Toutes les alertes"], ...Object.entries(p.slos || {}).map(([id, d]) => [id, `SLO ${d.name}`]), ...s.components.map((c) => [c.id, comps[c.id]])];
      return `<div class="rows">${active.map(([id, m]) => `<div class="rowi"><div class="main"><b>${esc(targets.find((t) => t[0] === m.target_of)?.[1] || m.target_of)}</b>
          <div class="facts">${fact(`jusqu'à ${new Date(m.until).toLocaleString("fr-FR")}`, "wait")}${m.reason ? fact(m.reason, "") : ""}</div></div>
          <button class="btn" data-unsilence="${id}" ${dis}>Lever</button></div>`).join("") || `<div class="rowi quiet">Aucun silence actif</div>`}</div>
        <div class="panel sets" style="margin-top:16px"><div class="set"><div class="sl"><b>Nouveau silence</b><span class="small quiet">Une maintenance prévue : les alertes de la cible ne comptent plus dans le badge. Les faits signés, eux, ne changent pas.</span></div>
          <div class="sv"><select id="mt" ${dis}>${targets.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("")}</select>
          <select id="md" ${dis}><option value="30">30 min</option><option value="60" selected>1 h</option><option value="240">4 h</option><option value="1440">24 h</option></select>
          <input class="num" id="mr" type="text" placeholder="raison" ${dis}><button class="btn primary" id="madd" ${dis}>Silencer</button></div><div class="sp"></div></div></div>`;
    },
    code: () => `<p class="small quiet">Toutes les règles en vigueur, en un document. Modifiez-le, comparez, puis signez les changements un par un : chacun suit la même loi (plus strict tout de suite, plus souple après le délai).</p>
      <textarea id="code" spellcheck="false" ${dis}>${esc(JSON.stringify(p.document, null, 2))}</textarea>
      <div class="decide"><button class="btn" id="codediff" ${dis}>Comparer</button><a class="btn" id="codedl" download="standard-rules.json" href="data:application/json,${encodeURIComponent(JSON.stringify(p.document, null, 2))}">Télécharger</a></div><div id="diff"></div>`,
    history: () => `<div class="rows">${p.history.map((h) => `<div class="rowi"><div class="main"><b>${esc(label(h.setting, h.value))}</b>
      <div class="facts">${fact(`par ${h.author}`, "")}${fact(ago(h.at), "")}${fact(h.outcome === "applied" ? "appliqué" : h.outcome === "pending" ? `plus souple : en attente ${Math.round(p.delay_ms / 60000)} min` : h.outcome, h.outcome === "applied" ? "ok" : h.outcome === "pending" ? "wait" : "bad")}</div></div></div>`).join("")
      || `<div class="rowi quiet">Aucun réglage signé : les valeurs par défaut s'appliquent.</div>`}</div>`,
  };
  function sloForm(sid, d, fresh = false) {
    return `<div class="sloform" data-slo="${sid}">
      <label>Nom</label><input type="text" data-slo-f="name" value="${esc(d.name)}" placeholder="ex. Commandes rapides" ${dis}>
      <div class="row4"><div><label>Indicateur</label><select data-slo-f="sli" ${dis}><option value="availability" ${d.sli === "availability" ? "selected" : ""}>Disponibilité</option><option value="latency" ${d.sli === "latency" ? "selected" : ""}>Latence sous un seuil</option></select></div>
        <div><label>Seuil (latence)</label><input class="num" type="number" data-slo-f="threshold_ms" value="${d.threshold_ms ?? ""}" ${dis}> ms</div>
        <div><label>Cible</label><input class="num" type="number" step="any" data-slo-f="target" value="${d.target}" ${dis}> %</div>
        <div><label>Fenêtre glissante</label><input class="num" type="number" data-slo-f="window_d" value="${d.window_d}" ${dis}> j</div></div>
      <label>Composants</label>${selectorInput(sid, d.selector)}
      <div class="decide"><button class="btn" data-preview="${sid}">Aperçu sur l'historique</button>
        <button class="btn primary" data-saveslo="${sid}" ${dis}>${fresh ? "Créer le SLO" : "Signer les changements"}</button>
        ${!fresh ? `<button class="btn danger" data-sloff="${sid}" ${dis}>Retirer</button>` : ""}</div><div class="preview" id="pv-${sid}"></div></div>`;
  }

  $("#obj").innerHTML = `${!signer ? `<div class="note warn">Ajoutez votre clé dans Réglages pour modifier ces règles.</div>`
      : !can ? `<div class="note warn">Seul ${esc(s.signing.grant?.holder || "l'ingénieur habilité")} peut modifier ces règles.</div>` : ""}
    ${tabs[objTab]()}<p id="objmsg" class="small quiet"></p>`;
  document.querySelectorAll("[data-objtab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.objtab === objTab)));

  const at = () => Math.max(Date.now(), s.signing.as_of + 1);
  const set = async (resource, status, el) => {
    $("#objmsg").textContent = "Signature dans ce navigateur";
    try {
      await signFact(s.signing.domain, at(), s.signing.grant, `run:policy/${resource}`, "value", status);
      $("#objmsg").textContent = "Signé. Le scanner l'applique à son prochain passage.";
      return true;
    } catch (err) { $("#objmsg").textContent = `Refusé par le noyau : ${err.message}`; if (el) el.disabled = false; return false; }
  };
  const reload = () => setTimeout(loadObjectives, 1500);
  document.querySelectorAll("[data-save]").forEach((b) => b.onclick = async () => {
    const input = document.querySelector(`[data-set="${b.dataset.save}"]`); b.disabled = true; if (await set(b.dataset.save, input.value.trim(), b)) reload(); });
  document.querySelectorAll("[data-toggle]").forEach((c) => c.onchange = async () => { if (await set(c.dataset.toggle, c.checked ? "on" : "off", c)) reload(); });
  document.querySelectorAll("[data-strategy]").forEach((b) => b.onclick = async () => { if (await set("global/strategy", b.dataset.strategy, b)) reload(); });
  $("#savedays")?.addEventListener("click", async () => {
    const days = [...document.querySelectorAll("[data-day]")].filter((c) => c.checked).map((c) => c.dataset.day).join(",");
    if (days && await set("global/deploy_days", days)) reload();
  });
  document.querySelectorAll("[data-savecomp]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    for (const key of ["objective", "p99_ms"]) {
      const input = document.querySelector(`[data-set="${b.dataset.savecomp}/${key}"]`);
      if (input.value.trim()) await set(`${b.dataset.savecomp}/${key}`, input.value.trim(), b);
    }
    reload();
  });
  document.querySelectorAll("[data-probe-off]").forEach((b) => b.onclick = async () => { b.disabled = true; if (await set(`${b.dataset.probeOff}/spec`, "off", b)) reload(); });
  $("#padd")?.addEventListener("click", async () => {
    const id = "p-" + crypto.randomUUID().replaceAll("-", "").slice(0, 8);
    if (await set(`${id}/spec`, `${$("#pm").value} ${$("#pp").value.trim()} ${$("#ps").value.trim()}`, $("#padd"))) reload();
  });
  const sloValues = (sid) => {
    const box = document.querySelector(`[data-slo="${sid}"]`), out = {};
    box.querySelectorAll("[data-slo-f]").forEach((i) => { out[i.dataset.sloF] = i.value.trim(); });
    out.selector = box.querySelector(`[data-slo-sel]`).value;
    return out;
  };
  document.querySelectorAll("[data-preview]").forEach((b) => b.onclick = async () => {
    const v = sloValues(b.dataset.preview), box = $(`#pv-${b.dataset.preview}`);
    box.innerHTML = `<span class="small quiet">Calcul sur l'historique enregistré</span>`;
    const q = new URLSearchParams({ sli: v.sli, target: v.target, window_d: v.window_d, threshold_ms: v.threshold_ms || 1000, selector: v.selector });
    const r = await (await fetch(`/api/preview?${q}`)).json();
    box.innerHTML = !r.minutes ? `<span class="small quiet">Pas encore d'historique pour ces composants.</span>`
      : `<div class="facts">${fact(`sur ${r.minutes < 1440 ? `${Math.round(r.minutes / 60)} h` : `${(r.minutes / 1440).toFixed(1)} j`} enregistrés, ${nf(r.events)} évènements`, "")}
        ${fact(`conformité ${pct(r.compliance, 3)}`, r.compliance >= v.target / 100 ? "ok" : "bad")}
        ${fact(r.budget < 0 ? `budget épuisé (${pct(-r.budget, 0)} au-delà)` : `budget restant ${pct(r.budget, 1)}`, r.budget < 0 ? "bad" : r.budget < 0.25 ? "wait" : "ok")}
        ${fact(`${r.fast_alerts} alerte(s) rapide(s), ${r.slow_alerts} lente(s) auraient sonné`, r.fast_alerts ? "wait" : "ok")}</div>`;
  });
  document.querySelectorAll("[data-saveslo]").forEach((b) => b.onclick = async () => {
    const sid = b.dataset.saveslo, v = sloValues(sid), old = (p.slos || {})[sid] || {};
    b.disabled = true;
    const keys = ["target", "sli", "threshold_ms", "window_d", "selector", "name"].filter((k) => v[k] !== "" && String(v[k]) !== String(old[k] ?? ""));
    for (const k of keys) if (!await set(`${sid}/${k}`, v[k], b)) return;
    reload();
  });
  document.querySelectorAll("[data-sloff]").forEach((b) => b.onclick = async () => { b.disabled = true; if (await set(`${b.dataset.sloff}/state`, "off", b)) reload(); });
  $("#madd")?.addEventListener("click", async () => {
    const id = "m-" + crypto.randomUUID().replaceAll("-", "").slice(0, 8);
    $("#madd").disabled = true;
    if (!await set(`${id}/target_of`, $("#mt").value)) return;
    if ($("#mr").value.trim()) await set(`${id}/reason`, $("#mr").value.trim().slice(0, 120));
    if (await set(`${id}/until`, String(Date.now() + Number($("#md").value) * 60000))) reload();
  });
  document.querySelectorAll("[data-unsilence]").forEach((b) => b.onclick = async () => { b.disabled = true; if (await set(`${b.dataset.unsilence}/until`, "0", b)) reload(); });
  const flatten = (doc) => {
    const out = {};
    for (const [k, v] of Object.entries(doc.global || {})) out[`global/${k}`] = v;
    for (const part of ["components", "slos", "probes", "silences"]) for (const [scope, keys] of Object.entries(doc[part] || {})) for (const [k, v] of Object.entries(keys)) out[`${scope}/${k}`] = v;
    return out;
  };
  const way = (key, old, nw) => {
    const w = p.ways[key];
    if (w === null || w === undefined) return "neutre";
    if (old === undefined) return "plus strict";
    if (w === "subset") return nw.split(",").every((d) => old.split(",").includes(d)) ? "plus strict" : "plus souple";
    if (w === "within") { const [a, b] = old.split("-").map(Number), [c, d] = String(nw).split("-").map(Number); return a <= c && d <= b ? "plus strict" : "plus souple"; }
    if (typeof w === "string") return nw === w || nw === old ? "plus strict" : "plus souple";
    if (w === 0) return "plus souple";
    return (Number(nw) - Number(old)) * w >= 0 ? "plus strict" : "plus souple";
  };
  $("#codediff")?.addEventListener("click", () => {
    let doc;
    try { doc = JSON.parse($("#code").value); } catch (err) { $("#diff").innerHTML = `<div class="note bad">JSON invalide : ${esc(err.message)}</div>`; return; }
    const before = flatten(p.document), after = flatten(doc);
    const changes = Object.entries(after).filter(([k, v]) => String(before[k] ?? "") !== String(v ?? ""));
    $("#diff").innerHTML = !changes.length ? `<p class="small quiet">Aucun changement.</p>` : `<div class="rows">${changes.map(([k, v]) => {
      const w = way(k.split("/")[1], before[k], v);
      return `<div class="rowi"><div class="main"><span class="sha">${esc(k)}</span> <span class="del">${esc(String(before[k] ?? "—"))}</span> → <span class="add">${esc(String(v))}</span>
        <div class="facts">${fact(w === "plus souple" ? `plus souple : appliqué dans ${Math.round(p.delay_ms / 60000)} min` : w === "neutre" ? "appliqué tout de suite" : "plus strict : appliqué tout de suite", w === "plus souple" ? "wait" : "ok")}</div></div></div>`; }).join("")}</div>
      <div class="decide"><button class="btn primary" id="codesign">Signer ${changes.length} changement${changes.length > 1 ? "s" : ""}</button></div>`;
    $("#codesign").onclick = async () => {
      $("#codesign").disabled = true;
      for (const [k, v] of changes) if (!await set(k, String(v))) return;
      reload();
    };
  });
}
document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-objtab]");
  if (t) { objTab = t.dataset.objtab; localSet("objtab", objTab); if (settingsData) loadObjectives(); }
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

const auto = (id) => state.autonomy.requirements.find((a) => a.id === id);

function requirementTables() {
  return `${DOMAINS.map(([label, test]) => {
      const rs = state.requirements.filter(test);
      return rs.length ? `<section><h2>${label}</h2><table class="table req"><colgroup><col><col style="width:150px"><col style="width:190px"><col style="width:210px"></colgroup>
        <thead><tr><th>Exigence</th><th>État</th><th>Mesure</th><th>Autonomie</th></tr></thead><tbody>
      ${rs.map((r) => `<tr><td><div class="name">${esc(name(r.id))}</div><div class="sub">${esc(r.property)} = ${esc(r.expect)}</div>
        ${r.where.length && r.state === "gap" ? `<ul class="where">${r.where.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</td>
        <td><span class="state ${r.state}"><i></i>${STATES[r.state]}</span></td>
        <td class="sub">${esc(measure(r))}</td>
        <td>${levelTag(auto(r.id).level)}<div class="sub">${LEVEL[auto(r.id).level][2]}</div></td></tr>`).join("")}</tbody></table></section>` : "";
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
