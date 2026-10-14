// Standard — operations console. Opens on the product in production (RUN); construction (BUILD) is one section away.
// Reads /api/state; signs your decisions and rules in this browser (sign.js). Nothing here is a permission: the kernel decides.
import { envelope, forgetSigner, importKeyFile, loadSigner, saveSigner } from "/sign.js";
import { createRules } from "/rules.js";

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
  lineage: "Chaque changement est jugé", inventory: "Dépôt entièrement couvert",
  "run-sources": "Métriques de production collectées", "run-slo": "Objectif de service tenu", "run-live": "main en production",
};
const DOMAINS = [
  ["Sécurité du code", (r) => repo(r) && r.domain === "code"],
  ["Dépendances et chaîne logicielle", (r) => repo(r) && ["deps", "supply"].includes(r.domain)],
  ["Intégration continue", (r) => repo(r) && r.domain === "ci"],
  ["Gouvernance du code", (r) => repo(r) && ["settings", "main", "inventory"].includes(r.domain)],
  ["Production", (r) => r.resource.startsWith("run:")],
];
const repo = (r) => r.resource.startsWith("repo:");
const STATES = {
  held: "Tenue", gap: "Écart", escalated: "Escaladée", unmeasured: "Non mesurée", pending: "En mesure",
};
const name = (id) => NAMES[id] || id;
const LEVEL = {
  autonomous: ["held", "Autonome", "L'agent joue seul, dans les règles"], decision: ["gap", "Ta décision", "L'agent prépare, tu dis oui ou non"],
  human: ["escalated", "Toi", "Aucun coup des règles n'y touche : c'est toi"], observed: ["pending", "Observation", "Standard mesure, personne n'agit par lui"],
};
const RAISE = {
  autonomous: "Déjà au maximum : l'agent joue seul quand les faits du scanner tiennent, et tu peux couper la route dans les règles.",
  decision: "Rallumer une route automatique de ce coup dans Règles du jeu.",
  human: "Un coup des règles qui atteigne ce réglage (aujourd'hui chez le fournisseur).",
  observed: "Une section [deploy] : Standard déploie main et revient en arrière sous les seuils des règles.",
};
const OP = { remediate: "Réparation", integrate: "Contribution", implement: "Implémentation", deploy: "Mise en production",
  canary: "Canari", rollback: "Retour arrière", restart: "Redémarrage", abort: "Retrait du canari" };
const levelTag = (lv) => `<span class="state ${LEVEL[lv][0]}"><i></i>${LEVEL[lv][1]}</span>`;
const VALUES = { met: "tenu", behind: "en retard", none: "aucun", current: "à jour", complete: "complète", green: "au vert", red: "en échec", all: "toutes",
  compliant: "conformes", "guard-only": "garde seule" };
function measure(r) {
  if (r.diagnostic_alignment === "stale") return "diagnostic périmé ; preuve à relire";
  if (r.diagnostic_conflict) return r.state === "held" ? "preuve tenue ; diagnostic divergent" : "diagnostic vert ; preuve attendue";
  if (!r.measured) return r.state === "held" ? "prouvée" : "en attente";
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
  standard: ["Standard", "standard"],
  decisions: ["Décisions", "both"], rules: ["Règles du jeu", "both"], coverage: ["Couverture des règles", "both"],
  run: ["Run", "run"], alerts: ["Alertes", "run"], autonomy: ["Autonomie", "run"], activity: ["Activité", "run"],
  contributions: ["Contributions", "build"], requests: ["Demandes", "build"],
  proofs: ["Preuves", "both"], settings: ["Clé de signature", "both"],
};
let state = null, signer = null, alerting = null;
const route = () => (location.hash.slice(2) in ROUTES ? location.hash.slice(2) : "standard");
window.addEventListener("hashchange", () => render());

const features = () => state.build.requests.flatMap((r) => r.features);
const candidates = () => [...state.build.contributions, ...state.run.repairs, ...features()];
// What waits for you: the moves only your decision can play (the same reading the agent plays from).
const pending = () => state.queue;

function frame() {
  const here = route(), waiting = pending().length, open = alerting?.open || 0;
  const badge = (id) => id === "decisions" && waiting ? `<span class="badge">${waiting}</span>`
    : id === "alerts" && open ? `<span class="badge alarm">${open}</span>` : "";
  const link = (id) => `<a href="#/${id}" ${id === here ? 'aria-current="page"' : ""}><span>${ROUTES[id][0]}</span>${badge(id)}</a>`;
  document.title = waiting ? `(${waiting}) Standard` : "Standard";
  $("#nav").innerHTML = `
    <div class="group">Niveau</div>${link("standard")}
    <div class="group">Toi</div>${link("decisions")}${link("rules")}${link("coverage")}
    <div class="group">Exploitation</div>${link("run")}${link("alerts")}${link("autonomy")}${link("activity")}
    <div class="group">Construction</div>${link("contributions")}${link("requests")}
    <div class="group">Preuves</div>${link("proofs")}${link("settings")}`;
  const others = state.products.length > 1;
  $("#product").innerHTML = `<div class="mark">${esc(state.product.slice(0, 1).toUpperCase())}</div><div>
    ${others ? `<select aria-label="Produit">${state.products.map((p) => `<option ${p === state.product ? "selected" : ""}>${esc(p)}</option>`).join("")}</select>`
      : `<b>${esc(state.product)}</b>`}<span>${state.assessment === "INDEPENDENT" ? "Évalué indépendamment" : "Laboratoire non qualifié"}</span></div>`;
  const env = ROUTES[here][1] === "build" ? `<span class="env build">Construction</span>`
    : ROUTES[here][1] === "standard" ? `<span class="env standard">Standard commun</span>` : `<span class="env run">Production</span>`;
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
  const views = { standard: standardView, decisions, rules: rulesView, coverage: coverageView, run: runView, alerts: alertsView, autonomy, activity, contributions, requests, proofs, settings };
  $("#view").innerHTML = banner() + views[route()]();
  if (route() === "run") loadRun();
  if (route() === "rules") loadRules();
  if (route() === "coverage") loadCoverage();
  if (route() === "settings") bindSettings();
  document.querySelectorAll("[data-review]").forEach((b) => b.addEventListener("click", () => openReview(b.dataset.review)));
  document.querySelectorAll("[data-agent-context]").forEach((b) => b.addEventListener("click", () => openAgentContext(b.dataset.agentContext, b.dataset.id)));
}

// ---- RUN: the product in production -------------------------------------------------------------------------------
function counts() {
  const by = (s) => state.requirements.filter((r) => r.state === s).length;
  return { total: state.requirements.length, held: by("held"), gap: by("gap"), escalated: by("escalated"),
    unmeasured: by("unmeasured") };
}

function standardLevel(c) {
  const ratio = c.held / Math.max(c.total, 1);
  if (c.escalated) return ["escalated", "Dette critique", "Une échéance Standard est dépassée : le système ne masque pas le retard, il l'escalade."];
  if (ratio === 1) return ["held", "Auditable", "Toutes les exigences Standard visibles ici disposent d'une preuve fraîche."];
  if (ratio >= 0.85 && !c.unmeasured) return ["gap", "Maintenu", "Le socle est largement tenu ; la montée dépend des écarts restants."];
  if (ratio >= 0.55) return ["gap", "Sous contrôle", "Le système mesure le terrain et pousse les écarts vers l'agent, ou vers toi."];
  return ["pending", "Observé", "Standard commence par rendre les trous visibles : rien n'est considéré conforme par silence."];
}

function blockers(limit = 6) {
  const order = { escalated: 0, gap: 1, unmeasured: 3, pending: 4, held: 5 };
  return [...state.requirements].filter((r) => r.state !== "held")
    .sort((a, b) => order[a.state] - order[b.state] || a.id.localeCompare(b.id)).slice(0, limit);
}

function autonomyBuckets() {
  const reqs = Object.fromEntries(state.requirements.map((r) => [r.id, r]));
  const rows = state.autonomy.requirements.map((a) => ({ ...a, req: reqs[a.id] })).filter((a) => a.req);
  return {
    alone: rows.filter((a) => a.level === "autonomous" && ["gap", "pending"].includes(a.req.state)),
    prepare: rows.filter((a) => a.level === "decision" && a.req.state !== "held"),
    people: rows.filter((a) => a.level === "human" && a.req.state !== "held"),
    waiting: rows.filter((a) => a.blocked || a.req.state === "unmeasured"),
  };
}

function standardView() {
  const c = counts(), lv = standardLevel(c), buckets = autonomyBuckets(), blocked = blockers();
  const pctHeld = Math.round((100 * c.held) / Math.max(c.total, 1));
  return `<div class="stdhead">
      <div class="hero"><i class="beacon ${lv[0] === "held" ? "" : lv[0] === "escalated" ? "esc" : "gap"}"></i><div>
        <h1>Niveau Standard : ${lv[1]}</h1>
        <p class="lede">${esc(lv[2])}</p></div></div>
      <div class="standard-score"><b>${pctHeld}<small>%</small></b><span>${c.held} exigences tenues sur ${c.total}</span></div>
    </div>
    <section class="stdgrid">
      <div class="stdpanel">
        <h2>Ce qui empêche de monter</h2>
        ${blocked.length ? `<div class="stdlist">${blocked.map((r) => `<a href="#/proofs"><span class="state ${r.state}"><i></i>${STATES[r.state]}</span><b>${esc(name(r.id))}</b><small>${esc(measure(r))}</small></a>`).join("")}</div>`
          : `<div class="clear">Aucun bloqueur visible : les preuves sont à jour.</div>`}
      </div>
      <div class="stdpanel">
        <h2>Ce que l'agent peut faire</h2>
        <div class="stdnums">
          <a href="#/autonomy"><b>${buckets.alone.length}</b><span>agir seul</span></a>
          <a href="#/decisions"><b>${pending().length}</b><span>t'attendent</span></a>
          <a href="#/autonomy"><b>${buckets.people.length}</b><span>à toi seul</span></a>
          <a href="#/proofs"><b>${buckets.waiting.length}</b><span>preuve attendue</span></a>
        </div>
        <p class="small quiet">L'agent joue les coups que les règles lui laissent ; les autres t'attendent dans Décisions. Il ne mesure jamais lui-même : le scanner le fait.</p>
        <div class="decide compact"><button class="btn" data-agent-context="patrol" data-id="wide">Contexte de patrouille</button>
          <span class="small quiet">Le contexte prépare une recherche ; aucune analyse n'est lancée ici.</span></div>
      </div>
      <div class="stdpanel">
        <h2>Cycle de montée</h2>
        <ol class="ladder">
          <li><b>Écart</b><span>une exigence Standard manque de preuve fraîche</span></li>
          <li><b>Obligation</b><span>la dette reste ouverte avec échéance</span></li>
          <li><b>Coup</b><span>l'agent propose, les règles disent qui joue</span></li>
          <li><b>Preuve</b><span>instrument indépendant, jamais l'agent</span></li>
          <li><b>Admission</b><span>le noyau ferme ou refuse, jamais l'interface</span></li>
        </ol>
      </div>
    </section>
    <section><h2>Carte du Standard</h2>${map()}</section>
    <section class="cols"><div><h2>À traiter maintenant</h2>${todo()}</div><div><h2>Derniers mouvements</h2>${feed(8)}</div></section>`;
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
  <div class="legend">${["held", "gap", "unmeasured", "escalated"].map((s) => `<span><i class="cell ${s}"></i>${STATES[s]}</span>`).join("")}</div>`;
}

function todo() {
  const items = [];
  for (const e of state.health.escalated) items.push(["alert", `${name(e.target)} a dépassé son échéance`, "À toi de trancher", "#/proofs", "Voir"]);
  for (const m of pending()) items.push(["wait", `${OP[m.op] || m.op} : à toi de décider`, m.resource, null, "Décider", m.resource]);
  for (const a of state.run.abandoned) items.push(["alert", `L'agent n'a pas su réparer « ${name(a.target)} »`, "Son dossier explique pourquoi", "#/activity", "Voir"]);
  if (!items.length) return `<div class="clear">Rien ne t'attend. L'agent surveille et répare en continu.</div>`;
  return `<div class="todo">${items.map(([kind, what, sub, href, cta, review]) => `
    <div class="task"><i class="dot ${kind}"></i><div class="what"><b>${esc(what)}</b><span>${esc(sub)}</span></div>
      ${review ? (review.startsWith("repo:") ? `<button class="btn primary" data-review="${esc(review)}">${cta}</button>` : `<a class="btn primary" href="#/decisions">${cta}</a>`) : `<a class="btn" href="${href}">${cta}</a>`}</div>`).join("")}</div>`;
}

function feed(limit) {
  const rows = state.history.slice(0, limit).map((c) => {
    const agent = c.author === "standard-agent";
    return `<li><i class="dot ${agent ? "agent" : "people"}"></i><div><div class="t">${esc(subject(c.subject))}</div>
      <div class="s">${agent ? "Joué par l'agent, sous les règles" : `Intégré, par ${esc(c.author)}`}</div></div>
      <time>${c.at > 946684800 ? ago(c.at * 1000) : ""}</time></li>`;
  });
  return `<ul class="feed">${rows.join("")}</ul>`;
}

function autonomy() {
  const a = state.autonomy, c = a.count, n = a.total, share = (k) => Math.round((100 * c[k]) / Math.max(n, 1));
  const blocked = a.requirements.filter((r) => r.blocked).length;
  return `<h1>Autonomie</h1>
    <p class="lede">Ce que Standard fait sans toi, pour chaque élément, sous les règles en vigueur. L'autonomie n'est jamais une confiance accordée à l'agent : c'est une route des règles qui tient sur les faits du scanner.</p>
    <section class="autosum">
      <div class="panel"><h2>Code et conformité</h2>
        <div class="bar">${["autonomous", "decision", "human"].map((k) => `<span class="seg-${k}" style="flex:${c[k]}" title="${LEVEL[k][1]} : ${c[k]}"></span>`).join("")}</div>
        <ul class="levels">${["autonomous", "decision", "human"].map((k) => `<li>${levelTag(k)}<b>${c[k]} sur ${n}</b><span>${share(k)} %</span><p>${esc(a.levels[k])}</p></li>`).join("")}</ul>
        ${blocked ? `<p class="small quiet">${plural(blocked, "exigence n'est pas mesurée", "exigences ne sont pas mesurées")} sur cette installation : leur autonomie reste théorique tant qu'aucun instrument ne les couvre.</p>` : ""}
      </div>
      <div class="panel"><h2>Exploitation</h2>${levelTag("observed")}<p>${esc(a.runtime.why)}</p>
        <p class="small quiet">Pour aller plus loin : ${esc(RAISE.observed)}</p></div>
    </section>
    ${["autonomous", "decision", "human"].map((lv) => {
      const rs = a.requirements.filter((r) => r.level === lv);
      return rs.length ? `<section class="lvl"><div class="lvlhead">${levelTag(lv)}<h2>${LEVEL[lv][2]}</h2><span class="quiet">${rs.length} sur ${n}</span></div>
        <div class="lvlbody"><div><h3>Pourquoi cette limite</h3><p>${esc(a.levels[lv])}</p><h3>Ce qui l'augmenterait</h3><p>${esc(RAISE[lv])}</p></div>
        <ul class="items">${rs.map((r) => `<li><b>${esc(name(r.id))}</b>${r.condition ? `<span class="cond">${esc(r.condition)}</span>` : ""}${r.blocked ? `<span class="cond bad">Non mesurée ici : autonomie théorique.</span>` : ""}</li>`).join("")}</ul></div></section>` : "";
    }).join("")}
    <section class="lvl"><div class="lvlhead">${levelTag("observed")}<h2>${LEVEL.observed[2]}</h2><span class="quiet">tous les composants en exploitation</span></div>
      <div class="lvlbody"><div><h3>Pourquoi cette limite</h3><p>${esc(a.runtime.why)}</p><h3>Ce qui l'augmenterait</h3><p>${esc(RAISE.observed)}</p></div>
      <ul class="items">${["APIs", "Workers et files", "Tâches planifiées", "Bases de données", "Services externes", "Processus"].map((k) => `<li><b>${k}</b></li>`).join("")}</ul></div></section>`;
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
function budgetBar(b) {
  if (b == null) return `<div class="bbar"><i style="width:0"></i></div><span class="small quiet">pas encore de données</span>`;
  const w = Math.max(0, Math.min(1, b)), tone = b < 0 ? "bad" : b < 0.25 ? "warn" : "ok";
  return `<div class="bbar ${tone}"><i style="width:${(w * 100).toFixed(1)}%"></i></div><span class="small ${tone}">${b < 0 ? `épuisé, dépassé de ${pct(-b, 0)}` : `${pct(b, 1)} restant`}</span>`;
}
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
    ${Object.keys(d.live.slos || {}).length ? `<section><h2>SLO <span class="quiet small">budget d'erreur sur la fenêtre de chaque SLO ; <a href="#/rules">régler</a></span></h2><div class="slostrip">${Object.entries(d.live.slos).map(([id, e]) => `
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
    const id = "m-" + crypto.randomUUID().replaceAll("-", "").slice(0, 8);
    await signRules({ sections: { silences: { [id]: { target_of: m.dataset.silence, reason: "silencée depuis Alertes",
      until: String(Date.now() + 3_600_000) } } } }, m);
    return;
  }
  const d = e.target.closest("[data-decide]");
  if (d) {
    d.disabled = true;
    try {
      await (d.dataset.no ? sayNo(d.dataset.decide) : sayYes(d.dataset.decide));
      d.textContent = d.dataset.no ? "Gelé" : "Oui signé : l'agent joue au prochain passage";
      setTimeout(refresh, 800);
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
    [/^the rules deploy directly$/, () => ["Les règles déploient directement : pas de canari", ""]],
    [/^the canary holds$/, () => ["Le canari tient", "ok"]],
    [/^(\w{7})\w* never answered: (\w{7})\w* still serves$/, (m) => [`${m[1]} n'a jamais répondu : ${m[2]} sert toujours, retour automatique`, "bad"]],
    [/^automatic restart is off$/, () => ["Redémarrage automatique désactivé", ""]],
    [/^deployments are frozen$/, () => ["Mises en production gelées", "wait"]],
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
  const can = Boolean(signer && live.grant && signer.identity === live.grant.holder);
  const ms = (live.moves || []).filter((m) => ["yours", "ready", "decided"].includes(m.status));
  const btn = (m) => `<button class="btn ${m.op === "abort" ? "danger" : m.op === "deploy" ? "primary" : ""}" data-decide="${esc(m.resource)}" ${can && m.status === "yours" ? "" : "disabled"}>
      ${OP[m.op] || m.op}${m.status === "yours" ? "" : " (l'agent s'en charge)"}</button>`;
  return `<div class="decide">${ms.map(btn).join("")}<span class="small quiet">${can
    ? "Oui est une signature de ce navigateur sur ce coup exact ; l'agent le joue, la garde l'exécute si les faits du scanner tiennent encore."
    : `Décisions réservées à ${esc(live.grant?.holder || "l'humain")}, avec sa clé dans ce navigateur.`}</span></div>`;
}

// ---- ALERTS: what is wrong now, and who took it -------------------------------------------------------------------
const ALERT_STATE = { failing: ["escalated", "En échec"], degraded: ["gap", "Dégradé"], escalated: ["escalated", "Échéance dépassée"],
  resolved: ["held", "Résolu"] };
function banner() {
  if (!alerting || !alerting.open || route() === "alerts") return "";
  return `<a class="alarm-bar hot" href="#/alerts"><i></i><b>${plural(alerting.open, "alerte ouverte", "alertes ouvertes")}</b><em>Voir</em></a>`;
}
function alertsView() {
  if (!alerting) return `<h1>Alertes</h1><div class="note bad">Les alertes sont indisponibles.</div>`;
  const grant = state.signing.grants.human, can = Boolean(signer && grant && signer.identity === grant.holder);
  const what = (a) => a.kind === "slo" ? `SLO <b>${esc(a.name)}</b>` : a.kind === "obligation" ? `Écart réglementaire : ${esc(name(a.name.replace(/^target:/, "")))}`
    : a.kind === "source" ? `Source de métriques ${esc(a.name)}` : `${esc(KIND[a.kind]?.[1] || a.kind)} <b>${esc([a.operation, a.name].filter(Boolean).join(" "))}</b>`;
  const why = (a) => a.why?.rule === "overdue" ? `échéance du ${due(a.why.due)} dépassée` : a.why?.rule === "source_down" ? "ne répond pas" : reason(a.why);
  const row = (a) => {
    const s = ALERT_STATE[a.closed_at ? "resolved" : a.state] || ["pending", a.state];
    return `<div class="rowi"><div class="main">${a.closed_at ? "" : `<span class="sev ${a.severity}">${a.severity === "page" ? "Page" : "Ticket"}</span>`}<span class="state ${s[0]}"><i></i>${s[1]}</span> ${what(a)}
      <div class="facts">${fact(`depuis ${ago(a.opened_ms)}`, "")}${a.why ? fact(why(a), "") : ""}
        ${a.closed_at ? fact(`résolu ${ago(a.closed_at * 1000)}`, "ok") : ""}
        ${a.silenced ? fact(`silencée jusqu'à ${new Date(Number(a.silenced.until)).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}${a.silenced.reason ? ` : ${a.silenced.reason}` : ""}`, "") : ""}</div></div>
      ${!a.closed_at && !a.silenced && can && a.subject ? `<button class="btn" data-silence="${esc(a.subject)}">Silencer 1 h</button>` : ""}</div>`;
  };
  const open = alerting.alerts.filter((a) => !a.closed_at), closed = alerting.alerts.filter((a) => a.closed_at);
  return `<h1>Alertes</h1><p class="lede">Ce qui se dégrade en production et les écarts dont l'échéance est passée. Un silence est une règle signée : il coupe le badge, jamais un fait.</p>
    <section><h2>Ouvertes <span class="quiet small">${open.length}</span></h2><div class="rows">${open.map(row).join("") || `<div class="rowi quiet">Aucune alerte ouverte</div>`}</div></section>
    ${closed.length ? `<section><h2>Résolues ces dernières 24 h</h2><div class="rows">${closed.map(row).join("")}</div></section>` : ""}
    ${alerting.silenced ? `<p class="small quiet">${plural(alerting.silenced, "alerte silencée", "alertes silencées")} (maintenance) : hors du badge, les faits signés ne changent pas.</p>` : ""}
    <p class="small quiet">Page : à prendre maintenant (composant en échec, SLO qui brûle vite son budget, échéance dépassée). Ticket : à traiter dans la journée (dégradé, consommation lente).
      Une alerte s'ouvre quand un composant passe dégradé ou en échec sur les 5 dernières minutes, ou quand une source se tait ;
      elle se ferme quand il revient. Pas encore d'e-mail ni de messagerie : seulement cette page, le badge et le titre de l'onglet.</p>`;
}
// ---- your three gestures ---------------------------------------------------------------------------------------------
async function admit(kind, body) {
  const statement = { id: `${kind}-${crypto.randomUUID().replaceAll("-", "")}`, at: Math.max(Date.now(), state.signing.as_of + 1),
    author: signer.identity, ...body };
  const env = await envelope(state.signing.domain, kind, statement, signer);
  const r = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
  const out = await r.json();
  if (!r.ok) throw new Error(out.refused || out.error);
  return out;
}
const sayYes = (resource) => admit("observation", { under: state.signing.grants.human.id, resource, property: "decision",
  status: "approve", level: "real" });
const sayNo = (scope) => admit("freeze", { scope });
// ---- the rule catalog against this product (lots 5 and 8) -----------------------------------------------------------
const STATE = { measured: ["Mesurée", "ok"], partial: ["Mesurée en partie", "ok"], failing: ["Enfreinte", "bad"],
  uncovered: ["Non mesurée : à déclarer", "wait"], patrolled: ["Lue par la patrouille", ""], human: ["Ta décision", ""],
  gap: ["Pas encore d'instrument", ""], "n/a": ["Sans objet", ""], unmeasured: ["Pas encore mesurée", "wait"] };
const WHO = { det: "déterministe", ai: "IA", human: "toi" };

function coverageView() {
  return `<h1>Couverture des règles</h1>
    <p class="lede">Les règles de sécurité et d'exploitation (OWASP ASVS 5.0, CWE Top 25, mise en production) contre ce produit. Une règle enfreinte ou non mesurée est une dette avec une échéance ;
      l'agent la répare par les blocs. Ce que seule une lecture peut vérifier passe par la patrouille, jamais par une dette.</p>
    <div id="coverage"><p class="quiet">Chargement</p></div>`;
}

async function loadCoverage() {
  let data;
  try {
    const r = await fetch("/api/coverage", { cache: "no-store" });
    data = await r.json();
    if (!r.ok) throw new Error(data.error);
  } catch (err) { $("#coverage").innerHTML = `<div class="note bad">Couverture indisponible : ${esc(err.message)}</div>`; return; }
  const all = data.categories.flatMap((c) => c.rules);
  const n = (s) => all.filter((r) => r.state === s).length;
  const can = Boolean(signer);
  const ids = [...new Set(Object.values(data.routes).map((r) => r.id).filter(Boolean))].sort();
  const missing = Object.entries(data.routes).filter(([, r]) => !r.id);
  $("#coverage").innerHTML = `
    ${data.app ? "" : `<div class="note warn">Indique dans Règles du jeu l'application du produit (@app, par exemple <span class="sha">shop.main:app</span>) : sans elle, les sondes de Standard ne peuvent pas la démarrer.</div>`}
    <section class="cols"><div class="panel"><h2>${all.length} règles</h2><div class="facts">
      ${fact(`${n("measured") + n("partial")} mesurées`, "ok")}${fact(`${n("failing")} enfreintes`, n("failing") ? "bad" : "")}
      ${fact(`${n("uncovered") + n("unmeasured")} non mesurées`, n("uncovered") ? "wait" : "")}${fact(`${n("patrolled")} par la patrouille`, "")}
      ${fact(`${n("n/a")} sans objet`, "")}</div></div>
    <div class="panel"><h2>Matrice d'accès</h2><p class="small quiet">Chaque route nomme un identifiant (allow("…")) ; tu donnes les rôles. Une route absente de la matrice est réservée aux administrateurs.</p>
      ${missing.length ? `<div class="note warn">${missing.length} route(s) sans identifiant : ${missing.map(([e]) => `<span class="sha">${esc(e)}</span>`).join(" ")}</div>` : ""}
      <div class="panel sets">${ids.map((id) => `<div class="set"><div class="sl"><b>${esc(id)}</b><span class="small quiet">${Object.entries(data.routes).filter(([, r]) => r.id === id).map(([e]) => esc(e)).join(" · ")}</span></div>
        <div class="sv"><input type="text" data-roles="${esc(id)}" value="${esc((data.access[id] || []).join(", "))}" placeholder="admin seulement" ${can ? "" : "disabled"}></div></div>`).join("") || `<div class="rowi quiet">Aucune route lue sur main</div>`}</div>
      ${ids.length ? `<button class="btn" id="signaccess" ${can ? "" : "disabled"}>Signer la matrice</button> <span id="accessmsg" class="small quiet"></span>` : ""}</div></section>
    ${data.categories.map((c) => `<details class="panel" ${c.rules.some((r) => ["failing", "uncovered"].includes(r.state)) ? "open" : ""}><summary><b>${esc(c.name)}</b> <span class="quiet small">${c.rules.length} règles</span>
        ${c.status ? fact(c.status === "none" ? "tenue" : c.status, c.status === "none" ? "ok" : "bad") : fact("pas encore mesurée", "wait")}${c.due ? fact(`échéance ${due(c.due)}`, "wait") : ""}</summary>
      <div class="rows">${c.rules.map((r) => `<div class="rowi"><div class="main"><b>${esc(r.id)}</b> <span class="small">${esc(r.do)}</span>
        <div class="facts">${fact(...STATE[r.state] || [r.state, ""])}${fact(`vérifiée par ${r.who.map((w) => WHO[w] || w).join(" + ")}`, "")}${r.block ? fact(`bloc ${r.block}`, "") : ""}</div></div></div>`).join("")}</div>
      ${c.why.length ? `<details><summary class="small">Pourquoi</summary><pre class="small">${esc(c.why.join("\n"))}</pre></details>` : ""}</details>`).join("")}`;
  const btn = $("#signaccess");
  if (btn) btn.onclick = () => {
    const access = {};
    document.querySelectorAll("[data-roles]").forEach((i) => {
      const roles = i.value.split(",").map((x) => x.trim()).filter(Boolean);
      if (roles.length) access[i.dataset.roles] = roles;
    });
    const kept = Object.fromEntries(Object.entries(data.access).filter(([k]) => !ids.includes(k)));
    signRules({ values: { access: { ...kept, ...access } } }, $("#accessmsg"));
  };
}

const { view: rulesView, load: loadRules, signRules: signRulesInto } = createRules({ $, esc, fact, ago, getSigner: () => signer, envelope });
const signRules = (changes, el) => signRulesInto(changes, { set textContent(v) { el.textContent = v; } });

function decisions() {
  const items = pending(), byResource = Object.fromEntries(candidates().map((c) => [c.resource, c]));
  return `<h1>Décisions</h1>
    <p class="lede">Les coups que seule ta décision peut jouer : les règles les gardent pour toi, ou aucun chemin automatique ne tient.
      Tout le reste (tests, absence de régression, périmètre, faits de production) est déjà mesuré. Oui porte sur ce coup exact ; non le gèle.</p>
    ${signer ? "" : `<div class="note warn" style="margin-top:24px">Pour décider, ajoute ta clé dans Clé de signature.</div>`}
    <section>${items.length ? `<div class="rows">${items.map((m) => {
      const c = byResource[m.resource];
      return `<div class="rowi"><div class="main"><b>${OP[m.op] || esc(m.op)}</b> ${c?.kind === "contribution" ? `<span class="quiet">par ${esc(c.author)}</span>` : c?.target ? `<span class="quiet">${esc(name(c.target))}</span>` : ""}
        <span class="sha">${esc(m.resource)}</span>
        <div class="facts">${m.refuted.map((x) => fact(`hors route automatique : ${x}`, "wait")).join("")}${m.turned_off.length ? fact(`route coupée par tes règles : ${m.turned_off.join(", ")}`, "wait") : ""}</div></div>
        ${m.resource.startsWith("repo:") ? `<button class="btn primary" data-review="${esc(m.resource)}">Lire et décider</button>`
          : `<button class="btn primary" data-decide="${esc(m.resource)}" ${signer ? "" : "disabled"}>Oui</button><button class="btn" data-decide="${esc(m.resource)}" data-no="1" ${signer ? "" : "disabled"}>Non</button>`}</div>`;
    }).join("")}</div>`
      : `<div class="empty"><b>Rien ne t'attend</b>L'agent joue seul ce que les règles lui laissent.</div>`}</section>`;
}

function activity() {
  const repairs = state.run.repairs;
  const progress = state.progress;
  return `
    <h1>Activité</h1><p class="lede">Tout ce qui a atteint la branche principale, et ce que l'agent prépare.</p>
    ${progress?.status === "unavailable" ? `<section><h2>Progression</h2><p>Mesure indisponible</p></section>`
      : progress ? `<section><h2>Progression</h2><p>${progress.pf} impasse${progress.pf === 1 ? "" : "s"} confirmée${progress.pf === 1 ? "" : "s"} · ${progress.waiting.length} tâche${progress.waiting.length === 1 ? "" : "s"} en attente</p></section>` : ""}
    ${repairs.length ? `<section><h2>Réparations de l'agent</h2><div class="rows">${repairs.map((p) => `
      <div class="rowi"><div class="main"><b>${esc(name(p.target))}</b> <span class="sha">${short(p.head)}</span>
        <div class="facts">${p.way === "recipe" ? fact("Recette", p.facts.reproduced === "yes" ? "ok" : "") : fact("Écrite par un modèle", "")}
          ${fact(p.facts.tests === "green" ? "Tests au vert" : p.facts.tests ? "Tests en échec" : "Tests en cours", p.facts.tests === "green" ? "ok" : p.facts.tests ? "bad" : "")}
          ${moveFact(p.move)}</div></div>
        <button class="btn ${p.awaiting ? "primary" : ""}" data-review="${esc(p.resource)}">${p.awaiting ? "Décider" : "Détails"}</button></div>`).join("")}</div></section>` : ""}
    ${state.run.abandoned.length ? `<section><h2>Ce que l'agent n'a pas su réparer</h2>${state.run.abandoned.map((a) => `
      <div class="panel"><b>${esc(name(a.target))}</b><pre style="margin-top:12px">${esc(a.dossier)}</pre></div>`).join("")}</section>` : ""}
    <section><h2>Historique de production</h2>${feed(50)}</section>`;
}

function fact(text, tone) {
  return `<span class="fact ${tone}"><i></i>${esc(text)}</span>`;
}
const MOVE = { ready: ["L'agent joue seul", "ok"], decided: ["Oui signé : l'agent joue", "ok"], yours: ["À toi de décider", "wait"],
  measuring: ["En mesure", ""], refuted: ["Refusé par les faits", "bad"], frozen: ["Gelé", "bad"], playing: ["En cours", "ok"],
  done: ["Joué", "ok"], failed: ["N'a pas abouti", "bad"] };
const moveFact = (m) => m?.status ? fact(MOVE[m.status]?.[0] || m.status, MOVE[m.status]?.[1] || "") : "";

const auto = (id) => state.autonomy.requirements.find((a) => a.id === id);

function requirementTables() {
  return `${DOMAINS.map(([label, test]) => {
      const rs = state.requirements.filter(test);
      return rs.length ? `<section><h2>${label}</h2><table class="table req"><colgroup><col><col style="width:150px"><col style="width:190px"><col style="width:210px"><col style="width:120px"></colgroup>
        <thead><tr><th>Exigence</th><th>État</th><th>Mesure</th><th>Autonomie</th><th></th></tr></thead><tbody>
      ${rs.map((r) => `<tr><td><div class="name">${esc(name(r.id))}</div><div class="sub">${esc(r.property)} = ${esc(r.expect)}</div>
        ${r.where.length && r.state === "gap" ? `<ul class="where">${r.where.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</td>
        <td><span class="state ${r.state}"><i></i>${STATES[r.state]}</span></td>
        <td class="sub">${esc(measure(r))}</td>
        <td>${auto(r.id) ? `${levelTag(auto(r.id).level)}<div class="sub">${LEVEL[auto(r.id).level][2]}</div>` : `<span class="state pending"><i></i>Non classée</span>`}</td>
        <td><button class="btn tiny" data-agent-context="target" data-id="${esc(r.id)}">Contexte</button></td></tr>`).join("")}</tbody></table></section>` : "";
    }).join("")}`;
}

// ---- BUILD: the product being built -------------------------------------------------------------------------------
function contributions() {
  const cs = state.build.contributions;
  const status = (c) => c.landed ? fact("En production", "ok") : c.stale ? fact("La branche principale a avancé : à rebaser", "wait")
    : c.blocked.length ? fact("Bloquée par les faits", "bad") : moveFact(c.move) || fact("Mesure en cours", "");
  return `<h1>Contributions</h1>
    <p class="lede">Le code poussé par d'autres que l'agent. Il n'entre qu'avec les tests au vert, aucun nouvel écart, et ton oui.</p>
    <section>${cs.length ? `<div class="rows">${cs.map((c) => `
      <div class="rowi"><div class="main"><b>${esc(c.branch)}</b> <span class="quiet">par ${esc(c.author)}</span> <span class="sha">${short(c.head)}</span>
        <div class="facts">${status(c)}
          ${fact(c.facts.tests === "green" ? "Tests au vert" : c.facts.tests ? "Tests en échec" : "Tests en cours", c.facts.tests === "green" ? "ok" : c.facts.tests ? "bad" : "")}
          ${fact(c.facts.regressions === "none" ? "Aucun nouvel écart" : c.facts.regressions ? "Ouvre un nouvel écart" : "Écarts en cours", c.facts.regressions === "none" ? "ok" : c.facts.regressions ? "bad" : "")}</div>
        ${c.why.length ? `<ul class="where">${c.why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</div>
        ${c.landed ? "" : `<button class="btn ${c.awaiting ? "primary" : ""}" data-review="${esc(c.resource)}">${c.awaiting ? "Décider" : "Détails"}</button>`}</div>`).join("")}</div>`
      : `<div class="empty"><b>Aucune contribution</b>Poussez une branche à votre nom, par exemple <span class="sha">git push origin HEAD:refs/heads/vous/ma-branche</span>.</div>`}</section>`;
}

const RSTATE = { proposed: ["pending", "Proposée"], contracted: ["gap", "Contrat signé"], delivered: ["held", "Livrée"], withdrawn: ["idle", "Retirée"] };
const TEMPLATE = `from app import ma_fonction


def test_cas_nominal():
    assert ma_fonction(2, 3) == 6


def test_cas_limite():
    assert ma_fonction(7, 0) == 0
`;
function contractFact(r) {
  const c = r.facts.contract, a = r.facts.accepted;
  if (r.state === "delivered") return fact("main passe le contrat", "ok");
  if (r.state === "contracted") return fact(a === "yes" ? "main passe le contrat : livraison au prochain passage" : "main ne passe pas encore le contrat", a === "yes" ? "ok" : "wait");
  if (!c) return fact("Le scanner n'a pas encore mesuré le contrat", "");
  if (c === "red") return fact("Chaque test échoue sur main : le contrat demande quelque chose de nouveau", "ok");
  if (c.startsWith("passes:")) return fact(`${c.slice(7)} test(s) passent déjà sur main : le contrat ne promet rien`, "bad");
  if (c === "empty") return fact("Le contrat ne contient aucun test", "bad");
  return fact(`Contrat : ${c}`, "bad");
}
function requests() {
  const rs = state.build.requests, grant = state.signing.grants.human;
  const can = Boolean(signer && grant && signer.identity === grant.holder);
  const feature = (f) => `<div class="rowi"><div class="main"><b>Implémentation</b> <span class="sha">${short(f.head)}</span>
      <div class="facts">${f.landed ? fact("Sur main", "ok") : f.stale ? fact("main a avancé : l'agent réimplémente", "wait") : ""}
        ${fact(f.facts.acceptance === "green" ? "Contrat tenu" : f.facts.acceptance ? `Contrat : ${f.facts.acceptance}` : "Contrat en mesure", f.facts.acceptance === "green" ? "ok" : f.facts.acceptance ? "bad" : "")}
        ${fact(f.facts.tests === "green" ? "Tests de main au vert" : f.facts.tests ? "Tests de main en échec" : "Tests en mesure", f.facts.tests === "green" ? "ok" : f.facts.tests ? "bad" : "")}
        ${fact(f.facts.regressions === "none" ? "Aucun nouvel écart" : f.facts.regressions ? "Ouvre un écart" : "Écarts en mesure", f.facts.regressions === "none" ? "ok" : f.facts.regressions ? "bad" : "")}
        ${moveFact(f.move)}</div>
      ${f.why.length ? `<ul class="where">${f.why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</div>
      ${f.landed ? "" : `<button class="btn ${f.awaiting ? "primary" : ""}" data-review="${esc(f.resource)}">${f.awaiting ? "Décider" : "Détails"}</button>`}</div>`;
  const card = (r) => {
    const st = RSTATE[r.state] || ["pending", r.state];
    const contributions = state.build.contributions.filter((c) => c.request === r.id);
    return `<div class="panel req"><div class="slohead"><div><b>${esc(r.title)}</b>
        <div class="small quiet"><span class="sha">${esc(r.id)}</span> · par ${esc(r.owner || "?")}${r.created ? ` · ${ago(r.created)}` : ""} · contrat <span class="sha">${esc(r.path)}</span></div></div>
        <span class="state ${st[0]}"><i></i>${st[1]}</span></div>
      <div class="facts">${contractFact(r)}${r.state === "contracted" && r.agent ? fact(`Agent : ${agentText(r.agent)}`, "") : ""}</div>
      ${r.contract_details.length && r.state === "proposed" ? `<ul class="where">${r.contract_details.slice(0, 4).map((w) => `<li>${esc(w.split("\n")[0])}</li>`).join("")}</ul>` : ""}
      <details><summary>Spécification et contrat</summary>${r.spec ? `<h3>Spécification</h3><pre>${esc(r.spec)}</pre>` : ""}
        ${r.contract ? `<h3>Tests d'acceptation (signés, immuables)</h3><pre>${esc(r.contract)}</pre>` : `<div class="note bad">Le contrat n'est pas dans le magasin des demandes.</div>`}</details>
      ${r.features.length || contributions.length ? `<div class="rows" style="margin-top:12px">${r.features.map(feature).join("")}
        ${contributions.map((c) => `<div class="rowi"><div class="main"><b>Contribution de ${esc(c.author)}</b> <span class="sha">${short(c.head)}</span>
          <div class="facts">${fact(c.facts.acceptance === "green" ? "Contrat tenu" : c.facts.acceptance ? `Contrat : ${c.facts.acceptance}` : "Contrat en mesure", c.facts.acceptance === "green" ? "ok" : c.facts.acceptance ? "bad" : "")}</div></div>
          <button class="btn" data-review="${esc(c.resource)}">Détails</button></div>`).join("")}</div>` : ""}
      <div class="decide compact"><button class="btn" data-agent-context="request" data-id="${esc(r.id)}">Contexte agent</button>
        <span class="small quiet">Dossier lisible par l'agent et par toi : demande, règles, preuves et limites.</span></div>
      ${r.state === "proposed" || r.state === "contracted" ? `<div class="decide">
        ${r.state === "proposed" ? `<button class="btn primary" data-contract="${esc(r.resource)}" ${can && r.facts.contract === "red" ? "" : "disabled"}>Signer le contrat</button>` : ""}
        <button class="btn danger" data-withdraw="${esc(r.resource)}" ${can ? "" : "disabled"}>Retirer</button>
        <span class="small quiet">${r.state === "proposed" ? "Signer le contrat, c'est dire quoi construire : l'agent l'implémente, les tests ne pourront plus changer." : "L'agent implémente ; l'implémentation entre seule si le contrat passe, sans régression, dans son périmètre."}</span></div>` : ""}
    </div>`;
  };
  return `<h1>Demandes</h1>
    <p class="lede">Une demande est une spécification et un contrat : des tests d'acceptation que vous écrivez et signez avant tout code.
      Le scanner vérifie qu'ils échouent sur main (sinon ils ne promettent rien). Ensuite l'agent, ou un contributeur, implémente sans pouvoir toucher aux tests ;
      elle entre avec le contrat tenu, les tests de main au vert, aucun nouvel écart et un périmètre respecté.</p>
    ${!signer ? `<div class="note warn">Ajoute ta clé dans Clé de signature pour écrire et signer une demande.</div>` : !can ? `<div class="note warn">Seul ${esc(grant?.holder || "l'humain")} écrit et signe les demandes ici.</div>` : ""}
    <section><h2>Nouvelle demande</h2><div class="panel sloform">
      <label for="rq-title">Titre</label><input type="text" id="rq-title" placeholder="ex. Multiplier deux nombres" ${can ? "" : "disabled"}>
      <label for="rq-spec">Spécification</label><textarea id="rq-spec" class="code sm" placeholder="Ce que la fonctionnalité doit faire, pour qui, et ses limites." ${can ? "" : "disabled"}></textarea>
      <label for="rq-contract">Tests d'acceptation (pytest)</label><textarea id="rq-contract" class="code" spellcheck="false" ${can ? "" : "disabled"}>${esc(TEMPLATE)}</textarea>
      <div class="decide"><button class="btn primary" id="rq-create" ${can ? "" : "disabled"}>Enregistrer et signer la demande</button><span id="rq-msg" class="small quiet"></span></div></div></section>
    <section><h2>Demandes <span class="quiet small">${rs.length}</span></h2>${rs.map(card).join("") || `<div class="empty"><b>Aucune demande</b>Écrivez la première ci-dessus.</div>`}</section>`;
}
function agentText(s) {
  if (s === "landing") return "implémentation acceptée par la loi, intégration en cours";
  if (s === "delivered") return "livraison enregistrée";
  if (s.startsWith("proposed")) return "implémentation proposée : le scanner la mesure, les règles disent qui la joue";
  if (s.startsWith("waiting: no model")) return "aucun modèle configuré : un contributeur peut l'implémenter (Standard-Request: dans le commit)";
  if (s.startsWith("waiting")) return "pas encore d'implémentation qui passe ses propres vérifications";
  return s;
}
async function signRequest(kind, body) {
  const grant = state.signing.grants.human;
  const statement = { id: `${kind}-${crypto.randomUUID().replaceAll("-", "")}`, at: Math.max(Date.now(), state.signing.as_of + 1),
    author: signer.identity, under: grant.id, ...body };
  const env = await envelope(state.signing.domain, kind, statement, signer);
  const r = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
  const out = await r.json();
  if (!r.ok) throw new Error(out.refused || out.error);
}
document.addEventListener("click", async (e) => {
  const c = e.target.closest("[data-contract]"), w = e.target.closest("[data-withdraw]");
  if (!c && !w && e.target.id !== "rq-create") return;
  if (e.target.id === "rq-create") {
    const title = $("#rq-title").value.trim(), spec = $("#rq-spec").value.trim(), contract = $("#rq-contract").value;
    if (!title || !spec || !contract.trim()) { $("#rq-msg").textContent = "Titre, spécification et tests sont nécessaires."; return; }
    e.target.disabled = true;
    try {
      const r = await fetch("/api/requests", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spec, contract }) });
      const digests = await r.json();
      if (!r.ok) throw new Error(digests.error);
      const id = title.toLowerCase().normalize("NFD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) + "-" + crypto.randomUUID().slice(0, 4);
      await signRequest("resource", { resource: `build:request/${id}`, type: "request", fields: { title: title.slice(0, 120), spec: digests.spec, contract: digests.contract } });
      $("#rq-msg").textContent = "Demande signée. Le scanner mesure le contrat sur main au prochain passage.";
      setTimeout(refresh, 1200);
    } catch (err) { $("#rq-msg").textContent = `Refusé : ${err.message}`; e.target.disabled = false; }
    return;
  }
  const el = c || w, r = state.build.requests.find((x) => x.resource === el.dataset.contract || x.resource === el.dataset.withdraw);
  el.disabled = true;
  try {
    await signRequest("transition", { resource: r.resource, operation: c ? "contract" : "withdraw", expected: r.expected, changes: {} });
    el.textContent = c ? "Contrat signé" : "Retirée";
    setTimeout(refresh, 1000);
  } catch (err) { el.textContent = `Refusé : ${err.message}`; }
});

function proofs() {
  const c = counts();
  return `<h1>Preuves</h1>
    <p class="lede">Chaque exigence tenue repose sur une observation signée par un instrument indépendant, inscrite dans un journal chaîné. C'est ce que vous remettez à un auditeur.</p>
    <section class="cols">
      <div class="panel"><h2>Journal</h2><p class="small quiet">Entrées : ${state.prefix.size}</p>
        <p class="small quiet">Tête : <span class="sha">${esc(state.prefix.head.slice(7, 23))}</span></p>
        <p class="small quiet">Loi : <span class="sha">${esc(state.law_digest.slice(7, 23))}</span></p>
        <p class="small quiet">${state.assessment === "INDEPENDENT" ? "Installation évaluée par un tiers indépendant." : "Laboratoire auto-évalué : garanties physiques non qualifiées."}</p></div>
      <div class="panel"><h2>Couverture</h2><p class="small quiet">${c.held} exigences tenues sur ${c.total}, ${c.unmeasured} non mesurées sur cette installation.</p>
        <button class="btn" id="export">Télécharger le rapport</button></div>
    </section>
    ${map()}
    ${requirementTables()}`;
}

function settings() {
  const grants = state.signing.grants;
  return `<h1>Clé de signature</h1>
    <p class="lede">Ta clé reste dans ce navigateur : elle y est importée sans pouvoir en sortir, et n'est jamais envoyée au serveur. Le navigateur fabrique lui-même ce qu'il signe : tes oui, tes non et tes règles.</p>
    <section class="panel">${signer
      ? `<div class="note ok">Ce navigateur signe en tant que <b>${esc(signer.identity)}</b>.</div><button class="btn danger" id="forget">Retirer la clé de ce navigateur</button>`
      : `<h2>Ajouter votre clé</h2>
        <label for="ident">Identité</label><input id="ident" type="text" value="${esc(grants.human?.holder || "")}" autocomplete="off">
        <label for="keyfile">Fichier de clé</label><input id="keyfile" type="file">
        <p class="small quiet">Installation de démonstration : le fichier créé par la cérémonie. En production, une passkey sur ton appareil.</p>
        <button class="btn primary" id="import">Ajouter la clé</button> <span id="msg" class="small quiet"></span>`}</section>`;
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
  if (cell) location.hash = "#/proofs";
});

// ---- agent context --------------------------------------------------------------------------------------------------
const bullets = (xs) => `<ul class="ctxbullets">${(xs || []).map((x) => `<li>${esc(x)}</li>`).join("") || `<li class="quiet">Aucun élément publié</li>`}</ul>`;
const jsonBlock = (v) => `<pre>${esc(JSON.stringify(v ?? {}, null, 2))}</pre>`;

async function openAgentContext(kind, id) {
  const dlg = $("#dlg"), body = $("#dlgbody");
  body.innerHTML = `<p class="quiet">Chargement du contexte agent</p>`;
  dlg.showModal();
  let ctx;
  try {
    const r = await fetch(`/api/agent-context?kind=${encodeURIComponent(kind)}&id=${encodeURIComponent(id)}`, { cache: "no-store" });
    ctx = await r.json();
    if (!r.ok || ctx.error) throw new Error(ctx.error || r.statusText);
  } catch (err) {
    body.innerHTML = `<div class="note bad">Contexte indisponible : ${esc(err.message)}</div><footer><button class="btn" id="close">Fermer</button></footer>`;
    $("#close").onclick = () => dlg.close();
    return;
  }
  const isRequest = ctx.kind === "request";
  const isPatrol = ctx.kind === "patrol";
  body.innerHTML = `<h2>Contexte agent · ${esc(ctx.title || ctx.id)}</h2>
    <p class="small quiet">Dossier de lecture. Rien ici n'autorise : seules les signatures admises par le noyau comptent.</p>
    <div class="ctxgrid">
      <section class="ctxcard"><h3>Decision packet</h3>${jsonBlock(ctx.decision)}</section>
      <section class="ctxcard"><h3>Mission</h3>${jsonBlock(ctx.mission)}</section>
      <section class="ctxcard"><h3>Law trace</h3>${jsonBlock(ctx.law_trace || ctx.law)}</section>
      <section class="ctxcard"><h3>Réglages des règles</h3>${jsonBlock(ctx.settings)}</section>
      <section class="ctxcard"><h3>Proof plan</h3>${jsonBlock(ctx.proof_plan || ctx.proof)}</section>
      <section class="ctxcard"><h3>Ce que l'agent peut faire</h3>${bullets(ctx.agent?.can)}<h3>Interdit</h3>${bullets(ctx.agent?.cannot)}</section>
      <section class="ctxcard"><h3>Admission</h3>${jsonBlock(ctx.admission)}</section>
      ${isPatrol ? `<section class="ctxcard"><h3>Effective law</h3>${jsonBlock(ctx.effective_law)}</section>
      <section class="ctxcard"><h3>Weak spots</h3>${jsonBlock(ctx.weak_spots)}</section>
      <section class="ctxcard"><h3>Known findings</h3>${jsonBlock(ctx.known_findings)}</section>
      <section class="ctxcard"><h3>Expected output</h3>${jsonBlock(ctx.expected_output)}</section>` : ""}
    </div>
    ${isRequest ? `<details class="ctxdoc"><summary>Spec et contrat signés</summary><h3>Spec</h3><pre>${esc(ctx.request?.spec || "")}</pre><h3>Contrat</h3><pre>${esc(ctx.request?.contract || "")}</pre></details>` : ""}
    <footer><span class="small quiet spacer">Préfixe ${esc(ctx.basis?.size)} · loi <span class="sha">${esc(String(ctx.law_digest || "").slice(7, 23))}</span></span><button class="btn" id="close">Fermer</button></footer>`;
  $("#close").onclick = () => dlg.close();
}

// ---- reading a move and deciding ------------------------------------------------------------------------------------
async function openReview(resource) {
  const item = candidates().find((i) => i.resource === resource);
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
  const grant = state.signing.grants.human, can = Boolean(signer && grant && signer.identity === grant.holder && item?.awaiting);
  body.innerHTML = `
    <h2>${item?.kind === "contribution" ? esc(item.branch) : item?.kind === "feature" ? `Demande : ${esc(item.title)}` : `Réparation : ${esc(name(item?.target))}`}</h2>
    <div class="quiet small">${item?.kind === "contribution" ? `par ${esc(item.author)}` : item?.kind === "feature" ? "implémentée par l'agent" : "par l'agent"}, commit <span class="sha">${short(head)}</span> sur <span class="sha">${short(resource.split("/").slice(-2)[0])}</span></div>
    <div class="facts">${fact(item?.facts.tests === "green" ? "Tests au vert" : "Tests non verts", item?.facts.tests === "green" ? "ok" : "bad")}
      ${["contribution", "feature"].includes(item?.kind) ? fact(item.facts.regressions === "none" ? "Aucun nouvel écart" : "Ouvre un nouvel écart", item.facts.regressions === "none" ? "ok" : "bad") : ""}
      ${item?.facts?.acceptance ? fact(item.facts.acceptance === "green" ? "Contrat d'acceptation tenu" : `Contrat : ${item.facts.acceptance}`, item.facts.acceptance === "green" ? "ok" : "bad") : ""}</div>
    <h3>Description</h3><pre>${esc(d.message)}</pre>
    <h3>Changements</h3><pre>${diff}</pre>
    ${!signer ? `<div class="note warn" style="margin-top:18px">Ajoute ta clé dans Clé de signature pour décider.</div>` : ""}
    ${signer && !item?.awaiting ? `<div class="note warn" style="margin-top:18px">Ce coup ne t'attend pas : l'agent le joue seul, il est encore en mesure, refusé par les faits ou déjà joué.</div>` : ""}
    <footer><span id="sigmsg" class="small quiet spacer"></span><button class="btn" id="close">Fermer</button>
      <button class="btn" id="no" ${can ? "" : "disabled"}>Non (geler ce coup)</button>
      <button class="btn primary" id="yes" ${can ? "" : "disabled"}>Oui</button></footer>`;
  $("#close").onclick = () => dlg.close();
  const sign = async (yes) => {
    $("#sigmsg").textContent = "Signature dans ce navigateur";
    try {
      await (yes ? sayYes(resource) : sayNo(resource));
      $("#sigmsg").textContent = yes ? "Oui : l'agent joue au prochain passage" : "Gelé";
      setTimeout(() => { dlg.close(); refresh(); }, 800);
    } catch (err) { $("#sigmsg").textContent = `Signature refusée par le noyau : ${err.message}`; }
  };
  if (can) { $("#yes").onclick = () => sign(true); $("#no").onclick = () => sign(false); }
}

// ---- start ----------------------------------------------------------------------------------------------------------
signer = await loadSigner().catch(() => null);
await refresh();
setInterval(() => { if (!$("#dlg").open && route() !== "settings") refresh(); }, 15000);
