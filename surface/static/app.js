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
  overview: ["Aperçu", "run"], activity: ["Activité", "run"], requirements: ["Exigences", "run"],
  contributions: ["Contributions", "build"], requests: ["Demandes", "build"],
  reviews: ["Revues", "both"], proofs: ["Preuves", "both"], settings: ["Réglages", "both"],
};
let state = null, signer = null;
const route = () => (location.hash.slice(2) in ROUTES ? location.hash.slice(2) : "overview");
window.addEventListener("hashchange", () => render());

function pending() {
  return [...state.build.contributions.filter((c) => c.awaiting_review), ...state.run.repairs.filter((r) => r.awaiting_review)];
}

function frame() {
  const here = route(), reviews = pending().length;
  const link = (id) => `<a href="#/${id}" ${id === here ? 'aria-current="page"' : ""}><span>${ROUTES[id][0]}</span>${
    id === "reviews" && reviews ? `<span class="badge">${reviews}</span>` : ""}</a>`;
  $("#nav").innerHTML = `
    <div class="group">Exploitation</div>${link("overview")}${link("activity")}${link("requirements")}
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
  const views = { overview, activity, requirements, contributions, requests, reviews, proofs, settings };
  $("#view").innerHTML = views[route()]();
  if (route() === "settings") bindSettings();
  document.querySelectorAll("[data-review]").forEach((b) => b.addEventListener("click", () => openReview(b.dataset.review)));
}

// ---- RUN: the product in production -------------------------------------------------------------------------------
function counts() {
  const by = (s) => state.requirements.filter((r) => r.state === s).length;
  return { total: state.requirements.length, held: by("held"), gap: by("gap"), escalated: by("escalated"),
    attest: by("attest"), unmeasured: by("unmeasured") };
}

function headline() {
  const c = counts(), reviews = pending().length;
  if (c.escalated) return ["esc", "Action requise", `${plural(c.escalated, "exigence a dépassé son échéance", "exigences ont dépassé leur échéance")} et attend une décision humaine.`];
  if (c.gap || reviews) {
    const gaveUp = new Set(state.run.abandoned.map((a) => a.target));
    const auto = state.requirements.filter((r) => r.state === "gap" && r.who === "agent" && !gaveUp.has(r.id)).length;
    const parts = [];
    if (auto) parts.push(`l'agent répare ${plural(auto, "écart", "écarts")} seul`);
    if (c.gap - auto > 0) parts.push(`${plural(c.gap - auto, "écart attend", "écarts attendent")} une personne`);
    if (reviews) parts.push(`${plural(reviews, "revue vous attend", "revues vous attendent")}`);
    return ["gap", "Sous contrôle", `${c.held} exigences sur ${c.total} sont tenues. ${parts.join(", ").replace(/^./, (x) => x.toUpperCase())}.`];
  }
  return ["", "Tout est tenu", `${c.held} exigences sur ${c.total} sont tenues et prouvées.`];
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
  for (const e of state.health.escalated) items.push(["alert", `${name(e.target)} a dépassé son échéance`, "Décision humaine requise", "#/requirements", "Voir"]);
  for (const p of pending()) items.push(["wait", p.kind === "contribution" ? `Relire la contribution de ${p.author}` : `Relire la réparation « ${name(p.target)} »`,
    "Tests au vert, aucun nouvel écart", null, "Relire", p.resource]);
  for (const a of state.run.abandoned) items.push(["alert", `L'agent n'a pas su réparer « ${name(a.target)} »`, "Son dossier explique pourquoi", "#/activity", "Voir"]);
  const attest = counts().attest;
  if (attest) items.push(["people", `${plural(attest, "exigence organisationnelle", "exigences organisationnelles")} à attester`, "Politiques, accès, continuité, fournisseurs", "#/requirements", "Voir"]);
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

function overview() {
  const [tone, title, line] = headline();
  return `
    <div class="hero"><i class="beacon ${tone}"></i><div><h1>${title}</h1><p class="lede">${esc(line)}</p></div></div>
    ${map()}
    <section class="cols">
      <div><h2>À traiter par vous</h2>${todo()}</div>
      <div><h2>Dernières mises en production</h2>${feed(6)}</div>
    </section>`;
}

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

function requirements() {
  return `<h1>Exigences</h1>
    <p class="lede">Ce que la loi impose à ce produit, mesuré par des instruments indépendants. On peut durcir une exigence à tout moment ; l'assouplir demande deux personnes et une heure de délai.</p>
    ${DOMAINS.map(([label, test]) => {
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
  if (cell) location.hash = "#/requirements";
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
setInterval(() => { if (!$("#dlg").open && route() !== "settings") refresh(); }, 10000);
