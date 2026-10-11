// The interface: reads /api/state, shows BUILD and RUN, and signs reviews in this browser (sign.js).
import { envelope, forgetSigner, importKeyFile, loadSigner, saveSigner } from "/sign.js";

const $ = (sel) => document.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (sha) => esc(String(sha || "").slice(0, 8));
const when = (ms) => new Date(Number(ms)).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });

let state = null, signer = null;
let mode = localStore("mode") || "BUILD";
let tab = localStore("tab") || "overview";

function localStore(key, value) {
  try {
    if (value === undefined) return localStorage.getItem("standard." + key);
    localStorage.setItem("standard." + key, value);
  } catch { return null; }
}

const STATE = { PROVEN: ["ok", "Tout est prouvé"], IN_PROGRESS: ["warn", "En cours"], ESCALATED: ["bad", "Escaladé"], FAULT: ["bad", "Panne"] };
const FACT = {
  tests: { green: ["ok", "tests verts"], red: ["bad", "tests rouges"] },
  regressions: { none: ["ok", "aucun nouvel écart"] },
  review: { approved: ["ok", "revue approuvée"], changes_requested: ["warn", "changements demandés"] },
  reproduced: { yes: ["ok", "reproduit à l'identique"] },
};

function chip(prop, value) {
  if (value === undefined) return `<span class="chip">${prop === "review" ? "pas encore relue" : `${esc(prop)} : non mesuré`}</span>`;
  const known = FACT[prop]?.[value];
  if (known) return `<span class="chip ${known[0]}">${esc(known[1])}</span>`;
  const bad = /^found|^red|^uncovered|^no/.test(value);
  return `<span class="chip ${bad ? "bad" : ""}">${esc(prop)} : ${esc(value)}</span>`;
}

// ---- navigation ---------------------------------------------------------------------------------------------------
function tabs() {
  const reviews = state ? pending().length : 0;
  const list = [["overview", "Vue d'ensemble"], mode === "BUILD" ? ["build", "Construction"] : ["run", "Exploitation"],
    ["reviews", "Revues" + (reviews ? `<span class="count">${reviews}</span>` : "")], ["law", "Loi"], ["identity", "Identité"]];
  if (!list.some(([id]) => id === tab)) tab = mode === "BUILD" ? "build" : "run";
  $("#tabs").innerHTML = list.map(([id, label]) => `<button role="tab" data-tab="${id}" aria-selected="${id === tab}">${label}</button>`).join("");
  document.querySelectorAll(".mode button").forEach((b) => b.classList.toggle("on", b.dataset.mode === mode));
}

document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-tab]");
  if (t) { tab = t.dataset.tab; localStore("tab", tab); render(); }
  const m = e.target.closest("[data-mode]");
  if (m) { mode = m.dataset.mode; localStore("mode", mode); tab = mode === "BUILD" ? "build" : "run"; localStore("tab", tab); render(); }
  const r = e.target.closest("[data-review]");
  if (r) openReview(r.dataset.review);
});

// ---- data -----------------------------------------------------------------------------------------------------------
async function refresh() {
  try {
    const r = await fetch("/api/state", { cache: "no-store" });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || r.statusText);
    state = body;
  } catch (err) {
    state = null;
    $("#view").innerHTML = `<div class="notice bad">Standard n'est pas joignable ou pas qualifié ici (${esc(err.message)}). Rien n'est attesté ni autorisé.</div>`;
    $("#health").textContent = "";
    return;
  }
  render();
}

function pending() {
  return [...state.build.contributions.filter((c) => c.awaiting_review), ...state.run.repairs.filter((r) => r.awaiting_review)];
}

function render() {
  tabs();
  const [cls, label] = STATE[state.health.state] || ["", state.health.state];
  const h = $("#health");
  h.className = `pill chip ${cls}`; h.textContent = label;
  const a = $("#assessment");
  a.className = `pill chip ${state.assessment === "INDEPENDENT" ? "ok" : "warn"}`;
  a.textContent = state.assessment === "INDEPENDENT" ? "Évaluation indépendante" : "Auto-évaluée (démo)";
  $("#where").textContent = `main ${state.main.slice(0, 8)}`;
  $("#who").innerHTML = signer ? `Signé en tant que <b>${esc(signer.identity)}</b>` : `Aucune identité dans ce navigateur`;
  const views = { overview, build, run, reviews, law, identity };
  $("#view").innerHTML = views[tab]();
  if (tab === "identity") bindIdentity();
}

// ---- views ----------------------------------------------------------------------------------------------------------
function overview() {
  const s = state, esc_ = s.health.escalated;
  const auto = s.history.filter((c) => c.author === "standard-agent").length;
  return `
  <h1>${mode === "BUILD" ? "Construire le produit" : "Exploiter le produit"}</h1>
  <p class="lede">${mode === "BUILD"
    ? "En BUILD, des personnes et l'agent proposent des fonctionnalités. Rien n'entre dans <b>main</b> sans les tests de main verts, aucun nouvel écart sur la loi et une revue humaine signée."
    : "En RUN, l'agent maintient le produit tout seul quand la correction est reproductible, prépare les autres pour une revue, et remonte aux humains ce qui dépasse son échéance."}</p>
  ${esc_.length ? `<div class="notice bad">${esc_.length} obligation(s) escaladée(s) aux humains de la racine.</div>` : ""}
  <div class="grid">
    <div class="card"><div class="metric">${s.health.open}</div><div class="label">obligations ouvertes</div></div>
    <div class="card"><div class="metric">${s.health.proven}</div><div class="label">exigences prouvées</div></div>
    <div class="card"><div class="metric">${pending().length}</div><div class="label">revues à signer</div></div>
    <div class="card"><div class="metric">${auto}</div><div class="label">changements faits seul par l'agent (récents)</div></div>
  </div>
  <h2>Historique de main</h2>
  <div class="list">${s.history.map((c) => `
    <div class="row"><span class="mono muted">${short(c.sha)}</span>
      <div class="main"><span class="title">${esc(c.subject)}</span>
        <div class="muted">${esc(c.author)}${c.author === "standard-agent" ? " · autonome" : ""} · ${when(c.at * 1000)}</div></div></div>`).join("")}</div>
  <p class="muted" style="margin-top:14px">Journal : ${s.prefix.size} entrées · loi <span class="mono">${esc(s.law_digest.slice(7, 19))}</span></p>`;
}

function build() {
  const cs = state.build.contributions;
  const status = (c) => c.landed ? `<span class="chip ok">intégrée dans main</span>`
    : c.stale ? `<span class="chip warn">main a avancé : l'auteur doit rebaser</span>`
    : c.blocked.length ? `<span class="chip bad">bloquée par la loi</span>`
    : c.awaiting_review ? `<span class="chip warn">attend une revue</span>`
    : c.facts.review === "approved" ? `<span class="chip">intégration en cours</span>` : `<span class="chip">mesure en cours</span>`;
  return `
  <h1>Construction</h1>
  <p class="lede">Les demandes de fonctionnalités et les contributions. Une contribution est un commit posé sur main, poussé par SSH dans la boîte de dépôt de son auteur.</p>
  <h2>Demandes</h2>
  <div class="empty">Les demandes (titre, critères d'acceptation, tests validés avant le code) arrivent à l'étape suivante.</div>
  <h2>Contributions</h2>
  ${cs.length ? `<div class="list">${cs.map((c) => `
    <div class="row">
      <div class="main"><span class="title">${esc(c.author)} / ${esc(c.branch)}</span> <span class="mono muted">${short(c.head)}</span>
        <div class="chips">${status(c)}${chip("tests", c.facts.tests)}${chip("regressions", c.facts.regressions)}${chip("review", c.facts.review)}</div>
        ${c.why.length ? `<ul class="why">${c.why.map((w) => `<li class="mono">${esc(w)}</li>`).join("")}</ul>` : ""}</div>
      ${c.landed ? "" : `<button class="btn ${c.awaiting_review ? "primary" : ""}" data-review="${esc(c.resource)}">${c.awaiting_review ? "Relire" : "Voir"}</button>`}
    </div>`).join("")}</div>` : `<div class="empty">Aucune contribution dans la boîte de dépôt.</div>`}`;
}

function run() {
  const r = state.run;
  const lane = (title, items) => `<div class="lane"><h3>${title}</h3>${items.length ? items.join("") : `<div class="empty">Rien</div>`}</div>`;
  const reason = (s) => s.startsWith("uncovered:LookupError") ? "non mesuré : instantané de données absent ou périmé"
    : s.startsWith("uncovered") ? "non mesuré par cette installation" : s;
  const gap = (g) => `<div class="card"><div class="title">${esc(g.target)}</div>
    <div class="muted mono">${esc(g.resource)} : ${esc(reason(g.status))} (attendu ${esc(g.expect)})</div>
    ${g.where.length && !g.status.startsWith("uncovered") ? `<ul class="why">${g.where.map((w) => `<li class="mono">${esc(w)}</li>`).join("")}</ul>` : ""}</div>`;
  return `
  <h1>Exploitation</h1>
  <p class="lede">Ce que la loi exige et que main ne tient pas encore, et qui s'en occupe.</p>
  <div class="three">
    ${lane("L'agent répare seul", r.gaps.filter((g) => g.autonomous).map(gap))}
    ${lane("L'agent prépare, un humain signe", r.gaps.filter((g) => !g.autonomous && !g.human).map(gap))}
    ${lane("Humains seulement", r.gaps.filter((g) => g.human).map(gap))}
  </div>
  <h2>Réparations de l'agent</h2>
  ${r.repairs.length ? `<div class="list">${r.repairs.map((p) => `
    <div class="row"><div class="main"><span class="title">${esc(p.target)}</span> <span class="mono muted">${short(p.head)}</span>
      <div class="chips"><span class="chip">${p.route === "recipe" ? "recette reproductible" : "revue humaine requise"}</span>
        ${chip("tests", p.facts.tests)}${p.route === "recipe" ? chip("reproduced", p.facts.reproduced) : chip("review", p.facts.review)}
        ${p.submitted ? `<span class="chip ok">admise par la loi</span>` : ""}</div></div>
      <button class="btn ${p.awaiting_review ? "primary" : ""}" data-review="${esc(p.resource)}">${p.awaiting_review ? "Relire" : "Voir"}</button></div>`).join("")}</div>`
    : `<div class="empty">Aucune réparation en cours.</div>`}
  ${r.abandoned.length ? `<h2>L'agent a abandonné : décision humaine</h2><div class="list">${r.abandoned.map((a) => `
    <div class="row"><div class="main"><span class="title">${esc(a.target)}</span> <span class="mono muted">main ${short(a.base)}</span>
      <pre>${esc(a.dossier)}</pre></div></div>`).join("")}</div>` : ""}
  <h2>Obligations ouvertes du dépôt</h2>
  <p class="muted">${r.tasks.filter((t) => t.resource.startsWith("org:")).length} obligations organisationnelles (attestations du responsable conformité) sont listées dans l'onglet Loi.</p>
  <table><thead><tr><th>Obligation</th><th>Besoin</th><th>Ressource</th><th>Échéance</th></tr></thead><tbody>
  ${r.tasks.filter((t) => !t.resource.startsWith("org:")).map((t) => `<tr><td class="mono">${esc(t.id)}</td><td>${esc(t.need)}</td><td class="mono">${esc(t.resource)}</td>
    <td>${when(t.due)}${t.escalated ? ` <span class="chip bad">escaladée</span>` : ""}</td></tr>`).join("")}
  </tbody></table>`;
}

function reviews() {
  const items = pending();
  return `
  <h1>Revues</h1>
  <p class="lede">Chaque signature porte sur une transition exacte (base → tête) : si un seul octet change, il faut relire. La loi a déjà vérifié les tests et l'absence de nouvel écart ; vous jugez le sens du changement.</p>
  ${signer ? "" : `<div class="notice warn">Pour signer, importez d'abord votre clé dans l'onglet Identité.</div>`}
  ${items.length ? `<div class="list">${items.map((i) => `
    <div class="row"><div class="main"><span class="title">${i.kind === "contribution" ? `${esc(i.author)} / ${esc(i.branch)}` : `Réparation ${esc(i.target)}`}</span>
      <div class="muted mono">${esc(i.resource)}</div>
      <div class="chips">${chip("tests", i.facts.tests)}${i.kind === "contribution" ? chip("regressions", i.facts.regressions) : ""}</div></div>
      <button class="btn primary" data-review="${esc(i.resource)}">Relire</button></div>`).join("")}</div>`
    : `<div class="empty">Aucune revue en attente.</div>`}`;
}

function law() {
  const t = state.law.targets;
  const who = (x) => x.human ? "humains" : x.repair === "remediate" ? (["sbom", "vulns", "actions"].includes(x.id) ? "agent seul" : "agent + revue") : x.repair || "—";
  const group = (title, rows) => `<h2>${title}</h2><table><thead><tr><th>Exigence</th><th>Ressource</th><th>Attendu</th><th>Réparée par</th></tr></thead><tbody>
    ${rows.map((x) => `<tr><td>${esc(x.id)}</td><td class="mono">${esc(x.resource)}</td><td>${esc(x.property)} = ${esc(x.expect)}</td><td>${who(x)}</td></tr>`).join("")}</tbody></table>`;
  return `
  <h1>Loi en vigueur</h1>
  <p class="lede">Les floors de Standard et les règles du client. On peut seulement durcir : assouplir exige deux humains et une heure de délai témoin.</p>
  ${group("Technique", t.filter((x) => x.resource.startsWith("repo:") && !x.human))}
  ${group("Gouvernance du dépôt", t.filter((x) => x.resource.startsWith("repo:") && x.human))}
  ${group("Organisation (ISO 27001, NIS2, DORA)", t.filter((x) => x.resource.startsWith("org:")))}
  <h2>Conditions d'entrée dans main</h2>
  <table><thead><tr><th>Condition</th><th>Faits exigés</th></tr></thead><tbody>
  ${Object.entries(state.law.conditions).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${(v.all || []).map((c) => chip(c.observed[0], c.observed[1])).join(" ")}</td></tr>`).join("")}
  </tbody></table>`;
}

function identity() {
  const grants = state.signing.grants;
  return `
  <h1>Identité</h1>
  <p class="lede">Votre clé reste dans ce navigateur : elle est importée dans le coffre du navigateur, non exportable, et n'est jamais envoyée au serveur. Le navigateur construit lui-même les octets qu'il signe.</p>
  ${signer ? `<div class="notice ok">Ce navigateur signe en tant que <b>${esc(signer.identity)}</b> · clé <span class="mono">${esc(signer.keyid.slice(7, 23))}</span></div>
    <button class="btn danger" id="forget">Oublier cette clé</button>`
  : `<div class="card">
    <label for="ident">Identité</label><input id="ident" type="text" placeholder="h3" value="${esc(grants.reviewer?.holder || "")}">
    <label for="keyfile">Fichier de clé</label><input id="keyfile" type="file">
    <p class="muted">Démo : la clé créée par la cérémonie (keys/h3.key pour le relecteur). En production, une passkey sur votre appareil : le noyau la vérifie déjà.</p>
    <button class="btn primary" id="import">Importer</button> <span id="msg" class="muted"></span></div>`}
  <h2>Rôles des personnes</h2>
  <table><thead><tr><th>Rôle</th><th>Identité</th><th>Capacité</th></tr></thead><tbody>
  ${Object.entries(grants).map(([k, g]) => `<tr><td>${k === "reviewer" ? "Relecteur" : k === "officer" ? "Responsable conformité" : esc(k)}</td><td>${esc(g.holder)}</td><td class="mono">${esc(g.id)}</td></tr>`).join("")}
  </tbody></table>`;
}

function bindIdentity() {
  $("#forget")?.addEventListener("click", async () => { await forgetSigner(); signer = null; render(); });
  $("#import")?.addEventListener("click", async () => {
    const file = $("#keyfile").files[0], ident = $("#ident").value.trim();
    try {
      if (!file || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(ident)) throw new Error("une identité et un fichier");
      const s = await importKeyFile(await file.text());
      await saveSigner(ident, s);
      signer = { identity: ident, ...s };
      render();
    } catch (err) { $("#msg").textContent = `Échec : ${err.message}`; }
  });
}

// ---- reviewing and signing -----------------------------------------------------------------------------------------
const grantFor = () => state.signing.grants.reviewer;   // reviews are signed under the reviewer's capability

async function openReview(resource) {
  const item = [...state.build.contributions, ...state.run.repairs].find((i) => i.resource === resource);
  const head = resource.split("/").pop();
  const dlg = $("#dlg"), body = $("#dlgbody");
  body.innerHTML = `<p class="muted">Chargement du dossier…</p>`;
  dlg.showModal();
  let dossier;
  try {
    const r = await fetch(`/api/dossier/${head}`);
    dossier = await r.json();
    if (!r.ok) throw new Error(dossier.error);
  } catch (err) { body.innerHTML = `<div class="notice bad">${esc(err.message)}</div><footer><button class="btn" id="close">Fermer</button></footer>`; $("#close").onclick = () => dlg.close(); return; }
  const diff = esc(dossier.diff).split("\n").map((l) => l.startsWith("+") && !l.startsWith("+++") ? `<span class="diff-add">${l}</span>`
    : l.startsWith("-") && !l.startsWith("---") ? `<span class="diff-del">${l}</span>` : l).join("\n");
  const grant = grantFor(resource);
  const can = signer && item?.awaiting_review && grant;
  body.innerHTML = `
    <h1>${item?.kind === "contribution" ? `${esc(item.author)} / ${esc(item.branch)}` : `Réparation ${esc(item?.target)}`}</h1>
    <p class="mono muted">${esc(resource)}</p>
    <div class="chips">${chip("tests", item?.facts.tests)}${item?.kind === "contribution" ? chip("regressions", item.facts.regressions) : ""}${chip("review", item?.facts.review)}</div>
    <h2>Dossier</h2><pre>${esc(dossier.message)}</pre>
    <h2>Changements</h2><pre>${diff}</pre>
    ${!signer ? `<div class="notice warn">Importez votre clé (onglet Identité) pour signer.</div>` : ""}
    ${signer && !item?.awaiting_review ? `<div class="notice warn">Cette transition n'attend pas de revue (déjà signée, bloquée par la loi, ou pas encore mesurée).</div>` : ""}
    <footer><span id="sigmsg" class="muted grow"></span>
      <button class="btn" id="close">Fermer</button>
      <button class="btn" id="changes" ${can ? "" : "disabled"}>Demander des changements</button>
      <button class="btn primary" id="approve" ${can ? "" : "disabled"}>Approuver et signer</button></footer>`;
  $("#close").onclick = () => dlg.close();
  const sign = async (verdict) => {
    $("#sigmsg").textContent = "Signature dans ce navigateur…";
    const bodyToSign = { id: `review-${crypto.randomUUID().replaceAll("-", "")}`, at: Math.max(Date.now(), state.signing.as_of + 1),
      author: signer.identity, under: grant.id, resource, property: "review", status: verdict, level: "real" };
    try {
      const env = await envelope(state.signing.domain, "observation", bodyToSign, signer);
      const r = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
      const out = await r.json();
      if (!r.ok) throw new Error(out.refused || out.error);
      $("#sigmsg").textContent = "Admis par le noyau.";
      setTimeout(() => { dlg.close(); refresh(); }, 700);
    } catch (err) { $("#sigmsg").textContent = `Refusé : ${err.message}`; }
  };
  if (can) { $("#approve").onclick = () => sign("approved"); $("#changes").onclick = () => sign("changes_requested"); }
}

// ---- start ----------------------------------------------------------------------------------------------------------
signer = await loadSigner().catch(() => null);
await refresh();
setInterval(() => { if (!$("#dlg").open && tab !== "identity") refresh(); }, 10000);
