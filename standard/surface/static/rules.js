// Standard — the rules of the game (D51). One document in the journal: who plays each move (the agent alone, or you),
// the thresholds the routes compare with, what production is judged against, silences. Every change here drafts the
// full new rules on the server, and this browser signs them: in force at once, unless the rules ask changes to wait.
// The kernel refuses anything looser than the socle; nothing here is a permission.

const OPS = {
  remediate: ["Réparer une exigence", { reproduced: "quand une recette la reproduit à l'identique", scoped: "quand les tests passent, sans régression, dans son périmètre, par les blocs" }],
  implement: ["Implémenter une demande signée", { accepted: "quand le contrat passe, avec les tests, sans régression, dans son périmètre, par les blocs" }],
  integrate: ["Intégrer une contribution", {}],
  deploy: ["Mettre main en production", { direct: "dans la fenêtre, avec du budget d'erreur", promote: "en promouvant un canari qui a tenu" }],
  canary: ["Démarrer un canari", { auto: "dans la fenêtre, avec du budget d'erreur" }],
  rollback: ["Revenir à la version précédente", { burn: "si le budget brûle vite juste après la bascule", failing: "si trop de requêtes échouent juste après la bascule", unanswered: "si la nouvelle version ne répond pas" }],
  restart: ["Redémarrer sans coupure", { failing: "si trop de requêtes échouent", burn: "si le budget brûle vite" }],
  abort: ["Retirer un canari", { auto: "toujours possible : retirer un canari est sûr" }],
};
const THRESHOLDS = {
  burn_fast: ["Brûlure rapide", "multiple du rythme du budget, pour agir seul"], failing: ["Échecs", "% de requêtes en échec, pour agir seul"],
  rollback_horizon_min: ["Horizon de retour", "minutes après la bascule"], rollback_migrations: ["Migrations traversées", "au plus, pour revenir seul (0 : jamais)"],
  restarts_per_hour: ["Redémarrages", "déjà faits dans l'heure, au plus"], freeze_below: ["Gel sous budget", "% de budget restant en dessous duquel on ne déploie plus seul"],
  canary_max_error_delta: ["Écart du canari", "points d'erreurs de plus que la version en place, au plus"],
  canary_min_requests: ["Requêtes du canari", "au moins, avant de promouvoir"], canary_bake_min: ["Cuisson du canari", "minutes, au moins"],
};
const PRODUCTION = {
  objective: ["Objectif de disponibilité", "%"], p99_ms: ["Latence p99", "ms"], window_s: ["Fenêtre de jugement", "s"],
  late_periods: ["Tâche planifiée en retard", "périodes"], burn_slow: ["Brûlure lente (ticket)", "×"],
  deploy_days: ["Jours de mise en production", "mon,tue,…"], deploy_hours: ["Heures", "HH-HH"], deploy_tz: ["Fuseau", "ex. Europe/Paris"],
  canary_percent: ["Part du trafic du canari", "%"], base_url: ["URL du produit (sondes)", "https://…"],
};

export function createRules({ $, esc, fact, ago, getSigner, envelope }) {
  let data = null;

  async function signRules(changes, msg) {
    const signer = getSigner();
    msg.textContent = "Signature dans ce navigateur";
    try {
      const r = await fetch("/api/rules/draft", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(changes) });
      const draft = await r.json();
      if (!r.ok) throw new Error(draft.error);
      const body = { id: `law-${crypto.randomUUID().replaceAll("-", "")}`, at: Math.max(Date.now(), draft.as_of + 1),
        author: signer.identity, client: draft.client };
      const env = await envelope(draft.domain, "law", body, signer);
      const a = await fetch("/api/admit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(env) });
      const out = await a.json();
      if (!a.ok) throw new Error(out.refused || out.error);
      msg.textContent = "En vigueur.";
      setTimeout(load, 600);
    } catch (err) { msg.textContent = `Refusé : ${err.message}`; }
  }

  function view() {
    return `<h1>Règles du jeu</h1>
      <p class="lede">Un seul document, dans le journal : qui joue chaque coup (l'agent seul, ou toi), les seuils que ses routes comparent,
        et ce contre quoi la production est jugée. Tu le signes ici, il s'applique tout de suite. Le noyau refuse tout ce qui serait plus lâche que le socle de Standard.</p>
      <div id="rules"><p class="quiet">Chargement</p></div>`;
  }

  async function load() {
    try {
      const r = await fetch("/api/settings", { cache: "no-store" });
      data = await r.json();
      if (!r.ok) throw new Error(data.error);
    } catch (err) { $("#rules").innerHTML = `<div class="note bad">Règles indisponibles : ${esc(err.message)}</div>`; return; }
    draw();
  }

  function draw() {
    const R = data.rules, s = R.settings, signer = getSigner();
    const can = Boolean(signer && data.signing.grant && signer.identity === data.signing.grant.holder);
    const dis = can ? "" : "disabled";
    const moves = Object.entries(OPS).filter(([op]) => R.routes[op]).map(([op, [label, routes]]) => {
      const on = new Set(R.routes[op].auto), socle = R.socle[op] || [];
      return `<div class="rowi"><div class="main"><b>${esc(label)}</b>
        <div class="facts">${socle.length ? socle.map((name) => `<label class="route"><input type="checkbox" data-op="${op}" data-route="${name}" ${on.has(name) ? "checked" : ""} ${dis}>
          L'agent seul ${esc(routes[name] || name)}</label>`).join("") : fact("Toujours ta décision", "wait")}
          ${socle.length && !on.size ? fact("Coupé : ta décision", "wait") : ""}</div></div></div>`;
    }).join("");
    const input = (key, [label, help], bound) => `<div class="set"><div class="sl"><b>${esc(label)}</b><span class="small quiet">${esc(help)}${bound
        ? ` · socle : ${bound.way === "ge" ? "au moins" : "au plus"} ${esc(bound.socle)}` : ""}</span></div>
      <div class="sv"><input type="text" data-set="${key}" value="${esc(s[key] ?? "")}" ${dis}><button class="btn tiny" data-save="${key}" ${dis}>Signer</button></div></div>`;
    const sections = (name, fields, title) => {
      const items = Object.entries(s[name] || {});
      return `<section><h2>${title} <span class="quiet small">${items.length}</span></h2><div class="rows">${items.map(([id, f]) => `
        <div class="rowi"><div class="main"><span class="sha">${esc(id)}</span> ${fields.map((k) => f[k] != null ? fact(`${k} : ${f[k]}`, "") : "").join("")}</div>
          <button class="btn tiny danger" data-drop="${name}/${id}" ${dis}>Retirer</button></div>`).join("") || `<div class="rowi quiet">Aucun</div>`}</div>
        <div class="decide compact"><input type="text" placeholder='${esc(JSON.stringify(Object.fromEntries(fields.map((k) => [k, "…"]))))}' data-new="${name}" ${dis}>
          <button class="btn tiny" data-add="${name}" ${dis}>Ajouter et signer</button></div></section>`;
    };
    $("#rules").innerHTML = `
      ${!signer ? `<div class="note warn">Ajoute ta clé dans Clé de signature pour changer les règles.</div>`
        : !can ? `<div class="note warn">Seul ${esc(data.signing.grant?.holder || "l'humain")} change les règles ici.</div>` : ""}
      <p id="rulesmsg" class="small quiet"></p>
      <section><h2>Qui joue quoi</h2><p class="small quiet">Coché : l'agent joue seul quand les faits du scanner tiennent. Décoché : le coup t'attend dans Décisions. Ta décision reste toujours possible.</p>
        <div class="rows">${moves}</div></section>
      <section><h2>Seuils des routes</h2><div class="panel sets">${Object.entries(THRESHOLDS).map(([k, v]) => input(k, v, R.bounds[k])).join("")}</div></section>
      <section><h2>Production</h2><div class="panel sets">${Object.entries(PRODUCTION).map(([k, v]) => input(k, v)).join("")}</div></section>
      <section><h2>Valeurs nommées <span class="quiet small">${Object.keys(R.values).length}</span></h2>
        <p class="small quiet">Chaque mot vague des règles de sécurité (sensible, critique, de confiance…) est une valeur ici. Non fixée, elle prend sa valeur stricte par défaut : refuser, la plus petite limite, la durée la plus courte. L'agent peut la proposer, seule ta signature la met en vigueur.</p>
        <div class="panel sets">${Object.entries(R.values).map(([k, v]) => `<div class="set"><div class="sl"><b>@${esc(k)}</b><span class="small quiet">${esc(v.doc)}${v.rules.length ? ` · règles : ${esc(v.rules.join(", "))}` : ""}${v.chosen ? "" : " · valeur par défaut"}</span></div>
          <div class="sv"><input type="text" data-value="${esc(k)}" value='${esc(v.current === undefined || v.current === null ? "" : JSON.stringify(v.current))}' placeholder="non fixée : règle non couverte" ${dis}><button class="btn tiny" data-savevalue="${esc(k)}" ${dis}>Signer</button></div></div>`).join("")}</div></section>
      ${sections("slos", ["name", "sli", "target", "window_d", "threshold_ms", "selector", "state"], "SLO")}
      ${sections("components", ["objective", "p99_ms", "counted"], "Composants")}
      ${sections("probes", ["spec"], "Sondes")}
      ${sections("silences", ["target_of", "until", "reason"], "Silences")}
      <section class="cols"><div class="panel"><h2>Historique</h2><div class="rows">${R.history.map((h) => `<div class="rowi"><div class="main">${h.kind === "genesis" ? "Règles initiales" : "Règles changées"}
          <div class="facts">${fact(`par ${h.author}`, "")}${fact(ago(h.at), "")}</div></div></div>`).join("")}</div></div></section>`;
    const msg = $("#rulesmsg");
    document.querySelectorAll("[data-route]").forEach((box) => box.onchange = () => {
      const op = box.dataset.op;
      const kept = [...document.querySelectorAll(`[data-op="${op}"]`)].filter((b) => b.checked).map((b) => b.dataset.route);
      signRules({ routes: { [op]: kept } }, msg);
    });
    document.querySelectorAll("[data-save]").forEach((b) => b.onclick = () => {
      const key = b.dataset.save, value = document.querySelector(`[data-set="${key}"]`).value.trim();
      signRules({ settings: { [key]: value } }, msg);
    });
    document.querySelectorAll("[data-savevalue]").forEach((b) => b.onclick = () => {
      const key = b.dataset.savevalue, raw = document.querySelector(`[data-value="${key}"]`).value.trim();
      try { signRules({ values: { [key]: raw === "" ? null : JSON.parse(raw) } }, msg); }
      catch (err) { msg.textContent = `Format : du JSON, par exemple ["a", "b"] ou 10 (${err.message})`; }
    });
    document.querySelectorAll("[data-drop]").forEach((b) => b.onclick = () => signRules({ drop: [b.dataset.drop.split("/")] }, msg));
    document.querySelectorAll("[data-add]").forEach((b) => b.onclick = () => {
      const name = b.dataset.add, prefix = { slos: "s", components: "c", probes: "p", silences: "m" }[name];
      try {
        const fields = JSON.parse(document.querySelector(`[data-new="${name}"]`).value);
        const id = fields.id || `${prefix}-${crypto.randomUUID().replaceAll("-", "").slice(0, prefix === "c" ? 12 : 8)}`;
        delete fields.id;
        signRules({ sections: { [name]: { [id]: fields } } }, msg);
      } catch (err) { msg.textContent = `Format : un objet JSON (${err.message})`; }
    });
  }

  return { view, load, signRules };
}
