// The production-objectives view owns its form state; signing stays in the browser.
export function createObjectives({ $, esc, KIND, localGet, localSet, nf, pct, msf, pctx, fact, ago, signFact, getSigner }) {
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
    ["components", "Composants"], ["probes", "Sondes"], ["silences", "Silences"], ["code", "Réglages en code"], ["history", "Historique"]];
  const DAYNAMES = { mon: "lun", tue: "mar", wed: "mer", thu: "jeu", fri: "ven", sat: "sam", sun: "dim" };
  const ZONES = ["UTC", "Europe/Paris", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Asia/Tokyo", "Asia/Singapore"];
  let settingsData = null, objTab = localGet("objtab") || "slos";
  function objectivesView() {
    return `<h1>Objectifs et réglages</h1><p class="lede">Ce que la production doit tenir, comment on est prévenu et ce que Standard a le droit d'y faire seul.
      Les réglages système vivent dans <span class="sha">standard/rules.json</span>, dans le dépôt : chaque changement fait ici est ce fichier, signé une fois, commité par l'agent et intégré par la loi.
      <b>Appliqué dès l'intégration, dans les bornes de la loi : un réglage qui demande moins que la loi ne permet rien de plus à l'agent.</b></p>
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
    const signer = getSigner();
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
    const lawText = (key) => p.law[key] ? `la loi : ${p.law[key][0] === "ge" ? "au moins" : "au plus"} ${p.law[key][1]}` : "";
    const pend = (name) => p.pending[name] ? `<span class="fact wait"><i></i>${esc(label(name, p.pending[name].value))} : plus souple, appliqué ${left(p.pending[name].applies_at)}</span>` : "";
    const field = (key, scope = "global", fallback = p.defaults[key]) => {
      const name = `${scope}/${key}`, v = value(name, fallback), [lab, unit, help] = SETTINGS[key], b = p.bounds[key];
      const input = key === "deploy_tz"
        ? `<select data-set="${name}" ${dis}>${ZONES.map((z) => `<option ${z === v ? "selected" : ""}>${z}</option>`).join("")}</select>`
        : `<input class="num" type="${["base_url", "deploy_hours"].includes(key) ? "text" : "number"}" data-set="${name}" value="${esc(v ?? "")}" ${b && typeof b[0] === "number" ? `min="${b[0]}" max="${b[1]}" step="any"` : ""} ${dis}>`;
      return `<div class="set"><div class="sl"><b>${lab}</b><span class="small quiet">${help}${p.law[key] ? ` Pour agir seul, ${lawText(key)}.` : ""}</span></div>
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
          <div class="set"><div class="sl"><b>Jours de mise en production</b><span class="small quiet">L'agent ne met en production seul que ces jours-là.</span></div>
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
      code: () => `<p class="small quiet">Le fichier de réglages système <span class="sha">standard/rules.json</span> de la branche principale${s.rules_file ? "" : " (pas encore créé : les valeurs par défaut s'appliquent)"}. Modifiez-le ici et signez-le une fois, ou changez-le par une contribution relue, comme du code. Les silences n'y figurent pas : ils sont signés à part.</p>
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

    $("#obj").innerHTML = `${(s.rules_landing || []).filter((x) => x.state !== "admitted").map((x) => `<div class="note warn">Changement de réglages signé, en cours d'intégration : ${esc(x.state || "commit en préparation")}</div>`).join("")}
      ${!signer ? `<div class="note warn">Ajoutez votre clé dans Réglages pour modifier ces réglages.</div>`
        : !can ? `<div class="note warn">Seul ${esc(s.signing.grant?.holder || "l'ingénieur habilité")} peut modifier ces réglages.</div>` : ""}
      ${tabs[objTab]()}<p id="objmsg" class="small quiet"></p>`;
    document.querySelectorAll("[data-objtab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.objtab === objTab)));

    const at = () => Math.max(Date.now(), s.signing.as_of + 1);
    // D35: every system setting lives in standard/rules.json on main. A change here is the whole new file, stored by digest and
    // signed once; the agent commits exactly that file and the law lands it after the scanner's checks. Silences
    // alone are signed statements, applied at once.
    const signRules = async (doc, el) => {
      $("#objmsg").textContent = "Signature des nouveaux réglages système dans ce navigateur";
      try {
        const r = await fetch("/api/system-settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ document: doc }) });
        const stored = await r.json();
        if (!r.ok) throw new Error(stored.error);
        await signFact(s.signing.domain, at(), s.signing.grant, `repo:config:rules/${stored.base}`, "rules", stored.digest);
        $("#objmsg").textContent = "Signé. L'agent commit standard/rules.json, la loi l'intègre après les mesures (tests, aucun écart).";
        return true;
      } catch (err) { $("#objmsg").textContent = `Refusé : ${err.message}`; if (el) el.disabled = false; return false; }
    };
    const draft = () => { const d = JSON.parse(JSON.stringify(p.document)); delete d.silences; return d; };
    const put = (doc, name, status) => {
      const [scope, key] = name.split("/"), num = Number(status);
      const value = status === null ? null : status !== "" && !Number.isNaN(num) && !["deploy_hours", "base_url", "name", "spec", "selector", "deploy_days"].includes(key) ? num : status;
      if (scope === "global") { doc.global[key] = value; return doc; }
      const part = { c: "components", s: "slos", p: "probes" }[scope[0]];
      doc[part] ||= {};
      if (value === null) { if (doc[part][scope]) delete doc[part][scope][key]; } else (doc[part][scope] ||= {})[key] = value;
      return doc;
    };
    const set = async (name, status, el) => {
      if (name.startsWith("m-")) {
        $("#objmsg").textContent = "Signature dans ce navigateur";
        try {
          await signFact(s.signing.domain, at(), s.signing.grant, `run:policy/${name}`, "value", status);
          $("#objmsg").textContent = "Signé. Appliqué au prochain passage du scanner.";
          return true;
        } catch (err) { $("#objmsg").textContent = `Refusé par le noyau : ${err.message}`; if (el) el.disabled = false; return false; }
      }
      return signRules(put(draft(), name, status), el);
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
      const doc = draft();
      for (const key of ["objective", "p99_ms"]) {
        const input = document.querySelector(`[data-set="${b.dataset.savecomp}/${key}"]`);
        put(doc, `${b.dataset.savecomp}/${key}`, input.value.trim() || null);
      }
      if (await signRules(doc, b)) reload();
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
      const doc = draft();
      for (const k of keys) put(doc, `${sid}/${k}`, v[k]);
      if (keys.length && await signRules(doc, b)) reload();
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
      const l = p.law[key];
      if (!l) return "neutre";
      return (l[0] === "ge" ? Number(nw) >= l[1] : Number(nw) <= l[1]) ? "dans la loi" : "hors loi";
    };
    $("#codediff")?.addEventListener("click", () => {
      let doc;
      try { doc = JSON.parse($("#code").value); } catch (err) { $("#diff").innerHTML = `<div class="note bad">JSON invalide : ${esc(err.message)}</div>`; return; }
      const before = flatten(p.document), after = flatten(doc);
      const changes = Object.entries(after).filter(([k, v]) => String(before[k] ?? "") !== String(v ?? ""));
      $("#diff").innerHTML = !changes.length ? `<p class="small quiet">Aucun changement.</p>` : `<div class="rows">${changes.map(([k, v]) => {
        const w = way(k.split("/")[1], before[k], v);
        return `<div class="rowi"><div class="main"><span class="sha">${esc(k)}</span> <span class="del">${esc(String(before[k] ?? "—"))}</span> → <span class="add">${esc(String(v))}</span>
          <div class="facts">${fact(w === "hors loi" ? `au-delà de la loi (${lawText(k.split("/")[1])}) : l'agent n'agira pas seul pour autant` : "appliqué dès l'intégration", w === "hors loi" ? "wait" : "ok")}</div></div></div>`; }).join("")}</div>
        <div class="decide"><button class="btn primary" id="codesign">Signer ce fichier (${changes.length} changement${changes.length > 1 ? "s" : ""})</button>
          <span class="small quiet">Une signature : l'agent commit le fichier, la loi l'intègre après les mesures.</span></div>`;
      $("#codesign").onclick = async () => {
        $("#codesign").disabled = true;
        delete doc.silences;
        if (await signRules(doc, $("#codesign"))) reload();
      };
    });
  }
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-objtab]");
    if (t) { objTab = t.dataset.objtab; localSet("objtab", objTab); if (settingsData) loadObjectives(); }
  });

  return { view: objectivesView, load: loadObjectives };
}
