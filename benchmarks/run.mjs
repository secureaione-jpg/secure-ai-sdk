#!/usr/bin/env node
/**
 * Score Secure AI's redaction API on the public PII test sets the ShinrAI PII
 * board uses, from the outside: the same calls any customer makes.
 *
 *     node fetch.mjs                                   # once: the test rows
 *     SAI_API_KEY=sai_... node run.mjs                 # call the API, score
 *     SAI_API_KEY=sai_... ORGANISATIONS=1 node run.mjs # with organisations hidden
 *     node run.mjs --score-only                        # re-score saved answers
 *     node run.mjs --score-only --markdown             # and write RESULTS.md
 *
 * Each document is sent once to POST /v1/redact and the answer is saved in
 * answers*.jsonl, so a re-run costs nothing and anyone can inspect exactly
 * what was hidden. One request at a time, politely.
 *
 * What is scored: whether each labelled value was hidden, whatever kind the
 * API thought it was ("hidden at all"), as strict, overlap and partial F1 —
 * the board's three span measures. The API returns what it hid (`map`: stand-
 * in -> real value), not what kind each value is, so the board's typed score
 * cannot be computed from outside; the hidden-at-all score is the question a
 * redactor answers, and it is what is reported here.
 */
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const API = (process.env.SAI_API_URL ?? "https://secureai.one/v1").replace(/\/+$/, "");
const KEY = process.env.SAI_API_KEY ?? "";
// ORGANISATIONS=1 hides companies; ORGANISATIONS=all also courts, ministries and states.
const ORGS = process.env.ORGANISATIONS === "all" ? "all" : !!process.env.ORGANISATIONS;
const SUFFIX = ORGS === "all" ? "-organisations-all" : ORGS ? "-organisations" : "";
const SCORE_ONLY = process.argv.includes("--score-only");
const CELLS = process.env.CELLS?.split(",");
const ROWS = join(here, ".field-suites.json");
const ANSWERS = join(here, `answers${SUFFIX}.jsonl`);

/** Each set's label -> the type it is graded as. Absent: not graded (dates,
 *  times, demographics, country, state, coordinates, CVV, SWIFT). ORG is
 *  always graded, as it is for every system on the board: with the default
 *  setting, which leaves organisations visible, each one counts as a miss.
 *  Leaving it out would compare our easier test with their harder one. */
const GRADED = {
  name: "PERSON", first_name: "PERSON", middle_name: "PERSON", last_name: "PERSON", PERSON: "PERSON",
  company_name: "ORG", ORG: "ORG", ORGANISATION: "ORG",
  email: "EMAIL", phone_number: "PHONE", fax_number: "PHONE",
  street_address: "ADDRESS", address: "ADDRESS", "ADDRESS/STREET": "ADDRESS",
  city: "CITY", "ADDRESS/CITY": "CITY", postcode: "POSTCODE",
  credit_card_number: "CARD", credit_debit_card: "CARD",
  ssn: "ID", national_id: "ID", tax_id: "ID", medical_record_number: "ID", employee_id: "ID",
  customer_id: "ID", account_number: "ID", bank_routing_number: "ID", certificate_license_number: "ID",
  health_plan_beneficiary_number: "ID", license_plate: "ID", vehicle_identifier: "ID",
  unique_identifier: "ID", unique_id: "ID", pin: "ID",
  ipv4: "NET", ipv6: "NET", mac_address: "NET", url: "NET",
  password: "SECRET", api_key: "SECRET", http_cookie: "SECRET", user_name: "SECRET",
};

/** Published partial F1 on the board, 2026-09-01 (huggingface.co/datasets/
 *  innovius/shinrai-pii-bench-results). Their numbers, not re-run here. */
const BOARD = {
  "grtl-en": { azure: 30.7, presidio: 44.2, best: [84.5, "lfm-encoder-pii"] },
  "nmtr-en": { azure: 46.5, presidio: 57.5, best: [93.9, "openmed-e5"] },
  "tab-en": { azure: 48.2, presidio: 72.8, best: [83.6, "bards-eu"] },
  "mapa-de": { azure: 55.9, presidio: 38.6, best: [55.9, "azure"] },
  "mapa-en": { azure: 23.4, presidio: 19.3, best: [53.4, "openmed-e5"] },
  "mapa-es": { azure: 28.2, presidio: 3.5, best: [73.0, "openmed-e5"] },
  "mapa-fr": { azure: 42.9, presidio: 25.1, best: [44.4, "bards-eu"] },
  "mapa-it": { azure: 11.2, presidio: 7.0, best: [36.6, "openmed-e5"] },
  "mapa-pt": { azure: 48.8, presidio: 25.8, best: [52.4, "bards-eu"] },
};

function goldOf(row) {
  const graded = [], excluded = [];
  for (const g of [...row.gold].sort((a, b) => a.start - b.start)) {
    const type = GRADED[g.label];
    if (!type) { excluded.push(g); continue; }
    const last = graded[graded.length - 1];
    // first/middle/last names next to each other are one person.
    if (type === "PERSON" && last?.type === "PERSON" && /^[\s.]*$/.test(row.text.slice(last.end, g.start)) && /_name$/.test(g.label)) {
      last.end = Math.max(last.end, g.end);
      continue;
    }
    graded.push({ start: g.start, end: g.end, type });
  }
  return { graded, excluded };
}

/** Every whole-word place a hidden value stands in the text. */
function placesOf(text, value) {
  const out = [];
  if (!value.trim()) return out;
  for (let i = text.indexOf(value); i !== -1; i = text.indexOf(value, i + 1)) {
    const before = text[i - 1] ?? " ", after = text[i + value.length] ?? " ";
    if (/[\p{L}\d]/u.test(before) && /[\p{L}\d]/u.test(value[0])) continue;
    if (/[\p{L}\d]/u.test(after) && /[\p{L}\d]/u.test(value[value.length - 1])) continue;
    out.push({ start: i, end: i + value.length });
  }
  return out;
}

/** The spans the API hid: each real value in the map, longest first, one place taken once. */
function hiddenSpans(text, map) {
  const out = [];
  for (const value of Object.values(map ?? {}).sort((a, b) => b.length - a.length)) {
    for (const s of placesOf(text, value)) if (!out.some((o) => s.start < o.end && s.end > o.start)) out.push(s);
  }
  return out;
}

/** The API's types beside the board's. Address, city and postcode are one
 *  place: the API hides "12 Rue X, 75001 Paris" as one address where a set may
 *  label three values, and grading that as two wrong types would score the
 *  labelling, not the redaction. */
const API_TYPE = {
  name: "PERSON", organisation: "ORG", email: "EMAIL", phone: "PHONE",
  address: "PLACE", postcode: "PLACE", card: "CARD", iban: "ID", ssn: "ID", govid: "ID",
  host: "NET", secret: "SECRET",
};
const boardType = (t) => (t === "ADDRESS" || t === "CITY" || t === "POSTCODE" ? "PLACE" : t);
const inter = (a, b) => Math.max(0, Math.min(a.end, b.end) - Math.max(a.start, b.start));
const MODES = ["strict", "overlap", "partial"];
const hit = (mode, g, p) => mode === "strict" ? g.start === p.start && g.end === p.end
  : mode === "overlap" ? inter(g, p) * 2 >= g.end - g.start : inter(g, p) > 0;

function tally(mode, graded, excluded, preds, typed = false) {
  // A hidden span on a value nobody graded, and on no graded value, is neither right nor wrong.
  const live = preds.filter((p) => graded.some((g) => inter(g, p) > 0) || !excluded.some((x) => inter(x, p) > 0));
  const used = new Set();
  let tp = 0;
  for (const g of graded) {
    const i = live.findIndex((p, k) => !used.has(k) && hit(mode, g, p) && (!typed || p.type === boardType(g.type)));
    if (i !== -1) { used.add(i); tp++; }
  }
  return { tp, gold: graded.length, pred: live.length };
}
const f1 = (t) => {
  const p = t.pred ? t.tp / t.pred : 0, r = t.gold ? t.tp / t.gold : 0;
  return p + r ? (200 * p * r) / (p + r) : 0;
};
const sum = (ts) => ts.reduce((a, t) => ({ tp: a.tp + t.tp, gold: a.gold + t.gold, pred: a.pred + t.pred }), { tp: 0, gold: 0, pred: 0 });

/** Half the 95% bootstrap interval of partial F1, over the cell's documents. */
function margin(docs) {
  let seed = 1234;
  const rand = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  const scores = [];
  for (let b = 0; b < 1000; b++) scores.push(f1(sum(docs.map(() => docs[Math.floor(rand() * docs.length)]))));
  scores.sort((x, y) => x - y);
  return (scores[974] - scores[25]) / 2;
}

async function redact(text) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(`${API}/redact`, {
      method: "POST",
      headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ text, spans: true, ...(ORGS ? { organisations: ORGS } : {}) }),
    }).catch(() => null);
    if (res?.ok) return res.json();
    if (res && res.status < 500 && res.status !== 429) throw new Error(`${res.status}: ${await res.text()}`);
    if (attempt >= 5) throw new Error(`gave up after ${res?.status ?? "network error"}`);
    await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
  }
}

if (!existsSync(ROWS)) { console.error("No test rows. Run: node fetch.mjs"); process.exit(1); }
const rows = JSON.parse(readFileSync(ROWS, "utf8")).filter((r) => !CELLS || CELLS.includes(r.cell));

// Answers already saved are reused, so a run can be stopped and resumed.
const saved = new Map();
if (existsSync(ANSWERS)) for (const line of readFileSync(ANSWERS, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const a = JSON.parse(line);
  saved.set(`${a.cell}|${a.id}`, a);
}
if (!SCORE_ONLY) {
  if (!KEY) { console.error("Set SAI_API_KEY (or use --score-only)."); process.exit(1); }
  const todo = rows.filter((r) => !saved.has(`${r.cell}|${r.id}`));
  console.log(`${todo.length} documents to send to ${API}/redact (${saved.size} already saved).`);
  let n = 0;
  for (const r of todo) {
    const answer = await redact(r.text);
    // The type of each hidden value, from `spans` (an API older than that
    // option answers without it, and only the untyped score is printed).
    const types = answer.spans ? Object.fromEntries(answer.spans.map((x) => [x.text, x.type])) : undefined;
    const record = { cell: r.cell, id: r.id, map: answer.map, names_decided: answer.names_decided, ...(types ? { types } : {}) };
    appendFileSync(ANSWERS, JSON.stringify(record) + "\n");
    saved.set(`${r.cell}|${r.id}`, record);
    if (++n % 50 === 0) console.log(`  ${n}/${todo.length}`);
  }
}

const perCell = {};
let undecided = 0;
for (const r of rows) {
  const a = saved.get(`${r.cell}|${r.id}`);
  if (!a) continue;
  if (a.names_decided === false) undecided++;
  const { graded, excluded } = goldOf(r);
  const preds = hiddenSpans(r.text, a.map);
  const c = (perCell[r.cell] ??= { strict: [], overlap: [], partial: [], noOrg: [], typed: [] });
  for (const m of MODES) c[m].push(tally(m, graded, excluded, preds));
  // Typed partial F1, the board's own measure, when the API said the types.
  if (a.types) {
    const typedPreds = preds.map((p) => ({ ...p, type: API_TYPE[a.types[r.text.slice(p.start, p.end)]] ?? "OTHER" }));
    c.typed.push(tally("partial", graded, excluded, typedPreds, true));
  }
  // Beside it, organisations left out of the grading: what the score is on
  // people, contacts and IDs alone. Never instead of it.
  c.noOrg.push(tally("partial", graded.filter((g) => g.type !== "ORG"), [...excluded, ...graded.filter((g) => g.type === "ORG")], preds));
}

const n = (x) => (Number.isFinite(x) ? x.toFixed(1) : "—").padStart(5);
console.log(`\nSecure AI (${API}), organisations ${ORGS === "all" ? "all hidden, public bodies too" : ORGS ? "hidden" : "shown"}. F1, hidden at all.`);
console.log("cell       docs   strict overlap partial    ±     w/o org  typed | board partial:  Azure  Presidio  best other");
for (const [cell, c] of Object.entries(perCell)) {
  const b = BOARD[cell] ?? {};
  console.log(`${cell.padEnd(9)} ${String(c.partial.length).padStart(5)}   ${MODES.map((m) => n(f1(sum(c[m])))).join("   ")}  ±${margin(c.partial).toFixed(1).padStart(4)}   ${n(f1(sum(c.noOrg)))}  ${n(c.typed.length ? f1(sum(c.typed)) : NaN)} |               ${n(b.azure)}   ${n(b.presidio)}   ${n(b.best?.[0])} ${b.best?.[1] ?? ""}`);
}
// --markdown: the same table as RESULTS.md (or RESULTS-organisations.md), to publish.
if (process.argv.includes("--markdown")) {
  const md = [
    `# Results — organisations ${ORGS === "all" ? "all hidden, public bodies too" : ORGS ? "hidden" : "shown (the API's default)"}`,
    "",
    `Scored ${new Date().toISOString().slice(0, 10)} against \`${API}/redact\`. F1, 0–100, "hidden at all"; ± is the 95% bootstrap margin of partial F1.`,
    `Other systems' figures are the ShinrAI board's typed partial F1 (2026-09-01), not re-run here.`,
    `"Partial w/o organisations" leaves company and public-body names out of the grading. It is shown beside the main score, never instead of it: the board grades organisations for everyone.`,
    "",
    "| Set | Docs | Strict | Overlap | Partial | ± | Partial w/o organisations | Typed partial | Azure | Presidio | Best other |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ...Object.entries(perCell).map(([cell, c]) => {
      const b = BOARD[cell] ?? {};
      const v = (x) => (Number.isFinite(x) ? x.toFixed(1) : "—");
      return `| ${cell} | ${c.partial.length} | ${MODES.map((m) => v(f1(sum(c[m])))).join(" | ")} | ${margin(c.partial).toFixed(1)} | ${v(f1(sum(c.noOrg)))} | ${c.typed.length ? v(f1(sum(c.typed))) : "—"} | ${v(b.azure)} | ${v(b.presidio)} | ${v(b.best?.[0])} ${b.best?.[1] ?? ""} |`;
    }),
    "",
    ...(undecided ? [`${undecided} documents came back with \`names_decided: false\`; they are scored as answered.`, ""] : []),
    `Answers: \`${ANSWERS.split(/[\\/]/).pop()}\`. Re-score them with \`node run.mjs --score-only\`.`,
  ];
  writeFileSync(join(here, `RESULTS${SUFFIX}.md`), md.join("\n") + "\n");
}
if (undecided) console.log(`\n${undecided} documents came back with names_decided: false (the name check did not finish); they are scored as answered.`);
console.log("\nThe board's figures are typed (the value must also be called the right kind). \"typed\" is that");
console.log("measure, with address, city and postcode as one place; the rest are hidden-at-all, the redactor's");
console.log("question. Same public splits; the board's own row samples are");
console.log("not published, so these are rows drawn with a fixed seed (TAB: all 127 test documents).");
