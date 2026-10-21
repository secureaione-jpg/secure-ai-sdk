#!/usr/bin/env node
/**
 * The four public test sets the ShinrAI PII board scores Azure AI Language
 * PII on (huggingface.co/datasets/innovius/shinrai-pii-bench-results,
 * FIELD-SUITES.md, 2026-08-31), loaded the way that page says it loads them,
 * so run.mjs can put the API's numbers beside the board's.
 *
 *     node fetch.mjs
 *
 *   grtl  gretelai/gretel-pii-masking-en-v1, validation (Apache-2.0)
 *   nmtr  nvidia/Nemotron-PII, test (CC BY 4.0)
 *   tab   ildpil/text-anonymization-benchmark, test (MIT), one annotator a
 *         document, annotator1 first
 *   mapa  joelniklaus/mapa, test (CC BY 4.0), de en fr es it pt
 *
 * 300 rows a cell, drawn with a fixed seed (the board's own sample is not
 * published, so the rows are the same sets but not the same 300). Writes
 * .field-suites.json: [{ cell, id, text, gold: [{ start, end, label }] }],
 * gold labels exactly as each set writes them; the test maps them.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const N = Number(process.env.N ?? 300);
const API = "https://datasets-server.huggingface.co";

async function get(url) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url).catch(() => null);
    if (res?.ok) return res.json();
    if (attempt >= 8) throw new Error(`${res?.status ?? "network"} for ${url}`);
    await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
  }
}
const rows = async (dataset, split, offset, length, where) => {
  const q = `dataset=${encodeURIComponent(dataset)}&config=default&split=${split}&offset=${offset}&length=${length}`;
  const body = await get(where ? `${API}/filter?${q}&where=${encodeURIComponent(where)}` : `${API}/rows?${q}`);
  return { rows: body.rows.map((r) => r.row), total: body.num_rows_total };
};

// mulberry32: a fixed seed, so a rerun draws the same rows.
function rng(seed) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const sample = (list, n, seed = 42) => {
  const r = rng(seed);
  const a = [...list];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a.slice(0, n);
};
/** A Python literal (the sets store repr() strings): lists, dicts, strings, numbers. */
function pyLiteral(src) {
  let i = 0;
  const ws = () => { while (/\s/.test(src[i])) i++; };
  const value = () => {
    ws();
    const c = src[i];
    if (c === "[" || c === "{") {
      const close = c === "[" ? "]" : "}";
      const list = [];
      const obj = {};
      i++;
      for (ws(); src[i] !== close; ws()) {
        const v = value();
        ws();
        if (c === "{") { i++; obj[v] = value(); } else list.push(v);
        ws();
        if (src[i] === ",") i++;
      }
      i++;
      return c === "[" ? list : obj;
    }
    if (c === "'" || c === '"') {
      i++;
      let str = "";
      while (src[i] !== c) {
        if (src[i] === "\\") {
          const n = src[++i];
          if (n === "x") { str += String.fromCharCode(parseInt(src.slice(i + 1, i + 3), 16)); i += 3; continue; }
          if (n === "u") { str += String.fromCharCode(parseInt(src.slice(i + 1, i + 5), 16)); i += 5; continue; }
          str += { n: "\n", t: "\t", r: "\r" }[n] ?? n;
          i++;
          continue;
        }
        str += src[i++];
      }
      i++;
      return str;
    }
    const m = /^(?:-?[\d.]+(?:e-?\d+)?|None|True|False)/.exec(src.slice(i));
    i += m[0].length;
    return m[0] === "None" ? null : m[0] === "True" ? true : m[0] === "False" ? false : Number(m[0]);
  };
  return value();
}

/** n rows from a big split: pages of 100 at seeded offsets. */
async function drawPages(dataset, split, total, n) {
  total ??= (await rows(dataset, split, 0, 1)).total;
  const r = rng(42);
  const out = [];
  const seen = new Set();
  while (out.length < n) {
    const offset = Math.floor((r() * (total - 100)) / 100) * 100;
    if (seen.has(offset)) continue;
    seen.add(offset);
    out.push(...(await rows(dataset, split, offset, 100)).rows);
  }
  return out.slice(0, n);
}

const out = [];

// MAPA_SPLIT=validation writes .field-suites-validation.json: somewhere to
// tune that is not the test. MAPA and TAB give their validation splits;
// Gretel and Nemotron, whose graded rows are a validation and a test split,
// give rows drawn from their train splits instead.
const MAPA_SPLIT = process.env.MAPA_SPLIT ?? "test";
const ALL = MAPA_SPLIT === "test";

// Gretel: surfaces without offsets, so every boundary-checked occurrence.
{
  const list = ALL
    ? await drawPages("gretelai/gretel-pii-masking-en-v1", "validation", 5000, N)
    : await drawPages("gretelai/gretel-pii-masking-en-v1", "train", undefined, N);
  for (const row of list) {
    const ents = pyLiteral(row.entities);
    const gold = [];
    for (const e of ents) {
      const v = e.entity;
      if (!v) continue;
      for (let i = row.text.indexOf(v); i !== -1; i = row.text.indexOf(v, i + 1)) {
        const before = row.text[i - 1] ?? " ";
        const after = row.text[i + v.length] ?? " ";
        if (/[\p{L}\d]/u.test(before) || /[\p{L}\d]/u.test(after)) continue;
        gold.push({ start: i, end: i + v.length, label: e.types[0] });
      }
    }
    out.push({ cell: "grtl-en", id: row.uid, text: row.text, gold });
  }
  console.log(`  grtl-en ${list.length}`);
}

// Nemotron: character spans.
{
  const list = ALL
    ? await drawPages("nvidia/Nemotron-PII", "test", 100000, N)
    : await drawPages("nvidia/Nemotron-PII", "train", undefined, N);
  for (const row of list) {
    const spans = pyLiteral(row.spans);
    out.push({ cell: "nmtr-en", id: row.uid, text: row.text, gold: spans.map((s) => ({ start: s.start, end: s.end, label: s.label })) });
  }
  console.log(`  nmtr-en ${list.length}`);
}

// TAB: the whole test (or validation) split, one annotator a document.
{
  const all = [];
  for (let offset = 0; ; offset += 100) {
    const { rows: page, total } = await rows("ildpil/text-anonymization-benchmark", ALL ? "test" : "validation", offset, 100);
    all.push(...page);
    if (offset + 100 >= total) break;
  }
  const byDoc = new Map();
  for (const row of all) (byDoc.get(row.doc_id) ?? byDoc.set(row.doc_id, []).get(row.doc_id)).push(row);
  for (const [id, versions] of byDoc) {
    const row = versions.sort((a, b) => a.annotator_id.localeCompare(b.annotator_id))[0];
    out.push({
      cell: "tab-en", id, text: row.text,
      gold: row.entity_mentions.map((m) => ({ start: m.start_offset, end: m.end_offset, label: m.entity_type })),
    });
  }
  console.log(`  tab-en ${byDoc.size} documents`);
}

// MAPA: tokens joined by spaces, BIO tags to spans.
// The filter endpoint has answered 500 for whole afternoons (validation,
// 2026-10-06); the plain rows of the split, filtered here, are the same rows
// in the same order.
const mapaRows = new Map();
async function mapaLanguage(lang, split = MAPA_SPLIT) {
  try {
    if (mapaRows.has(split)) throw new Error("filter already failed");
    const all = [];
    for (let offset = 0; ; offset += 100) {
      const { rows: page, total } = await rows("joelniklaus/mapa", split, offset, 100, `"language"='${lang}'`);
      all.push(...page);
      if (offset + 100 >= total) break;
    }
    return all;
  } catch (e) {
    console.log(`  filter failed (${e.message.slice(0, 40)}); reading the whole ${split} split`);
    if (!mapaRows.has(split)) {
      const list = [];
      for (let offset = 0; ; offset += 100) {
        const { rows: page, total } = await rows("joelniklaus/mapa", split, offset, 100);
        list.push(...page);
        if (offset + 100 >= total) break;
      }
      mapaRows.set(split, list);
    }
    return mapaRows.get(split).filter((r) => r.language === lang);
  }
}

/* Practice only: MAPA's validation split holds 35 graded Italian values and
   50 French, too few to tune on without fitting the noise. Its train split,
   never scored, adds MAPA_TRAIN rows a language (default 300). */
const MAPA_TRAIN = Number(process.env.MAPA_TRAIN ?? 300);

for (const lang of ["de", "en", "fr", "es", "it", "pt"]) {
  let all = await mapaLanguage(lang);
  if (!ALL && MAPA_TRAIN > 0) all = [...all, ...sample(await mapaLanguage(lang, "train"), MAPA_TRAIN, 7)];
  for (const row of sample(all, N)) {
    let text = "";
    const starts = [];
    row.tokens.forEach((t, i) => { if (i) text += " "; starts.push(text.length); text += t; });
    const gold = [];
    let open = null;
    const close = () => { if (open) gold.push(open); open = null; };
    row.tokens.forEach((t, i) => {
      const coarse = row.coarse_grained[i];
      const fine = row.fine_grained[i];
      if (coarse === "O") return close();
      const type = coarse.slice(2);
      const label = type === "ADDRESS" ? `ADDRESS/${fine.slice(2)}` : type;
      if (coarse.startsWith("B-") || !open || open.type !== type || (type === "ADDRESS" && fine.startsWith("B-"))) {
        close();
        open = { start: starts[i], end: starts[i] + t.length, label, type };
      } else {
        open.end = starts[i] + t.length;
      }
    });
    close();
    out.push({ cell: `mapa-${lang}`, id: `${row.file_name}#${row.sentence_number}`, text, gold: gold.map(({ start, end, label }) => ({ start, end, label })) });
  }
  console.log(`  mapa-${lang} ${Math.min(N, all.length)} of ${all.length}`);
}

const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, ALL ? ".field-suites.json" : `.field-suites-${MAPA_SPLIT}.json`), JSON.stringify(out));
console.log(`  wrote ${out.length} rows to ${ALL ? ".field-suites.json" : `.field-suites-${MAPA_SPLIT}.json`}`);
