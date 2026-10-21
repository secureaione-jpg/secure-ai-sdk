# Secure AI — public, verifiable PII benchmarks

Run the same public test sets Microsoft Azure AI Language is scored on, against
Secure AI's live redaction API, and check the numbers yourself. No Secure AI
code is needed: the kit sends each document to `POST /v1/redact` like any
customer would, saves the answers, and scores them.

```bash
node fetch.mjs                              # download the public test rows (Hugging Face)
SAI_API_KEY=sai_... node run.mjs            # send them to the API and score
SAI_API_KEY=sai_... ORGANISATIONS=1 node run.mjs   # with company names hidden too
SAI_API_KEY=sai_... ORGANISATIONS=all node run.mjs # and courts, ministries, states
node run.mjs --score-only                   # re-score saved answers, no API calls
node run.mjs --score-only --markdown        # and write RESULTS.md to publish
```

Node 18 or later. `CELLS=grtl-en,tab-en` limits the run to some sets. On Windows
PowerShell, set the key first: `$env:SAI_API_KEY="sai_..."; node run.mjs`.

## The test sets

| Cell | Set | Split | Licence |
|---|---|---|---|
| grtl-en | gretelai/gretel-pii-masking-en-v1 | validation, 300 rows | Apache-2.0 |
| nmtr-en | nvidia/Nemotron-PII | test, 300 rows | CC BY 4.0 |
| tab-en | ildpil/text-anonymization-benchmark | test, all 127 documents | MIT |
| mapa-de/en/fr/es/it/pt | joelniklaus/mapa | test, up to 300 rows a language | CC BY 4.0 |

These are the sets, splits and three span measures (strict, overlap, partial
F1) of the ShinrAI PII board
([innovius/shinrai-pii-bench-results](https://huggingface.co/datasets/innovius/shinrai-pii-bench-results)),
whose 2026-09-01 scores for Azure, Presidio and about twenty other systems
are printed beside ours.

## Read the numbers honestly

- **The other systems' scores are the board's, not re-run here.** The board
  does not publish its 300-row samples, so these rows are drawn from the same
  splits with a fixed seed. TAB is the exception: all 127 test documents, the
  same as the board.
- **Two ways of scoring.** "Hidden at all" asks whether each labelled value
  was hidden, whatever kind the API called it: the question a redactor
  answers. "Typed" is the board's own measure, from the `spans` the API
  returns: the value must also be called the right kind. Address, city and
  postcode count as one kind there, because the API hides "12 High St, Leeds"
  as one address where a set may label two values.
- **Small sets move.** MAPA's languages have 40–170 labelled values each; the
  ± column is the 95% bootstrap margin. A difference smaller than it is noise.
- **Organisations count against us.** By default the API leaves company names
  and public bodies ("Court of Cassation", "Turkish Government") visible: a
  company is usually what a question is about. TAB marks them all, so most of
  TAB's labels are misses for us by design. The "w/o org" column shows the
  same answers graded on people, contacts and IDs alone. It sits beside the
  main score, never instead of it. `ORGANISATIONS=1` hides companies;
  `ORGANISATIONS=all` hides public bodies as well (needs the API version with
  that option).
- **Dates, times, ages, genders, countries and other ungraded labels** are
  neither right nor wrong here, as on the board.

## What gets sent

Only the public test documents in `.field-suites.json`. Answers are saved to
`answers.jsonl` (or `answers-organisations.jsonl`) — stand-in → real value
for each document — so anyone can see exactly what was hidden.
