# Document library

The **Document library** (menu: Document library) holds your whole security document set in one place: the
policy hierarchy, the built-in Word templates, and your own official versions with every old version kept.
It sits next to **Policies**, which still handles reading and accepting policies.

## What is in it
Folders follow a five-tier model. Each tier changes at a different speed, so a new patch deadline changes one
standard, not a policy.

| Folder | What it holds | Built-in templates |
| --- | --- | --- |
| Tier 1: Information Security Policy | The umbrella policy everything inherits from | 1 (full) |
| Tier 2: Topic policies | P-01 to P-13: risk, conduct and acceptable use, HR security, assets and data, access, cryptography, operations, secure development, vendors, incidents, continuity, physical, AI | 13 (full) |
| Tier 3: Standards | The measurable values a policy points to (password length, patch deadlines, backup targets) | 13 (skeleton) |
| Tier 4: Procedures and plans | The steps people perform and the record each step leaves | 20 (skeleton) |
| SOC 2 additions | System description, commitments register, CSOC/CUEC register, oversight charter, fraud risk, restore test report | 6 (skeleton) |

A full policy template has a document control table (owner, approver, version, review date, classification,
framework mapping, linked GRC-pal controls), numbered statements each with a **How it is tested** column, roles,
exceptions, enforcement and revision history. Skeletons give the structure and the questions to answer.
Everything is written with `[Company Name]` and `[bracketed]` placeholders. Replace them, delete the grey
guidance, and drop any statement that is not true today: every "must" is something an auditor will test.

## The Explorer view
- **Left:** the folders, with counts. **Documents** shows one row per document (number, title, owner, official
  version, next review). **All files** shows one row per file: every official version (all versions, all
  products) and each document's current template, with size, who added it and its SHA-256.
- Search by number, title or owner. Admins can add a document that is not in the built-in set.

## Working on one document
1. **Download the template**, adapt it in Word, then **upload it as your official version**
   (`.docx`, `.pdf`, `.xlsx` or `.pptx`).
2. A new upload is a **Draft**. Choose **major** (a commitment changed: 2.0, should be re-approved and re-read)
   or **minor** (wording: 1.1). Use **Product / variant** when the same policy exists for several products;
   each product has its own version line (Product A 1.0, 1.1 ... and Product B 1.0 ...).
3. **Send to review**, then **Approve**. A different admin must approve (segregation of duties); if there is only
   one active admin the approval is marked self-approved so the auditor can see it. Approving a version makes
   the earlier approved version of the same product **Superseded**. Nothing is deleted: archive a version with a
   reason to hide it from staff.
4. **Replace the template** at any time by uploading your own. Everyone then downloads your template; the old one
   stays in the template history and **Restore the built-in template** brings the shipped one back.
5. **Edit details** changes the title, owner, approver, classification and next review date. The document number
   never changes, so renaming "Access Control Policy" keeps it as P-05.

## Who can do what
| Role | Sees | Can do |
| --- | --- | --- |
| Admin | Everything | Upload, approve, archive, replace templates, edit details, add documents |
| Auditor | Everything, read-only | Download every version and template; check hashes against the audit log |
| Control owner | Only documents with an approved official version, approved versions only | Download the published copy |

## How an auditor tests it
- Every upload, approval, status change, template replacement, rename and (for non-admins) download is in the
  hash-chained audit log (`doclib.*`) with the version, product, approver and SHA-256.
- Files are stored write-once in the evidence store (`doclib_upload/`). The SHA-256 on the page must equal the hash
  in the audit entry and in the evidence manifest.
- Sample a policy: approved version, approver (not the uploader), approval date within the review period, next
  review date in the future.

## For maintainers: rebuilding the built-in templates
The templates are generated, then committed, so the running portal needs no extra library. Edit
`tools/doctemplates/registry.yaml` (list of documents) or `tools/doctemplates/policies.yaml` (Tier 1 and 2 text),
then run `python tools/build_doc_templates.py` (needs `python-docx`, included in the `dev` extra) and commit the
files in `grcpal/starter/doctemplates/`. A test checks that the catalog matches the sources, that every template
is a valid Word file, and that no organization name has slipped in.
