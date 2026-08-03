"""Knowledge-base search (flow/05-contract.md v1.1 increment).

Keyword search (TF-IDF/cosine over `data/kb/docs/*.md`) and semantic search
(cached OPENCODE embeddings, falling back to TF-IDF+LSA per ADR decision 12
when the `/embeddings` route is unavailable) — same library-style seam as
`scan_runner.py`/`alert_normalizer.py`: read-only except `embed_kb_docs`
(writes `data/kb/.embeddings_cache.json`), no `st.*`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import requests
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

ROOT = Path(__file__).resolve().parent.parent
KB_DIR = ROOT / "data" / "kb"
KB_DOCS_DIR = KB_DIR / "docs"
KB_EMBED_CACHE = KB_DIR / ".embeddings_cache.json"

EMBEDDINGS_MODEL = "text-embedding-3-small"
EMBEDDINGS_TIMEOUT_SECONDS = 30
SNIPPET_WIDTH = 160

logger = logging.getLogger(__name__)

_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n?(.*)$", re.DOTALL)
# Section-bounded so a doc with a "## Vulnerable" prose section but no java fence
# never accidentally picks up the "## Fixed" snippet below it.
_VULNERABLE_SECTION_RE = re.compile(r"^##\s+Vulnerable\s*$(.*?)(?=^##\s|\Z)", re.DOTALL | re.MULTILINE)
_JAVA_FENCE_RE = re.compile(r"```java\n(.*?)```", re.DOTALL)

# Flips True on the first /embeddings failure and stays True for the rest of
# this process — without it, a dead endpoint (confirmed 404 in this env) would
# re-attempt one HTTP call per embed_kb_docs()/semantic search_kb() invocation
# forever, which is exactly the retry-storm the card forbids.
_embeddings_unavailable = False


@dataclass
class KBDoc:
    doc_id: str
    title: str
    path: Path
    body: str
    category: str


@dataclass
class KBIndex:
    doc_ids: list[str]
    vectors: "scipy.sparse.spmatrix"
    vectorizer: TfidfVectorizer
    docs: dict[str, KBDoc]


@dataclass
class KBHit:
    doc_id: str
    title: str
    path: str
    score: float
    snippet: str
    # v1.2 (flow/05-contract.md) — additive, so every pre-v1.2 caller keeps working.
    category: str = ""
    body: str = ""
    vulnerable_code: str | None = None


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text.strip()
    raw_meta, body = match.groups()
    meta: dict[str, str] = {}
    for line in raw_meta.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            meta[key.strip()] = value.strip()
    return meta, body.strip()


def _extract_vulnerable_code(body: str) -> str | None:
    """First fenced java block under a `## Vulnerable` heading, or None.

    None is the normal case for `owasp-top10/*` and `rules/*` docs, which carry no
    such section — callers must render nothing rather than treat it as an error.
    """
    section = _VULNERABLE_SECTION_RE.search(body)
    if not section:
        return None
    fence = _JAVA_FENCE_RE.search(section.group(1))
    return fence.group(1).strip() if fence else None


def _load_docs(docs_dir: Path) -> list[KBDoc]:
    docs = []
    for path in sorted(Path(docs_dir).rglob("*.md")):
        meta, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
        doc_id = path.relative_to(docs_dir).with_suffix("").as_posix()
        title = meta.get("title") or doc_id
        # Every shipped doc has `category:` frontmatter; the path segment is defensive.
        category = meta.get("category") or doc_id.split("/")[0]
        docs.append(KBDoc(doc_id=doc_id, title=title, path=path, body=body, category=category))
    return docs


def build_kb_index(docs_dir: Path = KB_DOCS_DIR) -> KBIndex:
    docs = _load_docs(Path(docs_dir))
    vectorizer = TfidfVectorizer(stop_words="english")
    vectors = vectorizer.fit_transform([doc.body for doc in docs])
    return KBIndex(
        doc_ids=[doc.doc_id for doc in docs],
        vectors=vectors,
        vectorizer=vectorizer,
        docs={doc.doc_id: doc for doc in docs},
    )


def _content_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _load_cache(cache_path: Path) -> dict:
    if not Path(cache_path).exists():
        return {}
    try:
        return json.loads(Path(cache_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache_path: Path, cache: dict) -> None:
    cache_path = Path(cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _embed_one(text: str) -> list[float]:
    """POST a single string to the OPENCODE embeddings endpoint. Raises on
    any HTTP/parse failure — callers decide how to treat that (fallback)."""
    base_url = os.environ.get("OPENCODE_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("OPENCODE_API_KEY", "")
    response = requests.post(
        f"{base_url}/embeddings",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": EMBEDDINGS_MODEL, "input": text},
        timeout=EMBEDDINGS_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["data"][0]["embedding"]


def embed_kb_docs(docs_dir: Path = KB_DOCS_DIR, cache_path: Path = KB_EMBED_CACHE) -> int:
    global _embeddings_unavailable
    docs = _load_docs(Path(docs_dir))
    cache = _load_cache(cache_path)
    newly_embedded = 0
    for doc in docs:
        digest = _content_hash(doc.body)
        if digest in cache or _embeddings_unavailable:
            continue
        try:
            vector = _embed_one(doc.body)
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            logger.warning("KB embeddings endpoint unavailable (%s) — falling back to "
                          "TF-IDF+LSA for the rest of this process", exc)
            _embeddings_unavailable = True
            continue
        cache[digest] = {"doc_id": doc.doc_id, "model": EMBEDDINGS_MODEL, "vector": vector}
        newly_embedded += 1
    if newly_embedded:
        _save_cache(cache_path, cache)
    return newly_embedded


def _snippet(body: str, query: str, width: int = SNIPPET_WIDTH) -> str:
    # Collapse whitespace up front so the offsets we compute below describe the same
    # string we return — the previous version sliced the raw body and only flattened
    # newlines afterwards, so the window could land mid-word ("nto a command, …").
    text = " ".join(body.split())
    if not text:
        return ""
    terms = [t for t in re.findall(r"\w+", query.lower()) if t]
    lower = text.lower()
    idx = next((lower.find(term) for term in terms if lower.find(term) != -1), -1)
    idx = max(idx, 0)
    start = max(0, idx - width // 2)
    end = min(len(text), start + width)
    # Snap both edges inward to a word boundary, never past the matched term itself.
    if start > 0:
        space = text.find(" ", start)
        if space != -1 and space < idx:
            start = space + 1
    if end < len(text):
        space = text.rfind(" ", start, end)
        if space > start:
            end = space
    excerpt = text[start:end].strip()
    # Ellipses mark that the excerpt is a window, not the whole doc.
    return f"{'… ' if start > 0 else ''}{excerpt}{' …' if end < len(text) else ''}"


def _hits_from_scores(
    docs: list[KBDoc], scores: np.ndarray, query: str, top_k: int, min_score: float = 0.0
) -> list[KBHit]:
    # min_score is applied globally across every category BEFORE the top_k cut, so
    # raising the threshold can legitimately empty a whole category (contract v1.2).
    ranked = [i for i in np.argsort(scores)[::-1] if float(scores[i]) >= min_score][:top_k]
    return [
        KBHit(
            doc_id=docs[i].doc_id,
            title=docs[i].title,
            path=str(docs[i].path.relative_to(ROOT)),
            score=float(scores[i]),
            snippet=_snippet(docs[i].body, query),
            category=docs[i].category,
            body=docs[i].body,
            vulnerable_code=_extract_vulnerable_code(docs[i].body),
        )
        for i in ranked
    ]


def _keyword_search(index: KBIndex, query: str, top_k: int, min_score: float) -> list[KBHit]:
    scores = cosine_similarity(index.vectorizer.transform([query]), index.vectors)[0]
    docs = [index.docs[doc_id] for doc_id in index.doc_ids]
    return _hits_from_scores(docs, scores, query, top_k, min_score)


def _lsa_fallback_search(query: str, top_k: int, min_score: float) -> list[KBHit]:
    index = build_kb_index(KB_DOCS_DIR)
    docs = [index.docs[doc_id] for doc_id in index.doc_ids]
    n_components = max(1, min(len(docs) - 1, 100))
    svd = TruncatedSVD(n_components=n_components)
    reduced_docs = svd.fit_transform(index.vectors)
    reduced_query = svd.transform(index.vectorizer.transform([query]))
    scores = cosine_similarity(reduced_query, reduced_docs)[0]
    return _hits_from_scores(docs, scores, query, top_k, min_score)


def _semantic_search(query: str, top_k: int, min_score: float) -> list[KBHit]:
    global _embeddings_unavailable
    docs = _load_docs(KB_DOCS_DIR)
    cache = _load_cache(KB_EMBED_CACHE)
    if not docs:
        return []
    hashes = [_content_hash(doc.body) for doc in docs]
    have_all_cached = all(h in cache for h in hashes)

    if have_all_cached and not _embeddings_unavailable:
        try:
            query_vector = _embed_one(query)
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            logger.warning("KB embeddings endpoint unavailable (%s) — falling back to "
                          "TF-IDF+LSA for the rest of this process", exc)
            _embeddings_unavailable = True
        else:
            doc_vectors = np.array([cache[h]["vector"] for h in hashes])
            scores = cosine_similarity([query_vector], doc_vectors)[0]
            return _hits_from_scores(docs, scores, query, top_k, min_score)

    return _lsa_fallback_search(query, top_k, min_score)


def search_kb(
    query: str, mode: str = "keyword", top_k: int = 5, min_score: float = 0.1
) -> list[KBHit]:
    if mode == "keyword":
        return _keyword_search(build_kb_index(KB_DOCS_DIR), query, top_k, min_score)
    if mode == "semantic":
        return _semantic_search(query, top_k, min_score)
    raise ValueError(f"unknown search mode: {mode!r}")
