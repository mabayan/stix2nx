# CLAUDE.md — Build Instructions for stix2nx

## Project Overview

Build `stix2nx`, a lightweight Python library that converts STIX (Structured Threat Information eXpression) JSON bundles into NetworkX graph objects. The library should be production-ready for public release on GitHub and PyPI.

STIX is the standard format for cyber threat intelligence. It represents threats as JSON "bundles" containing typed objects (threat actors, malware, vulnerabilities, etc.) and relationships between them. The data is implicitly a graph, but the JSON format is flat — just an array of objects with string ID references. This library bridges that gap.

---

## Core API Design

### Main Entry Point

A single function: `stix_to_graph()`

```python
from stix2nx import stix_to_graph

G = stix_to_graph(
    source,                    # str (file path or directory) OR list[str] (JSON strings) OR list[dict] (parsed dicts)
    graph_type="multidigraph", # "multidigraph" (default) or "digraph"
    include_scos=True,         # Whether SCOs become nodes (default True) or are skipped
)
```

**Input formats supported:**
- A file path (str ending in `.json`) → reads and parses the file
- A directory path (str) → globs for all `*.json` files in the directory (non-recursive), parses each as a STIX bundle, merges into one graph
- A list of JSON strings → each is parsed as a STIX bundle
- A list of Python dicts → each is treated as a parsed STIX bundle
- Multiple bundles (from directory or list inputs) are merged into a single graph (nodes deduplicated by ID, edges accumulated)

**How source type is detected:**
- If `source` is a `str` and it's a path to an existing directory → directory mode
- If `source` is a `str` and it ends with `.json` or is a path to an existing file → single file mode
- If `source` is a `list` where elements are `str` → JSON strings mode (each string is a full JSON bundle)
- If `source` is a `list` where elements are `dict` → parsed dicts mode

**Output:**
- `nx.MultiDiGraph` when `graph_type="multidigraph"` (default) — allows multiple edges between same node pair (e.g., threat-actor A both "uses" and "attributed-to" malware B). This is the technically correct representation but some NetworkX algorithms don't support multigraphs.
- `nx.DiGraph` when `graph_type="digraph"` — collapses multiple edges between the same pair into one (last-write-wins on attributes). Broader algorithm compatibility but potential data loss.

### How Objects Map to Graph Elements

**SDOs (STIX Domain Objects) → Nodes**
All 18 SDO types become nodes. Every STIX property on the object becomes a NetworkX node attribute. List-valued properties are kept as Python lists (not serialized to strings).

Example: a threat-actor node would have attributes like:
- `type`: "threat-actor"
- `name`: "APT28"
- `aliases`: ["Fancy Bear", "Sofacy", "Pawn Storm"]  ← Python list
- `threat_actor_types`: ["nation-state"]  ← Python list
- `sophistication`: "expert"
- `created`: "2017-05-31T21:31:48.000Z"
- etc.

The node ID in NetworkX is the STIX `id` field (e.g., `"threat-actor--abc123"`).

**SCOs (STIX Cyber-observable Objects) → Nodes (when `include_scos=True`)**
Observable objects (ipv4-addr, domain-name, file, url, email-addr, etc.) become nodes with all their properties as attributes. When `include_scos=False`, these objects are skipped entirely.

Note: Some indicators contain SCO references embedded in their `pattern` string (e.g., `[file:hashes.'SHA-256' = 'abc123']`). The library does NOT parse STIX pattern expressions to extract embedded SCO references — it only promotes SCO objects that exist as standalone objects in the bundle. This is an intentional scope limitation; pattern parsing is a separate complex problem.

**Relationship Objects → Edges**
STIX `relationship` objects become directed edges from `source_ref` to `target_ref`. Edge attributes include:
- `relationship_type`: e.g., "uses", "targets", "exploits", "indicates"
- `id`: the relationship object's own STIX ID
- `start_time`: if present
- `stop_time`: if present
- `confidence`: if present
- Any other properties on the relationship object

**Sighting Objects → Nodes + Edges**
Sightings are conceptually different from relationships — they record "entity X was observed by entity Y at time T." They are represented as:
- The sighting itself becomes a **node** (with all its properties as attributes)
- A directed edge is created from the sighting node to `sighting_of_ref` (what was sighted), with `relationship_type="sighting_of"`
- For each entry in `where_sighted_refs`, a directed edge is created from the sighting node to that identity, with `relationship_type="seen_by"`
- For each entry in `observed_data_refs`, a directed edge is created from the sighting node to that observed-data object, with `relationship_type="observed"`

**Marking Definitions and Language Content → Skipped**
`marking-definition` and `language-content` objects are metadata, not threat intelligence entities. They are not added to the graph.

### Handling Multiple Bundles

When multiple bundles are provided (list of JSON strings or list of dicts), they are merged into a single graph:
- Nodes with the same STIX ID are deduplicated (later bundle's attributes overwrite earlier ones if there's a conflict — last-write-wins)
- Edges are accumulated (not deduplicated — it's valid for the same relationship to appear in multiple bundles)

### STIX Version Handling

The library must handle both STIX 2.0 and STIX 2.1 bundles:
- STIX 2.0 bundles have `"spec_version": "2.0"` on the bundle; STIX 2.1 moves `spec_version` to individual objects
- STIX 2.0 uses `created_by_ref` as a direct property; 2.1 is the same but has additional object types
- The key structural difference: STIX 2.1 added `infrastructure`, `malware-analysis`, `location`, `note`, `opinion`, `grouping` SDO types and all SCO types. STIX 2.0 had `observed-data` with embedded `objects` dict instead of standalone SCOs.
- The library should handle both gracefully — parse what's there, skip what isn't, never crash on version differences.

For STIX 2.0 bundles where SCOs are embedded inside `observed-data` objects as a nested `objects` dict: when `include_scos=True`, extract those embedded observables as standalone nodes with synthetic IDs (prefixed with the observed-data ID to ensure uniqueness). When `include_scos=False`, skip them.

---

## Project Structure

```
stix2nx/
├── src/
│   └── stix2nx/
│       ├── __init__.py          # Exports stix_to_graph
│       ├── converter.py         # Core conversion logic
│       ├── parsers.py           # Input parsing (file, JSON strings, dicts)
│       └── utils.py             # Helper functions
├── tests/
│   ├── __init__.py
│   ├── test_basic.py            # Unit tests with small hand-crafted bundles
│   ├── test_sco.py              # Tests for SCO inclusion/exclusion
│   ├── test_sightings.py        # Tests for sighting node+edge creation
│   ├── test_digraph.py          # Tests for DiGraph vs MultiDiGraph output
│   ├── test_stix20.py           # Tests specific to STIX 2.0 bundles
│   ├── test_stix21.py           # Tests specific to STIX 2.1 bundles
│   ├── test_merge.py            # Tests for merging multiple bundles
│   ├── test_attack.py           # Integration test against MITRE ATT&CK curated subset
│   ├── conftest.py              # Shared fixtures (sample bundles, etc.)
│   └── data/
│       ├── attack-subset.json   # Curated ~1MB ATT&CK subset (checked in)
│       └── build_subset.py      # Script to regenerate subset from full ATT&CK bundle
├── examples/
│   └── visualize_attack.py      # Script that produces the visualization for the README
├── README.md
├── CLAUDE.md                    # This file
├── LICENSE                      # MIT License
├── CHANGELOG.md
├── pyproject.toml
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── workflows/
│       └── ci.yml               # GitHub Actions: lint + test on Python 3.10, 3.11, 3.12, 3.13
└── .gitignore
```

---

## Dependencies

**Runtime dependencies (and ONLY these):**
- `stix2` (>=3.0.0) — official OASIS STIX 2 Python library
- `networkx` (>=3.0)

**Test dependencies (dev only):**
- `pytest`
- `requests` (only used in test_attack.py to download the live ATT&CK bundle)
- `matplotlib` (only used in examples/visualize_attack.py)

**Python version:** >=3.10

---

## Package Configuration (pyproject.toml)

Use modern Python packaging with `pyproject.toml` (no setup.py, no setup.cfg):

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "stix2nx"
version = "0.1.0"
description = "Convert STIX cyber threat intelligence bundles to NetworkX graphs"
readme = "README.md"
license = "MIT"
requires-python = ">=3.10"
authors = [
    { name = "Marlon Abayan", email = "mabayan@users.noreply.github.com" }
]
keywords = ["stix", "stix2", "networkx", "threat-intelligence", "cybersecurity", "mitre-attack", "cti"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
    "Topic :: Scientific/Engineering :: Information Analysis",
]
dependencies = [
    "stix2>=3.0.0",
    "networkx>=3.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "requests>=2.28",
    "matplotlib>=3.5",
]

[project.urls]
Homepage = "https://github.com/mabayan/stix2nx"
Repository = "https://github.com/mabayan/stix2nx"
Issues = "https://github.com/mabayan/stix2nx/issues"
```

---

## Test Suite Design

All tests should be runnable with a single command: `pytest`

### Unit Tests (test_basic.py, test_sco.py, test_sightings.py, test_digraph.py, test_stix20.py, test_stix21.py, test_merge.py)

Use hand-crafted minimal STIX bundles as fixtures in conftest.py. Each test should be fast and deterministic (no network calls).

**test_basic.py:**
- Test that SDOs become nodes with correct attributes
- Test that Relationship objects become edges with correct attributes
- Test that node IDs match STIX IDs
- Test that list-valued properties remain Python lists
- Test that all properties are preserved (not just a subset)
- Test that marking-definitions and language-content are excluded
- Test with empty bundle (should return empty graph)
- Test with bundle containing only nodes and no relationships

**test_sco.py:**
- Test that SCOs become nodes when `include_scos=True`
- Test that SCOs are excluded when `include_scos=False`
- Test that SCO properties are correctly mapped to node attributes
- Test observable types: ipv4-addr, domain-name, file (with hashes dict), url, email-addr

**test_sightings.py:**
- Test that sighting objects become nodes
- Test that sighting_of_ref becomes an edge with `relationship_type="sighting_of"`
- Test that where_sighted_refs become edges with `relationship_type="seen_by"`
- Test that observed_data_refs become edges with `relationship_type="observed"`
- Test sighting with all three ref types present
- Test sighting with only sighting_of_ref (minimal case)

**test_digraph.py:**
- Test MultiDiGraph output preserves multiple edges between same node pair
- Test DiGraph output when there are multiple relationships between same pair (verify only one edge exists, last-write-wins)
- Test that both graph types have the same node set
- Test that algorithm compatibility works (e.g., shortest_path works on both)

**test_stix20.py:**
- Test with a STIX 2.0 bundle (spec_version on bundle, not objects)
- Test that STIX 2.0 observed-data with embedded objects dict extracts SCOs correctly when include_scos=True
- Test that STIX 2.0 bundles without the newer SDO types (infrastructure, location, etc.) work fine

**test_stix21.py:**
- Test with a STIX 2.1 bundle (spec_version on individual objects)
- Test STIX 2.1-specific types: infrastructure, malware-analysis, location, note, opinion, grouping
- Test that standalone SCOs are handled correctly

**test_merge.py:**
- Test merging two bundles with no overlap → all nodes from both present
- Test merging two bundles with overlapping node IDs → deduplicated, later attributes win
- Test merging two bundles with overlapping edges → both edges preserved in MultiDiGraph
- Test providing 3+ bundles

### Integration Test (test_attack.py)

This test uses a curated ~1MB subset of the MITRE ATT&CK Enterprise STIX bundle, checked into the repo at `tests/data/attack-subset.json`. An optional live mode downloads and tests against the full ~30MB bundle.

#### Building the Curated Subset

Create a script `tests/data/build_subset.py` that downloads the full ATT&CK Enterprise bundle from `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` and extracts a representative subset targeting ~1MB / ~200-300 objects. The subset MUST include:

- **The `x-mitre-matrix` and `x-mitre-tactic` objects** (the ATT&CK matrix structure, ~15 objects)
- **~30 `attack-pattern` objects** (techniques) — pick ones that are heavily connected
- **~8 `intrusion-set` objects** (threat actor groups) — include APT28, APT29, Lazarus Group, and a few others that are well-connected
- **~10 `malware` objects** — pick ones used by the selected intrusion sets
- **~5 `tool` objects** (legitimate tools used maliciously, e.g., Mimikatz, Cobalt Strike)
- **~5 `campaign` objects** — if present in ATT&CK
- **~3 `course-of-action` objects** (mitigations)
- **~3 `identity` objects** (the MITRE identity used as `created_by_ref`, plus sector identities if present)
- **All `relationship` objects that connect any of the above selected nodes to each other** — this is the key part. Walk the relationships and include only those where both `source_ref` and `target_ref` are in the selected node set. This should yield ~100-200 relationships.
- **~5 `vulnerability` objects** — if present (ATT&CK has limited vulnerability coverage, but include what's there)
- **A few SCO objects** if present, or craft 3-4 synthetic but valid SCOs (an `ipv4-addr`, a `domain-name`, a `file` with hashes, a `url`) and a couple of `indicator` objects that reference them via relationships. This ensures SCO handling is tested even though ATT&CK is primarily SDO-focused.
- **1-2 `sighting` objects** — ATT&CK may not include sightings. If not, craft 2 synthetic but valid sighting objects: one sighting linking an indicator to an intrusion-set with `where_sighted_refs` pointing to an identity. This ensures the sighting→node+edge logic is tested on realistic-ish data.

The script should:
1. Download the full bundle
2. Select the objects described above using a deterministic algorithm (not random — same output every run for a given ATT&CK version)
3. Verify referential integrity: every `source_ref` and `target_ref` in included relationships points to an included node
4. Add the synthetic SCOs and sightings if the real bundle doesn't have them (clearly comment these as synthetic)
5. Write the result to `tests/data/attack-subset.json`
6. Print a summary: object count by type, total file size, node count, edge count

**Check `tests/data/attack-subset.json` into the repo.** It should be ~1MB or less — small enough for git, large enough to be a meaningful integration test.

Also check in `tests/data/build_subset.py` so anyone can regenerate the subset from a newer ATT&CK version.

#### Test Code

```python
import pytest
import os

LIVE_FLAG = os.environ.get("STIX2NX_LIVE_ATTACK", "false").lower() == "true"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
SUBSET_PATH = os.path.join(os.path.dirname(__file__), "data", "attack-subset.json")

@pytest.fixture
def attack_bundle_path(tmp_path):
    """Get ATT&CK bundle. Default: curated subset. With STIX2NX_LIVE_ATTACK=true: full live bundle."""
    if LIVE_FLAG:
        try:
            import requests
            resp = requests.get(ATTACK_URL, timeout=120)
            resp.raise_for_status()
            live_path = tmp_path / "enterprise-attack.json"
            live_path.write_text(resp.text)
            print(f"\nUsing live ATT&CK bundle from {ATTACK_URL} ({len(resp.text) // 1024 // 1024}MB)")
            return str(live_path)
        except Exception as e:
            print(f"\nLive ATT&CK download failed ({e}), falling back to curated subset")
            return SUBSET_PATH
    return SUBSET_PATH

# Minimum thresholds: low enough for the subset, meaningful enough to catch breakage
# When running live, the actual numbers will be much higher
MIN_NODES = 100
MIN_EDGES = 80

def test_attack_loads(attack_bundle_path):
    """ATT&CK bundle converts to a graph without error."""
    from stix2nx import stix_to_graph
    G = stix_to_graph(attack_bundle_path)
    assert len(G.nodes) >= MIN_NODES
    assert len(G.edges) >= MIN_EDGES

def test_attack_has_expected_types(attack_bundle_path):
    """ATT&CK graph contains the core node types."""
    from stix2nx import stix_to_graph
    G = stix_to_graph(attack_bundle_path)
    types = {data["type"] for _, data in G.nodes(data=True)}
    assert "attack-pattern" in types
    assert "intrusion-set" in types
    assert "malware" in types
    assert "tool" in types
    assert "relationship" not in types  # relationships should be edges, not nodes

def test_attack_relationship_attributes(attack_bundle_path):
    """Edges have relationship_type attributes."""
    from stix2nx import stix_to_graph
    G = stix_to_graph(attack_bundle_path)
    rel_types = set()
    for u, v, data in G.edges(data=True):
        if "relationship_type" in data:
            rel_types.add(data["relationship_type"])
    assert "uses" in rel_types  # ATT&CK heavily uses "uses" relationships

def test_attack_node_attributes(attack_bundle_path):
    """Nodes have expected STIX attributes preserved."""
    from stix2nx import stix_to_graph
    G = stix_to_graph(attack_bundle_path)
    # Find any attack-pattern node and verify it has a name
    for n, data in G.nodes(data=True):
        if data.get("type") == "attack-pattern":
            assert "name" in data
            assert "id" in data
            assert isinstance(data["id"], str)
            break

def test_attack_digraph(attack_bundle_path):
    """ATT&CK converts to DiGraph without error."""
    from stix2nx import stix_to_graph
    G = stix_to_graph(attack_bundle_path, graph_type="digraph")
    assert len(G.nodes) >= MIN_NODES

def test_attack_no_scos(attack_bundle_path):
    """ATT&CK converts with include_scos=False without error."""
    from stix2nx import stix_to_graph
    G_with = stix_to_graph(attack_bundle_path, include_scos=True)
    G_without = stix_to_graph(attack_bundle_path, include_scos=False)
    # With SCOs should have >= as many nodes
    assert len(G_with.nodes) >= len(G_without.nodes)

def test_attack_sightings(attack_bundle_path):
    """Sighting objects in the subset become nodes with edges."""
    from stix2nx import stix_to_graph
    G = stix_to_graph(attack_bundle_path)
    sighting_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "sighting"]
    # The curated subset includes synthetic sightings
    assert len(sighting_nodes) >= 1
    # Each sighting should have at least a sighting_of edge
    for sn in sighting_nodes:
        edge_types = [d.get("relationship_type") for _, _, d in G.edges(sn, data=True)]
        assert "sighting_of" in edge_types
```

To run with curated subset (default, used in CI): `pytest tests/test_attack.py -v`
To run with full live ATT&CK bundle: `STIX2NX_LIVE_ATTACK=true pytest tests/test_attack.py -v`

---

## README.md Structure

The README should be purely technical. No company pitch, no lengthy STIX background. Structure:

### 1. Title + One-Line Description

```
# stix2nx

Convert STIX cyber threat intelligence bundles to NetworkX graphs.
```

### 2. Installation

```
pip install stix2nx
```

### 3. Quick Start (5-line example)

```python
from stix2nx import stix_to_graph

# Convert a STIX bundle file to a NetworkX graph
G = stix_to_graph("enterprise-attack.json")

print(f"{len(G.nodes)} nodes, {len(G.edges)} edges")
# → 14,532 nodes, 21,847 edges (example numbers, use actual ATT&CK numbers)
```

### 4. Before/After Comparison

Show two side-by-side code blocks:

**Before (without stix2nx):** ~25-30 lines of boilerplate code using `stix2` MemoryStore, manually iterating objects, building a NetworkX graph, handling relationships, handling sightings, handling SCOs, etc.

**After (with stix2nx):** 3 lines.

Make the contrast visceral — the before code should be the actual painful code someone would write, not a strawman.

### 5. API Reference

Document `stix_to_graph()` parameters:
- `source`: str (file path or directory path) | list[str] (JSON strings) | list[dict] (parsed bundles)
  - File path: reads and parses a single `.json` file
  - Directory path: globs all `*.json` files in the directory, merges into one graph
  - list[str]: each string is parsed as a full STIX bundle JSON
  - list[dict]: each dict is treated as a parsed STIX bundle
- `graph_type`: "multidigraph" (default) | "digraph"
  - Explain: MultiDiGraph allows multiple edges between the same pair of nodes, which is technically correct for STIX (a threat actor can both "uses" and "attributed-to" the same malware). However, some NetworkX algorithms (like certain centrality measures) only work on simple DiGraphs. Choose based on your use case.
- `include_scos`: bool (default True)
  - Explain: When True, STIX Cyber-observable Objects (IP addresses, domain names, file hashes, etc.) become nodes. When False, only SDOs and relationships are included.
- Returns: `nx.MultiDiGraph` or `nx.DiGraph`

### 6. Graph Structure

Explain how STIX objects map to graph elements:
- SDOs → nodes (all properties as attributes)
- SCOs → nodes (when include_scos=True)
- Relationships → directed edges (with relationship_type, start_time, stop_time, confidence as attributes)
- Sightings → nodes + edges (sighting_of, seen_by, observed edges)
- Marking definitions → skipped

### 7. Working with the Graph

Show 3-4 practical examples of things you can do once you have the graph:

```python
# Find all techniques used by APT28
apt28 = [n for n, d in G.nodes(data=True) if d.get("name") == "APT28"][0]
techniques = [
    G.nodes[target]["name"]
    for _, target, data in G.edges(apt28, data=True)
    if data.get("relationship_type") == "uses"
    and G.nodes[target]["type"] == "attack-pattern"
]
```

```python
# Most connected threat actors (by degree)
actors = [(n, G.degree(n)) for n, d in G.nodes(data=True) if d["type"] == "intrusion-set"]
top_actors = sorted(actors, key=lambda x: x[1], reverse=True)[:10]
```

```python
# Merging multiple bundles
G = stix_to_graph(["enterprise-attack.json", "mobile-attack.json", "ics-attack.json"])
```

### 8. Visualization Example

Include a generated PNG image in the README showing a subgraph of the ATT&CK data (e.g., a threat actor neighborhood). Show the code used to generate it (referencing `examples/visualize_attack.py`). Keep the visualization clean — use color-coding by node type, reasonable layout (spring or kamada-kawai), and readable labels.

The visualization script (`examples/visualize_attack.py`) should:
- Load the ATT&CK bundle
- Extract a subgraph around one well-known threat actor (e.g., APT28/Fancy Bear — pick one that has interesting connections)
- Include 1-2 hops out from that actor
- Color nodes by type (threat actors = red, malware = purple, attack patterns = orange, tools = blue, etc.)
- Save the output as `examples/apt_subgraph.png`
- This PNG is referenced in the README via `![Threat Actor Subgraph](examples/apt_subgraph.png)`

### 9. Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests (uses curated ATT&CK subset, no network needed)
pytest

# Run integration test with full live ATT&CK bundle (~30MB download)
STIX2NX_LIVE_ATTACK=true pytest tests/test_attack.py -v

# Regenerate the curated subset from latest ATT&CK (requires network)
python tests/data/build_subset.py
```

### 10. STIX Version Support

Note: supports both STIX 2.0 and STIX 2.1 bundles.

### 11. License

MIT

---

## GitHub Issue Templates

### .github/ISSUE_TEMPLATE/bug_report.md

```markdown
---
name: Bug Report
about: Report a bug in stix2nx
title: "[BUG] "
labels: bug
---

**Describe the bug**
A clear description of what went wrong.

**To reproduce**
Steps or minimal code example that triggers the bug.

**STIX input**
If possible, include the STIX bundle (or a minimal subset) that caused the issue.
Paste inline or attach as a file.

**Expected behavior**
What you expected to happen.

**Environment**
- Python version:
- stix2nx version:
- stix2 version:
- networkx version:
- OS:
```

### .github/ISSUE_TEMPLATE/feature_request.md

```markdown
---
name: Feature Request
about: Suggest an enhancement
title: "[FEATURE] "
labels: enhancement
---

**What are you trying to do?**
Describe the task or workflow.

**Why doesn't current functionality cover this?**
What's missing or inconvenient.

**Proposed solution**
If you have one in mind.
```

---

## GitHub Actions CI (.github/workflows/ci.yml)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      - name: Run tests
        run: pytest -v
```

---

## CHANGELOG.md

```markdown
# Changelog

## [0.1.0] - YYYY-MM-DD

### Added
- Initial release
- `stix_to_graph()` function converting STIX bundles to NetworkX graphs
- Support for STIX 2.0 and 2.1
- MultiDiGraph and DiGraph output options
- SCO inclusion/exclusion toggle
- Sightings as nodes with typed edges
- Multiple bundle merging
- MITRE ATT&CK integration test
```

---

## .gitignore

Standard Python .gitignore. Include:
```
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.eggs/
*.egg
.pytest_cache/
.tox/
venv/
.venv/
*.so
.DS_Store
```

---

## Implementation Notes

### Error Handling
- If a relationship's `source_ref` or `target_ref` refers to an object not in the bundle, create the edge anyway (NetworkX allows edges to nodes that don't exist yet — they auto-create empty nodes). Log a warning but don't crash. This is common in real-world STIX data where bundles are incomplete.
- If JSON parsing fails, raise a clear `ValueError` with the position/content that failed.
- If an object has no `type` field, skip it with a warning.
- If an object has no `id` field, skip it with a warning.

### Performance Considerations
- The ATT&CK Enterprise bundle is ~30MB / ~14,000+ objects. The conversion should complete in under 10 seconds on a modern machine. Don't do anything O(n²).
- Use simple iteration, not the `stix2` library's parsing/validation (which is slow). Parse the JSON directly with `json.load()` and extract fields manually rather than constructing full `stix2` Python objects. The `stix2` dependency is listed for ecosystem compatibility and for users who want to interoperate, but the core parsing should just be raw JSON dict processing for speed.

### Code Style
- Type hints on all public functions
- Docstrings on all public functions (Google style)
- Keep it simple — no metaclasses, no abstract base classes, no over-engineering. This is a utility library.
