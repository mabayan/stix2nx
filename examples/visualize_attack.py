#!/usr/bin/env python3
"""Visualize a threat actor neighborhood from the ATT&CK STIX bundle.

Generates a subgraph centered on a well-known threat actor (APT28/Fancy Bear),
showing 1-2 hops of connections color-coded by node type.

Usage:
    python examples/visualize_attack.py

Output:
    examples/apt_subgraph.png
"""

import os
import sys

import matplotlib.pyplot as plt
import networkx as nx

# Add project root to path if needed
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from stix2nx import stix_to_graph

SUBSET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "tests", "data", "attack-subset.json"
)
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "apt_subgraph.png")

# Color scheme by node type
TYPE_COLORS = {
    "intrusion-set": "#e74c3c",     # red
    "malware": "#9b59b6",           # purple
    "attack-pattern": "#e67e22",    # orange
    "tool": "#3498db",              # blue
    "campaign": "#2ecc71",          # green
    "indicator": "#f39c12",         # yellow
    "identity": "#1abc9c",          # teal
    "course-of-action": "#95a5a6",  # gray
    "vulnerability": "#e91e63",     # pink
    "sighting": "#00bcd4",          # cyan
}
DEFAULT_COLOR = "#bdc3c7"  # light gray for unknown types


def get_label(data):
    """Get a short display label for a node."""
    name = data.get("name", "")
    if name:
        # Truncate long names
        return name[:25] + "..." if len(name) > 25 else name
    return data.get("id", "?")[:20]


def main():
    print(f"Loading ATT&CK subset from {SUBSET_PATH}...")
    G = stix_to_graph(SUBSET_PATH)
    print(f"Full graph: {len(G.nodes)} nodes, {len(G.edges)} edges")

    # Find APT28
    apt28_id = None
    for n, d in G.nodes(data=True):
        if d.get("name") == "APT28":
            apt28_id = n
            break

    if not apt28_id:
        # Fall back to any intrusion-set
        for n, d in G.nodes(data=True):
            if d.get("type") == "intrusion-set":
                apt28_id = n
                print(f"APT28 not found, using {d.get('name', n)}")
                break

    if not apt28_id:
        print("No intrusion-set found in subset, exiting")
        sys.exit(1)

    # Extract 2-hop ego graph (undirected for neighborhood extraction)
    undirected = G.to_undirected()
    ego = nx.ego_graph(undirected, apt28_id, radius=2)

    # Limit to manageable size — keep only closest nodes if too many
    if len(ego.nodes) > 60:
        ego = nx.ego_graph(undirected, apt28_id, radius=1)

    # Create directed subgraph from original graph
    subgraph = G.subgraph(ego.nodes).copy()
    print(f"Subgraph around {G.nodes[apt28_id].get('name', apt28_id)}: "
          f"{len(subgraph.nodes)} nodes, {len(subgraph.edges)} edges")

    # Prepare visualization
    fig, ax = plt.subplots(1, 1, figsize=(16, 12))

    # Node properties
    node_colors = []
    node_sizes = []
    labels = {}
    for n, d in subgraph.nodes(data=True):
        node_type = d.get("type", "unknown")
        node_colors.append(TYPE_COLORS.get(node_type, DEFAULT_COLOR))
        # Make the focal node larger
        node_sizes.append(800 if n == apt28_id else 400)
        labels[n] = get_label(d)

    # Layout
    pos = nx.kamada_kawai_layout(subgraph)

    # Draw edges
    nx.draw_networkx_edges(
        subgraph, pos, ax=ax,
        edge_color="#cccccc", alpha=0.5, arrows=True,
        arrowsize=10, width=0.8,
        connectionstyle="arc3,rad=0.1",
    )

    # Draw nodes
    nx.draw_networkx_nodes(
        subgraph, pos, ax=ax,
        node_color=node_colors, node_size=node_sizes,
        edgecolors="#333333", linewidths=0.5, alpha=0.9,
    )

    # Draw labels
    nx.draw_networkx_labels(
        subgraph, pos, labels, ax=ax,
        font_size=7, font_family="sans-serif",
    )

    # Legend
    legend_elements = []
    types_present = {d.get("type", "unknown") for _, d in subgraph.nodes(data=True)}
    for type_name in sorted(types_present):
        if type_name in TYPE_COLORS:
            legend_elements.append(
                plt.scatter([], [], c=TYPE_COLORS[type_name], s=100, label=type_name)
            )
    ax.legend(handles=legend_elements, loc="upper left", fontsize=9, framealpha=0.8)

    focal_name = G.nodes[apt28_id].get("name", apt28_id)
    ax.set_title(f"STIX Threat Actor Neighborhood: {focal_name}", fontsize=14, pad=20)
    ax.axis("off")
    plt.tight_layout()

    # Save
    plt.savefig(OUTPUT_PATH, dpi=150, bbox_inches="tight", facecolor="white")
    print(f"Saved visualization to {OUTPUT_PATH}")
    plt.close()


if __name__ == "__main__":
    main()
