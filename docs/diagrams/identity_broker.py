"""Token flow as a Mermaid-style sequence diagram; the phases match section 5 of the solution design."""

from pathlib import Path

import diagrams
from common import OUT_DIR
from diagrams.k8s.compute import Pod
from diagrams.k8s.controlplane import APIServer
from diagrams.onprem.security import Vault
from matplotlib.figure import Figure
from matplotlib.image import imread
from matplotlib.patches import FancyBboxPatch, Rectangle

FONT = ["Helvetica", "Arial", "DejaVu Sans"]
ACTOR_FILL, ACTOR_EDGE = "#ececff", "#9370db"
NOTE_FILL, NOTE_EDGE = "#fff5ad", "#aaaa33"
PHASE_FILLS = ("#eef4fd", "#f6f8fb")
LINE, TEXT = "#333333", "#1f2937"

ACTORS = {
    "app": "Client app",
    "client_proxy": "Client\nVault Proxy",
    "k8s": "Kubernetes API",
    "vault": "HashiCorp Vault",
    "server_proxy": "Server\nVault Proxy",
    "mcp": "Orders MCP server",
}

# Official icons bundled with the diagrams library
ICONS = {
    "app": Pod,
    "client_proxy": Vault,
    "k8s": APIServer,
    "vault": Vault,
    "server_proxy": Vault,
    "mcp": Pod,
}

PHASES = [
    (
        "1. Proxy logs in to Vault",
        [
            ("call", "client_proxy", "vault", "auth/kubernetes login with SA token"),
            ("call", "vault", "k8s", "TokenReview"),
            ("reply", "k8s", "vault", "ServiceAccount is valid"),
            ("reply", "vault", "client_proxy", "Vault token, kept in Proxy memory"),
        ],
    ),
    (
        "2. App requests a JWT",
        [
            ("call", "app", "client_proxy", "read identity/oidc/token/mcp-orders"),
            ("call", "client_proxy", "vault", "same read + Proxy's Vault token"),
            ("reply", "vault", "client_proxy", "JWT: 5 min, aud=mcp-orders, groups"),
            ("reply", "client_proxy", "app", "JWT"),
        ],
    ),
    (
        "3. App calls the server",
        [
            ("note", "app", "Cache JWT until\n60 s before expiry"),
            ("call", "app", "mcp", "tools/call with Authorization: Bearer JWT"),
        ],
    ),
    (
        "4. Server verifies the JWT",
        [
            ("call", "mcp", "server_proxy", "read JWKS (if not cached)"),
            ("call", "server_proxy", "vault", "identity/oidc/.well-known/keys"),
            ("reply", "vault", "server_proxy", "public keys"),
            ("reply", "server_proxy", "mcp", "public keys"),
            ("note", "mcp", "Check RS256 signature,\niss, aud, exp, iat, sub"),
        ],
    ),
    (
        "5. Server authorises the tool",
        [
            ("note", "mcp", "Map groups to tools,\nthen require(tool)"),
            ("reply", "mcp", "app", "tool result, tool error or 401"),
        ],
    ),
]

MARGIN, GAP = 1.75, 3.05
ACTOR_W, ACTOR_H, TOP_ACTOR_H = 1.9, 0.72, 1.3
ICON_H = 0.5
NOTE_W = 2.65
X = {name: MARGIN + i * GAP for i, name in enumerate(ACTORS)}
WIDTH = 2 * MARGIN + GAP * (len(ACTORS) - 1)


def step_height(step: tuple) -> float:
    return 0.86 if step[0] == "note" else 0.56


def phase_height(steps: list) -> float:
    return 0.56 + sum(step_height(step) for step in steps) + 0.1


def box(ax, cx: float, cy: float, w: float, h: float, fill: str, edge: str) -> None:
    style = "round,pad=0,rounding_size=0.05"
    patch = FancyBboxPatch(
        (cx - w / 2, cy - h / 2),
        w,
        h,
        boxstyle=style,
        fc=fill,
        ec=edge,
        lw=1.3,
        zorder=4,
    )
    ax.add_patch(patch)


def actor_label(ax, name: str, y: float) -> None:
    ax.text(
        X[name], y, ACTORS[name], ha="center", va="center", fontsize=11.5,
        fontweight="bold", color=TEXT, family=FONT, zorder=5,
    )  # fmt: skip


def actor(ax, name: str, y: float) -> None:
    box(ax, X[name], y, ACTOR_W, ACTOR_H, ACTOR_FILL, ACTOR_EDGE)
    actor_label(ax, name, y)


def actor_with_icon(ax, name: str, y: float) -> None:
    box(ax, X[name], y, ACTOR_W, TOP_ACTOR_H, ACTOR_FILL, ACTOR_EDGE)
    cls = ICONS[name]
    image = imread(Path(diagrams.__file__).parent.parent / cls._icon_dir / cls._icon)
    width = ICON_H * image.shape[1] / image.shape[0]
    centre = y - 0.3
    extent = (
        X[name] - width / 2,
        X[name] + width / 2,
        centre + ICON_H / 2,
        centre - ICON_H / 2,
    )
    ax.imshow(image, extent=extent, aspect="auto", zorder=5)
    actor_label(ax, name, y + 0.3)


def message(ax, step: tuple, y: float, fill: str) -> None:
    kind, source, target, label = step
    x0, x1 = X[source], X[target]
    direction = 1 if x1 > x0 else -1
    head = 0.14
    style = (0, (4, 3)) if kind == "reply" else "solid"
    ax.plot([x0, x1 - direction * head], [y, y], color=LINE, lw=1.4, ls=style, zorder=3)
    tip = [
        (x1, y),
        (x1 - direction * head, y - 0.055),
        (x1 - direction * head, y + 0.055),
    ]
    ax.fill(*zip(*tip), color=LINE, zorder=3)
    ax.text(
        (x0 + x1) / 2, y - 0.1, label, ha="center", va="bottom", fontsize=10.5, color=TEXT,
        family=FONT, zorder=5, bbox={"fc": fill, "ec": "none", "pad": 1.2},
    )  # fmt: skip


def note(ax, step: tuple, y: float) -> None:
    _, name, label = step
    box(ax, X[name], y, NOTE_W, 0.62, NOTE_FILL, NOTE_EDGE)
    ax.text(
        X[name], y, label, ha="center", va="center", fontsize=10.5, color=TEXT,
        family=FONT, zorder=5,
    )  # fmt: skip


def main() -> None:
    top = 0.85
    first = top + TOP_ACTOR_H / 2 + 0.25
    body = sum(phase_height(steps) + 0.16 for _, steps in PHASES)
    bottom = first + body + 0.1 + ACTOR_H / 2
    height = bottom + 0.65

    fig = Figure(figsize=(WIDTH, height), dpi=170, facecolor="white")
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, WIDTH)
    ax.set_ylim(height, 0)
    ax.set_autoscale_on(False)
    ax.axis("off")

    for name in ACTORS:
        ax.plot([X[name]] * 2, [top, bottom], color="#999999", lw=1.1, zorder=2)
        actor_with_icon(ax, name, top)
        actor(ax, name, bottom)

    y = first
    for index, (title, steps) in enumerate(PHASES):
        fill = PHASE_FILLS[index % 2]
        size = phase_height(steps)
        ax.add_patch(
            Rectangle((0.2, y), WIDTH - 0.4, size, fc=fill, ec="none", zorder=1)
        )
        ax.text(
            0.34, y + 0.1, title, ha="left", va="top", fontsize=11.5, fontweight="bold",
            color=TEXT, family=FONT, zorder=5, bbox={"fc": fill, "ec": "none", "pad": 1.2},
        )  # fmt: skip
        row = y + 0.56
        for step in steps:
            row_height = step_height(step)
            centre = row + row_height / 2
            if step[0] == "note":
                note(ax, step, centre)
            else:
                message(ax, step, centre + 0.12, fill)
            row += row_height
        y += size + 0.16

    fig.savefig(OUT_DIR / "identity-broker.png", metadata={"Software": None})


main()
