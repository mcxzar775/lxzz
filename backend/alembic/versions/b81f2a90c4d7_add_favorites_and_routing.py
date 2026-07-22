"""add favorite nodes and connection routing policies

Revision ID: b81f2a90c4d7
Revises: 7c21d9f428b1
Create Date: 2026-07-23 01:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b81f2a90c4d7"
down_revision: str | None = "7c21d9f428b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "favorite_nodes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("node_id", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_favorite_nodes_created_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["vpngate_nodes.id"],
            name=op.f("fk_favorite_nodes_node_id_vpngate_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_favorite_nodes")),
        sa.UniqueConstraint("node_id", name=op.f("uq_favorite_nodes_node_id")),
    )
    op.create_index(
        op.f("ix_favorite_nodes_node_id"),
        "favorite_nodes",
        ["node_id"],
        unique=True,
    )
    op.add_column(
        "vpn_connections",
        sa.Column(
            "routing_mode",
            sa.String(length=32),
            server_default="AUTO",
            nullable=False,
        ),
    )
    op.add_column(
        "vpn_connections",
        sa.Column("preferred_country_code", sa.String(length=8), nullable=True),
    )
    op.create_index(
        op.f("ix_vpn_connections_routing_mode"),
        "vpn_connections",
        ["routing_mode"],
        unique=False,
    )
    op.create_index(
        op.f("ix_vpn_connections_preferred_country_code"),
        "vpn_connections",
        ["preferred_country_code"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_vpn_connections_preferred_country_code"),
        table_name="vpn_connections",
    )
    op.drop_index(
        op.f("ix_vpn_connections_routing_mode"),
        table_name="vpn_connections",
    )
    op.drop_column("vpn_connections", "preferred_country_code")
    op.drop_column("vpn_connections", "routing_mode")
    op.drop_index(op.f("ix_favorite_nodes_node_id"), table_name="favorite_nodes")
    op.drop_table("favorite_nodes")
