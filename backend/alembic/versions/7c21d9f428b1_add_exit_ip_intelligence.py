"""add exit IP intelligence fields

Revision ID: 7c21d9f428b1
Revises: 4663fd393f70
Create Date: 2026-07-22 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "7c21d9f428b1"
down_revision: str | None = "4663fd393f70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vpngate_nodes",
        sa.Column("classified_exit_ip", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "vpngate_nodes",
        sa.Column("exit_country_code", sa.String(length=8), nullable=True),
    )
    op.add_column(
        "vpngate_nodes",
        sa.Column("exit_country_name", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "vpngate_nodes",
        sa.Column("exit_city", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "vpngate_nodes",
        sa.Column("intelligence_source", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "vpngate_nodes",
        sa.Column(
            "intelligence_checked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "vpngate_nodes",
        sa.Column(
            "network_classification_reasons",
            sa.JSON(),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
    )
    op.create_index(
        op.f("ix_vpngate_nodes_classified_exit_ip"),
        "vpngate_nodes",
        ["classified_exit_ip"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_vpngate_nodes_classified_exit_ip"),
        table_name="vpngate_nodes",
    )
    op.drop_column("vpngate_nodes", "network_classification_reasons")
    op.drop_column("vpngate_nodes", "intelligence_checked_at")
    op.drop_column("vpngate_nodes", "intelligence_source")
    op.drop_column("vpngate_nodes", "exit_city")
    op.drop_column("vpngate_nodes", "exit_country_name")
    op.drop_column("vpngate_nodes", "exit_country_code")
    op.drop_column("vpngate_nodes", "classified_exit_ip")
