"""initial_schema

Revision ID: 001
Revises: 
Create Date: 2026-02-14 20:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('password_hash', sa.String(length=256), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('email', sa.String(length=128), nullable=True),
        sa.Column('display_name', sa.String(length=128), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('is_ldap', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    # Rules table
    op.create_table('rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=128), nullable=True),
        sa.Column('src_ip', sa.String(length=64), nullable=True),
        sa.Column('dst_ip', sa.String(length=64), nullable=True),
        sa.Column('src_port', sa.Integer(), nullable=True),
        sa.Column('dst_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=10), nullable=True),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Security Events table
    op.create_table('security_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=True),
        sa.Column('destination_ip', sa.String(length=64), nullable=True),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=10), nullable=True),
        sa.Column('action', sa.String(length=20), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('anomaly_score', sa.Float(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_events_event_type'), 'security_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_security_events_source_ip'), 'security_events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_security_events_timestamp'), 'security_events', ['timestamp'], unique=False)

    # Audit Log table
    op.create_table('audit_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource', sa.String(length=128), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_log_timestamp'), 'audit_log', ['timestamp'], unique=False)
    op.create_index(op.f('ix_audit_log_username'), 'audit_log', ['username'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_log_username'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_timestamp'), table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_index(op.f('ix_security_events_timestamp'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_source_ip'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_event_type'), table_name='security_events')
    op.drop_table('security_events')
    op.drop_table('rules')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_table('users')
