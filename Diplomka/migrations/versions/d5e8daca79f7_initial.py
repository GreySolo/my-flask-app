"""initial

Revision ID: d5e8daca79f7
Revises: 
Create Date: 2025-04-29 20:01:25.864148

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'd5e8daca79f7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('notifications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('message', sa.String(length=255), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('is_read', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('logs')
    op.drop_table('logs_archive')
    with op.batch_alter_table('projects', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=False))
        batch_op.alter_column('id',
               existing_type=mysql.BIGINT(unsigned=True),
               type_=sa.Integer(),
               existing_nullable=False,
               autoincrement=True)
        batch_op.alter_column('created_at',
               existing_type=mysql.TIMESTAMP(),
               type_=sa.DateTime(),
               existing_nullable=True,
               existing_server_default=sa.text('CURRENT_TIMESTAMP'))
        batch_op.drop_index('id')
        batch_op.create_foreign_key(None, 'users', ['user_id'], ['id'])

    with op.batch_alter_table('requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('title', sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))
        batch_op.create_foreign_key(None, 'users', ['user_id'], ['id'])
        batch_op.drop_column('client')
        batch_op.drop_column('object')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('created_at',
               existing_type=mysql.TIMESTAMP(),
               type_=sa.DateTime(),
               existing_nullable=True,
               existing_server_default=sa.text('CURRENT_TIMESTAMP'))
        batch_op.create_unique_constraint(None, ['username'])
        batch_op.drop_column('notifications')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('notifications', mysql.TINYINT(display_width=1), server_default=sa.text("'1'"), autoincrement=False, nullable=True))
        batch_op.drop_constraint(None, type_='unique')
        batch_op.alter_column('created_at',
               existing_type=sa.DateTime(),
               type_=mysql.TIMESTAMP(),
               existing_nullable=True,
               existing_server_default=sa.text('CURRENT_TIMESTAMP'))

    with op.batch_alter_table('requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('object', mysql.VARCHAR(length=255), nullable=False))
        batch_op.add_column(sa.Column('client', mysql.VARCHAR(length=255), nullable=False))
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('created_at')
        batch_op.drop_column('user_id')
        batch_op.drop_column('title')

    with op.batch_alter_table('projects', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_index('id', ['id'], unique=True)
        batch_op.alter_column('created_at',
               existing_type=sa.DateTime(),
               type_=mysql.TIMESTAMP(),
               existing_nullable=True,
               existing_server_default=sa.text('CURRENT_TIMESTAMP'))
        batch_op.alter_column('id',
               existing_type=sa.Integer(),
               type_=mysql.BIGINT(unsigned=True),
               existing_nullable=False,
               autoincrement=True)
        batch_op.drop_column('user_id')

    op.create_table('logs_archive',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_id', mysql.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('action', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('timestamp', mysql.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.create_table('logs',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('user_id', mysql.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('action', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('timestamp', mysql.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='logs_ibfk_1'),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.drop_table('notifications')
    # ### end Alembic commands ###
