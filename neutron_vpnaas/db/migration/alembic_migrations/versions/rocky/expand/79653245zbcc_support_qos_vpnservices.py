# Copyright 2017 Eayun, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""support qos vpnservices

Revision ID: 79653245zbcc
Revises: 95601446dbcc
Create Date: 2017-04-10 10:14:41.724811

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '79653245zbcc'
down_revision = '95601446dbcc'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.ROCKY]


def upgrade():
    def upgrade():
        op.create_table(
            'qos_vpnservice_policy_bindings',
            sa.Column('vpn_service_id',
                      sa.String(length=36),
                      sa.ForeignKey('vpnservices.id', ondelete='CASCADE'),
                      nullable=False),
            sa.Column('qos_policy_id',
                      sa.String(length=36),
                      sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                      nullable=False),
            sa.PrimaryKeyConstraint('vpn_service_id', 'qos_policy_id'),
            sa.UniqueConstraint('vpn_service_id', 'qos_policy_id',
                name='vpn_service_id0qos_policy_id_constraint'))
