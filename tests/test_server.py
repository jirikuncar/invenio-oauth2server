# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015, 2016 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

"""Test server views."""

from __future__ import absolute_import, print_function

from flask import url_for
from flask_principal import AnonymousIdentity

from invenio_oauth2server.models import Token


def test_user_identity_init(resource_fixture):
    """Test that user identity is loaded properly when a token is used."""
    app = resource_fixture
    with app.test_client() as client:
        # test without token (anonymous user)
        request_res = client.get(app.url_for_test0resource)
        assert request_res.status_code == 200
        assert isinstance(app.identity, AnonymousIdentity)

        # test with token
        request_res = client.get(app.url_for_test0resource_token)
        assert request_res.status_code == 200
        assert app.identity.user.id == app.user_id


def test_token_revocation(models_fixture):
    """Test that user token can not be used after revocation."""
    import base64

    app = models_fixture

    def _base64(text):
        return base64.b64encode(text.decode('utf-8')).encode('utf-8')

    auth_code = _base64(u'client_test_u1c1:client_test_u1c1')

    with app.test_client() as client:
        tok = Token.query.filter_by(
            refresh_token='dev_refresh_2').first()
        assert tok is not None

        revoke_url = '/oauth/revoke'
        args = 'token=dev_access_1'
        res = client.post(revoke_url, query_string=args, headers={
            'Authorization': 'Basic %s' % auth_code,
        })
        assert res.status_code == 200

        tok = Token.query.filter_by(
            access_token='dev_access_1').first()
        assert tok is None
