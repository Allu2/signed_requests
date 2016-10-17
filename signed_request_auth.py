#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  signed_request_auth.py
#  
#  Copyright 2016 Aleksi Palomäki <aleksi.ajp@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  
__author__ = "Aleksi Palomäki"
import time
import urlparse
from json import dumps
from requests.auth import AuthBase

from jwcrypto import jws

from json_builder import hash_params


class SignedRequest(AuthBase):
    def generate_authorization_header(self):
        # print(dumps(self.json_structure, indent=2))
        """
        Generates the actual PoP token and the string for Authorization header
        :return:
        """
        token = jws.JWS(dumps(self.json_structure).encode("utf-8"))
        token.add_signature(key=self.sign_key, alg=self.alg, header=self.header, protected=self.protected)
        authorization_header = "PoP {}".format(token.serialize(compact=True))
        return authorization_header

    def __init__(self,
                 token=None,  # Required
                 sign_method=False,
                 sign_url=False,
                 sign_path=False,
                 sign_query=False,
                 sign_header=False,
                 sign_body=False,
                 key=None,  # Required
                 alg=None,
                 protected=None,
                 header=None):

        """

        :param token:  Token for the "at" field                             (Required)
        :param sign_method: Do we add method to the signed part?            (Optional)
        :param sign_url: Do we add url to the signed part?                  (Optional)
        :param sign_path: Do we add path to the signed part?                (Optional)
        :param sign_query: Do we add query parameters to the signed part?   (Optional)
        :param sign_header: Do we add headers to the signed part?           (Optional)
        :param sign_body: Do we add content of body to the signed part?     (Optional)
        :param key: JWK used to sign the signed part                        (Required)
        :param alg: Algorithm used in key (Defaults to HS256)               (Optional)
        :param protected: Protected field for the signing                   (Optional)
        :param header: Header part for the signing                          (Optional)
        """
        if alg is None:
            if protected is None and header is None:
                header = dumps({"typ": "JWS",
                                "alg": "HS256"})

        self.sign_method = sign_method
        self.sign_url = sign_url
        self.sign_path = sign_path
        self.sign_query = sign_query
        self.sign_header = sign_header
        self.sign_body = sign_body

        self.sign_key = key
        self.alg = alg
        self.header = header
        self.protected = protected

        if self.sign_key is None:
            raise TypeError("Key can't be type None.")

        self.json_structure = {
            "at": token,  # Required
            "ts": time.time()  # Optional but Recommended.
        }

    def __call__(self, r):
        """

        :param r: PreparedRequest object
        :return: PreparedRequest object
        """
        hasher = hash_params()
        # print(r.__dict__)

        if self.sign_query:
            params = urlparse.parse_qsl(urlparse.urlparse(r.url).query)
            # print(params)
            keys = []
            for item in params:
                keys.append(item[0])
            hash = hasher.hash(params)
            self.json_structure["q"] = [keys, hash]  # 'q' for query
        auth_header_has_content = r.headers.get("Authorization", False)
        if auth_header_has_content:  # TODO: Naive attempt to consider existing stuff in Authorization, I need to read more about requests to know if this could work.
            r.headers['Authorization'] = "{},{}".format(self.generate_authorization_header(),
                                                        r.headers['Authorization']).rstrip(",")
        else:
            r.headers['Authorization'] = self.generate_authorization_header()
        print(r.headers)
        return r
