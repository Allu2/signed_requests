#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  json_builder.py
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
import base64
import hashlib
from urllib import quote_plus as precent_encode


class hash_params:
    def __init__(self):
        pass

    def _hash_string(self, string):
        """

        :param string:  string in query string format to be hashed, for example "a=1&b=2&c=3"
        :return: byte array(octet stream) representation of hashed string
        """
        sha = hashlib.sha256()
        sha.update(string)
        return sha.digest()

    def base64_encode(self, sha_digest):
        """

        :param sha_digest: byte array(octet stream) representation of hashed string, we base 64 encode it here
        :return: base64url_safe encode of the hash with padding removed.
        """
        return base64.urlsafe_b64encode(sha_digest).replace("=",
                                                            "")  # Note how we remove padding here, apparently everyone does.

    def _hash_list(self, param_list):
        """

        :param list: list as [["key", "value"], ["key2", "value2"]] or [("key", "value"), ("key2", "value2")]
        :return: byte array(octet stream) representation of hashed string
        """
        string = ""
        for pair in param_list:
            string += "{}={}&".format(precent_encode(pair[0]), precent_encode(pair[1]))
        string = string.rstrip("&")
        return self._hash_string(string)

    def _hash_list_and_dict(self, list, dict):
        """

        :param list: list of keys as ["key1", "key2"]
        :param dict: dict as  {"key", "value}
        :return: byte array(octet stream) representation of hashed string
        """
        string = ""
        for key in list:
            string += "{}={}&".format(precent_encode(key), precent_encode(dict[key]))
        string = string.rstrip("&")
        return self._hash_string(string)

    def hash(self, hashable, dictionary=None):
        """

        :return: base64 representation of hash
        :param hashable:
        """
        if isinstance(hashable, list) and dictionary is None:
            hash_value = self.base64_encode(self._hash_list(hashable))

        elif isinstance(hashable, str):
            hash_value = self.base64_encode(self._hash_string(hashable))
        elif isinstance(dictionary, dict):
            hash_value = self.base64_encode(self._hash_list_and_dict(hashable, dictionary))
        else:
            raise TypeError("Invalid type, only hash(hashable) supports only string, dict and list ")
        return hash_value
