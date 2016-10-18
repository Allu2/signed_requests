#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  json_builder.py
#
# MIT License
#
# Copyright (c) 2016 Aleksi Palomäki
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
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
