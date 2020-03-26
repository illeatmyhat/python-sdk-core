# coding: utf-8

# Copyright 2019 IBM All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Dict, Optional

from requests import Request

from .authenticator import Authenticator
from ..iam_token_manager import IAMTokenManager
from ..utils import has_bad_first_or_last_char

class IAMAuthenticator(Authenticator):
    """The IAMAuthenticator utilizes an apikey, or client_id and client_secret pair to
    obtain a suitable bearer token, and adds it to requests.

    The bearer token will be sent as an Authorization header in the form:

        Authorization: Bearer <bearer-token>

    Args:
        apikey: The IAM api key.

    Keyword Args:
        url: The URL representing the IAM token service endpoint. If not specified, a suitable default value is used.
        client_id: The client_id and client_secret fields are used to form
            a "basic" authorization header for IAM token requests. Defaults to None.
        client_secret: The client_id and client_secret fields are used to form
            a "basic" authorization header for IAM token requests. Defaults to None.
        disable_ssl_verification: A flag that indicates whether verification of
        the server's SSL certificate should be disabled or not. Defaults to False.
        headers: Default headers to be sent with every IAM token request. Defaults to None.
        proxies: Dictionary for mapping request protocol to proxy URL. Defaults to None.
        proxies.http (optional): The proxy endpoint to use for HTTP requests.
        proxies.https (optional): The proxy endpoint to use for HTTPS requests.

    Attributes:
        token_manager (IAMTokenManager): Retrives and manages IAM tokens from the endpoint specified by the url.

    Raises:
        ValueError: The apikey, client_id, and/or client_secret are not valid for IAM token requests.
    """
    authentication_type = 'iam'

    def __init__(self,
                 apikey: str,
                 *,
                 url: Optional[str] = None,
                 client_id: Optional[str] = None,
                 client_secret: Optional[str] = None,
                 disable_ssl_verification: Optional[bool] = False,
                 headers: Optional[Dict[str, str]] = None,
                 proxies: Optional[Dict[str, str]] = None):
        self.token_manager = IAMTokenManager(
            apikey, url, client_id, client_secret, disable_ssl_verification,
            headers, proxies)
        self.validate()

    def validate(self):
        """Validates the apikey, client_id, and client_secret for IAM token requests.

        Ensure the apikey is not none, and has no bad characters. Additionally, ensure the
        both the client_id and client_secret are both set if either of them are defined.

        Raises:
            ValueError: The apikey, client_id, and/or client_secret are not valid for IAM token requests.
        """
        if self.token_manager.apikey is None:
            raise ValueError('The apikey shouldn\'t be None.')

        if has_bad_first_or_last_char(self.token_manager.apikey):
            raise ValueError(
                'The apikey shouldn\'t start or end with curly brackets or quotes. '
                'Please remove any surrounding {, }, or \" characters.')

        if (self.token_manager.client_id and
                not self.token_manager.client_secret) or (
                    not self.token_manager.client_id and
                    self.token_manager.client_secret):
            raise ValueError(
                'Both client_id and client_secret should be initialized.')

    def authenticate(self, req: Request):
        """Adds IAM authentication information to the request.

        The IAM bearer token will be added to the request's headers in the form:

            Authorization: Bearer <bearer-token>

        Args:
            req: The request to add IAM authentication information too. Must contain a key to a dictionary
            called headers.
        """
        headers = req.get('headers')
        bearer_token = self.token_manager.get_token()
        headers['Authorization'] = 'Bearer {0}'.format(bearer_token)

    def set_client_id_and_secret(self, client_id: str, client_secret: str):
        """Set the client_id and client_secret pair the token manager will use for IAM token requests.

        Args:
            client_id: The client id to be used in basic auth.
            client_secret: The client secret to be used in basic auth.

        Raises:
            ValueError: The apikey, client_id, and/or client_secret are not valid for IAM token requests.
        """
        self.token_manager.set_client_id_and_secret(client_id, client_secret)
        self.validate()

    def set_disable_ssl_verification(self, status: bool = False):
        """Set the flag that indicates whether verification of the server's SSL certificate should be
        disabled or not. Defaults to False.

        Keyword Arguments:
            status: Headers to be sent with every IAM token request. Defaults to None.
        """
        self.token_manager.set_disable_ssl_verification(status)

    def set_headers(self, headers: Dict[str, str]):
        """Headers to be sent with every IAM token request.

        Args:
            headers: Headers to be sent with every IAM token request.
        """
        self.token_manager.set_headers(headers)

    def set_proxies(self, proxies: Dict[str, str]):
        """Sets the proxies the token manager will use to communicate with IAM on behalf of the host.

        Args:
            proxies: Dictionary for mapping request protocol to proxy URL.
            proxies.http (optional): The proxy endpoint to use for HTTP requests.
            proxies.https (optional): The proxy endpoint to use for HTTPS requests.
        """
        self.token_manager.set_proxies(proxies)
