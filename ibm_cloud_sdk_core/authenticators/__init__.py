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
"""The ibm_cloud_sdk_core project supports the following types of authentication:

  Basic Authentication
  Bearer Token
  Identity and Access Management (IAM)
  Cloud Pak for Data
  No Authentication

  The authentication types that are appropriate for a particular service may vary from service to service.
  Each authentication type is implemented as an Authenticator for consumption by a service.

classes:
  Authenticator: Abstract Base Class. Implement this interface to provide custom authentication schemes to services.
  BasicAuthenticator: Authenticator for passing supplied basic authentication information to service endpoint.
  BearerTokenAuthenticator: Authenticator for passing supplied bearer token to service endpoint.
  CloudPakForDataAuthenticator: Authenticator for passing CP4D authentication information to service endpoint.
  IAMAuthenticator: Authenticator for passing IAM authentication information to service endpoint.
  NoAuthAuthenticator: Performs no authentication. Useful for testing purposes.

functions:
  get_authenticator_from_environment: Get authenticator from external sources.
"""

from .authenticator import Authenticator
from .basic_authenticator import BasicAuthenticator
from .bearer_token_authenticator import BearerTokenAuthenticator
from .cp4d_authenticator import CloudPakForDataAuthenticator
from .iam_authenticator import IAMAuthenticator
from .no_auth_authenticator import NoAuthAuthenticator
from ..utils import read_external_sources

def get_authenticator_from_environment(service_name: str) -> Authenticator:
    """Look for external configuration of authenticator.

    Try to get authenticator from external sources, with the following priority:
    1. Credentials file(ibm-credentials.env)
    2. Environment variables
    3. VCAP Services(Cloud Foundry)

    Args:
        service_name: The service name.

    Returns:
        The authenticator found from service information.
    """
    authenticator = None
    config = read_external_sources(service_name)
    if config:
        authenticator = _construct_authenticator(config)
    return authenticator

def _construct_authenticator(config):
    auth_type = config.get('AUTH_TYPE').lower() if config.get('AUTH_TYPE') else 'iam'
    authenticator = None

    if auth_type == 'basic':
        authenticator = BasicAuthenticator(
            username=config.get('USERNAME'),
            password=config.get('PASSWORD'))
    elif auth_type == 'bearertoken':
        authenticator = BearerTokenAuthenticator(
            bearer_token=config.get('BEARER_TOKEN'))
    elif auth_type == 'cp4d':
        authenticator = CloudPakForDataAuthenticator(
            username=config.get('USERNAME'),
            password=config.get('PASSWORD'),
            url=config.get('AUTH_URL'),
            disable_ssl_verification=config.get('AUTH_DISABLE_SSL'))
    elif auth_type == 'iam' and config.get('APIKEY'):
        authenticator = IAMAuthenticator(
            apikey=config.get('APIKEY'),
            url=config.get('AUTH_URL'),
            client_id=config.get('CLIENT_ID'),
            client_secret=config.get('CLIENT_SECRET'),
            disable_ssl_verification=config.get('AUTH_DISABLE_SSL'))
    elif auth_type == 'noauth':
        authenticator = NoAuthAuthenticator()

    return authenticator
