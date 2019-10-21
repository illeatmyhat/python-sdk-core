from .authenticators import Authenticator, BasicAuthenticator, BearerTokenAuthenticator, CloudPakForDataAuthenticator, IAMAuthenticator, NoAuthAuthenticator
from .utils import read_external_sources

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
