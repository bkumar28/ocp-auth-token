import requests
from requests_oauthlib import OAuth2Session
from urllib3.util import make_headers
from urllib.parse import parse_qs, urlencode, urlparse


class OCPLoginException(Exception):
    """Base class for all OCP login-related exceptions."""


class OCPLoginRequestException(OCPLoginException):
    """Exception raised for HTTP request errors during OCP login."""

    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.req_info = {}
        for k, v in kwargs.items():
            self.req_info["req_" + k] = v

    def __str__(self):
        error_msg = self.msg
        for k, v in self.req_info.items():
            error_msg += f"\t{k}: {v}\n"
        return error_msg


class OCPLogin:
    """
    Handles OpenShift authentication and token management using OAuth2.

    Attributes:
        ocp_username (str): OpenShift username.
        ocp_password (str): OpenShift password.
        host (str): OpenShift API host URL.
        verify_ssl (bool/str): SSL verification flag or path to CA cert.
        ssl_ca_cert (str): Path to SSL certificate file.
        api_key (dict): Dictionary to store the access token.
        api_key_prefix (dict): Optional prefix for token header.
    """

    def __init__(
        self,
        ocp_username,
        ocp_password,
        verify_ssl=False,
        host="https://localhost:6443",
        api_key=None,
        api_key_prefix=None,
        ssl_ca_cert=None,
    ):
        self.ocp_username = ocp_username
        self.ocp_password = ocp_password
        self.host = host
        self.ocp_auth_endpoint = ""
        self.ocp_token_endpoint = ""

        self.api_key = api_key or {}
        self.api_key_prefix = api_key_prefix or {}

        # SSL/TLS verification settings
        self.verify_ssl = ssl_ca_cert if verify_ssl and ssl_ca_cert else verify_ssl
        self.ssl_ca_cert = ssl_ca_cert

    def access_token(self):
        """
        Retrieves an access token and stores it in the `api_key` attribute.
        """
        self.discover()
        self.token = self.login()

        self.api_key = {"authorization": f"Bearer {self.token['access_token']}"}
        self.api_key_expires = self.token["expires_in"]
        self.api_key_scope = self.token["scope"]

    def discover(self):
        """
        Discovers the OpenShift OAuth authorization and token endpoints.
        """
        url = f"{self.host}/.well-known/oauth-authorization-server"
        response = requests.get(url, verify=self.verify_ssl)

        if response.status_code != 200:
            raise OCPLoginRequestException(
                "Couldn't find OpenShift's OAuth API.",
                method="GET",
                url=url,
                reason=response.reason,
                status_code=response.status_code,
            )

        oauth_info = response.json()
        self.ocp_auth_endpoint = oauth_info["authorization_endpoint"]
        self.ocp_token_endpoint = oauth_info["token_endpoint"]

    def login(self):
        """
        Performs the OAuth2 login flow and returns the token response as JSON.
        """
        session = OAuth2Session(client_id="openshift-challenging-client")

        authorization_url, state = session.authorization_url(
            self.ocp_auth_endpoint,
            state="1",
            code_challenge_method="S256"
        )

        # Basic Auth headers for the login request
        auth_headers = make_headers(
            basic_auth=f"{self.ocp_username}:{self.ocp_password}"
        )

        # Step 1: Request authorization code
        response = session.get(
            authorization_url,
            headers={
                "X-Csrf-Token": state,
                "authorization": auth_headers.get("authorization"),
            },
            verify=self.verify_ssl,
            allow_redirects=False,
        )

        if response.status_code != 302:
            raise OCPLoginRequestException(
                "Authorization failed.",
                method="GET",
                url=authorization_url,
                reason=response.reason,
                status_code=response.status_code,
            )

        # Step 2: Extract query parameters from redirect
        query_params = parse_qs(urlparse(response.headers["Location"]).query)
        token_request_data = {
            "grant_type": "authorization_code",
            **{k: v[0] for k, v in query_params.items()}
        }

        # Step 3: Exchange code for token
        response = session.post(
            self.ocp_token_endpoint,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic b3BlbnNoaWZ0LWNoYWxsZW5naW5nLWNsaWVudDo=",
            },
            data=urlencode(token_request_data),
            verify=self.verify_ssl,
        )

        if response.status_code != 200:
            raise OCPLoginRequestException(
                "Failed to obtain an authorization token.",
                method="POST",
                url=self.ocp_token_endpoint,
                reason=response.reason,
                status_code=response.status_code,
            )

        return response.json()

    def logout(self):
        """
        Logs out the current session by deleting the access token from OpenShift.
        """
        url = f"{self.host}/apis/oauth.openshift.io/v1/oauthaccesstokens/{self.api_key}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "apiVersion": "oauth.openshift.io/v1",
            "kind": "DeleteOptions"
        }

        requests.delete(url, headers=headers, json=payload, verify=self.verify_ssl)


if __name__ == "__main__":
    # Example usage
    initial_kwargs = {
        "ocp_username": "admin",
        "ocp_password": "admin@123"
    }

    ocp = OCPLogin(**initial_kwargs)
    ocp.access_token()

    print("=== OpenShift Access Token ===")
    print("Access Token:", ocp.token.get("access_token"))
    print("Expires In:", ocp.token.get("expires_in"), "seconds")
    print("Scope:", ocp.token.get("scope"))
