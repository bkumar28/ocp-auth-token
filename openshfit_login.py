import requests
from requests_oauthlib import OAuth2Session
from urllib3.util import make_headers
from urllib.parse import parse_qs, urlencode, urlparse


class OCPLoginException(Exception):
    """The base class for the OCPLogin exceptions"""


class OCPLoginRequestException(OCPLoginException):
    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.req_info = {}
        for k, v in kwargs.items():
            self.req_info["req_" + k] = v

    def __str__(self):
        error_msg = self.msg
        for k, v in self.req_info.items():
            error_msg += "\t{0}: {1}\n".format(k, v)
        return error_msg


class OCPLogin:
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

        # Authentication Settings
        self.api_key = {}

        if api_key:
            self.api_key = api_key

        """dict to store API key(s)"""
        self.api_key_prefix = {}

        if api_key_prefix:
            self.api_key_prefix = api_key_prefix

        """SSL/TLS verification
           Set this to false to skip verify SSL certificate when calling API
           from https server.
        """
        self.verify_ssl = verify_ssl

        """Set this to customize the certificate file to verify_ssl the peer."""
        self.ssl_ca_cert = ssl_ca_cert

    def access_token(self):
        # python-requests takes either a bool or a path to a ca file as the 'verify_ssl' param
        if self.verify_ssl and self.ssl_ca_cert:
            self.verify_ssl = self.ssl_ca_cert  # path

        self.discover()

        self.token = self.login()
        self.api_key = {"authorization": "Bearer " + self.token["access_token"]}
        self.api_key_expires = self.token["expires_in"]
        self.api_key_scope = self.token["scope"]

    def discover(self):
        url = "{0}/.well-known/oauth-authorization-server".format(self.host)
        ret = requests.get(url, verify=self.verify_ssl)
        if ret.status_code != 200:
            raise OCPLoginRequestException(
                "Couldn't find OpenShift's OAuth API",
                method="GET",
                url=url,
                reason=ret.reason,
                status_code=ret.status_code,
            )

        oauth_info = ret.json()
        self.ocp_auth_endpoint = oauth_info["authorization_endpoint"]
        self.ocp_token_endpoint = oauth_info["token_endpoint"]

    def login(self):
        os_oauth = OAuth2Session(client_id="openshift-challenging-client")

        authorization_url, state = os_oauth.authorization_url(
            self.ocp_auth_endpoint, state="1", code_challenge_method="S256"
        )
        auth_headers = make_headers(
            basic_auth="{0}:{1}".format(self.ocp_username, self.ocp_password)
        )

        # Request authorization code using basic auth credentials
        ret = os_oauth.get(
            authorization_url,
            headers={
                "X-Csrf-Token": state,
                "authorization": auth_headers.get("authorization"),
            },
            verify=self.verify_ssl,
            allow_redirects=False,
        )

        if ret.status_code != 302:
            raise OCPLoginRequestException(
                "Authorization failed.",
                method="GET",
                url=authorization_url,
                reason=ret.reason,
                status_code=ret.status_code,
            )

        qwargs = {}
        for k, v in parse_qs(urlparse(ret.headers["Location"]).query).items():
            qwargs[k] = v[0]
        qwargs["grant_type"] = "authorization_code"

        # Using authorization code given to us in the Location header of the
        # previous request, request a token
        ret = os_oauth.post(
            self.ocp_token_endpoint,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                # This is just base64 encoded 'openshift-challenging-client:'
                "Authorization": "Basic b3BlbnNoaWZ0LWNoYWxsZW5naW5nLWNsaWVudDo=",
            },
            data=urlencode(qwargs),
            verify=self.verify_ssl,
        )
        if ret.status_code != 200:
            raise OCPLoginRequestException(
                "Failed to obtain an authorization token.",
                method="POST",
                url=self.ocp_token_endpoint,
                reason=ret.reason,
                status_code=ret.status_code,
            )
        return ret.json()

    def logout(self):
        url = "{0}/apis/oauth.openshift.io/v1/oauthaccesstokens/{1}".format(
            self.host, self.api_key
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(self.api_key),
        }
        json = {"apiVersion": "oauth.openshift.io/v1", "kind": "DeleteOptions"}

        requests.delete(url, headers=headers, json=json, verify=self.verify_ssl)


if __name__ == "__main__":
    initial_kwargs = {
        "ocp_username": "admin",
        "ocp_password": "admin@123"
    }
    ocp = OCPLogin(**initial_kwargs)
    ocp.access_token()
    print("---Token-----", ocp.token)
