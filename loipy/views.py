import json
import pickle
from base64 import b64encode
from typing import Dict, List, Tuple
from urllib.parse import urlencode

import flask
import yes
from flask import Blueprint, current_app, jsonify, redirect, session
from flask.helpers import make_response
from oic.oic.message import (
    AuthorizationErrorResponse,
    TokenErrorResponse,
    UserInfoErrorResponse,
)
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import (
    InvalidAccessToken,
    InvalidAuthenticationRequest,
    InvalidClientAuthentication,
    OAuthError,
)
from pyop.util import should_fragment_encode

yes_proxy_views = Blueprint("yes_proxy", __name__, url_prefix="")


def make_userid(sub, iss):
    return json.dumps((sub, iss))


def map_scope(scopes: List) -> Tuple[Dict, bool]:
    """Decide which claims are to be used in the request to the yes® service
    based on one or multiple scope values in the request from the legacy
    service. Also returns a flag indicating if the second factor from the user
    should be requested (SCA)."""

    scope = None
    for s in scopes:
        if s == "openid":
            continue
        if scope is None:
            scope = s
        else:
            raise ValueError("Too many scope values.")
    if scope is None:
        raise ValueError("Missing scope value")

    try:
        claims = {
            "userinfo": current_app.yes_proxy_config["scope_to_claims_mapping"][scope]
        }
        sca = current_app.yes_proxy_config["scope_to_sca_mapping"][scope]
    except KeyError:
        raise ValueError("Scope missing from one of the internal scope mappings.")
    return claims, sca


@yes_proxy_views.route("/yes/auth", methods=["GET"])
def authentication_endpoint():
    # parse authentication request
    try:
        auth_req = current_app.provider.parse_authentication_request(
            urlencode(flask.request.args), flask.request.headers
        )
    except InvalidAuthenticationRequest as e:
        current_app.logger.debug("received invalid authn request", exc_info=True)
        error_url = e.to_error_url()
        if error_url:
            return redirect(error_url, 303)
        else:
            # show error to user
            return make_response("Something went wrong: {}".format(str(e)), 400)

    # import pdb; pdb.set_trace()
    try:
        yessession = yes.YesIdentitySession(*map_scope(auth_req.get("scope")))
    except ValueError:
        return oauth_error_response(
            auth_req,
            "invalid_scope",
            "Scope contains illegal value or too many values.",
        )
    yesflow = yes.YesIdentityFlow(current_app.yes_proxy_config["yes"], yessession)
    session["auth_req"] = pickle.dumps(auth_req)
    session["yes"] = pickle.dumps(yessession)
    ac_redirect = yesflow.start_yes_flow()
    return redirect(ac_redirect, 303)


@yes_proxy_views.route("/yes/accb", methods=["GET"])
def account_chooser_callback():
    yessession = pickle.loads(session["yes"])
    yesflow = yes.YesIdentityFlow(current_app.yes_proxy_config["yes"], yessession)
    auth_req = pickle.loads(session["auth_req"])
    try:
        authorization_endpoint_uri = yesflow.handle_ac_callback(**flask.request.args)
    except yes.YesUserCanceledError:
        return oauth_error_response(
            auth_req, "access_denied", "User canceled the bank selection."
        )
    except yes.YesUnknownIssuerError:
        return oauth_error_response(
            auth_req,
            "temporarily_unavailable",
            "The selected bank is not available.",
        )
    finally:
        session["yes"] = pickle.dumps(yessession)

    return redirect(authorization_endpoint_uri, 303)


def oauth_error_response(auth_req, oauth_error, oauth_error_description):
    response = AuthorizationErrorResponse()
    response["error"] = oauth_error
    response["error_description"] = oauth_error_description
    if "state" in auth_req:
        response["state"] = auth_req["state"]
    response_url = response.request(
        auth_req["redirect_uri"], should_fragment_encode(auth_req)
    )
    return redirect(response_url, 303)


@yes_proxy_views.route("/yes/oidccb", methods=["GET"])
def oidc_callback():
    yessession = pickle.loads(session["yes"])
    yesflow = yes.YesIdentityFlow(current_app.yes_proxy_config["yes"], yessession)
    auth_req = pickle.loads(session["auth_req"])

    try:
        yesflow.handle_oidc_callback(**flask.request.args)
    except yes.YesAccountSelectionRequested as exception:
        return redirect(exception.redirect_uri, 303)
    except yes.YesOAuthError as exception:
        return oauth_error_response(
            auth_req, exception.oauth_error, exception.oauth_error_description
        )
    finally:
        session["yes"] = pickle.dumps(yessession)

    data_id_token = yesflow.send_token_request()
    data_userinfo = yesflow.send_userinfo_request()
    userid = make_userid(data_userinfo["sub"], data_id_token["iss"])

    data_userinfo["sub"] = userid

    current_app.redis_client.set(
        userid,
        json.dumps(data_userinfo),
        ex=current_app.yes_proxy_config["user_data_expiration_seconds"],
    )
    del session["yes"]
    del session["auth_req"]
    # automagic authentication
    authn_response = current_app.provider.authorize(auth_req, userid)
    response_url = authn_response.request(
        auth_req["redirect_uri"], should_fragment_encode(auth_req)
    )
    return redirect(response_url, 303)


@yes_proxy_views.route("/.well-known/openid-configuration")
def provider_configuration():
    return jsonify(current_app.provider.provider_configuration.to_dict())


@yes_proxy_views.route("/jwks")
def jwks_uri():
    return jsonify(current_app.provider.jwks)


@yes_proxy_views.route("/yes/token", methods=["POST"])
def token_endpoint():
    try:
        token_response = current_app.provider.handle_token_request(
            flask.request.get_data().decode("utf-8"), flask.request.headers
        )
        return jsonify(token_response.to_dict())
    except InvalidClientAuthentication as e:
        current_app.logger.debug(
            "invalid client authentication at token endpoint", exc_info=True
        )
        error_resp = TokenErrorResponse(
            error="invalid_client", error_description=str(e)
        )
        response = make_response(error_resp.to_json(), 401)
        response.headers["Content-Type"] = "application/json"
        response.headers["WWW-Authenticate"] = "Basic"
        return response
    except OAuthError as e:
        current_app.logger.debug("invalid request: %s", str(e), exc_info=True)
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        response = make_response(error_resp.to_json(), 400)
        response.headers["Content-Type"] = "application/json"
        return response


@yes_proxy_views.route("/yes/userinfo", methods=["GET", "POST"])
def userinfo_endpoint():
    try:
        response = current_app.provider.handle_userinfo_request(
            flask.request.get_data().decode("utf-8"), flask.request.headers
        )
        return jsonify(response.to_dict())
    except (BearerTokenError, InvalidAccessToken) as e:
        error_resp = UserInfoErrorResponse(
            error="invalid_token", error_description=str(e)
        )
        response = make_response(error_resp.to_json(), 401)
        response.headers["WWW-Authenticate"] = AccessToken.BEARER_TOKEN_TYPE
        response.headers["Content-Type"] = "application/json"
        return response
