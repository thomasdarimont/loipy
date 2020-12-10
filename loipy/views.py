import json
import pickle
from typing import Dict, List, Tuple
from urllib.parse import urlencode

import flask
import yes
from flask import Blueprint, current_app, jsonify, redirect, session
from flask.helpers import make_response
from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import (
    InvalidAccessToken,
    InvalidAuthenticationRequest,
    InvalidClientAuthentication,
    OAuthError,
)
from pyop.util import should_fragment_encode

yes_proxy_views = Blueprint("yes_proxy", __name__, url_prefix="")


def map_scope(scopes: List) -> Tuple[Dict, bool]:
    """Decide which claims are to be used in the request to the yes® service
    based on one or multiple scope values in the request from the legacy
    service. Also returns a flag indicating if the second factor from the user
    should be requested (SCA)."""

    for s in scopes:
        if s == "openid":
            continue
        claims = {
            "userinfo": current_app.yes_proxy_config["scope_to_claims_mapping"][s]
        }
        sca = current_app.yes_proxy_config["scope_to_sca_mapping"][s]
        return claims, sca

    raise Exception("Illegal scope value")


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

    yessession = yes.YesIdentitySession(*map_scope(auth_req.get("scope")))
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
        raise InvalidAuthenticationRequest(
            "User canceled the bank selection.", auth_req, oauth_error="access_denied"
        )
    except yes.YesUnknownIssuerError:
        raise InvalidAuthenticationRequest(
            "The selected bank is not available.",
            auth_req,
            oauth_error="temporarily_unavailable",
        )
    finally:
        session["yes"] = pickle.dumps(yessession)

    return redirect(authorization_endpoint_uri, 303)


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
        raise InvalidAuthenticationRequest(
            exception.oauth_error_description,
            auth_req,
            oauth_error=exception.oauth_error,
        )
    finally:
        session["yes"] = pickle.dumps(yessession)

    yesflow.send_token_request()
    data_userinfo = yesflow.send_userinfo_request()
    userid = data_userinfo["sub"]

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
