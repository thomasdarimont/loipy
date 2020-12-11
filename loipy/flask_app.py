import json
import logging
import os

from flask.app import Flask
from flask.helpers import url_for
from flask_redis import FlaskRedis
from flask_session import Session
from jwkest.jwk import RSAKey, rsa_load
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from yaml import SafeLoader, load


class RedisUserinfo:
    def __init__(self, redis_client):
        self._db = redis_client

    def __getitem__(self, item):
        return json.loads(self._db.get(item))

    def __contains__(self, item):
        return self._db.exists(item)

    def get_claims_for(self, user_id, requested_claims):
        return json.loads(self._db.get(user_id))


class SimpleSubjectIdentifierFactory:
    def create_public_identifier(self, user_id):
        return user_id

    def create_pairwise_identifier(self, user_id, sector_identifier):
        raise NotImplementedError(
            "The yes® proxy does not support pairwise identifiers."
        )


def init_yes_proxy(app):
    app.redis_client = FlaskRedis(app)
    app.config.SESSION_TYPE: "redis"
    app.config.SESSION_REDIS = app.redis_client
    app.config.SESSION_PERMANENT: False

    with app.app_context():
        issuer = app.yes_proxy_config["iss"]
        authentication_endpoint = url_for("yes_proxy.authentication_endpoint")
        jwks_uri = url_for("yes_proxy.jwks_uri")
        token_endpoint = url_for("yes_proxy.token_endpoint")
        userinfo_endpoint = url_for("yes_proxy.userinfo_endpoint")

    configuration_information = {
        "issuer": issuer,
        "authorization_endpoint": authentication_endpoint,
        "jwks_uri": jwks_uri,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "scopes_supported": ["openid"]
        + list(app.yes_proxy_config["scope_to_claims_mapping"].keys()),
        "response_types_supported": ["code", "code id_token"],  # code and hybrid
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "claims_parameter_supported": True,
    }

    print(json.dumps(configuration_information, indent=2))

    userinfo_db = RedisUserinfo(app.redis_client)
    signing_key = RSAKey(key=rsa_load(app.yes_proxy_config["private_key"]), alg="RS256")
    provider = Provider(
        signing_key,
        configuration_information,
        AuthorizationState(
            SimpleSubjectIdentifierFactory(),
            access_token_lifetime=app.yes_proxy_config["user_data_expiration_seconds"],
        ),
        app.yes_proxy_config["clients"],
        userinfo_db,
    )

    return provider


def yes_proxy_init_app(name=None):
    with open(os.environ.get("LOIPY_CONFIG_FILE", "configuration.yml"), "r") as f:
        yes_proxy_config = load(f, Loader=SafeLoader)
    logging.basicConfig(level=yes_proxy_config["log_level"])

    name = name or __name__
    app = Flask(name)
    app.config.update(**yes_proxy_config["flask"])
    app.yes_proxy_config = yes_proxy_config
    Session(app)

    from .views import yes_proxy_views

    app.register_blueprint(yes_proxy_views)

    # Initialize the yes_proxy after views to be able to set correct urls
    app.provider = init_yes_proxy(app)

    return app
