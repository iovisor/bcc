# Copyright 2015 PLUMgrid
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import flask
import flask.ext.cors
import flask.json as json
import flask.views
import flask_swagger
import werkzeug.exceptions as exc
import logging
import os
import yaml
import uuid

import iomodule.core as core
import iomodule.core.mmanager as mmanager
import iomodule.core.ifc_iomodule as ifc_iomodule
import iomodule.plugins.bridge as bridge
import iomodule.plugins.passthrough as passthrough
import iomodule.plugins.tunnel as tunnel
import iomodule.plugins.p4switch as p4switch

_dir = os.path.dirname(__file__)

logging.basicConfig(level=logging.INFO)
app = flask.Flask(__name__)

Dumper = yaml.SafeDumper
Dumper.ignore_aliases = lambda self, data: True

with open(os.path.join(_dir, "iomodule/schemas/core.yaml")) as f:
    schema = yaml.load(f)

class ModuleTypeAPI(flask.views.MethodView):
    @staticmethod
    @app.route("/module_types/", endpoint="get_module_types", methods=["GET"])
    def get():
        "Get a list of module types\n---\n%s"
        mods = []
        for mod in [passthrough, bridge, tunnel, p4switch]:
            mods.append({
                    "capabilities": mod.cls.capabilities(),
                    "uuid": mod.cls.uuid(),
                    "name": mod.cls.typename()
                })
        return flask.jsonify(data=mods)

ModuleTypeAPI.get.__doc__ %= yaml.dump(schema["paths"]["/module_types/"]["get"], Dumper=Dumper)

class ModuleAPI(flask.views.MethodView):

    @staticmethod
    @app.route("/modules/", endpoint="get_modules", defaults={"uuid": None}, methods=["GET"])
    def get_all(uuid):
        "Get a list of modules\n---\n%s"
        data = []
        for k, v in iomodules.items():
            data.append({"uuid": k,
                "capabilities": v.capabilities(),
                "module_type": v.typename()})
        return flask.jsonify(data=data)

    @staticmethod
    @app.route("/modules/", endpoint="post_module", methods=["POST"])
    def post():
        "Creates a new module in the system\n---\n%s"
        obj = flask.request.get_json()
        if not obj:
            raise exc.BadRequest("Expected json object")
        obj["uuid"] = obj.get("uuid", str(uuid.uuid4()))
        if obj["module_type"] == "Bridge":
            m = bridge.cls(mmanager=mm, name=obj["uuid"][:8],
                    config=obj.get("config"))
        elif obj["module_type"] == "Passthrough":
            m = passthrough.cls(mmanager=mm, name=obj["uuid"][:8],
                    config=obj.get("config"))
        elif obj["module_type"] == "Tunnel":
            m = tunnel.cls(mmanager=mm, name=obj["uuid"][:8],
                    config=obj.get("config"))
        elif obj["module_type"] == "P4Switch":
            m = p4switch.cls(mmanager=mm, name=obj["uuid"][:8],
                    config=obj.get("config"))
        iomodules[obj["uuid"]] = m
        return flask.jsonify(data=obj)

    @staticmethod
    @app.route("/modules/<uuid>", endpoint="put_module", methods=["PUT"])
    def put(uuid):
        "Updates a module in the system\n---\n%s"
        obj = flask.request.get_json()
        if not obj:
            raise exc.BadRequest("Expected json object")
        if uuid not in iomodules:
            raise exc.BadRequest("Object %s does not exist" % uuid)

        return flask.jsonify(data={})

    @staticmethod
    @app.route("/modules/<uuid>", endpoint="delete_module", methods=["DELETE"])
    def delete(uuid):
        "Deletes a module from the system\n---\n%s"
        return flask.jsonify(data={})

    @staticmethod
    @app.route("/modules/<uuid>", endpoint="get_module", methods=["GET"])
    def get(uuid):
        "Get a module from the system\n---\n%s"
        m = iomodules.get(uuid)
        if not m:
            raise exc.BadRequest("Object %s does not exist" % uuid)
        data = {"uuid": uuid,
                "capabilities": m.capabilities(),
                "module_type": m.typename()}
        return flask.jsonify(data=data)

ModuleAPI.get_all.__doc__ %= yaml.dump(schema["paths"]["/modules/"]["get"], Dumper=Dumper)
ModuleAPI.post.__doc__ %= yaml.dump(schema["paths"]["/modules/"]["post"], Dumper=Dumper)
ModuleAPI.get.__doc__ %= yaml.dump(schema["paths"]["/modules/{uuid}"]["get"], Dumper=Dumper)
ModuleAPI.delete.__doc__ %= yaml.dump(schema["paths"]["/modules/{uuid}"]["delete"], Dumper=Dumper)
ModuleAPI.put.__doc__ %= yaml.dump(schema["paths"]["/modules/{uuid}"]["put"], Dumper=Dumper)

class ConnectionAPI(flask.views.MethodView):
    @staticmethod
    @app.route("/connections/", endpoint="get_connections", defaults={"uuid": None}, methods=["GET"])
    def get_all(uuid):
        "Get a list of connections\n---\n%s"
        data = [{"uuid": k, "iomodules": v} for k, v in connections.items()]
        return flask.jsonify(data=data)

    @staticmethod
    @app.route("/connections/", endpoint="post_connection", methods=["POST"])
    def post():
        "Creates a new connection in the system\n---\n%s"
        obj = flask.request.get_json()
        if not obj:
            raise exc.BadRequest("Expected json object")
        obj["uuid"] = obj.get("uuid", str(uuid.uuid4()))
        if not isinstance(obj.get("iomodules"), list):
            raise exc.BadRequest("Missing iomodules[] from body")
        if len(obj["iomodules"]) != 2:
            raise exc.BadRequest("Length of iomodules[] should be exactly 2")
        ioms = [iomodules.get(m["uuid"]) for m in obj["iomodules"]]
        if not (ioms[0] and ioms[1] and ioms[0] != ioms[1]):
            raise exc.BadRequest("Malformed iomodule[]")
        ifc1 = ioms[0].ifc_lookup(obj["iomodules"][0].get("interface"))
        if not ifc1:
            ifc1 = ioms[0].ifc_create(obj["uuid"][:8],
                config=obj["iomodules"][0].get("config"))
        ifc2 = ioms[1].ifc_lookup(obj["iomodules"][1].get("interface"))
        if not ifc2:
            ifc2 = ioms[1].ifc_create(obj["uuid"][:8],
                config=obj["iomodules"][1].get("config"))
        mm.connect(ifc1, ifc2, ioms[0], ioms[1])
        connections[obj["uuid"]] = obj["iomodules"]
        return flask.jsonify(data=obj)

    #@staticmethod
    #@app.route("/connections/<uuid>", endpoint="put_connection", methods=["PUT"])
    #def put(uuid):
    #    "Updates a module in the system\n---\n%s"
    #    obj = flask.request.get_json()
    #    if not obj:
    #        raise exc.BadRequest("Expected json object")
    #    return flask.jsonify(data={})

    @staticmethod
    @app.route("/connections/<uuid>", endpoint="delete_connection", methods=["DELETE"])
    def delete(uuid):
        "Deletes a connection from the system\n---\n%s"
        return flask.jsonify(data={})

    @staticmethod
    @app.route("/connections/<uuid>", endpoint="get_connection", methods=["GET"])
    def get(uuid):
        "Get a connection from the system\n---\n%s"
        return flask.jsonify(data={})

ConnectionAPI.get_all.__doc__ %= yaml.dump(schema["paths"]["/connections/"]["get"], Dumper=Dumper)
ConnectionAPI.post.__doc__ %= yaml.dump(schema["paths"]["/connections/"]["post"], Dumper=Dumper)
ConnectionAPI.get.__doc__ %= yaml.dump(schema["paths"]["/connections/{uuid}"]["get"], Dumper=Dumper)
ConnectionAPI.delete.__doc__ %= yaml.dump(schema["paths"]["/connections/{uuid}"]["delete"], Dumper=Dumper)
#ConnectionAPI.put.__doc__ %= yaml.dump(schema["paths"]["/connections/{uuid}"]["put"], Dumper=Dumper)

# enable cors to work with petstore.swagger.io
flask.ext.cors.CORS(app)

@app.route("/spec")
def spec():
    swag = flask_swagger.swagger(app)
    swag["info"]["version"] = "0.1.0"
    swag["info"]["title"] = "IOModule Manager API"
    return flask.jsonify(swag)

@app.errorhandler(400)
def error_400(exception):
    return exception.description, 400, {"Content-Type": "text/plain"}

mm = mmanager.ModuleManager()
iomodules = {"interfaces": ifc_iomodule.cls(mmanager=mm, name="interfaces")}
connections = {}
try:
    app.run()
finally:
    del mm
    connections.clear()
    iomodules.clear()
