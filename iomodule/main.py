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
import yaml
import uuid

import iomodule.core as core
import iomodule.core.mmanager as mmanager
import iomodule.plugins.bridge as bridge
import iomodule.plugins.passthrough as passthrough

logging.basicConfig(level=logging.INFO)
app = flask.Flask(__name__)

Dumper = yaml.SafeDumper
Dumper.ignore_aliases = lambda self, data: True

with open("iomodule/schemas/core.yaml") as f:
    schema = yaml.load(f)

@app.route("/module_types/", methods=["GET"])
def get_module_types():
    "Get a list of module types\n---\n%s"
    mods = []
    for mod in [passthrough, bridge]:
        mods.append({
                "capabilities": mod.cls.capabilities(),
                "uuid": mod.cls.uuid(),
                "name": mod.cls.typename()
            })
    return flask.jsonify(data=mods)

get_module_types.__doc__ %= yaml.dump(schema["paths"]["/module_types/"]["get"], Dumper=Dumper)

@app.route("/modules/", defaults={"uuid": None}, methods=["GET"])
def module_get_all(uuid):
    "Get a list of modules\n---\n%s"
    data = []
    for k, v in iomodules.items():
        data.append({"uuid": k,
            "capabilities": v.capabilities(),
            "module_type": v.typename()})
    return flask.jsonify(data=data)

@app.route("/modules/", methods=["POST"])
def module_post():
    "Creates a new module in the system\n---\n%s"
    obj = flask.request.get_json()
    if not obj:
        raise exc.BadRequest("Expected json object")
    obj["uuid"] = str(uuid.uuid4())
    if obj["module_type"] == "Bridge":
        m = bridge.cls(mmanager=mm, name=obj["uuid"][:8])
    elif obj["module_type"] == "Passthrough":
        m = bridge.cls(mmanager=mm)
    iomodules[obj["uuid"]] = m
    return flask.jsonify(data=obj)

@app.route("/modules/<uuid>", methods=["PUT"])
def module_put(uuid):
    "Updates a module in the system\n---\n%s"
    obj = flask.request.get_json()
    if not obj:
        raise exc.BadRequest("Expected json object")
    if uuid not in iomodules:
        raise exc.BadRequest("Object %s does not exist" % uuid)

    return flask.jsonify(data={})

@app.route("/modules/<uuid>", methods=["DELETE"])
def module_delete(uuid):
    "Deletes a module from the system\n---\n%s"
    return flask.jsonify(data={})

@app.route("/modules/<uuid>", methods=["GET"])
def module_get(uuid):
    "Get a module from the system\n---\n%s"
    m = iomodules.get(uuid)
    if not m:
        raise exc.BadRequest("Object %s does not exist" % uuid)
    data = {"uuid": uuid,
            "capabilities": m.capabilities(),
            "module_type": m.typename()}
    return flask.jsonify(data=data)

module_get_all.__doc__ %= yaml.dump(schema["paths"]["/modules/"]["get"], Dumper=Dumper)
module_post.__doc__ %= yaml.dump(schema["paths"]["/modules/"]["post"], Dumper=Dumper)
module_get.__doc__ %= yaml.dump(schema["paths"]["/modules/{uuid}"]["get"], Dumper=Dumper)
module_delete.__doc__ %= yaml.dump(schema["paths"]["/modules/{uuid}"]["delete"], Dumper=Dumper)
module_put.__doc__ %= yaml.dump(schema["paths"]["/modules/{uuid}"]["put"], Dumper=Dumper)

@app.route("/connections/", defaults={"uuid": None}, methods=["GET"])
def connection_get_all(uuid):
    "Get a list of connections\n---\n%s"
    obj = flask.request.get_json()
    return flask.jsonify(data=[])

@app.route("/connections/", methods=["POST"])
def connection_post():
    "Creates a new connection in the system\n---\n%s"
    obj = flask.request.get_json()
    if not obj:
        raise exc.BadRequest("Expected json object")
    return flask.jsonify(data=[])

#@app.route("/connections/<uuid>", methods=["PUT"])
#def connection_put(uuid):
#    "Updates a module in the system\n---\n%s"
#    obj = flask.request.get_json()
#    if not obj:
#        raise exc.BadRequest("Expected json object")
#    return flask.jsonify(data={})

@app.route("/connections/<uuid>", methods=["DELETE"])
def connection_delete(uuid):
    "Deletes a connection from the system\n---\n%s"
    return flask.jsonify(data={})

@app.route("/connections/<uuid>", methods=["GET"])
def connection_get(uuid):
    "Get a connection from the system\n---\n%s"
    return flask.jsonify(data={})

connection_get_all.__doc__ %= yaml.dump(schema["paths"]["/connections/"]["get"], Dumper=Dumper)
connection_post.__doc__ %= yaml.dump(schema["paths"]["/connections/"]["post"], Dumper=Dumper)
connection_get.__doc__ %= yaml.dump(schema["paths"]["/connections/{uuid}"]["get"], Dumper=Dumper)
connection_delete.__doc__ %= yaml.dump(schema["paths"]["/connections/{uuid}"]["delete"], Dumper=Dumper)
#connection_put.__doc__ %= yaml.dump(schema["paths"]["/connections/{uuid}"]["put"], Dumper=Dumper)

# enable cors to work with petstore.swagger.io
flask.ext.cors.CORS(app)

@app.route("/spec")
def spec():
    swag = flask_swagger.swagger(app)
    swag["info"]["version"] = "0.1.0"
    swag["info"]["title"] = "IOModule Manager API"
    return flask.jsonify(swag)

mm = mmanager.ModuleManager()
iomodules = {}
try:
    app.run()
finally:
    iomodules.clear()
