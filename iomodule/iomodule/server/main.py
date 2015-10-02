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
import flask.views
import flask.ext.cors
import flask_swagger
import logging

import iomodule.plugins.bridge
import iomodule.plugins.passthrough

logging.basicConfig(level=logging.INFO)
app = flask.Flask(__name__)

import yaml
import uuid
with open("iomodule/schemas/core.yaml") as f:
    schema = yaml.load(f)
class ModuleTypeAPI(flask.views.MethodView):
    def get(self):
        "Get a list of module types\n---\n%s"
        print("In ModuletypeAPI.get()")
        return flask.jsonify(data=[{"capabilities": ["ebpf"]},
            {"uuid": str(uuid.uuid4())}])

ModuleTypeAPI.get.__doc__ %= yaml.dump(schema["paths"]["/module_types"]["get"])

module_types_view = ModuleTypeAPI.as_view("module_types")
app.add_url_rule("/module_types", view_func=module_types_view, methods=["GET"])

@app.route("/spec")
@flask.ext.cors.cross_origin()
def spec():
    swag = flask_swagger.swagger(app)
    swag["info"]["version"] = "0.1.0"
    swag["info"]["title"] = "IOModule Manager API"
    return flask.jsonify(swag)

app.run()
