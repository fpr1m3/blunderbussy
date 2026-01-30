"""deserialize.py - Object loader endpoint.

Accepts base64-encoded serialized Python objects from form data
and deserializes them for processing.
"""
import base64
import pickle
from flask import Blueprint, request, jsonify

bp = Blueprint('deserialize', __name__)

@bp.route('/load', methods=['POST'])
def load_object():
    data = request.form['data']
    obj = pickle.loads(base64.b64decode(request.form['data']))
    return jsonify({"type": type(obj).__name__, "value": str(obj)})
