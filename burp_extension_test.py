#/usr/bin/env python3
import subprocess
from flask import Flask, request

import time

app = Flask(__name__)

@app.route("/xss2")
@app.route("/xss1")
def osi():
    return '<p> hello ' + request.args['input'] + '!<p>'

if __name__ == "__main__":
	app.run(host='127.0.0.1', port=8000)
