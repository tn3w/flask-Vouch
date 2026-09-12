"""Demo app behind the mini Vouch gate: python -m mini.app"""

from flask import Flask, g, redirect

from .vouch import Vouch

app = Flask(__name__)
app.config["SECRET_KEY"] = "development-secret-change-me"

vouch = Vouch(app, exclude=[r"^/reset$"], interactive=False)


@app.route("/")
def index():
    return f'Passed: {g.get("vouch")} <a href="/reset">challenge again</a>'


@app.route("/reset")
def reset():
    response = redirect("/")
    response.delete_cookie(vouch.options["cookie_name"], path="/")
    return response


if __name__ == "__main__":
    app.run(debug=True)
