from flask import Flask

from flask_vouch import RotationCaptcha, Vouch

app = Flask(__name__)
vouch = Vouch(app, secret="change-me", challenge_handler=RotationCaptcha())


@app.route("/")
@vouch.challenge
def index():
    return "You passed the challenge!"


if __name__ == "__main__":
    app.run()
