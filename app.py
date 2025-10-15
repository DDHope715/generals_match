import os
import requests
from flask import Flask, render_template, jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-secret")

# ---------------- Web 路由 ----------------
@app.get("/")
def index():
    return render_template("index.html")

@app.route('/stats')
def get_stats():
    try:
        response = requests.get('https://generals.io/api/replaysForUsername?u=mashiro&offset=0&count=200')
        response.raise_for_status()
        replays = response.json()

        wins = 0
        loses = 0

        for replay in replays:
            if replay.get('type') == 'custom':
                ranking = replay.get('ranking', [])
                if ranking and ranking[0].get('name') == 'mashiro':
                    wins += 1
                else:
                    loses += 1

        return jsonify({'wins': wins, 'loses': loses})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
