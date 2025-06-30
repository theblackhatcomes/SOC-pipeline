from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)
ALERTS_FILE = "detected_alerts.json"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
            alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return jsonify(alerts)
        except json.JSONDecodeError:
            return jsonify([])
    return jsonify([])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 