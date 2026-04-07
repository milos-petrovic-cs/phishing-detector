from flask import Flask, render_template, request, jsonify
import os
from detector import analyze

app = Flask(__name__)

VT_API_KEY = os.getenv("VT_API_KEY", "")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_url():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()
    api_key = (data or {}).get("vt_key", "").strip() or VT_API_KEY

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        result = analyze(url, vt_api_key=api_key or None)
        return jsonify({
            "url": result.url,
            "verdict": result.verdict,
            "risk_percent": result.risk_percent,
            "score": result.score,
            "flags": result.flags,
            "virustotal": result.virustotal,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
