from flask import Flask, request, jsonify
import sys
import os

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

# Import SafeNet analyzer
from analyze_url import analyze


app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "message": "SafeNet AI Backend is running",
        "status": "success"
    })


@app.route("/api/analyze", methods=["POST"])
def analyze_url():

    try:
        # Get JSON data
        data = request.get_json()

        # Check if URL exists
        if not data or "url" not in data:
            return jsonify({
                "error": "URL is required"
            }), 400

        url = data["url"].strip()

        # Check empty URL
        if not url:
            return jsonify({
                "error": "URL cannot be empty"
            }), 400

        # Analyze URL using SafeNet
        result = analyze(url)

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":

    print("\n===================================")
    print("       SAFENET AI BACKEND")
    print("===================================")
    print("Server running at:")
    print("http://127.0.0.1:5000")
    print("===================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )