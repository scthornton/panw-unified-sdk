"""Flask middleware example — scan all AI interactions.

Intercepts requests to your AI endpoint and scans prompts before they
reach your model, then scans responses before returning to the user.

Usage:
    pip install flask
    python examples/flask_middleware.py
"""

from flask import Flask, jsonify, request

from pan_ai_security import UnifiedClient
from pan_ai_security.exceptions import PanAISecurityError

app = Flask(__name__)
security = UnifiedClient()


@app.before_request
def scan_incoming_prompt():
    """Scan incoming prompts before they reach the AI model."""
    if request.path != "/api/chat" or request.method != "POST":
        return None

    data = request.get_json(silent=True) or {}
    prompt = data.get("prompt", "")

    if not prompt:
        return None

    try:
        result = security.scan(prompt=prompt)
        if result.is_blocked:
            threats = [t.threat_type for t in result.threats]
            return jsonify({
                "error": "Request blocked by AI security policy",
                "threats": threats,
                "scan_id": result.scan_id,
            }), 403
    except PanAISecurityError as e:
        app.logger.error("Security scan failed: %s", e)
        # Fail open or closed depending on your policy
        # return jsonify({"error": "Security scan unavailable"}), 503

    return None


@app.route("/api/chat", methods=["POST"])
def chat():
    """Your AI chat endpoint."""
    data = request.get_json() or {}
    prompt = data.get("prompt", "")

    # Your AI model logic here
    ai_response = f"Echo: {prompt}"

    # Scan the response before returning
    try:
        result = security.scan(prompt=prompt, response=ai_response)
        if result.is_blocked:
            return jsonify({
                "response": "I'm unable to provide that information.",
                "blocked": True,
            })
    except PanAISecurityError:
        pass  # Fail open on response scanning

    return jsonify({"response": ai_response})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
