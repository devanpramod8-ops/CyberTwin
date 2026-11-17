
import re
import hashlib
from pathlib import Path

import ipaddress
from urllib.parse import urlsplit


from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


@app.route("/")
def home():
    return render_template("index.html")


# Detect some common file formats using magic bytes
def detect_file_type(header):
    if header.startswith(b"%PDF-"):
        return "PDF Document", [".pdf"]

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image", [".png"]

    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG Image", [".jpg", ".jpeg"]

    if header.startswith((b"PK\x03\x04", b"PK\x05\x06",
                          b"PK\x07\x08")):
        return "ZIP Archive", [".zip"]

    if header.startswith(b"MZ"):
        return "Windows Executable Format", [
            ".exe", ".dll", ".sys", ".scr"
        ]

    return "Unknown", []


@app.route("/scan-file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({"error": "Please select a file"}), 400

    filename = Path(
        uploaded_file.filename.replace("\\", "/")
    ).name

    extension = Path(filename).suffix.lower()

    sha256 = hashlib.sha256()
    file_size = 0
    header = b""

    while True:
        chunk = uploaded_file.stream.read(1024 * 1024)

        if not chunk:
            break

        if not header:
            header = chunk[:16]

        sha256.update(chunk)
        file_size += len(chunk)

    detected_type, expected_extensions = detect_file_type(header)

    warnings = []

    if expected_extensions and extension not in expected_extensions:
        warnings.append(
            "File extension does not match its detected signature."
        )

    risky_extensions = {
        ".exe", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".scr", ".msi"
    }

    if extension in risky_extensions:
        warnings.append(
            "This file type can execute code. "
            "Only open it if you trust its source."
        )

    if detected_type == "Windows Executable Format":
        warnings.append(
            "Windows executable signature detected. "
            "Do not run untrusted files."
        )

    if detected_type == "Unknown":
        warnings.append(
            "File type could not be verified using "
            "the supported signatures."
        )

    return jsonify({
        "filename": filename,
        "size_bytes": file_size,
        "extension": extension or "Unknown",
        "detected_type": detected_type,
        "sha256": sha256.hexdigest(),
        "warnings": warnings,
        "status": "Analysis completed",
        "note": (
            "This is a basic static inspection, not an "
            "antivirus scan. No malware verdict is provided."
        )
    })


@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "File too large. Maximum size is 50 MB."
    }), 413


@app.route("/scan-link", methods=["POST"])
def scan_link():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not isinstance(url, str):
        return jsonify({"error": "Invalid URL"}), 400

    url = url.strip()

    if not url or len(url) > 2048:
        return jsonify({
            "error": "Enter a URL under 2048 characters."
        }), 400

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Unsupported protocol")

        hostname = parsed.hostname

        if not hostname or any(c.isspace() for c in url):
            raise ValueError("Invalid hostname")

        # Validate port number, if present
        port = parsed.port

    except ValueError:
        return jsonify({
            "error": "Enter a valid HTTP or HTTPS URL."
        }), 400

    warnings = []

    if parsed.scheme.lower() == "http":
        warnings.append(
            "This link uses HTTP instead of HTTPS. "
            "The connection is not encrypted by HTTPS."
        )

    try:
        ipaddress.ip_address(hostname)
        warnings.append(
            "The URL uses an IP address instead of a domain name."
        )
    except ValueError:
        pass

    suspicious_words = [
        "verify", "password", "urgent",
        "account", "login", "update", "secure"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        warnings.append(
            "Potentially sensitive or urgency-related terms: "
            + ", ".join(found_words)
        )

    if parsed.username is not None or "@" in parsed.netloc:
        warnings.append(
            "The URL contains user information or an @ symbol "
            "that could make its destination misleading."
        )

    if len(url) > 120:
        warnings.append(
            "The URL is unusually long."
        )

    if hostname.count(".") >= 4:
        warnings.append(
            "The hostname contains multiple subdomain levels."
        )

    return jsonify({
        "url": url,
        "domain": hostname,
        "protocol": parsed.scheme.upper(),
        "warnings": warnings,
        "status": "Analysis completed",
        "note": (
            "This is a URL structure inspection only. "
            "The destination was not visited, and "
            "no phishing or malware verdict was made."
        )
    })

@app.route("/scan-message", methods=["POST"])
def scan_message():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    message = message.strip()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    if len(message) > 10000:
        return jsonify({"error": "Message exceeds 10,000 characters."}), 400

    patterns = {
        "Urgent or threatening language": (
            r"\b(?:urgent|act now|immediately|"
            r"account (?:will be )?(?:blocked|suspended)|"
            r"final warning)\b"
        ),
        "Sensitive information request": (
            r"\b(?:password|otp|one.time password|"
            r"verification code|security code|pin)\b"
        ),
        "Prize or reward language": (
            r"\b(?:you (?:have )?won|claim your prize|"
            r"lottery|free reward|cash prize)\b"
        ),
        "Payment-related language": (
            r"\b(?:pay now|payment required|"
            r"bank account|transfer money|"
            r"update your payment)\b"
        )
    }

    findings = []

    for label, pattern in patterns.items():
        if re.search(pattern, message, re.IGNORECASE):
            findings.append(label)

    links = re.findall(
        r"https?://[^\s<>\"']+",
        message,
        re.IGNORECASE
    )

    if links:
        findings.append(
            f"Message contains {len(links)} web link(s)."
        )

    return jsonify({
        "message_length": len(message),
        "links": links,
        "warnings": findings,
        "analysis_type": "Rule-Based Message Inspection",
        "note": (
            "This is a basic text-pattern inspection. "
            "No phishing or malware verdict was made."
        )
    })


    if ai_client is None:
        return jsonify({
            "error": "AI chatbot is not configured."
        }), 503

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({
            "error": "Message must be text."
        }), 400

    message = message.strip()

    if not message:
        return jsonify({
            "error": "Please enter a question."
        }), 400

    if len(message) > 2000:
        return jsonify({
            "error": "Maximum question length is 2,000 characters."
        }), 400

    try:
        response = ai_client.responses.create(
            model="gpt-4.1-mini",
            instructions=(
                "You are CyberTwin AI Assistant, a friendly "
                "cybersecurity education and safety assistant. "
                "Explain cybersecurity concepts in simple language. "
                "Help users understand phishing, malware, passwords, "
                "suspicious messages, and security scan warnings. "
                "Provide defensive and preventive guidance. "
                "CyberTwin performs basic static file inspection, "
                "URL structure inspection, and rule-based message "
                "inspection. Never claim these checks prove that "
                "something is safe or malicious. "
                "Do not claim to have scanned anything yourself. "
                "Keep answers clear, concise, and practical."
            ),
            input=message,
            max_output_tokens=400
        )

        return jsonify({
            "reply": response.output_text
        })

    except Exception:
        app.logger.exception("AI chatbot request failed")
        return jsonify({
            "error": (
                "AI service unavailable. Check the server logs, "
                "API key, billing, and model access."
            )
        }), 502

if __name__ == "__main__":
    app.run(debug=True)
