import os
import uuid
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
import crypt

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _save(file_storage) -> str:
    """Сохраняет загруженный файл, возвращает путь."""
    name = f"{uuid.uuid4().hex}_{secure_filename(file_storage.filename)}"
    path = os.path.join(UPLOAD_DIR, name)
    file_storage.save(path)
    return path


def _cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate-key", methods=["POST"])
def generate_key():
    key = crypt.generate_key()
    key_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}.key")
    with open(key_path, "wb") as f:
        f.write(key)
    return send_file(key_path, as_attachment=True, download_name="secret.key")


@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    key_file = request.files.get("key_file")

    if not file or not key_file:
        return jsonify({"error": "Нужен файл и ключ"}), 400

    src = _save(file)
    key_path = _save(key_file)
    out = src + ".enc"

    try:
        key = open(key_path, "rb").read()
        data = open(src, "rb").read()
        open(out, "wb").write(crypt.encrypt(data, key))
        return send_file(out, as_attachment=True, download_name=file.filename + ".enc")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        _cleanup(src, key_path)


@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    key_file = request.files.get("key_file")

    if not file or not key_file:
        return jsonify({"error": "Нужен файл и ключ"}), 400

    src = _save(file)
    key_path = _save(key_file)
    out_name = file.filename[:-4] if file.filename.endswith(".enc") else file.filename
    out = src + ".dec"

    try:
        key = open(key_path, "rb").read()
        data = open(src, "rb").read()
        open(out, "wb").write(crypt.decrypt(data, key))
        return send_file(out, as_attachment=True, download_name=out_name)
    except Exception as e:
        return jsonify({"error": "Неверный ключ или повреждённый файл"}), 400
    finally:
        _cleanup(src, key_path)
