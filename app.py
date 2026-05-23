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
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate-key", methods=["POST"])
def generate_key():
    """Генерирует случайный ключ и возвращает его в виде hex-строки"""
    key_hex = crypt.generate_key_hex()
    return jsonify({"key": key_hex})


@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    key_hex = request.form.get("key")

    if not file:
        return jsonify({"error": "Нужен файл"}), 400
    
    if not key_hex:
        return jsonify({"error": "Нужен ключ"}), 400

    # Проверка и преобразование ключа
    if not crypt.validate_key(key_hex):
        return jsonify({"error": "Неверный формат ключа. Ключ должен быть 64 hex-символа (32 байта)"}), 400

    src = _save(file)
    out = src + ".enc"

    try:
        key = crypt.key_from_hex(key_hex)
        data = open(src, "rb").read()
        encrypted_data = crypt.encrypt(data, key)
        open(out, "wb").write(encrypted_data)
        
        # Отправляем файл и удаляем только после отправки
        response = send_file(out, as_attachment=True, download_name=file.filename + ".enc")
        
        # Удаляем временные файлы после отправки
        @response.call_on_close
        def cleanup():
            _cleanup(src, out)
        
        return response
    except Exception as e:
        _cleanup(src, out)
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    key_hex = request.form.get("key")

    if not file:
        return jsonify({"error": "Нужен файл"}), 400
    
    if not key_hex:
        return jsonify({"error": "Нужен ключ"}), 400

    # Проверка и преобразование ключа
    if not crypt.validate_key(key_hex):
        return jsonify({"error": "Неверный формат ключа. Ключ должен быть 64 hex-символа (32 байта)"}), 400

    src = _save(file)
    out_name = file.filename[:-4] if file.filename.endswith(".enc") else file.filename + ".dec"
    out = src + ".dec"

    try:
        key = crypt.key_from_hex(key_hex)
        data = open(src, "rb").read()
        decrypted_data = crypt.decrypt(data, key)
        open(out, "wb").write(decrypted_data)
        
        # Отправляем файл и удаляем только после отправки
        response = send_file(out, as_attachment=True, download_name=out_name)
        
        # Удаляем временные файлы после отправки
        @response.call_on_close
        def cleanup():
            _cleanup(src, out)
        
        return response
    except Exception as e:
        _cleanup(src, out)
        return jsonify({"error": "Неверный ключ или повреждённый файл"}), 400