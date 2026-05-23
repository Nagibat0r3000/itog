import os
import io
import uuid
import shutil
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
import crypt

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB

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

    if not crypt.validate_key(key_hex):
        return jsonify({"error": "Неверный формат ключа. Ключ должен быть 64 hex-символа (32 байта)"}), 400

    src = _save(file)
    out = src + ".enc"

    try:
        key = crypt.key_from_hex(key_hex)
        data = open(src, "rb").read()
        encrypted_data = crypt.encrypt(data, key)
        
        # Не сохраняем результат на диск — отправляем сразу из памяти
        response = send_file(
            io.BytesIO(encrypted_data),
            as_attachment=True,
            download_name=file.filename + ".enc",
            mimetype="application/octet-stream"
        )
        
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # ВАЖНО: удаляем исходный файл (результат даже не создавался на диске)
        _cleanup(src)


@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    key_hex = request.form.get("key")

    if not file:
        return jsonify({"error": "Нужен файл"}), 400
    
    if not key_hex:
        return jsonify({"error": "Нужен ключ"}), 400

    if not crypt.validate_key(key_hex):
        return jsonify({"error": "Неверный формат ключа. Ключ должен быть 64 hex-символа (32 байта)"}), 400

    src = _save(file)
    out_name = file.filename[:-4] if file.filename.endswith(".enc") else file.filename + ".dec"

    try:
        key = crypt.key_from_hex(key_hex)
        data = open(src, "rb").read()
        decrypted_data = crypt.decrypt(data, key)
        
        # Отправляем результат из памяти, без сохранения на диск
        response = send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=out_name,
            mimetype="application/octet-stream"
        )
        
        return response
    except Exception as e:
        return jsonify({"error": "Неверный ключ или повреждённый файл"}), 400
    finally:
        # Удаляем загруженный файл
        _cleanup(src)


if __name__ == "__main__":
    # Очистка папки при старте
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    print("Сервер запущен. Временные файлы не сохраняются.")
    app.run(debug=True)
