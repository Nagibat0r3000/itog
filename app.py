import io
from flask import Flask, render_template, request, send_file, jsonify
import crypt

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate-key", methods=["POST"])
def generate_key():
    key_hex = crypt.generate_key().hex()
    return jsonify({"key": key_hex})


@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    key_hex = request.form.get("key")

    if not file:
        return jsonify({"error": "Нужен файл"}), 400
    
    if not key_hex:
        return jsonify({"error": "Нужен ключ"}), 400

    try:
        key = crypt.key_from_hex(key_hex)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        data = file.read()
        encrypted_data = crypt.encrypt(data, key)
        
        return send_file(
            io.BytesIO(encrypted_data),
            as_attachment=True,
            download_name=file.filename + ".enc",
            mimetype="application/octet-stream"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    key_hex = request.form.get("key")

    if not file:
        return jsonify({"error": "Нужен файл"}), 400
    
    if not key_hex:
        return jsonify({"error": "Нужен ключ"}), 400

    try:
        key = crypt.key_from_hex(key_hex)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        data = file.read()
        decrypted_data = crypt.decrypt(data, key)
        
        out_name = file.filename[:-4] if file.filename.endswith(".enc") else file.filename + ".dec"
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=out_name,
            mimetype="application/octet-stream"
        )
    except Exception:
        return jsonify({"error": "Неверный ключ или повреждённый файл"}), 400


if __name__ == "__main__":
    print("Сервер запущен. Файлы не сохраняются на диск.")
    app.run(debug=True)