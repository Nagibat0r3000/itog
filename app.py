import io
from flask import Flask, render_template, request, send_file, jsonify
import crypt

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB


@app.route("/")
def index():
    """Главная страница"""
    return render_template("index.html")


@app.route("/generate-key", methods=["POST"])
def generate_key():
    """Генерирует случайный AES-256 ключ и возвращает в hex-формате"""
    return jsonify({"key": crypt.generate_key().hex()})


def process_file(endpoint, file, key_hex):
    """
    Общая логика для шифрования и расшифровки.
    Проверяет входные данные, обрабатывает файл и возвращает результат.
    """
    if not file:
        return jsonify({"error": "Нужен файл"}), 400
    if not key_hex:
        return jsonify({"error": "Нужен ключ"}), 400

    try:
        key = crypt.key_from_hex(key_hex)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    try:
        data = file.read()
        result = endpoint(data, key)
        return send_file(
            io.BytesIO(result),
            as_attachment=True,
            download_name=file.filename
        )
    except Exception:
        return jsonify({"error": "Ошибка обработки"}), 500


@app.route("/encrypt", methods=["POST"])
def encrypt():
    """Шифрует загруженный файл"""
    file = request.files.get("file")
    key_hex = request.form.get("key")

    def operation(data, key):
        return crypt.encrypt(data, key)

    response = process_file(operation, file, key_hex)
    if isinstance(response, tuple):
        return response

    response.download_name = file.filename + ".enc"
    return response


@app.route("/decrypt", methods=["POST"])
def decrypt():
    """Расшифровывает загруженный файл (должен быть .enc)"""
    file = request.files.get("file")
    key_hex = request.form.get("key")

    def operation(data, key):
        return crypt.decrypt(data, key)

    response = process_file(operation, file, key_hex)
    if isinstance(response, tuple):
        return response

    if file.filename.endswith(".enc"):
        name = file.filename[:-4]
    else:
        name = file.filename + ".dec"
    response.download_name = name
    return response


if __name__ == "__main__":
    print("Сервер запущен. Адрес: http://127.0.0.1:5000")
    app.run(debug=True)