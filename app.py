from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import tempfile
from detector import MaliciousContentDetector

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize the detector
detector = MaliciousContentDetector()

@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/scan_file', methods=['POST'])
def scan_file():
    """Scan an uploaded file for malicious content."""
    if 'file' not in request.files:
        return jsonify({'threats': [], 'count': 0, 'error': 'No file provided'}), 200

    file = request.files['file']
    if file.filename == '':
        return jsonify({'threats': [], 'count': 0, 'error': 'No file selected'}), 200

    try:
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            file.save(temp_file.name)
            temp_filename = temp_file.name

        # Scan the file
        threats = detector.scan_file(temp_filename)

        # Clean up
        os.unlink(temp_filename)

        return jsonify({
            'threats': threats,
            'count': len(threats),
            'error': None
        })
    except Exception as e:
        return jsonify({'threats': [], 'count': 0, 'error': str(e)}), 200

@app.route('/scan_text', methods=['POST'])
def scan_text():
    """Scan text content for malicious content."""
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'threats': [], 'count': 0, 'error': 'No text provided'}), 200

    try:
        # Scan the text
        threats = detector.scan_content(data['text'])

        return jsonify({
            'threats': threats,
            'count': len(threats),
            'error': None
        })
    except Exception as e:
        return jsonify({'threats': [], 'count': 0, 'error': str(e)}), 200

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
