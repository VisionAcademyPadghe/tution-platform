from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/attendance', methods=['POST'])
def mark_attendance():
    data = request.json
    # Access all data sent from the frontend
    # Example: Print all attendance records
    for record in data:
        print(record)
    # Process and store attendance data
    # For demonstration, simply return success response
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)
