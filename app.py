from flask import Flask, render_template, request, redirect, url_for
from utils.aws_logs import fetch_cloudtrail_logs
from utils.anomaly import detect_anomalies
from utils.alerts import send_alert

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("dashboard.html", logs=None, anomalies=None)

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    # Capture the credentials and region from the form
    aws_access_key = request.form.get('aws_access_key')
    aws_secret_key = request.form.get('aws_secret_key')
    region = request.form.get('region')

    if not aws_access_key or not aws_secret_key or not region:
        return redirect(url_for('index'))

    # Fetch logs using the provided credentials
    logs = fetch_cloudtrail_logs(aws_access_key, aws_secret_key, region)

    # Detect anomalies
    anomalies = [log for log in logs if detect_anomalies(log)]

    # Send email alerts if any anomalies are detected
    # if anomalies:
    #     send_alert("Anomaly Detected", f"Anomalies: {anomalies}")

    return render_template("dashboard.html", logs=logs, anomalies=anomalies)

if __name__ == "__main__":
    app.run(debug=True)
