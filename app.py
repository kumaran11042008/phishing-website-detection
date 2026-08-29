from flask import Flask, render_template, request
import time

from database.database import (
    create_database,
    save_scan,
    get_scan_history,
    get_dashboard_stats
)
from utils.predictor import Predictor


app = Flask(__name__)


# ==========================================
# DATABASE
# ==========================================

create_database()


# ==========================================
# LOAD MACHINE LEARNING MODEL
# ==========================================

predictor = Predictor()


# ==========================================
# HOME / SCAN PAGE
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    url = ""

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            # Start scan timer
            start_time = time.time()

            # Run ML prediction
            result = predictor.predict(url)

            # Calculate scan time
            scan_time = round(time.time() - start_time, 2)

            # Add scan time to result
            result["scan_time"] = scan_time

            # ==========================================
            # SAVE SCAN TO DATABASE
            # ==========================================

            save_scan(
                url=url,
                prediction=result["prediction"],
                confidence=result["confidence"],
                risk=result["risk"],
                risk_score=result["risk_score"],
                scan_time=scan_time
            )

    stats = get_dashboard_stats()

    return render_template(
        "index.html",
        result=result,
        url=url,
        stats=stats
    )


# ==========================================
# ABOUT PAGE
# ==========================================

@app.route("/about")
def about():

    return "<h2>About - Phishing Website Detection System</h2>"


# ==========================================
# SCAN HISTORY PAGE
# ==========================================

@app.route("/history")
def history():

    scans = get_scan_history()

    return render_template(
        "history.html",
        scans=scans
    )

# ==========================================
# SECURITY DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    stats = get_dashboard_stats()

    return render_template(
        "dashboard.html",
        stats=stats
    )


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(debug=True)