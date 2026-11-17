import json
import logging
import os
from datetime import datetime

from flask import Flask, abort, redirect, render_template, request, url_for

import config
from model.predict import ModelLoadError, get_status, predict_url
from utils.database import (get_dashboard_stats, get_history, get_scan,
                            init_db, save_scan)
from utils.validation import InvalidURLError

app = Flask(__name__)
init_db()
log = logging.getLogger("phishguard")

PER_PAGE = 15


def load_training_report():
    """Offline training info (NOT live scan counts). None if the report is missing."""
    try:
        with open(config.MODEL_REPORT_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; form-action 'self'; frame-ancestors 'none'")
    return response


@app.template_filter("pretty_time")
def pretty_time(value):
    """New rows hold ISO timestamps; rows from older versions are shown as stored."""
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y, %I:%M %p")
    except (TypeError, ValueError):
        return value or ""


@app.context_processor
def inject_globals():
    return {"model_status": get_status(), "app_version": config.APP_VERSION}


@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard", stats=get_dashboard_stats(),
                           training=load_training_report())


@app.route("/dashboard")
def dashboard_alias():
    return redirect(url_for("dashboard"), code=301)


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    if request.method == "POST":
        submitted = request.form.get("url", "")
        try:
            result = predict_url(submitted)
            scan_id = save_scan(result)
            # Post/Redirect/Get: refreshing the page does not re-submit the form.
            return redirect(url_for("scanner", scan=scan_id))
        except InvalidURLError as exc:
            return render_template("scanner.html", active="scanner", error=str(exc),
                                   submitted=submitted[:2048], result=None), 400
        except ModelLoadError as exc:
            return render_template("scanner.html", active="scanner", error=str(exc),
                                   submitted=submitted[:2048], result=None), 503
        except Exception:
            log.exception("Unexpected error while analysing a URL")
            return render_template("scanner.html", active="scanner",
                                   error="Something went wrong while analyzing this URL. Please try again.",
                                   submitted=submitted[:2048], result=None), 500

    result = None
    scan_id = request.args.get("scan", type=int)
    if scan_id is not None:
        row = get_scan(scan_id)
        if row is None:
            abort(404)
        details = json.loads(row["details"]) if row.get("details") else None
        result = {**row, "details": details}
    return render_template("scanner.html", active="scanner", result=result, error=None,
                           submitted=result["url"] if result else "")


@app.route("/history")
def history():
    page = max(request.args.get("page", 1, type=int), 1)
    flt = request.args.get("filter", "all")
    flt = flt if flt in ("Phishing", "Legitimate") else "all"
    rows, total = get_history(page=page, per_page=PER_PAGE, result_filter=None if flt == "all" else flt)
    pages = max((total + PER_PAGE - 1) // PER_PAGE, 1)
    return render_template("history.html", active="history", scans=rows, total=total,
                           page=page, pages=pages, filter=flt)


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", active="", code=404, title="Page not found",
                           message="The page or scan you asked for does not exist."), 404


@app.errorhandler(500)
def server_error(_):
    return render_template("error.html", active="", code=500, title="Something went wrong",
                           message="An unexpected error occurred. Details were written to the server log."), 500


if __name__ == "__main__":
    # debug is OFF by default: Flask's debugger would expose code and file paths in the browser.
    # For development only:  set FLASK_DEBUG=1
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
