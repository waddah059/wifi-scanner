from flask import Flask, render_template, request
from scanner import scan_router_network, scan_hotspot_network

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    option = request.form.get("network_type")

    if option == "router":
        devices = scan_router_network()
        return render_template("results.html", devices=devices, scan_type="Router Wi-Fi")

    elif option == "hotspot":
        devices = scan_hotspot_network()
        return render_template("results.html", devices=devices, scan_type="Phone Hotspot")

    else:
        return "Invalid option"

if __name__ == "__main__":
    app.run(debug=True)