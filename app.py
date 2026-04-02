from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "description": "Protege contra ataques de downgrade y fuerza el uso de HTTPS.",
        "risk_if_missing": "Alto",
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "description": "Reduce el riesgo de ataques XSS e inyección de contenido.",
        "risk_if_missing": "Alto",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "description": "Ayuda a prevenir ataques de clickjacking.",
        "risk_if_missing": "Medio",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "description": "Evita que el navegador interprete tipos MIME incorrectamente.",
        "risk_if_missing": "Medio",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "description": "Controla cuánta información de referencia se comparte.",
        "risk_if_missing": "Bajo",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "description": "Restringe el acceso a funciones sensibles del navegador.",
        "risk_if_missing": "Bajo",
    },
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def calculate_score(findings: list[dict]) -> int:
    score = 100
    for item in findings:
        if item["status"] == "missing":
            if item["risk"] == "Alto":
                score -= 20
            elif item["risk"] == "Medio":
                score -= 10
            elif item["risk"] == "Bajo":
                score -= 5
    return max(score, 0)


def overall_level(score: int) -> str:
    if score >= 85:
        return "Bueno"
    if score >= 60:
        return "Moderado"
    return "Crítico"


def analyze_url(url: str) -> dict:
    result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "security_findings": [],
        "present_headers": {},
        "score": 0,
        "overall_risk": "Desconocido",
        "errors": [],
    }

    if not is_valid_url(url):
        result["errors"].append("La URL ingresada no es válida.")
        return result

    try:
        response = requests.get(
            url,
            timeout=6,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 Security-Header-Analyzer"},
        )

        headers = response.headers
        result["final_url"] = response.url
        result["status_code"] = response.status_code

        parsed_final = urlparse(response.url)
        if parsed_final.scheme != "https":
            result["security_findings"].append({
                "header": "HTTPS",
                "status": "missing",
                "risk": "Alto",
                "message": "El sitio final no utiliza HTTPS.",
            })
        else:
            result["security_findings"].append({
                "header": "HTTPS",
                "status": "present",
                "risk": "Bajo",
                "message": "El sitio utiliza HTTPS.",
            })

        for header, meta in SECURITY_HEADERS.items():
            value = headers.get(header)
            if value:
                result["security_findings"].append({
                    "header": header,
                    "status": "present",
                    "risk": "Bajo",
                    "message": f"{meta['name']} presente.",
                })
                result["present_headers"][header] = value
            else:
                result["security_findings"].append({
                    "header": header,
                    "status": "missing",
                    "risk": meta["risk_if_missing"],
                    "message": f"{meta['name']} ausente. {meta['description']}",
                })

        result["score"] = calculate_score(result["security_findings"])
        result["overall_risk"] = overall_level(result["score"])

    except requests.exceptions.MissingSchema:
        result["errors"].append("La URL no tiene un formato válido.")
    except requests.exceptions.ConnectionError:
        result["errors"].append("No se pudo establecer conexión con el sitio.")
    except requests.exceptions.Timeout:
        result["errors"].append("La solicitud tardó demasiado en responder.")
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"Error al analizar la URL: {str(e)}")

    return result


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_url = request.form.get("url", "")
        url = normalize_url(raw_url)
        analysis = analyze_url(url)
        return render_template("resultados.html", analysis=analysis)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)