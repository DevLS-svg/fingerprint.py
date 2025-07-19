import requests
from datetime import datetime

def analisar_headers(headers):
    analise = []

    if "Strict-Transport-Security" not in headers:
        analise.append("⚠️ Ausência de HSTS – vulnerável a downgrade e MITM.")
    if "X-Frame-Options" not in headers:
        analise.append("⚠️ Sem proteção contra clickjacking.")
    if "X-Content-Type-Options" not in headers or headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        analise.append("⚠️ Sem proteção contra MIME-type sniffing.")
    if "Content-Security-Policy" not in headers:
        analise.append("⚠️ Política CSP não definida – risco de XSS aumentado.")
    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
        analise.append("⚠️ CORS inseguro – origem aberta.")
    if "Server" in headers and any(char.isdigit() for char in headers["Server"]):
        analise.append(f"🔎 'Server' revela versão exata: {headers['Server']}")
    if "X-Powered-By" in headers:
        analise.append(f"🔎 'X-Powered-By' revela tecnologia: {headers['X-Powered-By']}")
    if "X-Client-IP" in headers:
        analise.append("⚠️ IP do cliente exposto via X-Client-IP.")

    return analise

def fingerprint(url):
    if not url.startswith("http"):
        url = "http://" + url
    try:
        response = requests.get(url, timeout=5)
        server = response.headers.get("Server", "Servidor não identificado")
        powered_by = response.headers.get("X-Powered-By", "Tecnologia não especificada")
        headers = response.headers

        print(f"\n📌 Informações de Fingerprinting para {url}")
        print(f"Servidor: {server}")
        print(f"Powered By: {powered_by}")
        print("\n🧾 Cabeçalhos HTTP:")
        for key, value in headers.items():
            print(f"- {key}: {value}")

        print("\n🔎 Análise de Segurança dos Headers:")
        analise = analisar_headers(headers)
        if analise:
            for item in analise:
                print(f"- {item}")
        else:
            print("✅ Nenhum problema evidente nos cabeçalhos.")

        with open("fingerprint_report.md", "w", encoding="utf-8") as f:
            f.write(f"# Relatório de Fingerprinting\n")
            f.write(f"**URL**: {url}\n")
            f.write(f"**Data**: {datetime.now()}\n")
            f.write(f"**Servidor**: {server}\n")
            f.write(f"**Powered By**: {powered_by}\n\n")
            f.write("## Cabeçalhos HTTP\n")
            for key, value in headers.items():
                f.write(f"- **{key}**: {value}\n")
            f.write("\n## Análise de Segurança dos Headers\n")
            if analise:
                for item in analise:
                    f.write(f"- {item}\n")
            else:
                f.write("✅ Nenhum problema evidente nos cabeçalhos.\n")
        print("\n✅ Relatório salvo como 'fingerprint_report.md'")

    except Exception as e:
        print(f"\n⚠️ Erro: {e}")

if __name__ == "__main__":
    alvo = input("Digite a URL alvo (ex: example.com): ")
    fingerprint(alvo)
