# fingerprint.py
Ferramenta em Python para fingerprinting ético e análise de headers HTTP. Detecta práticas inseguras (como ausência de HSTS, CSP e X-Frame-Options) e gera relatório técnico em Markdown para responsible disclosure.
markdown
# 🔍 fingerprint_basic.py – Fingerprinting Ético com Análise de Headers

Ferramenta simples e eficaz criada por **DevLS**, para coleta e análise de cabeçalhos HTTP com foco em segurança da informação e responsible disclosure.

---

## 🧠 Funcionalidades

- Faz requisição HTTP a partir de uma URL alvo
- Coleta e exibe cabeçalhos HTTP
- Detecta automaticamente configurações inseguras
- Gera relatório em **Markdown** com todos os dados
- Identifica práticas ausentes como HSTS, CSP, X-Frame-Options, entre outras

---

## 📦 Requisitos

Instale o Python e a biblioteca `requests`:

```bash
# Termux (Android)
pkg install python

# Windows ou Linux
pip install requests
🚀 Uso
bash
python fingerprint_basic.py
Digite a URL alvo como solicitado (ex: example.com) e aguarde a análise.

📁 Saída
📝 Relatório gerado: fingerprint_report.md

Contém:

Cabeçalhos HTTP coletados

Análise técnica de segurança

Possíveis vetores de ataque passivos

⚔️ Exemplo de saída
bash
📌 Informações de Fingerprinting para http://example.com
Servidor: Apache/2.4.29
Powered By: PHP/5.6

🧾 Cabeçalhos HTTP:
- Server: Apache/2.4.29
- X-Powered-By: PHP/5.6
...

🔎 Análise de Segurança dos Headers:
- ⚠️ Ausência de HSTS – vulnerável a downgrade e MITM.
- ⚠️ Sem proteção contra clickjacking.
- ⚠️ Política CSP não definida – risco de XSS aumentado.
...
🙌 Propósito Ético
Esta ferramenta foi criada com o único objetivo de auxiliar profissionais de segurança e promover a responsible disclosure, ajudando administradores de sistemas e sites a corrigirem falhas que poderiam ser exploradas por agentes maliciosos.

Nenhum dado sensível é coletado. Apenas cabeçalhos públicos obtidos via requisição HTTP padrão.

🧭 Juramento da Ética Hacker
Reconheço que, com grande conhecimento, vem grande responsabilidade. Comprometo-me a usar minhas habilidades para proteger, nunca para prejudicar. Jamais explorarei vulnerabilidades para ganho pessoal ou com intenção maliciosa. Reportarei falhas de forma responsável, respeitando a privacidade e a legalidade. Acredito no livre acesso à informação, na transparência e na melhoria da sociedade por meio da tecnologia. Sou um hacker — não para quebrar, mas para construir. Agirei sempre com integridade, curiosidade e honra.

Desenvolvido por: DevLS ///Certificações: Solyd, Desec, TryHackMe.
