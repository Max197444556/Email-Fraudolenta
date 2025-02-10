from flask import Flask, request, render_template
import numpy as np
import re
import requests
from urllib.parse import urlparse
import socket
import ssl
from html.parser import HTMLParser
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import logging

app = Flask(__name__)

# Configura il logging
logging.basicConfig(level=logging.DEBUG)

# Lista di domini legittimi
WHITELIST_DOMAINS = ["ingv.it", "terremoti.ingv.it", "google.com", "amazon.com", "microsoft.com"]

# Liste di domini sospetti
SHORTENED_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly"]
PHISHING_DOMAINS = ["fake-amazon.com", "phishing-site.com", "secure-login.net"]
MALICIOUS_DOMAINS = ["injuredexpulsion.net"]

# Funzione per addestrare un modello dummy
def create_dummy_model():
    emails = [
        "Congratulations! You've won a $1000 gift card. Click here to claim your prize: http://fakewebsite.com",
        "Hi, can we schedule a meeting for tomorrow?",
        "Your account has been compromised. Please reset your password immediately: http://phishing-site.com",
        "Reminder: Your appointment is at 3 PM today.",
        "Your Amazon Prime payment failed. Click <a href='http://fake-amazon.com'>here</a> to update your payment method.",
        "Your Amazon order has been shipped. Track your package here: https://amazon.com/tracking."
    ]
    labels = [1, 0, 1, 0, 1, 0]  # 1 = fraudolenta, 0 = legittima

    vectorizer = TfidfVectorizer()
    X_tfidf = vectorizer.fit_transform(emails).toarray()

    link_counts = [len(re.findall(r'https?://[^\s]+', email)) for email in emails]
    grammar_errors = [check_grammar(email) for email in emails]
    sender_scores = [analyze_sender("no-reply@amazon.com") for _ in emails]
    hidden_links = [detect_hidden_links(email) for email in emails]
    suspicious_domains = [analyze_link_domains(email) for email in emails]
    suspicious_text = [detect_suspicious_text(email) for email in emails]

    # Combina le feature correttamente
    X_combined = np.hstack((X_tfidf, np.array(link_counts).reshape(-1, 1), np.array(grammar_errors).reshape(-1, 1), np.array(sender_scores).reshape(-1, 1), np.array(hidden_links).reshape(-1, 1), np.array(suspicious_domains).reshape(-1, 1), np.array(suspicious_text).reshape(-1, 1))

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_combined, labels)

    return model, vectorizer

# Funzione per controllare errori grammaticali
def check_grammar(text):
    blob = TextBlob(text)
    return len(blob.correct().split()) - len(text.split())

# Funzione per analizzare il dominio del mittente
def analyze_sender(sender):
    if not sender:
        return 0  # Se il mittente non è fornito, consideralo legittimo

    # Domini sospetti
    suspicious_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    domain = sender.split("@")[-1] if "@" in sender else ""

    # Se il dominio è sospetto, restituisci 1 (pericoloso), altrimenti 0 (legittimo)
    return 1 if domain in suspicious_domains else 0

# Funzione per rilevare pulsanti con link nascosti
def detect_hidden_links(text):
    return len(re.findall(r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\']', text))

# Funzione per analizzare i domini dei link
def analyze_link_domains(text):
    links = re.findall(r'https?://[^\s]+', text)
    return sum(1 for link in links if urlparse(link).netloc in SHORTENED_DOMAINS or urlparse(link).netloc in PHISHING_DOMAINS)

# Funzione per rilevare testo sospetto intorno ai link
def detect_suspicious_text(text):
    suspicious_phrases = ["clicca qui", "aggiorna ora", "verifica subito", "azione richiesta"]
    return sum(1 for phrase in suspicious_phrases if phrase in text.lower())

# Funzione per controllare link malevoli
def check_malicious_link(link):
    domain = urlparse(link).netloc
    logging.debug(f"Analisi del dominio: {domain}")

    # Verifica se il dominio o un suo sottodominio è nella whitelist
    for whitelist_domain in WHITELIST_DOMAINS:
        if domain.endswith(whitelist_domain):
            logging.debug(f"Dominio {domain} trovato nella whitelist.")
            return False

    # Verifica se il dominio è sospetto
    if domain in MALICIOUS_DOMAINS:
        logging.debug(f"Dominio {domain} trovato nella lista dei domini malevoli.")
        return True

    # Verifica i domini accorciati
    if "tinyurl.com" in domain:
        try:
            response = requests.head(link, allow_redirects=True)
            final_url = response.url
            final_domain = urlparse(final_url).netloc
            if final_domain in PHISHING_DOMAINS or final_domain in MALICIOUS_DOMAINS:
                logging.debug(f"Dominio {domain} è un URL accorciato che punta a un dominio sospetto.")
                return True
        except Exception as e:
            logging.error(f"Errore durante il controllo dell'URL accorciato: {e}")

    # Verifica il dominio su VirusTotal
    if check_virustotal(domain):
        logging.debug(f"Dominio {domain} segnalato come malevolo da VirusTotal.")
        return True

    logging.debug(f"Dominio {domain} considerato sicuro.")
    return False

# Funzione per verificare il certificato SSL
def check_ssl_certificate(link):
    try:
        domain = urlparse(link).netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True
    except Exception:
        return False

# Funzione per preprocessare e analizzare un'email
def process_email(email_text, sender):
    try:
        processed_text = email_text.lower()
        tfidf_features = vectorizer.transform([processed_text]).toarray()
        link_count = len(re.findall(r'https?://[^\s]+', email_text))
        grammar_errors = check_grammar(email_text)
        sender_score = analyze_sender(sender)
        hidden_links = detect_hidden_links(email_text)
        suspicious_domains = analyze_link_domains(email_text)
        suspicious_text = detect_suspicious_text(email_text)

        links = re.findall(r'https?://[^\s]+', email_text)
        malicious_links = []
        for link in links:
            if check_malicious_link(link):
                malicious_links.append(link)
            else:
                webpage_analysis = analyze_webpage_content(link)
                if webpage_analysis.get("is_suspicious", False):
                    malicious_links.append(link)
                if not check_ssl_certificate(link):
                    malicious_links.append(link)

        features = np.hstack((tfidf_features, np.array([[link_count, grammar_errors, sender_score, hidden_links, suspicious_domains, suspicious_text]])))

        return features, malicious_links
    except Exception as e:
        logging.error(f"Errore durante il processamento dell'email: {e}")
        return None, []

# Crea il modello e il vectorizer
model, vectorizer = create_dummy_model()

# Pagina principale
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    try:
        if request.method == 'POST':
            email_text = request.form.get('email_text', '')
            sender = request.form.get('sender', '')
            action = request.form.get('action', '')

            logging.debug(f"Email text: {email_text}")
            logging.debug(f"Sender: {sender}")
            logging.debug(f"Action: {action}")

            if action == "analyze_sender":
                sender_score = analyze_sender(sender)
                if sender_score == 1:
                    result = {
                        "status": "fraud",
                        "message": "Risultato: <strong>MITTENTE PERICOLOSO</strong>",
                        "links": []
                    }
                else:
                    result = {
                        "status": "safe",
                        "message": "Risultato: <strong>MITTENTE LEGITTIMO</strong>",
                        "links": []
                    }
            else:
                features, malicious_links = process_email(email_text, sender)
                prediction = model.predict(features)[0]

                if prediction == 1 or malicious_links:
                    result = {
                        "status": "fraud",
                        "message": "Risultato: <strong>FRAUDOLENTA</strong>",
                        "links": malicious_links
                    }
                else:
                    result = {
                        "status": "safe",
                        "message": "Risultato: <strong>LEGITTIMA</strong>",
                        "links": []
                    }
    except Exception as e:
        logging.error(f"Errore durante l'analisi: {e}")
        result = {
            "status": "error",
            "message": f"Errore durante l'analisi: {str(e)}",
            "links": []
        }

    return render_template('index.html', result=result)

# Avvia l'app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)