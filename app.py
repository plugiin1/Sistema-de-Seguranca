import os
import json
import logging # Requisito de Auditoria
from flask import Flask
from flask_limiter import Limiter # Requisito Força Bruta
from flask_limiter.util import get_remote_address
import firebase_admin
from firebase_admin import credentials, firestore
from config import Config
from routes import auth_bp

def create_app():
    """Application Factory: Cria e configura a instância do App."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- 1. CONFIGURAÇÃO DE LOGS (Req 5.1, 5.2) ---
    # Isso cria o arquivo security_audit.log que você tem no .gitignore
    logging.basicConfig(
        filename='security_audit.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    # --- 2. PROTEÇÃO CONTRA FORÇA BRUTA (Req 1.11) ---
    # Limita o número de requisições para evitar ataques automatizados
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
    # Injetamos o limiter no config para as rotas usarem se necessário
    app.config['LIMITER'] = limiter

    # Inicialização do Firebase
    try:
        firebase_info = os.environ.get('FIREBASE_JSON')
        if firebase_info:
            cred = credentials.Certificate(json.loads(firebase_info))
        else:
            cred = credentials.Certificate("firebase-key.json")
        
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        
        # Injeta o banco de dados na configuração para os serviços usarem
        app.config['FIREBASE_DB'] = firestore.client()
    except Exception as e:
        app.logger.error(f"Erro Crítico Firebase: {e}")

    # Registro de Blueprints
    app.register_blueprint(auth_bp)

    return app

app = create_app()

if __name__ == '__main__':
    # ssl_context='adhoc' garante HTTPS local (Req 3.1)
    app.run(debug=True, ssl_context='adhoc', port=5000)