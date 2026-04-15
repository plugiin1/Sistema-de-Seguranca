import os
import json
from flask import Flask
import firebase_admin
from firebase_admin import credentials, firestore
from config import Config
from routes import auth_bp

def create_app():
    """Application Factory: Cria e configura a instância do App."""
    app = Flask(__name__)
    app.config.from_object(Config)

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
        print(f"Erro Crítico Firebase: {e}")

    # Registro de Blueprints
    app.register_blueprint(auth_bp)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc', port=5000)