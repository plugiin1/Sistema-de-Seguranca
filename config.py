import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv() 

class Config:
    # Chave mestra para sessões
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'chave-estática-local-segura')
    
    # Segurança de Cookies (Essencial para Cybersecurity)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Credenciais de E-mail
    EMAIL_REMETENTE = os.environ.get('EMAIL_REMETENTE', 'email_teste@gmail.com')
    SENHA_APP = os.environ.get('SENHA_APP', 'senha_teste_123')