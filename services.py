import bcrypt
import secrets
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart # <-- Nova importação aqui
from datetime import datetime, timezone
from config import Config

class SecurityService:
    @staticmethod
    def is_password_strong(password):
        # Mínimo 8 caracteres, maiúsculas, minúsculas, números e símbolos
        regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        return re.match(regex, password) is not None

    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')

    @staticmethod
    def verify_password(password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    @staticmethod
    def generate_otp():
        return str(secrets.randbelow(900000) + 100000)

class DatabaseService:
    def __init__(self, db):
        self.db = db

    def check_duplicate(self, username, email):
        """Verifica exaustivamente se o usuário ou e-mail já existem em qualquer tabela."""
        # Verifica na coleção principal de usuários
        if self.db.collection('users').document(username).get().exists:
            return True
        
        # Verifica se o e-mail já está em uso na coleção principal
        email_query = self.db.collection('users').where('email', '==', email).limit(1).get()
        if len(email_query) > 0:
            return True

        # Verifica na 'sala de espera' (cadastros pendentes de 2FA)
        if self.db.collection('pending_users').document(username).get().exists:
            return True
        
        pending_email_query = self.db.collection('pending_users').where('email', '==', email).limit(1).get()
        if len(pending_email_query) > 0:
            return True

        return False

class EmailService:
    @staticmethod
    def get_html_template(titulo, mensagem, codigo):
        """Gera o design do e-mail em HTML"""
        return f"""
        <!DOCTYPE html>
        <html>
        <body style="background-color: #f4f4f5; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; padding: 40px 20px; margin: 0;">
            <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; padding: 40px 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
                <div style="text-align: center; margin-bottom: 25px;">
                    <h2 style="color: #111827; margin: 0; font-size: 24px;">🛡️ {titulo}</h2>
                </div>
                
                <p style="color: #4b5563; font-size: 16px; line-height: 1.6; text-align: center; margin-bottom: 30px;">
                    {mensagem}
                </p>
                
                <div style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 25px; text-align: center; margin-bottom: 30px;">
                    <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #111827;">{codigo}</span>
                </div>
                
                <p style="color: #6b7280; font-size: 14px; text-align: center; margin-bottom: 0;">
                    ⏳ Este código expira em <strong>10 minutos</strong>.
                </p>
                
                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 35px 0;">
                
                <p style="color: #9ca3af; font-size: 12px; text-align: center; margin: 0; line-height: 1.5;">
                    Se você não solicitou esta ação, por favor ignore este e-mail. Sua conta continua segura.<br><br>
                    <strong>Sistema de Autenticação Segura</strong> &copy; 2026
                </p>
            </div>
        </body>
        </html>
        """

    @staticmethod
    def send_code(destinatario, codigo, assunto):
        # descobre qual é o tipo de e-mail pelo tema
        titulo = "Alerta de Segurança"
        mensagem = "Use o código de verificação abaixo para continuar."

        if "Ative" in assunto:
            titulo = "Ativação de Conta"
            mensagem = "Bem-vindo! Para concluir seu cadastro de forma segura, use o código de verificação abaixo."
        elif "Recuperação" in assunto:
            titulo = "Recuperação de Senha"
            mensagem = "Recebemos um pedido para redefinir sua senha. Confirme sua identidade com o código abaixo."
        elif "Login" in assunto:
            titulo = "Acesso Seguro (2FA)"
            mensagem = "Identificamos uma tentativa de login na sua conta. Use o código abaixo para liberar o acesso."

        # Monta a estrutura do e-mail que aceita HTML
        msg = MIMEMultipart('alternative')
        msg['Subject'] = assunto
        msg['From'] = f"Sistema Seguro <{Config.EMAIL_REMETENTE}>" # Deixa o remetente mais bonito
        msg['To'] = destinatario

        # Gera o HTML e anexa na mensagem
        html_content = EmailService.get_html_template(titulo, mensagem, codigo)
        msg.attach(MIMEText(html_content, 'html'))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(Config.EMAIL_REMETENTE, Config.SENHA_APP)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"❌ ERRO GRAVE NO E-MAIL: {e}")
            return False