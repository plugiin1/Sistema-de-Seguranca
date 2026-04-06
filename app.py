from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import pyotp
import secrets
import logging
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

app = Flask(__name__)
# Chave segura para as sessões do Flask
app.secret_key = secrets.token_urlsafe(32)
# Req 1.9: Sessões com tempo de expiração (30 min)
app.permanent_session_lifetime = timedelta(minutes=30)

# Configuração do Banco de Dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Req 2.6 e 2.7: Configuração de logs de auditoria
logging.basicConfig(filename='security_audit.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- CONFIGURAÇÕES DE CRIPTOGRAFIA (Req 3.4, 3.5, 3.6) ---
# CHAVE FIXA DEFINIDA PARA NÃO PERDER ACESSO AOS DADOS NO BANCO!
# Em um ambiente real, esta chave deve ser carregada de uma variável de ambiente (.env)
ENCRYPTION_KEY = b'T4x_ExemploDeChaveGeradaPeloTerminal='
ENCRYPTION_KEY = b'MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI='

# --- MODELOS DE BANCO DE DADOS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    totp_secret = db.Column(db.String(32), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.Float, default=0.0)

class RecoveryToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

# Cria as tabelas no banco de dados (se não existirem)
with app.app_context():
    db.create_all()

# --- ROTAS DE AUTENTICAÇÃO ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')

        if action == 'register':
            if User.query.filter_by(username=username).first():
                flash('Usuário já existe.', 'danger')
                return redirect(url_for('login'))

            # Req 1.1 a 1.4: Bcrypt com salt único e custo justificado (12)
            salt = bcrypt.gensalt(rounds=12)
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Req 1.5: Gerar segredo para 2FA
            totp_secret = pyotp.random_base32()
            
            new_user = User(username=username, password_hash=hashed_pw, totp_secret=totp_secret)
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'Conta criada! Anote seu código 2FA: {totp_secret}', 'success')
            return redirect(url_for('login'))

        elif action == 'login':
            user = User.query.filter_by(username=username).first()
            
            if user:
                # Req 1.11: Proteção contra força bruta
                if time.time() < user.lock_until:
                    flash('Conta bloqueada temporariamente.', 'danger')
                    return render_template('login.html')

                if bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
                    user.failed_attempts = 0
                    db.session.commit()
                    session['temp_user_id'] = user.id
                    return redirect(url_for('verify_2fa'))
                else:
                    user.failed_attempts += 1
                    time.sleep(1) # Atraso para mitigar força bruta
                    if user.failed_attempts >= 3:
                        user.lock_until = time.time() + 60
                    db.session.commit()
            flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Req 1.6: Validação do 2FA após autenticação primária
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        user = User.query.get(session['temp_user_id'])
        
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_code):
            session.pop('temp_user_id')
            session.permanent = True # Ativa a expiração
            session['user_id'] = user.id
            logging.info(f"Login bem-sucedido: {user.username}")
            return redirect(url_for('dashboard'))
        else:
            flash('Código 2FA inválido.', 'danger')
            
    return render_template('2fa.html')

@app.route('/logout')
def logout():
    # Req 1.10: Invalidação de sessão no logout
    session.clear()
    flash('Sessão encerrada com segurança.', 'info')
    return redirect(url_for('login'))

# --- ROTAS DE RECUPERAÇÃO DE SENHA ---

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Req 2.2 e 2.3: Gera token seguro com expiração de 15 min
            token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(minutes=15)
            
            novo_token = RecoveryToken(token=token, user_id=user.id, expires_at=expires)
            db.session.add(novo_token)
            db.session.commit()
            
            logging.info(f"Req 2.6: Solicitação de recuperação gerada para {username}")
            flash(f'Acesse este link para resetar: https://127.0.0.1:5000/reset/{token}', 'success')
        else:
            flash('Se o usuário existir, um link foi gerado.', 'info') 
            
    return render_template('recuperar.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    recovery = RecoveryToken.query.filter_by(token=token).first()
    
    if not recovery:
        logging.error("Req 2.7: Falha - Tentativa com token inexistente.")
        flash('Token inválido.', 'danger')
        return redirect(url_for('login'))
        
    # Req 2.5: Falha correta para token expirado
    if datetime.now() > recovery.expires_at:
        db.session.delete(recovery)
        db.session.commit()
        logging.error(f"Req 2.7: Falha - Token expirado.")
        flash('O token expirou. Solicite um novo.', 'danger')
        return redirect(url_for('recuperar'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        user = User.query.get(recovery.user_id)
        
        salt = bcrypt.gensalt(rounds=12)
        user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        
        # Req 2.4: Deleta o token após o uso
        db.session.delete(recovery)
        db.session.commit()
        
        logging.info(f"Req 2.7: Sucesso - Senha alterada para ID {user.id}")
        flash('Senha atualizada com sucesso!', 'success')
        return redirect(url_for('login'))
        
    return render_template('recuperar.html', reset_mode=True)

# --- ÁREA LOGADA ---

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    mensagem = ""

    if request.method == 'POST':
        dado_sensivel = request.form.get('dado_sensivel')
        # Req 3.4 e 3.5: Criptografia em repouso (AES)
        user.encrypted_data = cipher_suite.encrypt(dado_sensivel.encode('utf-8'))
        db.session.commit()
        mensagem = "Dado salvo de forma segura no Banco de Dados!"

    dado_descriptografado = ""
    if user.encrypted_data:
        dado_descriptografado = cipher_suite.decrypt(user.encrypted_data).decode('utf-8')

    return render_template('dashboard.html', 
                           username=user.username, 
                           dado_salvo=user.encrypted_data,
                           dado_limpo=dado_descriptografado,
                           mensagem=mensagem)

if __name__ == '__main__':
    # Print customizado para o terminal
    print("\n" + "="*55)
    print("🚀 SISTEMA DE SEGURANÇA INICIADO COM SUCESSO!")
    print("👉 SEGURE 'CTRL' E CLIQUE NO LINK ABAIXO PARA ACESSAR:")
    print("🔗 https://127.0.0.1:5000/")
    print("="*55 + "\n")
    
    # Req 3.1, 3.2 e 3.3: Comunicação HTTPS (TLS)
    app.run(debug=True, ssl_context='adhoc', port=5000)