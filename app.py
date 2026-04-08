import os
import json
from flask import Flask, render_template, request, session, redirect, url_for, flash
import bcrypt
import secrets
import logging
import time
import re
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from markupsafe import Markup
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.permanent_session_lifetime = timedelta(minutes=30)

# --- CONFIGURAÇÕES DO E-MAIL ---
EMAIL_REMETENTE = 'jcmcs312@gmail.com'
SENHA_APP = 'pxqf aaat uewd yuwx'

# --- INICIALIZAÇÃO DO FIREBASE ---
try:
    # Tenta pegar a chave pelas variáveis de ambiente do Vercel
    firebase_json_string = os.environ.get('FIREBASE_JSON')
    
    if firebase_json_string:
        # Se achou a variável (está rodando no Vercel)
        cred_dict = json.loads(firebase_json_string)
        cred = credentials.Certificate(cred_dict)
    else:
        # Se não achou (está rodando no seu computador local)
        cred = credentials.Certificate("firebase-key.json")
        
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Erro ao conectar com o Firebase: {e}")

# --- FUNÇÕES AUXILIARES DE SEGURANÇA ---
def is_password_strong(password):
    if len(password) < 8: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[0-9]", password): return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False
    return True

def enviar_email_2fa(destinatario, codigo, assunto="Seu Código de Segurança"):
    msg = MIMEText(f"Olá!\n\nSeu código de verificação é: {codigo}\n\nEste código expira em 10 minutos.")
    msg['Subject'] = assunto
    msg['From'] = EMAIL_REMETENTE
    msg['To'] = destinatario

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL_REMETENTE, SENHA_APP)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Erro no envio do e-mail: {e}")
        return False

# --- AUTENTICAÇÃO ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_ref = db.collection('users').document(username)

        if action == 'register':
            email = request.form.get('email')
            confirm_password = request.form.get('confirm_password')
            
            if password != confirm_password:
                flash('As senhas não coincidem. Tente novamente.', 'danger')
                return redirect(url_for('login'))
                
            if not is_password_strong(password):
                flash('Sua senha é fraca. Ela deve ter no mínimo 8 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.', 'danger')
                return redirect(url_for('login'))

            if user_ref.get().exists:
                flash('Usuário já existe.', 'danger')
                return redirect(url_for('login'))

            salt = bcrypt.gensalt(rounds=12)
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            
            # GERA O CÓDIGO NO CADASTRO
            codigo = str(secrets.randbelow(900000) + 100000)
            expiracao = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            if enviar_email_2fa(email, codigo, "Ative sua conta - Sistema Seguro"):
                db.collection('pending_users').document(username).set({
                    'username': username,
                    'email': email,
                    'password_hash': hashed_pw,
                    'codigo_2fa': codigo,
                    'expiracao_2fa': expiracao
                })
                session['temp_reg_username'] = username
                flash('Enviamos um código para o seu e-mail. Verifique para concluir o cadastro!', 'info')
                return redirect(url_for('ativar_conta'))
            else:
                flash('Erro ao enviar o e-mail de verificação. Tente novamente.', 'danger')
                return redirect(url_for('login'))

        elif action == 'login':
            user_doc = user_ref.get()
            
            if user_doc.exists:
                user_data = user_doc.to_dict()
                
                if time.time() < user_data.get('lock_until', 0):
                    flash('Conta bloqueada temporariamente devido a múltiplas tentativas.', 'danger')
                    return render_template('login.html')

                saved_hash = user_data['password_hash'].encode('utf-8')
                
                if bcrypt.checkpw(password.encode('utf-8'), saved_hash):
                    user_ref.update({'failed_attempts': 0})
                    
                    # Gera código para o Login
                    codigo = str(secrets.randbelow(900000) + 100000)
                    expiracao = datetime.now(timezone.utc) + timedelta(minutes=10)
                    
                    user_ref.update({'codigo_2fa': codigo, 'expiracao_2fa': expiracao})
                    enviar_email_2fa(user_data['email'], codigo, "Código de Login - Sistema Seguro")
                    
                    session['temp_username'] = username
                    return redirect(url_for('verify_2fa'))
                else:
                    falhas = user_data.get('failed_attempts', 0) + 1
                    time.sleep(1) 
                    update_data = {'failed_attempts': falhas}
                    if falhas >= 3:
                        update_data['lock_until'] = time.time() + 60
                    user_ref.update(update_data)
                    
            flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html')

# --- VERIFICAÇÃO DE CADASTRO ---
@app.route('/ativar_conta', methods=['GET', 'POST'])
def ativar_conta():
    if 'temp_reg_username' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        username = session['temp_reg_username']
        otp_digitado = request.form.get('otp_code')
        
        pending_ref = db.collection('pending_users').document(username)
        pending_doc = pending_ref.get()
        
        if pending_doc.exists:
            data = pending_doc.to_dict()
            
            if datetime.now(timezone.utc) <= data['expiracao_2fa']:
                if otp_digitado == data['codigo_2fa']:
                    # Move para a coleção de usuários reais
                    db.collection('users').document(username).set({
                        'username': data['username'],
                        'email': data['email'],
                        'password_hash': data['password_hash'],
                        'failed_attempts': 0,
                        'lock_until': 0.0,
                        'codigo_2fa': None,
                        'expiracao_2fa': None
                    })
                    pending_ref.delete() # Remove da sala de espera
                    session.pop('temp_reg_username')
                    flash('Conta ativada com sucesso! Você já pode fazer login.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Código incorreto.', 'danger')
            else:
                pending_ref.delete()
                flash('O código expirou. Você precisa refazer o cadastro.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Dados de cadastro não encontrados. Tente novamente.', 'danger')
            return redirect(url_for('login'))

    return render_template('ativar_conta.html')

# --- 2FA (LOGIN) ---
@app.route('/2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = session['temp_username']
        otp_digitado = request.form.get('otp_code')
        
        user_ref = db.collection('users').document(username)
        user_data = user_ref.get().to_dict()
        
        codigo_salvo = user_data.get('codigo_2fa')
        expiracao = user_data.get('expiracao_2fa')
        
        if codigo_salvo and expiracao:
            if datetime.now(timezone.utc) <= expiracao:
                if otp_digitado == codigo_salvo:
                    user_ref.update({'codigo_2fa': None, 'expiracao_2fa': None})
                    session.pop('temp_username')
                    session.permanent = True 
                    session['username'] = username
                    return redirect(url_for('dashboard'))
                else:
                    flash('Código incorreto.', 'danger')
            else:
                flash('O código expirou. Faça login novamente para receber outro.', 'danger')
        else:
            flash('Nenhum código ativo encontrado. Faça login novamente.', 'danger')
            
    return render_template('2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sessão encerrada com segurança.', 'info')
    return redirect(url_for('login'))

# --- RECUPERAÇÃO DE SENHA ---
@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        username = request.form.get('username')
        user_ref = db.collection('users').document(username)
        user_doc = user_ref.get() # Busca os dados para pegar o e-mail
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            
            # Gera o token do link
            token = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(minutes=15)
            
            # Gera o código OTP e envia por e-mail
            codigo = str(secrets.randbelow(900000) + 100000)
            enviar_email_2fa(user_data['email'], codigo, "Código de Recuperação de Senha")
            
            # Salva o token E o código no banco de dados
            db.collection('recovery_tokens').document(token).set({
                'username': username,
                'expires_at': expires,
                'codigo_2fa': codigo
            })
            
            flash(Markup(f'Link gerado! <a href="/reset/{token}" class="alert-link text-decoration-underline fw-bold">Clique aqui para redefinir sua senha</a>'), 'success')
        else:
            flash('Se o usuário existir, um link foi gerado.', 'info') 
            
    return render_template('recuperar.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_ref = db.collection('recovery_tokens').document(token)
    token_doc = token_ref.get()
    
    if not token_doc.exists:
        flash('Token inválido.', 'danger')
        return redirect(url_for('login'))
        
    token_data = token_doc.to_dict()
    
    if datetime.now(timezone.utc) > token_data['expires_at']:
        token_ref.delete()
        flash('O token expirou. Solicite um novo.', 'danger')
        return redirect(url_for('recuperar'))
        
    if request.method == 'POST':
        otp_digitado = request.form.get('otp_code') 
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        username = token_data['username']
        
        # Verifica se o código do e-mail está certo
        if otp_digitado != token_data.get('codigo_2fa'):
            flash('Código de verificação incorreto.', 'danger')
            return render_template('recuperar.html', reset_mode=True)
        
        if new_password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('recuperar.html', reset_mode=True)
            
        if not is_password_strong(new_password):
            flash('A nova senha é fraca.', 'danger')
            return render_template('recuperar.html', reset_mode=True)
        
        # Se estiver certa! Atualiza a senha no banco
        salt = bcrypt.gensalt(rounds=12)
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')
        
        db.collection('users').document(username).update({'password_hash': new_hash})
        token_ref.delete()
        
        flash('Senha atualizada com sucesso!', 'success')
        return redirect(url_for('login'))
        
    return render_template('recuperar.html', reset_mode=True)

# --- ÁREA LOGADA ---
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc', port=5000)