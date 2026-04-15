from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from markupsafe import Markup
from datetime import datetime, timedelta, timezone
import time
from services import SecurityService, DatabaseService, EmailService

# Criamos o Blueprint para as rotas de autenticação
auth_bp = Blueprint('auth', __name__)

def get_services():
    from flask import current_app
    db = current_app.config['FIREBASE_DB']
    return DatabaseService(db), SecurityService(), EmailService()

@auth_bp.route('/', methods=['GET', 'POST'])
def login():
    db_service, sec_service, mail_service = get_services()
    db = db_service.db

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')

        # FLUXO DE CADASTRO
        if action == 'register':
            email = request.form.get('email')
            confirm_password = request.form.get('confirm_password')

            if password != confirm_password:
                flash('As senhas não coincidem.', 'danger')
                return redirect(url_for('auth.login'))

            if db_service.check_duplicate(username, email):
                flash('Usuário ou e-mail já cadastrados.', 'danger')
                return redirect(url_for('auth.login'))

            if not sec_service.is_password_strong(password):
                flash('Senha fraca. Siga os requisitos de segurança.', 'danger')
                return redirect(url_for('auth.login'))

            hashed = sec_service.hash_password(password)
            codigo = sec_service.generate_otp()
            exp = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            if mail_service.send_code(email, codigo, "Ative sua conta - Sistema Seguro"):
                db.collection('pending_users').document(username).set({
                    'username': username, 'email': email, 'password_hash': hashed,
                    'codigo_2fa': codigo, 'expiracao_2fa': exp
                })
                session['temp_reg_username'] = username
                flash('Enviamos um código para o seu e-mail. Verifique para concluir!', 'info')
                return redirect(url_for('auth.ativar_conta'))
            else:
                flash('Erro ao enviar e-mail. Tente novamente.', 'danger')
                return redirect(url_for('auth.login'))

        # FLUXO DE LOGIN
        elif action == 'login':
            user_ref = db.collection('users').document(username)
            user_doc = user_ref.get()
            if user_doc.exists:
                data = user_doc.to_dict()
                if time.time() < data.get('lock_until', 0):
                    flash('Conta bloqueada temporariamente.', 'danger')
                    return render_template('login.html')

                if sec_service.verify_password(password, data['password_hash']):
                    user_ref.update({'failed_attempts': 0})
                    codigo = sec_service.generate_otp()
                    exp = datetime.now(timezone.utc) + timedelta(minutes=10)
                    user_ref.update({'codigo_2fa': codigo, 'expiracao_2fa': exp})
                    
                    mail_service.send_code(data['email'], codigo, "Código de Login")
                    session['temp_username'] = username
                    # É AQUI QUE ELE CHAMA O 2FA!
                    return redirect(url_for('auth.verify_2fa')) 
                
                falhas = data.get('failed_attempts', 0) + 1
                time.sleep(1)
                update = {'failed_attempts': falhas}
                if falhas >= 3: update['lock_until'] = time.time() + 60
                user_ref.update(update)

            flash('Credenciais inválidas.', 'danger')
    return render_template('login.html')

@auth_bp.route('/ativar_conta', methods=['GET', 'POST'])
def ativar_conta():
    if 'temp_reg_username' not in session:
        return redirect(url_for('auth.login'))
        
    db_service, sec_service, _ = get_services()
    db = db_service.db
        
    if request.method == 'POST':
        username = session['temp_reg_username']
        otp_digitado = request.form.get('otp_code')
        
        pending_ref = db.collection('pending_users').document(username)
        pending_doc = pending_ref.get()
        
        if pending_doc.exists:
            data = pending_doc.to_dict()
            if datetime.now(timezone.utc) <= data['expiracao_2fa'] and otp_digitado == data['codigo_2fa']:
                db.collection('users').document(username).set({
                    'username': data['username'], 'email': data['email'],
                    'password_hash': data['password_hash'], 'failed_attempts': 0,
                    'lock_until': 0.0, 'codigo_2fa': None, 'expiracao_2fa': None
                })
                pending_ref.delete()
                session.pop('temp_reg_username')
                flash('Conta ativada com sucesso! Você já pode fazer login.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Código incorreto ou expirado.', 'danger')
        else:
            flash('Sessão inválida.', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('ativar_conta.html')

@auth_bp.route('/2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_username' not in session:
        return redirect(url_for('auth.login'))
    
    db_service, sec_service, _ = get_services()
    db = db_service.db
    
    if request.method == 'POST':
        username = session['temp_username']
        otp_digitado = request.form.get('otp_code')
        user_ref = db.collection('users').document(username)
        user_data = user_ref.get().to_dict()
        
        codigo_salvo = user_data.get('codigo_2fa')
        expiracao = user_data.get('expiracao_2fa')
        
        if codigo_salvo and expiracao and datetime.now(timezone.utc) <= expiracao and otp_digitado == codigo_salvo:
            user_ref.update({'codigo_2fa': None, 'expiracao_2fa': None})
            session.pop('temp_username')
            session.permanent = True 
            session['username'] = username
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Código inválido ou expirado.', 'danger')
            
    return render_template('2fa.html')

@auth_bp.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    db_service, sec_service, mail_service = get_services()
    db = db_service.db

    if request.method == 'POST':
        username = request.form.get('username')
        user_ref = db.collection('users').document(username)
        user_doc = user_ref.get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            import secrets as sec
            token = sec.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(minutes=15)
            codigo = sec_service.generate_otp()
            
            mail_service.send_code(user_data['email'], codigo, "Recuperação de Senha")
            db.collection('recovery_tokens').document(token).set({
                'username': username, 'expires_at': expires, 'codigo_2fa': codigo
            })
            flash(Markup(f'Link gerado! <a href="/reset/{token}" class="alert-link text-decoration-underline fw-bold">Clique aqui</a>'), 'success')
        else:
            flash('Se o usuário existir, um link de recuperação foi gerado.', 'info') 
            
    return render_template('recuperar.html')

@auth_bp.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db_service, sec_service, _ = get_services()
    db = db_service.db
    token_ref = db.collection('recovery_tokens').document(token)
    token_doc = token_ref.get()
    
    if not token_doc.exists:
        flash('Link inválido.', 'danger')
        return redirect(url_for('auth.login'))
        
    token_data = token_doc.to_dict()
    if datetime.now(timezone.utc) > token_data['expires_at']:
        token_ref.delete()
        flash('Link expirado.', 'danger')
        return redirect(url_for('auth.recuperar'))
        
    if request.method == 'POST':
        otp_digitado = request.form.get('otp_code') 
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        username = token_data['username']
        
        if otp_digitado != token_data.get('codigo_2fa'):
            flash('Código do e-mail incorreto.', 'danger')
            return render_template('recuperar.html', reset_mode=True)
        if new_password != confirm_password:
            flash('Senhas não coincidem.', 'danger')
            return render_template('recuperar.html', reset_mode=True)
        if not sec_service.is_password_strong(new_password):
            flash('A nova senha é fraca.', 'danger')
            return render_template('recuperar.html', reset_mode=True)
        
        new_hash = sec_service.hash_password(new_password)
        db.collection('users').document(username).update({'password_hash': new_hash})
        token_ref.delete()
        flash('Senha atualizada com sucesso!', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('recuperar.html', reset_mode=True)

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Sessão encerrada.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    return render_template('dashboard.html', username=session['username'])