import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from login.db import get_db
from .functions import logger_register

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, firstname, lastname, project, role, verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, generate_password_hash(password), firstname, lastname, -2, 'none', 0),
                )
                db.commit()
                logger_register(f'User with username "{username}"has registered, waiting for admin approval.', 'Register')
            
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        elif user['verified'] == 0:
            error = 'Account has not been verified by admin.'
        elif user['project'] == -2 and ((user['role'] != 'admin') and (user['role'] != 'Gerente de Operaciones') and (user['role'] != 'Analista de Operaciones')):
            error = 'Account has not been assigned a project.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['role'] = user['role']
            logger_register('User with username "'+username+'", and role "'+user['role']+'" has logged in.', 'Login')
            if user['role'] == 'admin':
                return redirect(url_for('start.index'))
            elif user['role'] == 'Gerente de Operaciones':
                return redirect(url_for('start.manager_project'))
            elif user['role'] == 'Analista de Operaciones':
                return redirect(url_for('start.client_list'))
            elif (user['role'] != 'admin') and (user['role'] != 'Gerente de Operaciones') and (user['role'] != 'Analista de Operaciones'):
                return redirect(url_for('start.user_view'))

        flash(error)

    
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    logger_register('User with username "'+g.user['username']+'" and role "'+g.user['role']+'" has logged out.', 'Logout')
    session.clear()
    return redirect(url_for('auth.login'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            logger_register("An unlogged user has tried to access a page that requiered login, redirected to login.","Logger")
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

def root_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            logger_register("An unlogged user has tried to access a page that requiered login, redirected to login.",g.user['username'])
            return redirect(url_for('auth.login'))

        elif g.user['role'] != 'admin':
            logger_register('User "'+g.user['username']+'" has tried to acces a page that required admin privileges, redirected to login',"Logger")
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

def manager_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            logger_register("An unlogged user has tried to access a page that requiered login, redirected to login.",g.user['username'])
            return redirect(url_for('auth.login'))

        elif (g.user['role'] != 'admin') and (g.user['role'] != 'Gerente de Operaciones'):
            logger_register('User "'+g.user['username']+'" has tried to acces a page that required manager privileges, redirected to login',"Logger")
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

def analist_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            logger_register("An unlogged user has tried to access a page that requiered login, redirected to login.",g.user['username'])
            return redirect(url_for('auth.login'))

        elif (g.user['role'] != 'admin') and (g.user['role'] != 'Analista de Operaciones'):
            logger_register('User "'+g.user['username']+'" has tried to acces a page that required analist privileges, redirected to login',"Logger")
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view