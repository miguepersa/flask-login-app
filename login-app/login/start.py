from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash
from login.auth import login_required
from login.auth import root_required
from login.db import get_db
from login.auth import manager_required
from .functions import logger_register

bp = Blueprint('start', __name__)
@bp.route('/start/admin/approve', methods=('POST', 'GET'))
@login_required
@root_required
def index():
    db = get_db()

    if request.method == 'POST':
        if 'approve' in request.form:
            # action of aprove button
            id = request.form['approve']
            db.execute(
                'UPDATE user SET verified = 1 WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'User with id "{id}", approved.', g.user['username'])
        elif 'reject' in request.form:
            # action of reject button
            id = request.form['reject']
            db.execute(
                'DELETE FROM user WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'User with id "{id}", rejected.', g.user['username'])
        elif 'assign_project' in request.form:
            project_description = request.form['project']
            user_id = request.form['assign_project']
            project = db.execute(
                'SELECT id FROM project WHERE description = ?',
                (project_description,)
            ).fetchone()
            if project is not None:
                db.execute(
                    'UPDATE user SET project = ? WHERE id = ?',
                    (project['id'], user_id)
                )
                db.commit()
                logger_register(f'Project "{project_description}", assigned to user id: {user_id}.', g.user['username'])
            
    db = get_db()
    users = db.execute(
        'SELECT * FROM user'
    ).fetchall()
    projects = db.execute(
        'SELECT * FROM project'
    ).fetchall()
    

    return render_template('/start/admin/approve.html', users=users, projects=projects)

@bp.route('/start/user/index.html', methods=('POST', 'GET'))
@login_required
def user_view():
    if (g.user['role'] == 'admin') or (g.user['role'] == 'Gerente de Operaciones'):
       return redirect(url_for('auth.login'))
    else:
        return render_template('/start/user/index.html')

@bp.route('/start/admin/create_project', methods=('POST', 'GET'))
@login_required
@root_required
def create_project():

    db = get_db()
    error = None

    if request.method == 'POST':
        if 'description' in request.form:
            description = request.form['description']
            init_date = request.form['init']
            end_date = request.form['end']

            if init_date > end_date:
                error = f"Init date cant be after End date."
                flash(error)
                db = get_db()
                projects = db.execute(
                    'SELECT * FROM project'
                ).fetchall()
                return render_template('/start/admin/create_project.html', projects=projects)


            try:
                db.execute(
                    "INSERT INTO project (description, init, end, status) VALUES (?, ?, ?, ?)", 
                    (description, init_date, end_date, 0),
                )
                db.commit()
                logger_register(f'Project "{description}", created.', g.user['username'])
            except db.IntegrityError:
                error = f"Project {description} is already created."
                flash(error)

        elif 'activate' in request.form:
            id = request.form['activate']
            db.execute(
                'UPDATE project SET status = 1 WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'Project with id "{id}", activated.', g.user['username'])
        elif 'deactivate' in request.form:
            id = request.form['deactivate']
            db.execute(
                'UPDATE project SET status = 0 WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'Project with id "{id}", deactivated.', g.user['username'])
        elif 'delete' in request.form:
            id = request.form['delete']
            db.execute(
                'DELETE FROM project WHERE id = ?',
                (id,)
            )
            db.execute(
                'UPDATE user SET project = -2 WHERE project = ?',
                (id,)
            )
            db.commit()
            logger_register(f'Project with id "{id}", deleted.', g.user['username'])
            logger_register(f'All users related to project with id "{id}", has been asigned with no projects.', g.user['username'])

    db = get_db()
    projects = db.execute(
        'SELECT * FROM project'
    ).fetchall()
    return render_template('/start/admin/create_project.html', projects=projects)


@bp.route('/start/manager/manager_project.html', methods=('POST', 'GET'))
@login_required
@manager_required
def manager_project():

    if (g.user['role'] != 'Gerente de Operaciones'):
       return redirect(url_for('auth.login'))
    
    db = get_db()
    error = None

    if request.method == 'POST':
        if 'description' in request.form:
            description = request.form['description']
            init_date = request.form['init']
            end_date = request.form['end']

            if init_date > end_date:
                error = f"Init date cant be after End date."
                flash(error)
                db = get_db()
                projects = db.execute(
                    'SELECT * FROM project'
                ).fetchall()
                return render_template('/start/manager/manager_project.html', projects=projects)


            try:
                db.execute(
                    "INSERT INTO project (description, init, end, status) VALUES (?, ?, ?, ?)", 
                    (description, init_date, end_date, 0),
                )
                db.commit()
                logger_register(f'Project "{description}", created.', g.user['username'])
            except db.IntegrityError:
                error = f"Project {description} is already created."
                flash(error)

        elif 'activate' in request.form:
            id = request.form['activate']
            db.execute(
                'UPDATE project SET status = 1 WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'Project with id "{id}", activated.', g.user['username'])
        elif 'deactivate' in request.form:
            id = request.form['deactivate']
            db.execute(
                'UPDATE project SET status = 0 WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'Project with id "{id}", deactivated.', g.user['username'])
        elif 'delete' in request.form:
            id = request.form['delete']
            db.execute(
                'DELETE FROM project WHERE id = ?',
                (id,)
            )
            db.execute(
                'UPDATE user SET project = -2 WHERE project = ?',
                (id,)
            )
            db.commit()
            logger_register(f'Project with id "{id}", deleted.', g.user['username'])
            logger_register(f'All users related to project with id "{id}", has been asigned with no projects.', g.user['username'])

    db = get_db()
    projects = db.execute(
        'SELECT * FROM project'
    ).fetchall()
    return render_template('/start/manager/manager_project.html', projects=projects)


@bp.route('/start/admin/create_user', methods=('POST', 'GET'))
@login_required
@root_required
def create_user():

    db = get_db()
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        role = request.form['role']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        if not firstname:
            error = 'First name is required.'
        elif not lastname:
            error = 'Last name is required.'
        elif not role:
            error = 'Role is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password, firstname, lastname, project, role, verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, generate_password_hash(password), firstname, lastname, -2, role, 1),
                )
                db.commit()
                logger_register(f'User with username "{username}", created.', g.user['username'])
            except db.IntegrityError:
                error = f"User {username} is already registered."
                flash(error)

    db = get_db()
    users = db.execute(
        'SELECT * FROM user'
    ).fetchall()
    projects = db.execute(
        'SELECT * FROM project'
    ).fetchall()
    

    return render_template('/start/admin/create_user.html', users=users, projects=projects)

@bp.route('/start/admin/modify_users.html', methods=('POST', 'GET'))
@login_required
@root_required
def modify_user():
    db = get_db()
    error = None
    
    if request.method == 'POST':
        if 'change' in request.form:
            user_id = request.form['change']
            new_role = request.form[f'role_{user_id}']
            new_project = request.form[f'project_{user_id}']
            
            db.execute(
                'UPDATE user SET role = ?, project = ? WHERE id = ?',
                (new_role, new_project, user_id)
            )
            db.commit()
            logger_register(f'User with id "{user_id}" has now role "{new_role}" and is assigned to project "new_project".', g.user['username'])
        elif 'delete' in request.form:
            id = request.form['delete']
            db.execute(
                'DELETE FROM user WHERE id = ?',
                (id,)
            )
            db.commit()
            logger_register(f'User with id "{id}"has been deleted.', g.user['username'])

    db = get_db()
    users = db.execute(
        'SELECT * FROM user'
    ).fetchall()
    projects = db.execute(
        'SELECT * FROM project'
    ).fetchall()

    # Only show one user at a time
    if request.args.get('id'):
        user_id = request.args.get('id')
        user = db.execute(
            'SELECT * FROM user WHERE id = ?',
            (user_id,)
        ).fetchone()
        if user:
            return render_template('/start/admin/modify_user.html', user=user, projects=projects)
        else:
            flash('User not found.', 'error')
    
    return render_template('/start/admin/modify_users.html', users=users, projects=projects)


@bp.route('/start/admin/logger.html', methods=('POST', 'GET'))
@login_required
@root_required
def logger_index():
    db = get_db()
    logger = db.execute(
        'SELECT * FROM logger'
    ).fetchall()

    return render_template('/start/admin/logger.html', logger = logger)
