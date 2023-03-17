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
from login.auth import analist_required
import re

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


@bp.route('/start/manager/modify_project.html', methods=('POST', 'GET'))
@login_required
@manager_required
def modify_project():

    db = get_db()
    error = None
    project_id = request.args.get('id')
    if project_id is None:
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        if 'description' in request.form:
            description = request.form['description']
            init_date = request.form['init']
            end_date = request.form['end']
            try:
                db.execute(
                    'UPDATE project SET description = ?, init = ?, end = ? WHERE id = ?',
                    (description, init_date, end_date, project_id)
                )
                db.commit()
                logger_register(f"Project with id {project_id} updated in database.", g.user['username'])
                db = get_db()
                if g.user['role'] == 'admin':
                    return redirect(url_for('start.create_project'))
                else:
                    return redirect(url_for('start.manager_project'))
            except db.IntegrityError:
                error = f"Project with id {project_id} could not be updated in database."
                flash(error)
    
    project = db.execute(
        'SELECT * FROM project WHERE id = ?', (project_id,)
    ).fetchall()
    return render_template('/start/manager/modify_project.html', project=project)


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

@bp.route('/start/analist/client_register.html', methods=('POST', 'GET'))
@login_required
@analist_required
def client_list():
    db = get_db()
    if 'dni' in request.form:
        err = 0
        dni = request.form['dni']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        birthdate = request.form['birthdate']
        phone = request.form['phone'].replace(' ','')
        email = request.form['email']
        address = request.form['address']

        if re.match(r"^(V|J|E)-\d+$", dni):
            pass
        else:
            error = f"DNI not valid, must start with V-, E- or J-, followed up by the corresponding numbers."
            flash(error)
            err = 1
        if re.match(r'^[\d()+-]+$', phone):
            pass
        else:
            error = f"Phone number not valid."
            flash(error)
            err = 1
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            pass
        else:
            error = f"Email not valid."
            flash(error)
            err = 1

        if err == 0:
            try:
                db.execute(
                    "INSERT INTO client (dni, firstname, lastname, birthdate, phone, email, address) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                    (dni, firstname, lastname, birthdate, phone, email, address),
                )
                db.commit()
                logger_register(f'Client "{firstname}'+' '+'{lastname}", created.', g.user['username'])
            except db.IntegrityError:
                error = f"Client with dni {dni} is already created."
                flash(error)

            db = get_db()
            clients = db.execute(
                'SELECT * FROM client'
            ).fetchall()

            return render_template('/start/analist/client_register.html', clients=clients)
        
    elif 'delete' in request.form:
        client_id = request.form['delete']
        # Retrieve the DNI of the client that has been deleted
        client = db.execute(
            'SELECT dni FROM client WHERE id = ?',
            (client_id,)
        ).fetchone()
        if client:
            dni = client['dni']
            # Delete all cars belonging to this client
            try:
                db.execute(
                    'DELETE FROM car WHERE owner = ?',
                    (dni,)
                )
                db.execute(
                    'DELETE FROM client WHERE id = ?',
                    (client_id,)
                )
                db.commit()
                logger_register(f'Client with id "{client_id}" and all its cars have been deleted.', g.user['username'])
            except db.IntegrityError:
                error = f"There was an error deleting the user and its car from database."
                flash(error)
        else:
            error = f"Client with id {client} does not exist."
            flash(error)


    db = get_db()
    clients = db.execute(
        'SELECT * FROM client'
    ).fetchall()

    return render_template('/start/analist/client_register.html', clients=clients)

@bp.route('/start/analist/car_register.html', methods=('POST', 'GET'))
@login_required
@analist_required
def car_list():
    db = get_db()
    owner = request.args.get('dni')
    if owner is None:
        return redirect(url_for("auth.login"))
    if request.method == 'POST':
        if 'plaque' in request.form:
            plaque = request.form['plaque']
            brand = request.form['brand']
            model = request.form['model']
            year = request.form['year']
            serial_car = request.form['serial_car']
            serial_mot = request.form['serial_mot']
            color = request.form['color']
            issue = request.form['issue']
            owner = request.args.get('dni')
            try:
                db.execute(
                    'INSERT INTO car (plaque, brand, model, year, serial_car, serial_mot, color, issue, owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (plaque, brand, model, year, serial_car, serial_mot, color, issue, owner)
                )
                db.commit()
                logger_register(f'Car with plaque "{plaque}" was registered to owner "{owner}".', g.user['username'])
            except db.IntegrityError:
                error = f"Car with plaque {plaque} is already registered, check plaque and serials."
                flash(error)

        elif 'delete' in request.form:
            id = request.form['delete']
            try:
                db.execute(
                    'DELETE FROM car WHERE id = ?',
                    (id,)
                )
                db.commit()
                logger_register(f"Car with id {id} was delete from registry.", g.user['username'])
            except:
                error = f"Car with id {id} is not in car database."
                flash(error)
        

    db = get_db()
    client = db.execute(
        'SELECT * FROM client WHERE dni = ?', (owner,)
    ).fetchall()
    cars = db.execute(
        'SELECT * FROM car WHERE owner = ?', (owner,)
    ).fetchall()

    return render_template('/start/analist/car_register.html', client=client, cars=cars)

@bp.route('/start/analist/car_modify.html', methods=('POST', 'GET'))
@login_required
@analist_required
def car_modify():
    db = get_db()
    car_id = request.args.get('car_id')
    owner = request.args.get('owner')
    if (car_id is None) or (owner is None):
        return redirect(url_for("auth.login"))
    if request.method == 'POST':
        if 'suelte' in request.form:
            plaque = request.form['plaque']
            brand = request.form['brand']
            model = request.form['model']
            year = request.form['year']
            serial_car = request.form['serial_car']
            serial_mot = request.form['serial_mot']
            color = request.form['color']
            issue = request.form['issue']
            try:
                db.execute(
                    'UPDATE car SET plaque = ?, brand = ?, model = ?, year = ?, serial_car = ?, serial_mot = ?, color = ?, issue = ?, owner = ? WHERE id = ?',
                    (plaque, brand, model, year, serial_car, serial_mot, color, issue, owner, car_id)
                )
                db.commit()
                logger_register(f"Car with plaque {plaque} updated in database.", g.user['username'])
                db = get_db()
                return redirect(url_for('start.car_list', dni=owner))
            except db.IntegrityError:
                error = f"Car with plaque {plaque} could not be updated in database."
                flash(error)

    db = get_db()
    client = db.execute(
        'SELECT * FROM client WHERE dni = ?', (owner,)
    ).fetchall()
    car = db.execute(
        'SELECT * FROM car WHERE id = ?', (car_id,)
    ).fetchall()

    return render_template('/start/analist/car_modify.html', client=client, car=car)

