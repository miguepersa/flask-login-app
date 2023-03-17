from datetime import datetime
from . import BaseTestsClass
from login.db import get_db
from flask import session
class LoginTest(BaseTestsClass):

    def test_loginNonExistentUser(self):
        print("loginNonExistetUser\n\n")

        res = self.client.post('/auth/login', data={
            'username':'nonexst',
            'password':'nonexst',
        }, follow_redirects=True)
        assert res.status_code == 200
        html = res.get_data(as_text=True)

        assert "Incorrect username." in html
        
        with self.app.app_context():
            try:
                db = get_db()
                assert db.execute("SELECT * FROM user WHERE username = 'nonexst'",).fetchone() is None
            except db.IntegrityError:
                pass
    
    def test_registerUser(self):
        print("registerUser\n\n")
        res = self.client.post('/auth/register', data={
            'username':'test',
            'password':'test',
            'firstname':'test',
            'secondname':'test'
        }, follow_redirects=True)
        
        assert res.status_code == 200
        
        html = res.get_data(as_text=True)
        
        assert res.request.path == '/auth/login'
        
        with self.app.app_context():
            assert get_db().execute("SELECT * FROM user WHERE username = 'test'",).fetchone() is not None
      
    def test_registerAlreadyRegisteredUser(self):
        print("registerAlreadyRegisteredUser\n\n")
        self.test_registerUser()
        res = self.client.post('/auth/register', data={
            'username':'test',
            'password':'test',
            'firstname':'test',
            'secondname':'test'
        }, follow_redirects=True)
        assert res.status_code == 200
        
        html = res.get_data(as_text=True)
        
        assert f'User test is already registered.' in html
        
        with self.app.app_context():
            assert get_db().execute("SELECT * FROM user WHERE username = 'admin'",).fetchone() is not None

    def test_registerUserAuthorize(self):
        print("registerUserAuthorize\n\n")
        self.test_registerUser()
        with self.app.app_context():
            get_db().execute("UPDATE user SET verified=1 WHERE username = 'test'",).fetchone()
            get_db().commit()
            assert get_db().execute("SELECT verified FROM user WHERE username = 'test'").fetchone()[0] == 1
    
    
    def test_loginAuthorizedWrongPassword(self):
        print("loginAuthorizedWrongPassword\n\n")
        self.test_registerUserAuthorize()
        res = self.client.post('/auth/login', data={
            'username':'test',
            'password':'testnt',
        }, follow_redirects=True)
        assert res.status_code == 200

        html = res.get_data(as_text=True)

        assert "Incorrect password." in html

    def test_loginNonAuthorizedWrongPassword(self):
        print("loginNonAuthorizedWrongPassword\n\n")
        self.test_registerUser()
        res = self.client.post('/auth/login', data={
            'username':'test',
            'password':'testo',
        }, follow_redirects=True)
        assert res.status_code == 200
        
        html = res.get_data(as_text=True)

        assert "Incorrect password." in html
    
    def test_loginAuthorized(self):
        print("loginAuthorized\n\n")
        self.test_registerUserAuthorize()
        with self.app.app_context():
            assert get_db().execute("Select verified FROM user WHERE username = 'test'").fetchone()[0] == 1
        res = self.client.post('/auth/login', data={
            'username':'test',
            'password':'test',
        }, follow_redirects=True)
        assert res.status_code == 200
        
        html = res.get_data(as_text=True)
        
        assert "Nothing here for now" in html
    
    def test_loginNonAuthorized(self):
        print("loginNonAuthorized\n\n")
        self.test_registerUser()
        res = self.client.post('/auth/login', data={
            'username':'test',
            'password':'test',
        }, follow_redirects=True)

        assert res.status_code == 200

        html = res.get_data(as_text=True)

        assert "Account has not been verified by admin." in html
    
    def test_logout(self):
        print("logout\n\n")
        self.test_loginAuthorized()
        res = self.client.get('/auth/logout',follow_redirects=True)
        html = res.get_data(as_text=True)

        assert res.request.path == '/auth/login'

        assert 'Log In' in html

    def test_loginRoot(self):
        print("loginRoot\n\n")
        res = self.client.post('/auth/login', data={
            'username':'admin',
            'password':'admin',
        }, follow_redirects=True)

        assert res.status_code == 200

        html = res.get_data(as_text=True)
        assert "Logged as: admin" in html

    def test_rootCreateProject(self,name='test_project'):
        print("rootCreateProject\n\n")
        self.test_loginRoot()
        if name != 'test_project':
            with self.app.app_context():
                db = get_db()
                assert db.execute("SELECT * FROM project WHERE description = 'test_project' ").fetchone() is None
        res = self.client.post('/start/admin/create_project', data={
            'description':name,
            'init':'2022-01-01',
            'end':'2023-01-01'
        }, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            data = db.execute("SELECT * FROM project WHERE description = 'test_project'").fetchone()
            assert data['end'] == '2023-01-01' and data['init'] == '2022-01-01' and data['description'] == 'test_project'
        assert res.status_code == 200

    def test_rootCreateUser(self):
        print("rootCreateUser\n\n")
        self.test_rootCreateProject()
        res = self.client.post('/start/admin/create_user', data={
            'username':'create',
            'password':'create',
            'firstanme':'create',
            'lastaname':'create',
            'role':'Gerente de Operaciones',
        }, follow_redirects=True)
        assert res.status_code == 200

    def test_rootCreateUserAlreadyRegistered(self):
        print("rootCreateUserAlreadyRegistered\n\n")
        self.test_registerUserAuthorize()
        self.test_loginRoot()
        res = self.client.post('/start/admin/create_user', data={
            'username':'test',
            'password':'test',
            'firstname':'test',
            'secondname':'test',
            'role':'Gerente de Operaciones',
        }, follow_redirects=True)
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert f'User test is already registered.' in html

    def test_rootApproveUser(self):
        print("rootApproveUser\n\n")
        self.test_registerUser()
        self.test_rootCreateProject()
        
        with self.app.app_context():
            id = get_db().execute("SELECT id FROM user WHERE verified = 0").fetchone()[0]
            assert get_db().execute("SELECT * FROM user WHERE verified = 0").fetchone() is not None
        with self.client.session_transaction() as session:
            session['aprove_user'] = id
        res = self.client.post('/start/admin/approve', data={

            'aprove':id,
        }, follow_redirects=True)
        with self.app.app_context():
            assert get_db().execute("SELECT * FROM user WHERE verified = 1").fetchone() is not None
        assert res.status_code == 200

    def test_rootRejectUser(self):
        print("rootRejectUser\n\n")
        self.test_registerUser()
        self.test_loginRoot()
        
        with self.app.app_context():
            db = get_db()
            id = db.execute("SELECT id FROM user WHERE verified = 0").fetchone()
            assert db.execute("SELECT * FROM user WHERE verified = 0").fetchone() is not None
        res = self.client.post('/start/admin/approve', data={
            'reject': id[0],
        }, follow_redirects=True)
        with self.app.app_context():
            db = get_db()
            data = db.execute("SELECT * FROM user WHERE verified = 1")
            count = 0
            for row in data:
                count = count + 1
            assert count == 1
        assert res.status_code == 200

    def test_loginEmptyAll(self):
        print("loginEmptyAll\n\n")
        res = self.client.post('/auth/login', data={
            'username':None,
            'password':None,
        },follow_redirects=True)
        assert res.status_code == 400

    def test_loginEmptyUser(self):
        print("loginEmptyUser\n\n")
        res = self.client.post('/auth/login', data={
            'username':None,
            'password':'test',
        },follow_redirects=True)
        assert res.status_code == 400

    def test_loginEmptyPassword(self):
        print("loginEmptyPassword\n\n")
        res = self.client.post('/auth/login', data={
            'username':'test',
            'password':None,
        },follow_redirects=True)
        
        assert res.status_code == 400

    def test_registerEmptyAll(self):
        print("registerEmptyAll\n\n")
        res = self.client.post('/auth/register', data={
            'username':None,
            'password':None,
        },follow_redirects=True)
        
        assert res.status_code == 400

    def test_registerEmptyUser(self):
        print("registerEmptyUser\n\n")
        res = self.client.post('/auth/register', data={
            'username':None,
            'password':'test',
        },follow_redirects=True)
        
        assert res.status_code == 400

    def test_registerEmptyPassword(self):
        print("registerEmptyPassword\n\n")
        res = self.client.post('/auth/register', data={
            'username':'test',
            'password':None,
        },follow_redirects=True)
        
        assert res.status_code == 400

    def test_rootActivateProject(self):
        print("rootActivateProject\n\n")
        self.test_rootCreateProject()
        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT status FROM project WHERE id = 1").fetchone()[0] == 0

        res = self.client.post('/start/admin/create_project', data={
            'activate':'1',
        }, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT status FROM project WHERE id = 1").fetchone()[0] == 1
        assert res.status_code == 200

    def test_rootDeactivateProject(self):
        print("rootDeactivateProject\n\n")
        self.test_rootActivateProject()
        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT status FROM project WHERE id = 1").fetchone()[0] == 1

        res = self.client.post('/start/admin/create_project', data={
            'deactivate':'1',
        }, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT status FROM project WHERE id = 1").fetchone()[0] == 0
        assert res.status_code == 200

    def test_rootModifyProject(self):
        self.test_rootCreateProject()
        print("rootCreateProject\n\n")
        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT * FROM project WHERE id = 1").fetchone() is not None
        with self.client.session_transaction() as session:
            session['modify_proyect'] = '1'
        res = self.client.post('/start/manager/modify_project.html', data={
            'init': '2021-01-01',
            'end': '2022-01-01'
        }, follow_redirects=True)
        
        with self.app.app_context():
            db = get_db()
            data = db.execute("SELECT * FROM project WHERE description = 'test_project'").fetchone()
            assert data['end'] == '2022-01-01' and data['start'] == '2021-01-01'
        assert res.status_code == 200

    def test_rootDeleteProject(self):
        self.test_rootCreateProject()
        print("rootDeleteProject\n\n")
        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT * FROM project WHERE id = 1").fetchone() is not None
        with self.client.session_transaction() as session:
            session['modify_proyect'] = '1'
        res = self.client.post('/start/manager/modify_project.html', data={
            'delete':'1'
        }, follow_redirects=True)
        
        with self.app.app_context():
            db = get_db()
            assert db.execute("SELECT * FROM project WHERE description = 'test_project'").fetchone() is None
        assert res.status_code == 200

    """def test_userChangeProject(self):
        print("rootUserChangeProyect\n\n")
        self.test_rootCreateUser()
        self.test_rootCreateProject()
        self.test_rootCreateProject('test_project2')
        with self.app.app_context():    
            db = get_db()
            p1 = db.execute("SELECT * FROM project WHERE description = 'test_project'").fetchone()
            p2 = db.execute("SELECT * FROM project WHERE description = 'test_project2'").fetchone()
            assert p1 is not None and p2 is not None
        with self.client.session_transaction() as session:
            session['modify_user'] = '2'
        res = self.client.post('/start/admin/approve', data={
            'project': 'test_project2',
            'assign_project':'2',
        }, follow_redirects=True)
        with self.app.app_context():    
            db = get_db()
            p1 = db.execute("SELECT * FROM project WHERE description = 'proyect1'").fetchone()
            p2 = db.execute("SELECT * FROM project WHERE description = 'proyect2'").fetchone()
            assert p1 is not None and p2 is not None
        assert res.status_code == 200"""

    def test_userDeleteUser(self):
            print("rootUserDeleteUser\n")
            self.test_rootCreateUser()
            with self.app.app_context():    
                db = get_db()
                u1 = db.execute("SELECT * FROM user WHERE id = '2'").fetchone()
                assert u1 is not None
            with self.client.session_transaction() as session:
                session['modify_user'] = '2'
            res = self.client.post('/start/admin/modify_users.html', data={
                'delete':session['modify_user'],
            }, follow_redirects=True)
            with self.app.app_context():    
                db = get_db()
                u1 = db.execute("SELECT * FROM user WHERE id = '2'").fetchone()
                assert u1 is None
            assert res.status_code == 200

    """def test_userChangeRole(self):
            print("rootUserChangeRole\n")
            self.test_rootCreateUser()
            with self.app.app_context():    
                db = get_db()
                u1 = db.execute("select * from user where id = 2").fetchone()
                # db.execute("INSERT INTO roles (name, description) VALUES ('mechanic_sup', 'Supervisor del area de mecanica')")
                # db.commit()
                # r1 = db.execute("select * from roles where id = 1").fetchone()
                # r2 = db.execute("select * from roles where id = 2").fetchone()
                assert u1 is not None
                assert u1['role'] == 'op_manager'
            with self.client.session_transaction() as session:
                session['modify_user'] = '2'
            res = self.client.post('/modifyUser/changeRole', data={
                'select':'mechanic_sup',
            }, follow_redirects=True)
            with self.app.app_context():    
                db = get_db()
                u1 = db.execute("select * from user where id = 2").fetchone()
                # r1 = db.execute("select * from roles where id = 1").fetchone()
                # r2 = db.execute("select * from roles where id = 2").fetchone()
                print(u1['role'])
                # assert u1 is not None and r1 is not None and r2 is not None
                assert u1 is not None
                assert u1['role'] == 'mechanic_sup'
            assert res.status_code == 200
            assert res.request.path == '/user/root'"""