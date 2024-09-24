from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import re
import classes
app = Flask(__name__, instance_relative_config=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    surname = db.Column(db.String(50))
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)



@app.route('/password', methods=['GET', 'POST'])
@login_required
def password():
    form = classes.ChangePasswordForm()
    if form.validate_on_submit():
        user = current_user
        if check_password_hash(user.password, form.old_password.data):
            user.password = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Пароль успешно изменен', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный старый пароль', 'error')
    return render_template('password.html', form=form)


def role_name(role_id):
    role = Role.query.get(role_id)
    return role.name if role else "Unknown"


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user


@app.route('/')
def index():
    return render_template('index.html', current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(login=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неверные логин или пароль', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/users')
def users():
    users = User.query.all() if current_user.is_authenticated and current_user.role_id == 1 else [
        current_user] if current_user.is_authenticated else []
    return render_template('users.html', users=users, role_name=role_name)


@app.route('/user/<int:user_id>')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)


@app.route('/user/create_user', methods=['GET', 'POST'])
def create_user():
    form = classes.UserForm()
    roles = Role.query.all()
    form.role_id.choices = [(role.id, role.name) for role in roles]
    if form.validate_on_submit():
        user = User(login=form.login.data, password=generate_password_hash(form.password.data),
                    surname=form.surname.data, first_name=form.first_name.data, middle_name=form.middle_name.data,
                    role_id=form.role_id.data)
        db.session.add(user)
        db.session.commit()
        flash('Пользователь успешно создан', 'success')
        return redirect(url_for('users'))
    return render_template('create_user.html', form=form, roles=roles)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == 'POST':
        user.surname = request.form['surname']
        user.first_name = request.form['first_name']
        user.middle_name = request.form['middle_name']
        user.role_id = request.form['role_id']
        db.session.commit()
        flash('Данные пользователя успешно обновлены', 'success')
        return redirect(url_for('users'))

    return render_template('edit_user.html', user=user, roles=roles)


@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь успешно удален', 'success')
    return redirect(url_for('users'))


@app.route('/user/<int:user_id>/confirm_delete', methods=['GET'])
@login_required
def confirm_delete(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('confirm_delete.html', user=user)


def validate_user_data(form):
    password = form.password.data

    if (len(password) < 8 or len(password) > 128):
        form.password.errors.append('Пароль должен быть от 8 до 128 символов')
        return False

    if not any(char.isupper() for char in password):
        form.password.errors.append('Пароль должен содержать хотя бы одну заглавную букву')
        return False

    if not any(char.islower() for char in password):
        form.password.errors.append('Пароль должен содержать хотя бы одну строчную букву')
        return False

    if not any(char.isdigit() for char in password):
        form.password.errors.append('Пароль должен содержать хотя бы одну цифру')
        return False

    if ' ' in password:
        form.password.errors.append('Пароль не должен содержать пробелы')
        return False

    # Проверяем на наличие только допустимых символов
    if not re.match(r'^[A-Za-zА-Яа-я0-9~!?@#$%^&*()_+\-=\[\]{}<>\\/|\'\".,:;]+$', password):
        form.password.errors.append('Пароль содержит недопустимые символы')
        return False

    return True


if __name__ == '__main__':
    app.run(debug=True)
