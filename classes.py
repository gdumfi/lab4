from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp

class UserForm(FlaskForm):
    login = StringField('Логин', validators=[
        DataRequired(),
        Length(min=5),
        Regexp('^[a-zA-Z0-9]+$', message='Логин должен содержать только латинские буквы и цифры')
    ])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password')])
    surname = StringField('Фамилия', validators=[DataRequired()])
    first_name = StringField('Имя', validators=[DataRequired()])
    middle_name = StringField('Отчество')
    role_id = SelectField('Роль', coerce=int, validators=[DataRequired()], default=2)


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[
        DataRequired(),
        Length(min=8, max=128),
        Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&^_-])[A-Za-z\\d@$!%*?&^_-]{8,}$',
               message="Пароль должен содержать минимум 8 символов, как минимум одну заглавную и одну строчную букву, одну цифру и один из следующих специальных символов: @$!%*?&^_-")
    ])
    confirm_password = PasswordField('Повторите новый пароль', validators=[DataRequired(), EqualTo('new_password',
                                                                                                   message='Пароли должны совпадать')])

