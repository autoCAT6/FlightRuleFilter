# -*- coding: UTF-8 -*-
from __future__ import unicode_literals
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
#from data import Articles
# from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import requests
import json
import logging
from datetime import datetime

app = Flask(__name__)
app.config.from_pyfile('config.py')

# 系统日志配置
handler = logging.FileHandler(app.config['LOGFILE'], encoding='UTF-8')
logging_format = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(message)s')
handler.setFormatter(logging_format)
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

# # Config MySQL
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = '123456'
# app.config['MYSQL_DB'] = 'myflaskapp'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# # init MYSQL
# mysql = MySQL(app)


# Index
@app.route('/')
def index():
    return render_template('home.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

# Single Article
@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']
        if username == 'admin' and password_candidate == 'admin':
            session['logged_in'] = True
            session['username'] = username
            flash('You are now logged in', 'success')
            return redirect(url_for('dashboard'))
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)


    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Utility functions
def to_int(str):
    # 先把None转为''
    if str == None or str == '' or str.isspace():
        return ''
    else:
        try:
            str = int(str)
        except Exception as e:
            app.logger.error('修改规则时输入格式错误')
            app.logger.error('%s', e)
            flash('输入格式错误，请检查后再试', 'danger')
        else:
            return str
def str_split(str):
    if str == None or str == '' or str.isspace():
        return ''
    else:
        return str.split() # split多个空格，不可以是单个

# Preprocess user input (add/edit)
def processInput(dict):
    if 'id' in dict.keys():
        dict["id"] = int(dict["id"])

    dict["maxFlightDistance"] = to_int(dict["maxFlightDistance"])
    dict["maxFlightTime"] = to_int(dict["maxFlightTime"])

    dict["maxStrideDays"] = to_int(dict["maxStrideDays"])
    dict["banAllDays"] = to_int(dict["banAllDays"])
    dict["banType"] = str_split(dict["banType"])
    dict["carrierBlack"] = str_split(dict["carrierBlack"])
    dict["carrierWhite"] = str_split(dict["carrierWhite"])
    dict["legTransferBlack"] = str_split(dict["legTransferBlack"])
    dict["legTransferWhite"] = str_split(dict["legTransferWhite"])
    dict["notSpanCity"] = str_split(dict["notSpanCity"])
    dict["permission"] = str_split(dict["permission"])
    dict["prohibition"] = str_split(dict["prohibition"])
    dict["transferBlack"] = str_split(dict["transferBlack"])
    dict["yesSpanCity"] = str_split(dict["yesSpanCity"])

    # remove keys with empty values
    removed = {x[0]:x[1] for x in dict.iteritems() if all(x)}

    return removed

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Get rules
    #response = requests.get(app.config['ENDPOINT']+app.config['GET_ALL_URL'])
    #rules = response.json()
    rules = {"id":1}
    # for rule in rules:
    #     for key in rule:
    #         if isinstance(rule[key], list):
    #             rule[key] = ' '.join(rule[key]) # 需要与split对应
    #         if rule[key] == None: # python中空串与None不同
    #             rule[key] = ''
            
            
    return render_template('dashboard.html', rules=rules)


# Add Rule
@app.route('/add_rule', methods=['POST'])
@is_logged_in
def add_rule():

    # preprocess input text
    dict = processInput(request.form.to_dict())
    form = json.dumps(dict)        
    header = {"Content-Type": "application/json"}    
    r = requests.post(app.config['ENDPOINT']+app.config['INSERT_URL'], headers=h, data=form)
    
    if r.status_code == 200:
        app.logger.info(form)
        app.logger.info('添加规则成功')
        flash('添加规则成功', 'success')
    else:
        app.logger.error('添加规则失败')
        flash('添加规则失败，请检查输入格式后再试', 'danger')



    return redirect('/dashboard')



# Edit Rule
@app.route('/edit_rule/<string:id>', methods=['POST'])
@is_logged_in
def edit_rule(id):

    # preprocess input text
    dict = processInput(request.form.to_dict())
    form = json.dumps(dict)            
    header = {"Content-Type": "application/json"}
    r = requests.put(app.config['ENDPOINT']+app.config['UPDATE_URL'], headers=header, data=form)
    
    print(form)
    if r.status_code == 200:
        app.logger.info(form)
        app.logger.info('修改规则成功')
        flash('修改规则成功', 'success')
    else:
        app.logger.error('修改规则失败')
        flash('修改规则失败，请检查输入格式后再试', 'danger')


    return redirect('/dashboard')


# Delete Rule
@app.route('/delete_rule/<string:id>', methods=['POST'])
@is_logged_in
def delete_rule(id):   
    dict = { "id": id }
    form = json.dumps(dict)
    r = requests.delete(app.config['ENDPOINT']+app.config['DELETE_URL'], data=form)
    if r.status_code == 200:
        app.logger.info('delete rule id = %s', id)
        app.logger.info('删除规则成功')
        flash('删除规则成功', 'success')
    else:
        app.logger.error('删除规则失败')
        flash('删除规则失败，请检查输入格式后再试', 'danger')
    return redirect('/dashboard')


if __name__ == '__main__':
    app.run(debug=True)
