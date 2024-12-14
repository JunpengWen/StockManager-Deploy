from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# 模拟用户凭据
user_credentials = {
    "owner": "ownerpass",
    "employee": "employeepass"
}

# 登录页面
@app.route('/')
def user_login():
    return render_template('userlogin.html')

# 处理登录逻辑
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in user_credentials and user_credentials[username] == password:
        if username == 'owner':
            # 跳转到 owner_dashboard 路由
            return redirect(url_for('owner_dashboard'))
        else:
            # 跳转到 employee_dashboard 路由
            return redirect(url_for('employee_dashboard'))
    else:
        return "Invalid username or password", 401

# Owner Dashboard 页面
@app.route('/owner_dashboard')
def owner_dashboard():
    return render_template('owner_dashboard.html')

# Employee Dashboard 页面
@app.route('/employee_dashboard')
def employee_dashboard():
    return render_template('employee_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)

