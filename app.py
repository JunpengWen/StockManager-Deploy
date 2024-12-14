from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Simulated user credentials
user_credentials = {
    "owner": "ownerpass",
    "employee": "employeepass"
}

# Login Page
@app.route('/')
def user_login():
    return render_template('userlogin.html')

# Handle login logic
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in user_credentials and user_credentials[username] == password:
        if username == 'owner':
            # Redirect to owner_dashboard route
            return redirect(url_for('owner_dashboard'))
        else:
            # Redirect to employee_dashboard route
            return redirect(url_for('employee_dashboard'))
    else:
        return "Invalid username or password", 401

# Owner Dashboard page
@app.route('/owner_dashboard')
def owner_dashboard():
    return render_template('owner_dashboard.html')

# Employee Dashboard page
@app.route('/employee_dashboard')
def employee_dashboard():
    return render_template('employee_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)

