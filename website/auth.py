from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from . import db

auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for("views.index"))
            else:
                flash("Incorrect password, try again.", category="error")
        else:
            flash("Username does not exist.", category="error")
    if current_user.is_authenticated:
        return redirect(url_for("views.index"))
    return render_template("login.html", user=current_user)


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    try:
        logout_user()
    except:
        pass
    if request.method == "POST":

        username = request.form.get("username")
        first_name = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(username=username).first()

        if user:
            flash("Username already exists.", category="error")
        elif len(username) < 6:
            flash("Username must be greater than 5 characters.", category="error")
        elif len(first_name) < 2:
            flash("First name must be greater than 1 character.", category="error")
        elif password1 != password2:
            flash("Passwords don't match.", category="error")
        elif len(password1) < 8:
            flash("Password must be at least 8 characters.", category="error")
        else:
            new_user = User(
                username=username,
                first_name=first_name,
                password=generate_password_hash(password1, method="sha256"),
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Account created!", category="success")
            return redirect(url_for("views.index"))

        return render_template(
            "signup.html",
            user=current_user,
            current_username=username,
            current_first_name=first_name,
        )

    return render_template("signup.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))