
from datetime import date
from functools import wraps

import requests
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# email = "lumhaa@javdeno.site"
# default = "https://www.example.com/default.jpg"
# size = 40
# gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(email.lower()).hexdigest() + "?"
# gravatar_url += urllib.urlencode({'d': default, 's': str(size)})
# print(gravatar_url)


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = db.session.execute(db.Select(Users).where(Users.id == user_id)).scalar()
    return user


# TODO: Configure Flask-Login


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text(1000), nullable=False)
    author_com = relationship('Users', back_populates='comments')
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship('BlogPost', back_populates='post_comments')


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author_com")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship('Users', back_populates='posts')
    post_comments = relationship('Comment', back_populates='parent_post')


# TODO: Create a User table for all your registered users. 


with app.app_context():
    db.create_all()


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            user_id = current_user.id
        except AttributeError:
            return abort(403)
        if user_id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    user_exists = False
    all_users = db.session.execute(db.Select(Users).order_by(Users.id)).scalars()
    form = RegisterForm()
    if form.validate_on_submit():
        for user in all_users:
            if user.email == form.email.data:
                user_exists = True

        if user_exists:
            flash("This email is already registered. Log in please.")
            return redirect(url_for('login'))

        elif not user_exists:
            new_user = Users(
                email=form.email.data,
                name=form.name.data,
                password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.Select(Users).where(Users.email == form.email.data)).scalar()
        if not user:
            flash("This email does not exist. Try again please.")
            return redirect(url_for('login'))
        else:
            pass_correct = check_password_hash(pwhash=user.password, password=form.password.data)
            if pass_correct:
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Wrong password. Try again please.")
                return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    try:
        user_id = current_user.id
    except AttributeError:
        user_id = None

    return render_template("index.html", all_posts=posts, user_id=user_id)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    post_comments = db.session.execute(db.Select(Comment).where(Comment.post_id == post_id)).scalars()
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    try:
        user_id = current_user.id
        if form.validate_on_submit():
            new_comment = Comment(
                text=form.comment.data,
                author_id=user_id,
                post_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()

    except AttributeError:
        user_id = None
        if form.validate_on_submit():
            flash("You have to be logged in to write comments.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, user_id=user_id, form=form, comments=post_comments, )


# TODO: Use a decorator so only an admin user can create a new post

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
