from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# import secrets
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import smtplib
import os

send_email = os.environ.get('SEND_EMAIL')
my_password = os.environ.get('EMAIL_APP_PWD')       # remember to allow app to send mail within mail acct security
receive_email = os.environ.get('RCV_EMAIL')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# app.config['SECRET_KEY'] = secrets.token_hex()    # alternative way to generate a secret key
ckeditor = CKEditor(app)
Bootstrap5(app)

# Initialise Gravatar (for user avatars)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
db = SQLAlchemy()
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONFIGURE TABLES
# Create a User table for all registered users.
class User(UserMixin, db.Model):  # a child class can inherit from multiple parents
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # ## PARENT of BlogPost AND Comment
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship('BlogPost', back_populates='author')
    # Similarly, the "author" refers to the author property in the Comment class for a List of users comments
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # ## CHILD of User
    # Create Foreign Key, "users.id" the users refers to the table_name of User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship('User', back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ## PARENT of Comment ##
    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # ## CHILD of User ##
    # Create Foreign Key, "users.id" the users refers to the table_name of User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "comments" refers to the comments property in the User class.
    comment_author = relationship('User', back_populates='comments')

    # ## CHILD of BlogPost ##
    # Create Foreign Key, "blog_posts.id" the blog_posts refers to the table_name of BlogPost.
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    # Create reference to the BlogPost object, the "comments" refers to the comments property in the BlogPost class.
    parent_post = relationship('BlogPost', back_populates='comments')

    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()

# note reminder on decorator functions ...
# def decorator_function(function):
#     def wrapper_function():
#         # your additional code to wrap in here
#         function()
#     return wrapper_function


def admin_only(function):
    @wraps(function)
    def check_for_admin(*args, **kwargs):
        # check that current user is admin ... ie. ID = 1
        if current_user.is_anonymous or current_user.id != 1:
            return abort(403)  # forbidden
        return function(*args, **kwargs)
    return check_for_admin


# Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        result = db.session.execute(db.select(User).where(User.email == email))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        passwd = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8)
        new_user = User(
            email=email,
            password=passwd,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


#  Retrieve a user from the database based on their email.
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        print(email)
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == email))
        valid_user = result.scalar()
        if valid_user:
            print('valid user')
            if check_password_hash(valid_user.password, password):
                print('logged in')
                login_user(valid_user)
                return redirect(url_for("get_all_posts"))
            else:
                flash('Sorry, that is not the correct password. Try again.')
        else:
            flash('Sorry, that email is not recognised. Try again.')
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                comment_author=current_user,
                parent_post=requested_post,
                text=form.comment.data
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('You need to be logged in to make a comment.')
            login_form = LoginForm
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


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
    return render_template("make-post.html", form=form, is_edit=False, current_user=current_user)


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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        usr_name = request.form.get('name')
        usr_email = request.form.get('email')
        usr_phone = request.form.get('phone')
        usr_msg = request.form.get('message')
        print(f'{usr_name}\n{usr_email}\n{usr_phone}\n{usr_msg}')
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()  # start tls (translate layer security)
            connection.login(user=send_email, password=my_password)
            connection.sendmail(
                from_addr=send_email,
                to_addrs=receive_email,
                msg=f"Subject:New Contact Request\n\n"
                    f"Name:    {usr_name}\n"
                    f"Email:   {usr_email}\n"
                    f"Phone:   {usr_phone}\n"
                    f"Message: {usr_msg}"
            )
        page_head = "Successfully sent your message"
    else:
        page_head = "Contact Me"
    return render_template("contact.html", page_head=page_head)


if __name__ == "__main__":
    app.run(debug=False, port=5002)
