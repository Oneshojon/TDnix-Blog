from datetime import date, datetime
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from urllib.parse import urlparse, urljoin
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, DateTime, func
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import Registration, CreatePostForm, LoginForm, CommentForm
# emailing
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import unicodedata
import smtplib
from forms import CreatePostForm
from dotenv import load_dotenv
import os
load_dotenv()

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
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
MY_EMAIL=os.getenv("MY_EMAIL")
EMAIL_PASS=os.getenv("EMAIL_PASS")
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(100), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # Foreign keys
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # relationships
    comments = relationship("Comment",
        back_populates="parent_post",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Comment.id.desc()")
    author = relationship("User", back_populates="posts")


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(1000), nullable=False)
    # relationships
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship("Comment", back_populates='author')

# Table for comments
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    # Relationships
    author = relationship("User", back_populates='comments')
    parent_post = relationship("BlogPost", back_populates='comments')
    # Foreign Keys
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'), nullable=False)

with app.app_context():
    db.create_all()

# user loader
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    reg_form = Registration()
    if request.method=="POST":
        email = reg_form.email.data.strip()
        new_user = User(
            user_name = reg_form.name.data,
            email = email,
            password = generate_password_hash(reg_form.password.data,
                                              method='pbkdf2:sha256', salt_length=8)

        )
        # check the email if it is not already registered
        user = db.session.execute(db.select(User).where
                                      (User.email == email)).scalar()
        if user is not None:
            flash("This email is already registered. Login instead", "info")
            user_data = {
                'email': email
            }
            prefilled_form = LoginForm(data=user_data)
            return redirect(url_for('login', form=prefilled_form))

        try:
            db.session.add(new_user)
            db.session.commit()
            # If we get here → success!

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred : {e}', 'danger')
            return redirect(url_for('register', form=reg_form))
        else:
            flash('Uer registration success!', 'success')
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=reg_form,
                           logged_in=current_user.is_authenticated)


def admin_only(f):
    """
    Custom decorator: only allows access if current_user.id == 1
    Returns 403 Forbidden otherwise
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated AND has admin id
        if not current_user.is_authenticated or current_user.id != 1:
            # 403 = Forbidden (better than 401 for this case)
            return abort(403)
        # If admin → continue with the original function
        return f(*args, **kwargs)

    return decorated_function

def is_safe_url(target):
    """Very important security check"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    return (
            test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc
    )

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST', 'GET'])
def login():
    """
    logs a user in to the application
    :return: New route
    """
    form = LoginForm()
    if request.method=='POST':
        email = form.email.data.strip()
        password = form.password.data.strip()
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # prefilled form
        user_data = {
            'email': email
        }
        prefilled_form = LoginForm(data=user_data)

        if user is None:
            flash(f"{email} is not registered. Cross-check your email or create register for an account", "danger")
            return redirect(url_for('login'))

        if check_password_hash(user.password, password=password):

            login_user(user)


            next_url = request.args.get('next')

            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            flash("Successfully logged in", "success")
            return redirect(url_for('get_all_posts'))
        else:
            flash("Incorrect password", "danger")
            return render_template("login.html", form=prefilled_form)


    return render_template("login.html",
                           form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           user_id=current_user.get_id())


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    comments = (db.session.execute(
        db.select(Comment)
        .where(Comment.post_id == post_id)
        .order_by(Comment.id.desc()))
                .scalars().all())

    form = CommentForm()

    if request.method == 'POST' and form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You have to login to comment", "danger")
            return redirect(url_for("login"))

        new_comment = Comment(
            text = form.comment.data,
            post_id = post_id,
            author_id = current_user.id
        )
        try:
            db.session.add(new_comment)
            db.session.commit()
            flash("Your comment was added!", "success")
            return redirect(url_for('show_post', post_id=post_id))
        except Exception as e:
            db.session.rollback()
            flash(f"Failed: {str(e)}")

    return render_template(
        "post.html",
        comments=comments,
        form=form,
        post=requested_post,
    logged_in=current_user.is_authenticated)


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
    return render_template("make-post.html",
                           form=form, logged_in=current_user.is_authenticated)


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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


def send_email(message, subject):
    connection = smtplib.SMTP("smtp.gmail.com", port=587)
    connection.starttls()
    connection.login(user=MY_EMAIL, password=EMAIL_PASS)

    msg=MIMEMultipart("alternative")
    msg["From"]=MY_EMAIL
    msg["To"]=MY_EMAIL
    msg["Subject"] = f"{subject}"

    body = f"{message}"

    msg.attach(MIMEText(body, "plain", "utf-8"))

    connection.send_message(msg=msg)
    connection.close()

@app.route("/contact", methods=['GET', "POST"])
def contact():
    if request.method=="POST":
        last_use = datetime.now()
        new_message = (f"User: {request.form['name']}\n"
                       f"Email: {request.form['email']}\n"
                       f"Phone Number: {request.form['phone']}\n"
                       f"Message: {request.form['message']}")
        send_email(new_message, "Blog message")
        flash("Success!!", "success")
        return redirect(url_for('contact'))

    return render_template("contact.html",
                           logged_in=current_user.is_authenticated)



if __name__ == "__main__":
    app.run(debug=True)
