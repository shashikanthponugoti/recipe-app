from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "recipes.db")

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_for_prod"  # change for production
app.permanent_session_lifetime = timedelta(days=7)

# ---------------------------
# Database helpers
# ---------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    con = get_db()
    cur = con.cursor()
    cur.execute(query, args)
    con.commit()
    return cur.lastrowid

# ---------------------------
# Create DB & tables if not exists
# ---------------------------
def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        """)
        cur.execute("""
        CREATE TABLE recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            ingredients TEXT,
            instructions TEXT,
            prep_time TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)
        conn.commit()
        conn.close()
        print("Initialized database at", DB_PATH)

init_db()

# ---------------------------
# Authentication utils
# ---------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login", next=request.endpoint))
        return f(*args, **kwargs)
    return decorated_function

def current_user():
    if "user_id" in session:
        return query_db("SELECT id, username FROM users WHERE id = ?", [session["user_id"]], one=True)
    return None

# ---------------------------
# Routes: Auth
# ---------------------------
@app.route("/")
def home():
    user = current_user()
    recipes = query_db("SELECT r.*, u.username FROM recipes r JOIN users u ON r.user_id=u.id ORDER BY created_at DESC")
    return render_template("index.html", recipes=recipes, user=user)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return redirect(url_for("register"))
        existing = query_db("SELECT id FROM users WHERE username = ?", [username], one=True)
        if existing:
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))
        pw_hash = generate_password_hash(password)
        user_id = execute_db("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
        session.permanent = True
        session["user_id"] = user_id
        flash("Registration successful. You're logged in.", "success")
        return redirect(url_for("home"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
        session.permanent = True
        session["user_id"] = user["id"]
        flash("Logged in successfully.", "success")
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

# ---------------------------
# Routes: Recipes CRUD
# ---------------------------
@app.route("/recipes")
def recipes_list():
    user = current_user()
    recipes = query_db("SELECT r.*, u.username FROM recipes r JOIN users u ON r.user_id=u.id ORDER BY created_at DESC")
    return render_template("recipes_list.html", recipes=recipes, user=user)

@app.route("/recipes/new", methods=["GET", "POST"])
@login_required
def recipe_new():
    user = current_user()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        ingredients = request.form.get("ingredients", "").strip()
        instructions = request.form.get("instructions", "").strip()
        prep_time = request.form.get("prep_time", "").strip()
        if not title:
            flash("Title is required.", "danger")
            return redirect(url_for("recipe_new"))
        execute_db("""
            INSERT INTO recipes (user_id, title, description, ingredients, instructions, prep_time)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session["user_id"], title, description, ingredients, instructions, prep_time))
        flash("Recipe created.", "success")
        return redirect(url_for("recipes_list"))
    return render_template("recipe_form.html", action="Create", recipe=None, user=user)

@app.route("/recipes/<int:recipe_id>")
def recipe_detail(recipe_id):
    user = current_user()
    recipe = query_db("SELECT r.*, u.username FROM recipes r JOIN users u ON r.user_id=u.id WHERE r.id = ?", [recipe_id], one=True)
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("recipes_list"))
    return render_template("recipe_detail.html", recipe=recipe, user=user)

@app.route("/recipes/<int:recipe_id>/edit", methods=["GET", "POST"])
@login_required
def recipe_edit(recipe_id):
    user = current_user()
    recipe = query_db("SELECT * FROM recipes WHERE id = ?", [recipe_id], one=True)
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("recipes_list"))
    # Authorization: can only edit own recipes (optional)
    if recipe["user_id"] != session["user_id"]:
        flash("You are not allowed to edit this recipe.", "danger")
        return redirect(url_for("recipes_list"))
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        ingredients = request.form.get("ingredients", "").strip()
        instructions = request.form.get("instructions", "").strip()
        prep_time = request.form.get("prep_time", "").strip()
        if not title:
            flash("Title is required.", "danger")
            return redirect(url_for("recipe_edit", recipe_id=recipe_id))
        execute_db("""
            UPDATE recipes
            SET title = ?, description = ?, ingredients = ?, instructions = ?, prep_time = ?
            WHERE id = ?
        """, (title, description, ingredients, instructions, prep_time, recipe_id))
        flash("Recipe updated.", "success")
        return redirect(url_for("recipe_detail", recipe_id=recipe_id))
    return render_template("recipe_form.html", action="Edit", recipe=recipe, user=user)

@app.route("/recipes/<int:recipe_id>/delete", methods=["POST"])
@login_required
def recipe_delete(recipe_id):
    recipe = query_db("SELECT * FROM recipes WHERE id = ?", [recipe_id], one=True)
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("recipes_list"))
    if recipe["user_id"] != session["user_id"]:
        flash("You are not allowed to delete this recipe.", "danger")
        return redirect(url_for("recipes_list"))
    execute_db("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    flash("Recipe deleted.", "success")
    return redirect(url_for("recipes_list"))

# ===== RUN APP =====
if __name__ == "__main__":
    # Render sets PORT env variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)