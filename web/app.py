import os
import sqlite3

import requests
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, jsonify
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "truyenhay.db")

app = Flask(__name__)
app.secret_key = "c8d23e019b744a5fa82eef11082d490c29758f8b8841a4a6b291dc8f7807d9b2"

# Ket noi database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def run_query(query, fetch="all"):
    db = get_db()
    cur = db.cursor()
    cur.execute(query)

    if fetch == "all":
        rows = cur.fetchall()
        return rows
    elif fetch == "one":
        row = cur.fetchone()
        return row
    else:
        db.commit()
        return None

@app.route("/")
def index():
    rows = run_query("SELECT * FROM truyen ORDER BY views DESC LIMIT 4")
    return render_template("index.html", truyen_list=rows)

@app.route("/truyen")
def truyen_list():
    query = request.args.get("q", "") #tim kiem
    if query: #Neu co
        sql = ("""SELECT * FROM truyen WHERE title LIKE '%{q}%'
            OR author LIKE '%{q}%' OR category LIKE '%{q}%'""").format(q=query)
        try:
            rows = run_query(sql)
        except sqlite3.Error as e: 
            return render_template("truyen.html", truyen_list=[], query=query, error=str(e)), 400
    else:
        rows = run_query("SELECT * FROM truyen ORDER BY id")
    return render_template("truyen.html", truyen_list=rows, query=query)

@app.route("/truyen/<truyen_id>", methods=["GET", "POST"])
def truyen_detail(truyen_id):
    db = get_db()
    cur = db.cursor()
    if request.method == "GET": #GET
        sql = ("SELECT * FROM truyen WHERE id = {t_id}").format(t_id=truyen_id)
        try: #Lay truyen
            truyen = run_query(sql, fetch="one")
        except sqlite3.Error as e:
            return f"Loi: {e}", 400
        if truyen == None:
            return "Không tìm thấy truyện !", 404
        
        try: #UPDATE views
            u_sql = "UPDATE truyen SET views = views + 1 WHERE id = {t_id}".format(t_id=truyen_id)
            run_query(u_sql, fetch="none")
        except sqlite3.Error as e:
            pass

        try: #Comments
            cmt_sql = ("SELECT * FROM comments WHERE truyen_id = {id} ORDER BY id"
                       ).format(id=truyen_id)
            comments = run_query(cmt_sql)
        except sqlite3.Error as e:
            comments =[]
        return render_template("truyen_detail.html", truyen=truyen, comments=comments)
        
    else: #POST
        username = request.form.get("username", "AnDanh")
        content = request.form.get("content","")
        is_sql = (
            """INSERT INTO comments (truyen_id, username, content) 
            VALUES ('{id}', '{uname}', '{cont}')
            """).format(id=truyen_id, uname=username, cont=content)
        try:
            cur.execute(is_sql)
            db.commit()
        except sqlite3.Error as e:
            pass
        return redirect(url_for("truyen_detail", truyen_id=truyen_id) + "#doc")
    
@app.route("/login", methods=["GET","POST"])
def login():
    error = None    

    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")

        sql = ("""SELECT * FROM users WHERE username = '{uname}' AND password = '{paswd}'"""
            ).format(uname=username, paswd=password)

        db = get_db()
        cur = db.cursor()
        success=False
        try:
            cur.execute(sql)
            user = cur.fetchone()
            success = user is not None
        except sqlite3.Error as e:
            success = False
            error = f"Loi: {e}",401

        #Ghi log
        cur.execute(
            "INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, ?)",
            (username, request.remote_addr, 1 if success else 0)
        )
        db.commit()

        if success:
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("index"))
        elif error is None:
            error = "Sai tên đăng nhập hoặc mật khẩu !"
    status_code = 401 if error else 200
    return render_template("login.html", error=error, success=None),status_code

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[!] Chua tim thay database")
    app.run(host="0.0.0.0", port=5000, debug=True)
