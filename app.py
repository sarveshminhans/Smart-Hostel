from flask import Flask, request, session, redirect, url_for, render_template, flash
import sqlite3
import hashlib
import os
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "smart_hostel_secret_key"
DB = "hostel.db"
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# -------------------- DATABASE --------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users & roles
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Admin','Student','Staff'))
    )
    """)

    # Students
    cur.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER UNIQUE,
        hostel TEXT,
        block TEXT,
        room TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Staff
    cur.execute("""
    CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        name TEXT,
        phone TEXT,
        designation TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Issue categories
    cur.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)
    default_categories = ['Plumbing', 'Electrical', 'Cleanliness', 'Internet', 'Furniture']
    for cat in default_categories:
        cur.execute("INSERT OR IGNORE INTO categories (name) VALUES (?)", (cat,))

    # Issue status workflow
    cur.execute("""
    CREATE TABLE IF NOT EXISTS issue_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)
    for status in ['Reported', 'Assigned', 'In Progress', 'Resolved', 'Closed']:
        cur.execute("INSERT OR IGNORE INTO issue_status (name) VALUES (?)", (status,))

    # Issues
    cur.execute("""
CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,

    hostel TEXT,
    block TEXT,
    room TEXT,

    category INTEGER,
    priority TEXT,
    visibility TEXT,
    status TEXT DEFAULT 'Reported',

    student_id INTEGER,
    assigned_to INTEGER,

    created_at TEXT,
    media TEXT,

    FOREIGN KEY(category) REFERENCES categories(id),
    FOREIGN KEY(student_id) REFERENCES students(id),
    FOREIGN KEY(assigned_to) REFERENCES staff(id)
)
""")


    # Issue history
    cur.execute("""
    CREATE TABLE IF NOT EXISTS issue_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER,
        status TEXT,
        remark TEXT,
        timestamp TEXT,
        FOREIGN KEY(issue_id) REFERENCES issues(id)
    )
    """)

    # Announcements
    cur.execute("""
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        hostel TEXT,
        created_at TEXT
    )
    """)

    # Announcement targeting
    cur.execute("""
    CREATE TABLE IF NOT EXISTS announcement_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        announcement_id INTEGER,
        target_type TEXT, -- 'hostel', 'role', 'block'
        target_value TEXT,
        FOREIGN KEY(announcement_id) REFERENCES announcements(id)
    )
    """)

    # Lost & Found
    cur.execute("""
    CREATE TABLE IF NOT EXISTS lost_found (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT,
        location TEXT,
        date TEXT,
        images TEXT,
        created_at TEXT,
        reported_by TEXT,
        reported_by_user_id INTEGER,
        status TEXT -- 'Lost', 'Found', 'Claimed',
    )
    """)

    # Comments
    cur.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER,
        user_id INTEGER,
        comment TEXT,
        timestamp TEXT,
        FOREIGN KEY(issue_id) REFERENCES issues(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Default admin account
    if cur.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        cur.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",
                    ("admin@123", hash_password("admin@123"), "Admin"))

    conn.commit()
    conn.close()

# -------------------- DECORATORS --------------------
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "Admin":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def staff_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "Staff":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# -------------------- HOME --------------------
@app.route("/")
def home():
    return render_template("home.html")
@app.route("/contact")
def contact():
    return render_template("contact.html")
@app.route("/about")
def about():
    return render_template("about.html")

@app.template_filter("format_datetime")
def format_datetime(value):
    """
    Converts ISO datetime string to readable format
    """
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return value
@app.template_filter("elapsed_time")
def elapsed_time(value):
    """
    Returns human-readable elapsed time from ISO datetime
    """
    if not value:
        return "—"

    try:
        created = datetime.fromisoformat(value)
        now = datetime.now()
        delta = now - created

        minutes = int(delta.total_seconds() // 60)
        hours = minutes // 60
        days = hours // 24

        if minutes < 1:
            return "Just now"
        elif minutes < 60:
            return f"{minutes} min ago"
        elif hours < 24:
            return f"{hours} hr {minutes % 60} min ago"
        else:
            return f"{days} day(s) ago"

    except Exception:
        return value

@app.template_filter("completion_time")
def completion_time(created_at, resolved_at):
    start = datetime.fromisoformat(created_at)
    end = datetime.fromisoformat(resolved_at)
    diff = end - start

    hours = diff.seconds // 3600
    minutes = (diff.seconds % 3600) // 60

    if diff.days > 0:
        return f"{diff.days}d {hours}h"
    return f"{hours}h {minutes}m"

# -------------------- AUTH --------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]
        hostel = request.form["hostel"]
        block = request.form["block"]
        room = request.form["room"]

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(password), "Student")
            )

            user_id = cur.lastrowid

            cur.execute(
                "INSERT INTO students (name, user_id, hostel, block, room) VALUES (?, ?, ?, ?, ?)",
                (name, user_id, hostel, block, room)
            )

            conn.commit()
            session["register_success"] = "Registration successful. Please log in."
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            session["register_error"] = "Username already exists"
            return redirect(url_for("register"))

        finally:
            conn.close()
    error = session.pop("register_error", None)
    success = session.pop("register_success", None)

    return render_template(
        "register.html",
        error=error,
        success=success
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]

            if user["role"] == "Admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "Student":
                return redirect(url_for("student_home"))
            else:
                return redirect(url_for("staff_home"))
        session["login_error"] = "Invalid username or password"
        return redirect(url_for("login"))

    error = session.pop("login_error", None)
    return render_template("login.html", error=error)



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------- STUDENT --------------------
@app.route("/student")
@login_required
def student_home():
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    conn = get_db()
    student = conn.execute("""
        SELECT id, name, hostel
        FROM students
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if not student:
        conn.close()
        flash("Student profile not found")
        return redirect(url_for("logout"))

    student_id = student["id"]
    total_issues = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE student_id = ?
    """, (student_id,)).fetchone()[0]

    pending_issues = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE student_id = ?
          AND status != 'Resolved'
    """, (student_id,)).fetchone()[0]

    resolved_issues = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE student_id = ?
          AND status = 'Resolved'
    """, (student_id,)).fetchone()[0]
    unresolved_issues = conn.execute("""
        SELECT
            i.id,
            i.title,
            i.status,
            i.priority,
            i.created_at,
            i.block,
            i.room,
            c.name AS category_name,
            s.name AS assigned_to_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        LEFT JOIN staff s ON i.assigned_to = s.id
        WHERE i.student_id = ?
          AND i.status != 'Resolved'
        ORDER BY i.created_at DESC
        LIMIT 5
    """, (student_id,)).fetchall()
    latest_item = conn.execute("""
        SELECT *
        FROM lost_found
        WHERE status<>'Claimed'
        ORDER BY datetime(created_at) DESC
        LIMIT 1
    """).fetchone()
    latest_announcement = conn.execute("""
        SELECT title, content, created_at
        FROM announcements
        WHERE hostel IS NULL OR hostel = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (student["hostel"],)).fetchone()

    conn.close()

    return render_template(
        "student_home.html",
        student_name=student["name"],
        latest_item=latest_item,
        unresolved_issues=unresolved_issues,
        stats={
            "total_issues": total_issues,
            "pending_issues": pending_issues,
            "resolved_issues": resolved_issues,
        },
        announcement=latest_announcement
    )



@app.route("/student/issues")
@login_required
def student_issues():
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    conn = get_db()
    student = conn.execute("""
        SELECT id,name
        FROM students
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()
    issues = conn.execute("""
        SELECT i.id,
               i.title,
               i.status,
               i.priority,
               i.created_at,
               i.block,
               i.room,
               c.name AS category_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.student_id = ?
        ORDER BY i.created_at DESC
    """, (student["id"],)).fetchall()

    conn.close()

    return render_template(
        "student_issues.html",
        issue=issues,       
        student_name=student["name"] if student else "Student"
    )

@app.route("/student/issue/<int:issue_id>")
@login_required
def student_issue_detail(issue_id):
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    conn = get_db()

    student = conn.execute("""
        SELECT id, name
        FROM students
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if not student:
        conn.close()
        flash("Student not found")
        return redirect(url_for("student_home"))

    issue = conn.execute("""
        SELECT i.*, c.name AS category_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.id = ? AND i.student_id = ?
    """, (issue_id, student["id"])).fetchone()

    if not issue:
        conn.close()
        flash("Issue not found or access denied")
        return redirect(url_for("student_issues"))

    history = conn.execute("""
        SELECT status, timestamp
        FROM issue_history
        WHERE issue_id = ?
        ORDER BY timestamp ASC
    """, (issue_id,)).fetchall()

    conn.close()

    return render_template(
        "student_issue_detail.html",
        issue=issue,
        history=history,
        student_name=student["name"]
    )



@app.route("/issue/report", methods=["GET", "POST"])
@login_required
def report_issue_category():
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    conn = get_db()

    if request.method == "POST":
        category = request.form.get("category")
        if not category:
            flash("Please select a category")
            return redirect(url_for("report_issue_category"))

        session["report_category"] = category
        conn.close()
        return redirect(url_for("report_issue_details"))

    categories = conn.execute(
        "SELECT name FROM categories ORDER BY name"
    ).fetchall()

    conn.close()

    return render_template(
        "issue_category.html",
        categories=categories
    )

@app.route("/issue/report/details", methods=["GET", "POST"])
@login_required
def report_issue_details():
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    if "report_category" not in session:
        return redirect(url_for("report_issue_category"))

    if request.method == "POST":
        session["report_priority"] = request.form["priority"]
        session["report_description"] = request.form["description"]

        media_files = []

        for file in request.files.getlist("media"):
            if file and file.filename:
                filename = secure_filename(file.filename)
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                media_files.append(filename)   

        session["report_media"] = ",".join(media_files)

        return redirect(url_for("report_issue_location"))

    return render_template(
        "issue_detail.html",
        category=session["report_category"]
    )


@app.route("/issue/report/location", methods=["GET", "POST"])
@login_required
def report_issue_location():
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    conn = get_db()

    student = conn.execute("""
        SELECT hostel, block, room
        FROM students
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if request.method == "POST":
        hostel = request.form.get("hostel")
        block = request.form.get("block")
        room = request.form.get("room")

        if request.form.get("is_common_area"):
            block = "Common Area"
            room = request.form.get("common_area")

        student_id = conn.execute("""
            SELECT id FROM students WHERE user_id = ?
        """, (session["user_id"],)).fetchone()["id"]

        category_id = conn.execute(
            "SELECT id FROM categories WHERE name=?",
            (session["report_category"],)
        ).fetchone()["id"]

        conn.execute("""
            INSERT INTO issues
            (title, description, hostel, block, room,
             category, priority, student_id, media, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session["report_category"] + " Issue",
            session["report_description"],
            hostel,
            block,
            room,
            category_id,
            session["report_priority"],
            student_id,
            session.get("report_media"),   
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        for k in list(session.keys()):
            if k.startswith("report_"):
                session.pop(k)

        return redirect(url_for("student_home"))

    conn.close()
    return render_template("issue_location.html", student=student)


@app.route("/announcements")
@login_required
def student_announcement():
    conn = get_db()

    if session.get("role") == "Student":
        student = conn.execute("""
            SELECT hostel, block
            FROM students
            WHERE user_id = ?
        """, (session["user_id"],)).fetchone()

        announcements = conn.execute("""
            SELECT DISTINCT a.*
            FROM announcements a
            LEFT JOIN announcement_targets t
                ON a.id = t.announcement_id
            WHERE
                t.target_type IS NULL
                OR (t.target_type = 'hostel' AND t.target_value = ?)
                OR (t.target_type = 'block' AND t.target_value = ?)
                OR (t.target_type = 'role' AND t.target_value = 'Student')
            ORDER BY a.created_at DESC
        """, (student["hostel"], student["block"])).fetchall()

    else:
        announcements = conn.execute("""
            SELECT *
            FROM announcements
            ORDER BY created_at DESC
        """).fetchall()

    conn.close()

    return render_template(
        "student_announcement.html",
        announcements=announcements
    )


# -------------------- ADMIN -------------------- #
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()

    total = conn.execute("SELECT COUNT(*) FROM issues").fetchone()[0]

    resolved = conn.execute("""
        SELECT COUNT(*) FROM issues WHERE status = 'Resolved'
    """).fetchone()[0]

    pending = conn.execute("""
        SELECT COUNT(*) FROM issues
        WHERE status IN ('Reported', 'Assigned', 'In Progress')
    """).fetchone()[0]

    avg_resolution = conn.execute("""
        SELECT AVG(
            (julianday(h.timestamp) - julianday(i.created_at)) * 24
        )
        FROM issues i
        JOIN issue_history h ON i.id = h.issue_id
        WHERE h.status = 'Resolved'
    """).fetchone()[0]

    stats = {
        "resolved": resolved,
        "pending": pending,
        "avg_resolution": round(avg_resolution, 2) if avg_resolution else 0,
        "announcements": conn.execute(
            "SELECT COUNT(*) FROM announcements"
        ).fetchone()[0],
        "resolved_percent": int((resolved / total) * 100) if total else 0
    }

    issue_categories = conn.execute("""
        SELECT c.name,
               COUNT(i.id) * 100.0 / (SELECT COUNT(*) FROM issues) AS percent
        FROM categories c
        LEFT JOIN issues i ON c.id = i.category
        GROUP BY c.id
    """).fetchall()

    critical_issues = conn.execute("""
        SELECT
            i.id,
            i.hostel,
            i.block,
            i.room,
            c.name AS category,
            i.created_at AS elapsed,
            i.status
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.assigned_to IS NULL
        ORDER BY i.created_at DESC
    """).fetchall()

    conn.close()

    return render_template(
        "adminhome.html",
        stats=stats,
        issue_categories=issue_categories,
        critical_issues=critical_issues
    )

@app.route("/admin/issues")
@admin_required
def admin_issues():
    conn = get_db()

    issues = conn.execute("""
        SELECT 
            i.*,
            c.name AS category_name,
            st.name AS assigned_to_name,
            stu.name AS reporter_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        LEFT JOIN staff st ON i.assigned_to = st.id
        LEFT JOIN students stu ON i.student_id = stu.id
        ORDER BY i.created_at DESC
    """).fetchall()

    conn.close()
    return render_template("adminissue.html", issues=issues)

@app.route("/admin/staff")
@admin_required
def admin_staff():
    conn = get_db()

    staff = conn.execute("""
        SELECT 
            s.id,
            s.name,
            s.designation,
            s.phone,
            u.username,
            COUNT(DISTINCT i.id) AS active_tasks
        FROM staff s
        JOIN users u ON s.user_id = u.id
        LEFT JOIN issues i
            ON i.assigned_to = s.id
            AND i.status IN ('Assigned', 'In Progress')
        GROUP BY s.id, s.name, s.designation, s.phone, u.username
        ORDER BY s.name
    """).fetchall()

    total_staff = len(staff)

    active_tasks = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE status IN ('Assigned', 'In Progress')
    """).fetchone()[0]

    active_issues = conn.execute("""
        SELECT 
            i.id,
            i.title,
            i.status,
            i.priority,
            i.created_at,
            i.hostel,
            i.block,
            i.room,
            c.name AS category_name,
            st.name AS staff_name
        FROM issues i
        LEFT JOIN staff st ON i.assigned_to = st.id
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.status IN ('Assigned', 'In Progress')
        ORDER BY i.created_at DESC
    """).fetchall()
    free_staff = sum(1 for s in staff if s["active_tasks"] == 0)

    conn.close()

    return render_template(
        "adminstaff.html",
        staff=staff,
        total_staff=total_staff,
        active_tasks=active_tasks,
        active_issues=active_issues,
        free_staff=free_staff
    )
@app.route("/admin/staff/delete/<int:staff_id>", methods=["POST"])
@admin_required
def delete_staff(staff_id):
    conn = get_db()

    staff = conn.execute(
        "SELECT user_id FROM staff WHERE id = ?",
        (staff_id,)
    ).fetchone()

    if not staff:
        conn.close()
        flash("Staff not found")
        return redirect(url_for("admin_staff"))

    active = conn.execute("""
        SELECT COUNT(*) FROM issues
        WHERE assigned_to = ?
        AND status IN ('Assigned', 'In Progress')
    """, (staff_id,)).fetchone()[0]

    if active > 0:
        conn.close()
        flash("Cannot delete staff with active tasks")
        return redirect(url_for("admin_staff"))

    conn.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (staff["user_id"],))

    conn.commit()
    conn.close()

    flash("Staff deleted successfully")
    return redirect(url_for("admin_staff"))



@app.route("/admin/staff/add", methods=["GET", "POST"])
@login_required
def add_staff():
    if session.get("role") != "Admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]
        designation = request.form["designation"]
        phone = request.form["phone"]

        conn = get_db()

        user_exists = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        phone_exists = conn.execute(
            "SELECT id FROM staff WHERE phone = ?",
            (phone,)
        ).fetchone()

        conn.close()

        if user_exists:
            session["error"] = "Username already exists"
            return redirect(url_for("add_staff"))

        if phone_exists:
            session["error"] = "Phone number already exists"
            return redirect(url_for("add_staff"))

        conn = get_db()

        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hash_password(password), "Staff")
        )
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        conn.execute(
            "INSERT INTO staff (user_id, name, designation, phone) VALUES (?, ?, ?, ?)",
            (user_id, name, designation, phone)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("admin_staff"))

    error = session.pop("error", None)
    return render_template("add_staff.html", error=error)



@app.route("/admin/staff/<int:staff_id>/assign", methods=["GET", "POST"])
@admin_required
def assign_tasks(staff_id):
    conn = get_db()

    if request.method == "POST":
        issue_ids = request.form.getlist("issue_ids")
        expected_time = request.form.get("expected_completion")
        instructions = request.form.get("instructions", "")

        if not issue_ids:
            flash("Please select at least one issue")
            conn.close()
            return redirect(url_for("assign_tasks", staff_id=staff_id))

        for issue_id in issue_ids:

            conn.execute("""
                UPDATE issues
                SET assigned_to = ?, status = 'Assigned'
                WHERE id = ?
            """, (staff_id, issue_id))

            conn.execute("""
                INSERT INTO issue_history
                (issue_id, status, remark, timestamp)
                VALUES (?, ?, ?, ?)
            """, (
                issue_id,
                "Assigned",
                f"Deadline: {expected_time}. {instructions}",
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

        flash("Tasks assigned successfully")
        return redirect(url_for("admin_issues"))

    staff = conn.execute("""
        SELECT id, name, designation, phone
        FROM staff
        WHERE id = ?
    """, (staff_id,)).fetchone()

    if not staff:
        conn.close()
        flash("Staff not found")
        return redirect(url_for("admin_staff"))

    issues = conn.execute("""
        SELECT 
            i.id,
            i.title,
            i.hostel,                          
            i.block,
            i.room,
            i.priority,
            c.name AS category_name,
            i.created_at
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.status = 'Reported'
        ORDER BY i.created_at ASC
    """).fetchall()

    active_task_count = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE assigned_to = ?
          AND status IN ('Assigned', 'In Progress')
    """, (staff_id,)).fetchone()[0]

    conn.close()

    return render_template(
        "task_assignment.html",
        staff=staff,
        issues=issues,
        active_tasks=active_task_count
    )


@app.route("/admin/issue/<int:issue_id>/assign")
@admin_required
def assign_issue_page(issue_id):
    conn = get_db()

    issue = conn.execute("""
        SELECT 
            i.id,
            i.title,
            i.description,
            i.hostel,
            i.block,
            i.room,
            i.status,
            i.priority,
            i.media,
            c.name AS category_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.id = ?
    """, (issue_id,)).fetchone()

    if not issue or issue["status"] != "Reported":
        conn.close()
        flash("Issue already assigned or invalid")
        return redirect(url_for("admin_issues"))

    staff = conn.execute("""
        SELECT 
            s.id,
            s.name,
            s.designation,
            s.phone,
            COUNT(DISTINCT i.id) AS active_tasks
        FROM staff s
        LEFT JOIN issues i
            ON i.assigned_to = s.id
            AND i.status IN ('Assigned', 'In Progress')
        GROUP BY s.id, s.name, s.designation, s.phone
        ORDER BY active_tasks ASC, s.name
    """).fetchall()

    conn.close()

    return render_template(
        "assign_issue.html",
        issue=issue,
        staff=staff
    )



@app.route("/admin/issue/<int:issue_id>/assign/<int:staff_id>", methods=["POST"])
@admin_required
def assign_issue(issue_id, staff_id):
    conn = get_db()

    issue = conn.execute("""
        SELECT status
        FROM issues
        WHERE id = ?
    """, (issue_id,)).fetchone()

    if not issue or issue["status"] != "Reported":
        conn.close()
        flash("Issue already assigned")
        return redirect(url_for("admin_issues"))

    conn.execute("""
        UPDATE issues
        SET assigned_to = ?, status = 'Assigned'
        WHERE id = ?
    """, (staff_id, issue_id))

    conn.execute("""
        INSERT INTO issue_history (issue_id, status, remark, timestamp)
        VALUES (?, 'Assigned', 'Assigned by admin', ?)
    """, (issue_id, datetime.now().isoformat()))

    conn.commit()
    conn.close()

    flash("Issue assigned successfully")
    return redirect(url_for("admin_issues"))



@app.route("/admin/announcements", methods=["GET", "POST"])
@admin_required
def admin_announcements():
    conn = get_db()

    if request.method == "POST":
        conn.execute("""
            INSERT INTO announcements (title, content, hostel, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            request.form["title"],
            request.form["content"],
            request.form.get("target_hostel"),
            datetime.now().isoformat()
        ))
        conn.commit()

    announcements = conn.execute("""
        SELECT *
        FROM announcements
        ORDER BY created_at DESC
    """).fetchall()
    hostels = conn.execute("""
        SELECT DISTINCT hostel
        FROM students
        WHERE hostel IS NOT NULL AND hostel != ''
        ORDER BY hostel
    """).fetchall()

    conn.close()

    return render_template(
        "adminannouncements.html",
        announcements=announcements,
        hostels=hostels
    )
@app.route("/admin/announcements/delete/<int:ann_id>")
@admin_required
def delete_announcement(ann_id):
    conn = get_db()
    conn.execute(
        "DELETE FROM announcements WHERE id = ?",
        (ann_id,)
    )
    conn.commit()
    conn.close()
    flash("Announcement deleted successfully")
    return redirect(url_for("admin_announcements"))

# -------------------- STAFF --------------------
@app.route("/staff")
@login_required
def staff_home():
    if session.get("role") != "Staff":
        return redirect(url_for("login"))

    conn = get_db()

    staff = conn.execute("""
    SELECT id, name, designation
    FROM staff
    WHERE user_id = ?
""", (session["user_id"],)).fetchone()


    if not staff:
        conn.close()
        flash("Staff profile not found")
        return redirect(url_for("logout"))

    staff_id = staff["id"]

    total_tasks = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE assigned_to = ?
    """, (staff_id,)).fetchone()[0]

    pending_tasks = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE assigned_to = ?
        AND status != 'Resolved'
    """, (staff_id,)).fetchone()[0]

    completed_tasks = conn.execute("""
        SELECT COUNT(*)
        FROM issues
        WHERE assigned_to = ?
        AND status = 'Resolved'
    """, (staff_id,)).fetchone()[0]

    issues = conn.execute("""
        SELECT i.*, c.name AS category_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.assigned_to = ? and i.status<>'Resolved'
        ORDER BY i.created_at DESC
    """, (staff_id,)).fetchall()

    conn.close()

    return render_template(
        "staff_home.html",
        issues=issues,
        stats={
            "total_tasks": total_tasks,
            "pending_tasks": pending_tasks,
            "completed_tasks": completed_tasks
        },
        staff=staff
    )
@app.route("/staff/issue/<int:issue_id>")
@login_required
def staff_view_issue(issue_id):
    if session.get("role") != "Staff":
        return redirect(url_for("login"))

    conn = get_db()

    staff = conn.execute("""
        SELECT id, name
        FROM staff
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if not staff:
        conn.close()
        flash("Staff profile not found")
        return redirect(url_for("logout"))

    staff_id = staff["id"]
    issue = conn.execute("""
        SELECT 
            i.*,
            c.name AS category_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.id = ?
          AND i.assigned_to = ?
    """, (issue_id, staff_id)).fetchone()

    if not issue:
        conn.close()
        flash("Issue not found or access denied")
        return redirect(url_for("staff_home"))
    history = conn.execute("""
        SELECT status, timestamp
        FROM issue_history
        WHERE issue_id = ?
        ORDER BY datetime(timestamp) ASC
    """, (issue_id,)).fetchall()

    conn.close()

    return render_template(
        "staff_view_issue.html",
        issue=issue,
        history=history,
        staff_name=staff["name"]
    )

@app.route("/staff/pending_issues")
@login_required
def pending_issues():
    if session.get("role") != "Staff":
        return redirect(url_for("login"))

    conn = get_db()
    staff = conn.execute("""
    SELECT id, name, designation
    FROM staff
    WHERE user_id = ?
""", (session["user_id"],)).fetchone()


    if not staff:
        conn.close()
        flash("Staff profile not found")
        return redirect(url_for("logout"))

    staff_id = staff["id"]
    issues = conn.execute("""
    SELECT *
    FROM issues
    WHERE assigned_to = ?
        AND status = 'Assigned'
    ORDER BY created_at DESC
""",(staff_id,)).fetchall()
    conn.close()
    return render_template("staff_pending_issues.html", issues=issues)

@app.route("/staff/in_progress")
@login_required
def staff_in_progress():
    if session.get("role") != "Staff":
        return redirect(url_for("login"))

    conn = get_db()

    staff = conn.execute("""
        SELECT id
        FROM staff
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    issues = conn.execute("""
        SELECT i.*, c.name AS category_name
        FROM issues i
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.assigned_to = ?
        AND i.status = 'In Progress'
        ORDER BY i.created_at DESC
    """, (staff["id"],)).fetchall()

    conn.close()

    return render_template(
        "staff_in_progress.html",
        issues=issues
    )

@app.route("/staff/resolved_issues")
@login_required
def resolved_issues():
    if session.get("role") != "Staff":
        return redirect(url_for("login"))

    conn = get_db()

    issues = conn.execute("""
        SELECT 
            i.id,
            i.hostel,
            i.block,
            i.room,
            i.created_at,
            c.name AS category_name,
            h.timestamp AS resolved_at
        FROM issues i
        JOIN issue_history h 
            ON i.id = h.issue_id
            AND h.status = 'Resolved'
        LEFT JOIN categories c ON i.category = c.id
        WHERE i.status = 'Resolved'
        ORDER BY h.timestamp DESC
    """).fetchall()

    conn.close()

    return render_template("staff_issue_resolved.html", issues=issues)
 
# -------------------- ISSUE UPDATE & ASSIGNMENT --------------------




@app.route("/issue/<int:issue_id>/update_status", methods=["POST"])
@login_required
def update_issue_status(issue_id):
    new_status = request.form["status"]
    remark = request.form.get("remark", "")
    conn = get_db()
    conn.execute("UPDATE issues SET status=? WHERE id=?", (new_status, issue_id))
    conn.execute("INSERT INTO issue_history (issue_id, status, remark, timestamp) VALUES (?,?,?,?)",
                 (issue_id, new_status, remark, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("home"))

# -------------------- COMMENTS --------------------
@app.route("/issue/<int:issue_id>/comments", methods=["GET","POST"])
@login_required
def issue_comments(issue_id):
    conn = get_db()
    if request.method == "POST":
        comment_text = request.form["comment"]
        conn.execute("INSERT INTO comments (issue_id, user_id, comment, timestamp) VALUES (?,?,?,?)",
                     (issue_id, session["user_id"], comment_text, datetime.now().isoformat()))
        conn.commit()
    comments = conn.execute("""
        SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.issue_id=?
        ORDER BY c.timestamp ASC
    """, (issue_id,)).fetchall()
    conn.close()
    return render_template("issue_comments.html", comments=comments, issue_id=issue_id)

# -------------------- LOST & FOUND --------------------
@app.route("/student/lostfound")
@login_required
def student_lost_found():
    if session.get("role") != "Student":
        return redirect(url_for("login"))

    conn = get_db()
    items = conn.execute("SELECT * FROM lost_found ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("student_lost_found.html", items=items)

@app.route("/lostfound", methods=["GET", "POST"])
@login_required
def lost_found():
    conn = get_db()


    student = conn.execute("""
        SELECT name,id
        FROM students
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if not student:
        conn.close()
        flash("Student profile not found")
        return redirect(url_for("logout"))

    reporter_name = student["name"]

    if request.method == "POST":
        description = request.form["description"]
        location = request.form["location"]
        date_str = request.form["date"]
        status = request.form["status"]

        images_files = []
        for file in request.files.getlist("images"):
            if file and file.filename:
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                images_files.append(filename)

        images_str = ",".join(images_files)

        conn.execute("""
            INSERT INTO lost_found
            (description, location, date, images, status, created_at, reported_by,reported_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?,?)
        """, (
            description,
            location,
            date_str,
            images_str,
            status,
            datetime.now().isoformat(),
            reporter_name,
            student["id"]
        ))

        conn.commit()
        conn.close()
        return redirect(url_for("student_lost_found"))


    items = conn.execute("""
        SELECT *
        FROM lost_found
        ORDER BY created_at DESC
    """).fetchall()

    conn.close()
    return render_template("lost_found.html", items=items)

@app.route("/lostfound/<int:item_id>/contact")
@login_required
def contact_owner(item_id):
    conn = get_db()

    item = conn.execute("""
        SELECT
            lf.*,
            s.name,
            s.hostel,
            s.block,
            s.room
        FROM lost_found lf
        JOIN students s ON lf.reported_by_user_id = s.id
        WHERE lf.id = ?
    """, (item_id,)).fetchone()

    conn.close()

    if not item:
        flash("Item not found")
        return redirect(url_for("student_lost_found"))

    return render_template(
        "contact_owner.html",
        item=item
    )

@app.route("/lostfound/<int:item_id>/claim", methods=["POST"])
@login_required
def claim_item(item_id):
    conn = get_db()

    item = conn.execute("""
        SELECT *
        FROM lost_found
        WHERE id = ?
    """, (item_id,)).fetchone()

    if not item:
        conn.close()
        flash("Item not found")
        return redirect(url_for("student_lost_found"))

    if item["status"] != "Found":
        conn.close()
        flash("This item cannot be claimed")
        return redirect(url_for("student_lost_found"))

    student = conn.execute("""
        SELECT id
        FROM students
        WHERE user_id = ?
    """, (session["user_id"],)).fetchone()

    if student and item["reported_by_user_id"] == student["id"]:
        conn.close()
        flash("You cannot claim your own reported item")
        return redirect(url_for("student_lost_found"))

    conn.execute("""
        UPDATE lost_found
        SET status = 'Claimed'
        WHERE id = ?
    """, (item_id,))

    conn.commit()
    conn.close()

    flash("Item claimed successfully")
    return redirect(url_for("contact_owner", item_id=item_id))


# -------------------- ANALYTICS DASHBOARD --------------------
@app.route("/admin/analytics")
@admin_required
def analytics():
    conn = get_db()
    # Count issues by category
    cat_counts = conn.execute("""
        SELECT c.name, COUNT(i.id) as count
        FROM categories c LEFT JOIN issues i ON c.id = i.category
        GROUP BY c.id
    """).fetchall()
    # Issue status counts
    status_counts = conn.execute("""
        SELECT s.name, COUNT(i.id)
        FROM issue_status s LEFT JOIN issues i ON s.name = i.status
        GROUP BY s.id
    """).fetchall()
    conn.close()
    return render_template("analytics.html", cat_counts=cat_counts, status_counts=status_counts)

# -------------------- MAIN --------------------
if __name__ == "__main__":
    init_db()
    app.run()    