
import streamlit as st
import sqlite3
import hashlib
import secrets
import pandas as pd
from supabase import create_client, Client
import base64

from datetime import datetime, date, time, timedelta
from pathlib import Path
from PIL import Image

# ==================================
# 1. APPLICATION SETTINGS
# ==================================

st.set_page_config(
    page_title="Leef Attendance System",
    
    page_icon="🎓",
    layout="wide"
)

DB_PATH = Path(__file__).with_name("attendance.db")
@st.cache_resource
def get_supabase() -> Client:
    return create_client(
        st.secrets["SUPABASE_URL"],
        st.secrets["SUPABASE_KEY"]
    )

# ==================================
# 2. DATABASE CONNECTION
# ==================================

def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    with connect_db() as conn:

        conn.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            check_in TEXT NOT NULL,
            check_out TEXT,
            reason TEXT,
            status TEXT DEFAULT 'inside',
            approved_by TEXT,
            FOREIGN KEY(student_id) REFERENCES students(id)
        );

        CREATE TABLE IF NOT EXISTS settings (
            setting TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)

        conn.execute("""
        INSERT OR IGNORE INTO settings
        VALUES ('break_start', '12:00')
        """)

        conn.execute("""
        INSERT OR IGNORE INTO settings
        VALUES ('break_end', '13:00')
        """)


create_database()



# ==================================
# 3. PASSWORD SECURITY
# ==================================

def hash_password(password):

    salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        260000
    )

    return salt + "$" + hashed.hex()


def check_password(password, stored):

    salt, saved_hash = stored.split("$")

    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        260000
    ).hex()

    return secrets.compare_digest(
        new_hash,
        saved_hash
    )


# ==================================
# 4. TIME FUNCTIONS
# ==================================

def current_time():
    return datetime.now()


def format_duration(minutes):

    hours = minutes // 60
    remaining = minutes % 60

    return f"{hours} hours {remaining} minutes"



def calculate_break(start, end):

    if start.tzinfo is not None:
        start = start.astimezone().replace(tzinfo=None)

    if end.tzinfo is not None:
        end = end.astimezone().replace(tzinfo=None)

    break_start = time.fromisoformat(
        get_setting("break_start")
    )

    break_end = time.fromisoformat(
        get_setting("break_end")
    )

    total_break = 0

    day = start.date()

    while day <= end.date():

        school_start = datetime.combine(
            day, time(9, 0)
        )

        school_end = datetime.combine(
            day, time(17, 0)
        )

        break_start_time = datetime.combine(
            day, break_start
        )

        break_end_time = datetime.combine(
            day, break_end
        )

        overlap_start = max(
            start, school_start, break_start_time
        )

        overlap_end = min(
            end, school_end, break_end_time
        )

        if overlap_end > overlap_start:
            total_break += int(
                (overlap_end - overlap_start).total_seconds() // 60
            )

        day += timedelta(days=1)

    return total_break

def get_setting(name):

    response = (
        get_supabase()
        .table("settings")
        .select("value")
        .eq("key", name)
        .limit(1)
        .execute()
    )

    if response.data:
        return response.data[0]["value"]

    return "12:00"


# ==================================
# 5. ADMIN SIGNUP
# ==================================


def signup():

    st.subheader("Create Admin / HOD Account")

    response = (
        get_supabase()
        .table("admins")
        .select("id", count="exact", head=True)
        .execute()
    )

    count = response.count or 0

    with st.form("signup"):

        username = st.text_input("Username")

        password = st.text_input(
            "Password",
            type="password"
        )

        confirm = st.text_input(
            "Confirm Password",
            type="password"
        )

        role = "admin" if count == 0 else "hod"

        if count == 0:
            st.info("The first account will be the Admin.")
        else:
            st.info("New accounts will be HOD accounts.")

        signup_code = ""

        if count > 0:
            signup_code = st.text_input(
                "HOD signup code",
                type="password"
            )

        submit = st.form_submit_button("Create Account")

        if submit:

            if len(username.strip()) < 3:
                st.error("Username must have at least 3 characters.")

            elif len(password) < 10:
                st.error("Password must have at least 10 characters.")

            elif password != confirm:
                st.error("Passwords do not match.")

            elif count > 0 and (
                not st.secrets.get("SIGNUP_CODE")
                or signup_code != st.secrets.get("SIGNUP_CODE")
            ):
                st.error("Invalid signup code.")

            else:

                try:
                    get_supabase().table("admins").insert({
                        "username": username.strip(),
                        "password_hash": hash_password(password),
                        "role": role,
                        "created_at": current_time().isoformat()
                    }).execute()

                    st.success("Account created successfully.")

                except Exception as e:

                    error_message = str(e).lower()

                    if "23505" in error_message or "duplicate key" in error_message:
                        st.error("Username already exists.")
                    else:
                        st.error("Could not create account. Please check your connection and try again.")


# ==================================
# 6. ADMIN LOGIN
# ==================================

def login():
    st.subheader("Admin / HOD Login")

    with st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        submit = st.form_submit_button("Login")

        if submit:
            response = (
                get_supabase()
                .table("admins")
                .select("*")
                .eq("username", username.strip())
                .limit(1)
                .execute()
            )

            if response.data:
                user = response.data[0]

                if check_password(password, user["password_hash"]):
                    st.session_state.admin = {
                        "id": user["id"],
                        "username": user["username"],
                        "role": user["role"]
                    }

                    st.rerun()
                else:
                    st.error("Incorrect username or password.")
            else:
                st.error("Incorrect username or password.")

# ==================================
# 7. PASSWORD RESET
# ==================================


def reset_password():

    st.subheader("Reset Password")

    with st.form("reset"):

        username = st.text_input("Username")

        reset_code = st.text_input(
            "Reset code",
            type="password"
        )

        new_password = st.text_input(
            "New password",
            type="password"
        )

        confirm = st.text_input(
            "Confirm new password",
            type="password"
        )

        submit = st.form_submit_button("Reset Password")

        if submit:

            if (
                not st.secrets.get("RESET_CODE")
                or reset_code != st.secrets.get("RESET_CODE")
            ):

                st.error("Invalid reset code.")

            elif len(new_password) < 10:

                st.error("Password must have at least 10 characters.")

            elif new_password != confirm:

                st.error("Passwords do not match.")

            else:

                try:

                    response = (
                        get_supabase()
                        .table("admins")
                        .update({
                            "password_hash": hash_password(new_password)
                        })
                        .eq("username", username.strip())
                        .execute()
                    )

                    if response.data:

                        st.success("Password reset successfully.")

                    else:

                        st.error("Username not found.")

                except Exception:

                    st.error("Could not reset password. Please try again.")


# ==================================
# 8. AUTHENTICATION PAGE
# ==================================

if "admin" not in st.session_state:

    #st.title("🎓 Student Attendance Monitoring System")
    
    #logo = Image.open(Path(__file__).parent / "images" / "leef_logo.png")
    

    logo_path = Path(__file__).parent / "images" / "leef_logo.png"

    logo_base64 = base64.b64encode(logo_path.read_bytes()).decode()

    st.markdown(
    f"""
    <div style="width:100%; text-align:center;">
        <img src="data:image/png;base64,{logo_base64}"
             style="width:150px; height:auto; display:block; margin:0 auto;">
    </div>
    """,
    unsafe_allow_html=True
    )
    st.markdown(
    """
    <h1 style="text-align: center; margin-top: 15px;">
        🎓 Leef Center Attendance System
    </h1>
    """,
    unsafe_allow_html=True
)

    #==========================================

    tab1, tab2, tab3 = st.tabs([
        "Login",
        "Signup",
        "Forgot Password"
    ])

    with tab1:
        login()

    with tab2:
        signup()

    with tab3:
        reset_password()

    st.stop()


admin = st.session_state.admin


# ==================================
# 9. SIDEBAR NAVIGATION
# ==================================

st.sidebar.title("Attendance System")

st.sidebar.write(
    "Logged in as: " + admin["username"]
)

st.sidebar.write(
    "Role: " + admin["role"].upper()
)

page = st.sidebar.radio(
    "Select Page",
    [
        "Dashboard",
        "Register Student",
        "Check In / Checkout",
        "HOD Approval",
        "Attendance Reports",
        "Settings"
    ]
)

if st.sidebar.button("Logout"):

    del st.session_state.admin
    st.rerun()


# ==================================
# 10. DASHBOARD
# ==================================

if page == "Dashboard":

    st.title("Attendance Dashboard")

    supabase = get_supabase()

    # Count registered students
    students_response = (
        supabase.table("students")
        .select("id", count="exact", head=True)
        .eq("is_active", True)
        .execute()
    )

    students = students_response.count or 0

    # Count students currently inside
    inside_response = (
        supabase.table("attendance")
        .select("id", count="exact", head=True)
        .eq("status", "inside")
        .is_("check_out", "null")
        .execute()
    )

    inside = inside_response.count or 0

    # Count pending approvals
    pending_response = (
        supabase.table("attendance")
        .select("id", count="exact", head=True)
        .eq("status", "pending")
        .execute()
    )

    pending = pending_response.count or 0

    # Count today's check-ins
    today_start = datetime.combine(
        date.today(), time.min
    ).astimezone()

    tomorrow_start = today_start + timedelta(days=1)

    today_response = (
        supabase.table("attendance")
        .select("id", count="exact", head=True)
        .gte("check_in", today_start.isoformat())
        .lt("check_in", tomorrow_start.isoformat())
        .execute()
    )

    today = today_response.count or 0

    # Display dashboard figures
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Registered Students", students)
    col2.metric("Currently Inside", inside)
    col3.metric("Pending Approval", pending)
    col4.metric("Today's Check-ins", today)

    # Show students currently inside
    st.subheader("Students Currently Inside")

    response = (
        supabase.table("attendance")
        .select("check_in, students(name)")
        .is_("check_out", "null")
        .eq("status", "inside")
        .order("check_in")
        .execute()
    )

    records = []

    for record in response.data:

        student = record.get("students")

        if isinstance(student, list):
            student = student[0] if student else {}

        if not student:
            student = {}

        records.append({
            "Name": student.get("name", "Unknown"),
            "Check-in": record.get("check_in")
        })

    st.dataframe(
        records,
        use_container_width=True,
        hide_index=True
    )

# ==================================
# 11. STUDENT REGISTRATION
# ==================================

elif page == "Register Student":

    if admin["role"] != "admin":
        st.error("Only Admin can register students.")
        st.stop()

    st.title("Register Student")

    with st.form("student_registration"):

        name = st.text_input("Student Full Name")

        submit = st.form_submit_button(
            "Register Student"
        )

        if submit:

            if not name.strip():
                st.error("Please enter the student's name.")

            else:
                get_supabase().table("students").insert({
                    "name": name.strip(),
                    "created_at": current_time().isoformat()
                }).execute()

                st.success(
                    name.strip() + " registered successfully."
                )

    st.subheader("Registered Students")

    response = (
        get_supabase()
        .table("students")
        .select("id, name, created_at")
        .eq("is_active", True)
        .order("id", desc=False)
        .execute()
    )

    st.dataframe(
        response.data,
        use_container_width=True,
        hide_index=True
    )

#============================================================================
#   DELETE STUDENT SECTION
#============================================================================
    st.subheader("Delete student")

    if admin["role"] == "admin":

        delete_response = (
            get_supabase()
            .table("students")
            .select("id, name, created_at")
            .eq("is_active", True)
            .order("id", desc=False)
            .execute()
    )
        

        active_students = delete_response.data or []

        if active_students:

            student_options = {
                f"{s['name']} (ID: {s['id']})": s["id"]
                for s in active_students
            }

            selected_student = st.selectbox(
                "Select student to archive",
                list(student_options.keys())
            )

            confirm_delete = st.checkbox(
                "I confirm that I want to delete this student."
            )

            if st.button("Delete Student", type="primary"):

                if confirm_delete:

                    student_id = student_options[selected_student]

                    get_supabase().table("students").update({
                        "is_active": False
                    }).eq("id", student_id).execute()

                    st.success("Student deleted successfully.")
                    st.rerun()

                else:
                    st.warning("Please confirm before deleting.")

        else:
            st.info("No active students available.")

    else:
        st.warning("Only Admin can delete students.")
#============================================================
# END OF DELETION FUNCTION
#============================================================

    if st.button("Transfer Existing Students to Supabase"):

        with connect_db() as conn:
            old_students = conn.execute("""
                SELECT id, name, created_at
                FROM students
            """).fetchall()

    ##        old_admins = conn.execute(
     #           "SELECT COUNT(*) FROM admins"
     #       ).fetchone()[0]
#
#            old_admin_rows = conn.execute("""
#                SELECT username, role
#                FROM admins
#            """).fetchall()
#
     #       old_attendance = conn.execute(
     #           "SELECT COUNT(*) FROM attendance"
     #       ).fetchone()[0]
#
            old_attendance_rows = conn.execute("""
                SELECT *
                FROM attendance
            """).fetchall()
#
     #       
     #   st.write("Old SQLite attendance details:", [dict(row) for row in old_attendance_rows])
#
     #   st.write("Old SQLite students:", len(old_students))
     #   st.write("Old SQLite student details:", [dict(row) for row in old_students])
     #   st.write("Old SQLite admin accounts:", old_admins)
     #   st.write("Old SQLite admin details:", [dict(row) for row in old_admin_rows])
     #   st.write("Old SQLite attendance records:", old_attendance)
#
     #   # Check existing Supabase records
        supabase = get_supabase()
#
     #   supabase_admins = supabase.table("admins").select(
     #       "id", count="exact", head=True
     #   ).execute()
#
     #   supabase_admin_rows = supabase.table("admins").select(
     #       "username, role"
     #   ).execute()
#
     #   st.write("Supabase admin details:", supabase_admin_rows.data)
#
     #   supabase_attendance = supabase.table("attendance").select(
     #       "id", count="exact", head=True
     #   ).execute()
#
     #   st.write("Supabase admin accounts:", supabase_admins.count)
     #   st.write("Supabase attendance records:", supabase_attendance.count)
#
    #=====================================================
               # Transfer students
    #=====================================================           
        existing = supabase.table("students").select(
            "id, name"
        ).execute()

        student_id_map = {}
        transferred = 0

        for student in old_students:

            matching_student = next(
                (
                    item for item in existing.data
                    if item["name"] == student["name"]
                ),
                None
            )

            if matching_student:
                new_student_id = matching_student["id"]

            else:
                new_student = supabase.table("students").insert({
                    "name": student["name"],
                    "created_at": student["created_at"],
                    "is_active": True
                }).execute()

                new_student_id = new_student.data[0]["id"]

                transferred += 1

            student_id_map[student["id"]] = new_student_id

        # Transfer attendance records
        attendance_transferred = 0

        for record in old_attendance_rows:

            new_student_id = student_id_map[record["student_id"]]

            existing_record = supabase.table("attendance").select(
                "id"
            ).eq(
                "student_id", new_student_id
            ).eq(
                "check_in", record["check_in"]
            ).execute()

            if not existing_record.data:

                supabase.table("attendance").insert({
                    "student_id": new_student_id,
                    "check_in": record["check_in"],
                    "check_out": record["check_out"],
                    "reason": record["reason"],
                    "status": record["status"],
                    "approved_by": record["approved_by"]
                }).execute()

                attendance_transferred += 1

        st.success(
            f"{attendance_transferred} attendance record(s) transferred!"
        )

        st.success(
            f"{transferred} existing student(s) transferred successfully!"
        )
        
        

# ==================================
# 12. STUDENT CHECK-IN / CHECKOUT
# ==================================

elif page == "Check In / Checkout":

    st.title("Student Movement")

    response = (
        get_supabase()
        .table("students")
        .select("id, name")
        .eq("is_active", True)
        .order("name")
        .execute()
    )

    students = response.data

    if not students:

        st.info("Register students first.")

    else:

        student_options = {
            f"{s['name']} (Record {s['id']})": s["id"]
            for s in students
        }

        selected = st.selectbox(
            "Select Student",
            list(student_options)
        )

        student_id = student_options[selected]

        response = (
            get_supabase()
            .table("attendance")
            .select("*")
            .eq("student_id", student_id)
            .is_("check_out", "null")
            .order("id", desc=True)
            .limit(1)
            .execute()
        )

        active = response.data[0] if response.data else None

        if active is None:

            st.info("Student is currently outside.")

            if st.button("Check In", type="primary"):

                get_supabase().table("attendance").insert({
                    "student_id": student_id,
                    "check_in": current_time().isoformat(),
                    "status": "inside"
                }).execute()

                st.success("Check-in recorded.")
                st.rerun()

        else:

            st.success("Student is currently inside.")

            st.write(
                "Check-in time: " +
                datetime.fromisoformat(
                    active["check_in"]
                ).strftime("%d %B %Y, %I:%M %p")
            )

            if active["status"] == "pending":

                st.warning(
                    "Checkout request is waiting for HOD approval."
                )

            else:

                with st.form("checkout_request"):

                    reason = st.text_area(
                        "Why is the student checking out?"
                    )

                    submit = st.form_submit_button(
                        "Submit Checkout Request"
                    )

                    if submit:

                        if len(reason.strip()) < 5:

                            st.error(
                                "Please provide a clear reason."
                            )

                        else:

                            get_supabase().table("attendance").update({
                                "reason": reason.strip(),
                                "status": "pending"
                            }).eq("id", active["id"]).execute()

                            st.success(
                                "Request sent to the HOD."
                            )

                            st.rerun()



# ==================================
# 13. HOD CHECKOUT APPROVAL
# ==================================

elif page == "HOD Approval":

    if admin["role"] != "hod":

        st.error("Access denied.")
        st.stop()

    st.title("HOD Checkout Approvals")

    supabase = get_supabase()

    response = (
        supabase
        .table("attendance")
        .select("id, student_id, check_in, reason")
        .eq("status", "pending")
        .is_("check_out", "null")
        .order("check_in")
        .execute()
    )

    requests = response.data or []

    students_response = (
        supabase
        .table("students")
        .select("id, name")
        .execute()
    )

    student_names = {
        student["id"]: student["name"]
        for student in students_response.data
    }

    if not requests:

        st.info("No pending checkout requests.")

    for request in requests:

        with st.container(border=True):

            st.subheader(
                student_names.get(
                    request["student_id"],
                    "Unknown student"
                )
            )

            st.write("Reason:", request["reason"])

            st.write("Check-in:", request["check_in"])

            col1, col2 = st.columns(2)

            if col1.button(
                "Approve",
                key=f"approve_{request['id']}"
            ):

                supabase.table("attendance").update({
                    "check_out": current_time().isoformat(),
                    "status": "approved",
                    "approved_by": admin["username"]
                }).eq("id", request["id"]).execute()

                st.success("Checkout approved.")
                st.rerun()

            if col2.button(
                "Reject",
                key=f"reject_{request['id']}"
            ):

                supabase.table("attendance").update({
                    "status": "inside",
                    "reason": None
                }).eq("id", request["id"]).execute()

                st.warning("Checkout request rejected.")
                st.rerun()




# ==================================
# 14. ATTENDANCE REPORTS
# ==================================

elif page == "Attendance Reports":

    st.title("Attendance Reports")

    start_date = st.date_input(
        "Start Date",
        date.today().replace(day=1)
    )

    end_date = st.date_input(
        "End Date",
        date.today()
    )

    if start_date > end_date:
        st.error("Invalid date range.")
        st.stop()

    response = (
        get_supabase()
        .table("attendance")
        .select(
            "id, check_in, check_out, reason, status, approved_by, "
            "student_id, students(id, name)"
        )
        .gte("check_in", start_date.isoformat() + "T00:00:00")
        .lt(
            "check_in",
            (end_date + timedelta(days=1)).isoformat() + "T00:00:00"
        )
        .order("check_in", desc=True)
        .execute()
    )

    records = []

    for record in response.data or []:

        student = record.get("students") or {}

        records.append({
            "id": record["id"],
            "check_in": record["check_in"],
            "check_out": record["check_out"],
            "reason": record["reason"],
            "status": record["status"],
            "approved_by": record["approved_by"],
            "student_id": record["student_id"],
            "name": student.get("name", "Unknown student")
        })

    report = []
    totals = []

    for record in records:

        start = datetime.fromisoformat(record["check_in"])

        end = (
            datetime.fromisoformat(record["check_out"])
            if record["check_out"]
            else current_time()
        )

        if start.tzinfo is not None:
            start = start.astimezone().replace(tzinfo=None)

        if end.tzinfo is not None:
            end = end.astimezone().replace(tzinfo=None)

        gross_minutes = max(
            0,
            int((end - start).total_seconds() // 60)
        )

        break_minutes = calculate_break(start, end)

        class_minutes = max(
            0,
            gross_minutes - break_minutes
        )

        week_start = (
            start.date() -
            timedelta(days=start.weekday())
        )

        month = start.strftime("%Y-%m")

        report.append({
            "Student Name": record["name"],
            "Date": start.strftime("%Y-%m-%d"),
            "Check In": start.strftime("%I:%M %p"),
            "Check Out": (
                datetime.fromisoformat(
                    record["check_out"]
                ).strftime("%I:%M %p")
                if record["check_out"]
                else "Still Inside"
            ),
            "Break Time": format_duration(break_minutes),
            "Time In Class": format_duration(class_minutes),
            "Status": record["status"],
            "Reason": record["reason"] or "",
            "Approved By": record["approved_by"] or ""
        })

        #=====================================================================
        #   Replaced part
        #======================================================================
        day_cursor = start.date()

        while day_cursor <= end.date():

            day_start = max(
                start,
                datetime.combine(day_cursor, time(9, 0))
            )

            day_end = min(
                end,
                datetime.combine(day_cursor, time(17, 0))
            )

            if day_end > day_start:
            
                day_gross = int(
                    (day_end - day_start).total_seconds() // 60
                )

                day_break = calculate_break(day_start, day_end)

                day_class = max(
                    0,
                    day_gross - day_break
                )

                day_week = (
                    day_cursor - timedelta(days=day_cursor.weekday())
                )

                totals.append({
                    "Student ID": record["student_id"],
                    "Student Name": record["name"],
                    "Date": day_cursor.isoformat(),
                    "Week Starting": day_week.isoformat(),
                    "Month": day_cursor.strftime("%Y-%m"),
                    "Minutes": day_class
                })

            day_cursor += timedelta(days=1)

    #=============================================================================

    if report:

        df = pd.DataFrame(report)

        st.subheader("Individual Attendance History")

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Daily Attendance Summary")

        daily = pd.DataFrame(totals)
        
        daily = daily.groupby(
            ["Student ID", "Student Name", "Date"],
            as_index=False
        )["Minutes"].sum()
        
        daily["Total Time In Class"] = (
            daily["Minutes"].apply(format_duration)
        )
        
        st.dataframe(
            daily.drop(columns=["Minutes"]),
            use_container_width=True,
            hide_index=True
        )


        st.subheader("Weekly Attendance Summary")

        weekly = pd.DataFrame(totals)

        weekly = weekly.groupby(
            ["Student ID", "Student Name", "Week Starting"],
            as_index=False
        )["Minutes"].sum()

        weekly["Total Time In Class"] = (
            weekly["Minutes"].apply(format_duration)
        )

        st.dataframe(
            weekly.drop(columns=["Minutes"]),
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Monthly Attendance Summary")

        monthly = pd.DataFrame(totals)

        monthly = monthly.groupby(
            ["Student ID", "Student Name", "Month"],
            as_index=False
        )["Minutes"].sum()

        monthly["Total Time In Class"] = (
            monthly["Minutes"].apply(format_duration)
        )

        st.dataframe(
            monthly.drop(columns=["Minutes"]),
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "Download Individual Report",
            df.to_csv(index=False).encode("utf-8"),
            "attendance_report.csv",
            "text/csv"
        )

        st.download_button(
            "Download Weekly Report",
            weekly.to_csv(index=False).encode("utf-8"),
            "weekly_report.csv",
            "text/csv"
        )

        st.download_button(
            "Download Monthly Report",
            monthly.to_csv(index=False).encode("utf-8"),
            "monthly_report.csv",
            "text/csv"
        )

    else:
        st.info("No attendance records found.")


# ==================================
# 15. BREAK TIME SETTINGS
# ==================================

elif page == "Settings":

    if admin["role"] != "admin":
        st.error("Only Admin can change settings.")
        st.stop()

    st.title("System Settings")

    st.subheader("Set Daily Break Time")

    
    with st.form("break_settings"):

        #break_start = st.time_input(
        #    "Break Start",
        #    time.fromisoformat(get_setting("break_start"))
        #)

        break_start = st.time_input(
            "Break Start",
            time.fromisoformat(get_setting("break_start")),
            format="12h"
        )


        #break_end = st.time_input(
        #    "Break End",
        #    time.fromisoformat(get_setting("break_end"))
        #)

        break_end = st.time_input(
            "Break End",
                 time.fromisoformat(get_setting("break_end")),
                 format="12h"
        )

        save = st.form_submit_button("Save Settings")

        if save:

            if break_end <= break_start:
                st.error(
                    "Break end must be later than break start."
                )

            else:

                supabase = get_supabase()

                supabase.table("settings").upsert({
                    "key": "break_start",
                    "value": break_start.strftime("%H:%M")
                }).execute()

                supabase.table("settings").upsert({
                    "key": "break_end",
                    "value": break_end.strftime("%H:%M")
                }).execute()

                st.toast("Break time updated!", icon="✅")
                