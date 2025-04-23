from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timezone
import os
from werkzeug.utils import secure_filename
from datetime import timedelta
import bcrypt
import smtplib
from email.mime.text import MIMEText
import random
import string
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
import cloudinary.api

now = datetime.now(timezone.utc)

# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})
# Database configuration
db_config = {
    'host': os.getenv('DB_HOST'),  # default to 'localhost' if not set
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': os.getenv('DATABASE_PORT')
}


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db_connection():
    return mysql.connector.connect(**db_config)


@app.route('/')
def home():
    return "Backend is running now!"


@app.route('/api/projects', methods=['GET', 'POST'])
def handle_projects():
    if request.method == 'GET':
        email = request.args.get('email')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            if email:
                # Get user's accessible categories first
                cursor.execute("""
                    SELECT c.name 
                    FROM user_access ua
                    JOIN categories c ON ua.category_id = c.id
                    WHERE ua.user_email = %s
                """, (email,))
                accessible_categories = [row['name'] for row in cursor.fetchall()]

                if not accessible_categories:
                    return jsonify([])  # Return empty if no access

                # Fetch only projects in accessible categories
                cursor.execute("""
                    SELECT * FROM projects 
                    WHERE category IN (%s)
                    """ % ','.join(['%s'] * len(accessible_categories)),
                               accessible_categories)
            else:
                # Admin or no email - return all projects
                cursor.execute("SELECT * FROM projects")

            projects = cursor.fetchall()
            # Add file URLs
            for project in projects:
                project['file_url'] = project['file_path']
            return jsonify(projects)

        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    elif request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            file_url = None
            file = request.files.get('file')

            if file and file.filename:
                # Validate file type
                filename = secure_filename(file.filename)
                if not allowed_file(filename):
                    return jsonify({"error": "File type not allowed"}), 400
                # Upload to Cloudinary
                upload_result = cloudinary.uploader.upload(
                    file,
                    folder=os.getenv('CLOUDINARY_FOLDER'),
                    resource_type="auto"
                )
                file_url = upload_result['secure_url']

            # Get form data
            data = request.form

            # Calculate AVE and PR values if not provided
            rate = float(data.get('rate', 0))
            height = float(data.get('height', 0))
            column = int(data.get('column', 0))
            ave_value = rate * height * column
            pr_value = ave_value * 3

            query = """
            INSERT INTO projects 
            (category, company, date, publication, section, page, title, colour, 
             rate, height, column_count, ave_value, pr_value, file_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                data.get('category'),
                data.get('company'),
                data.get('date'),
                data.get('publication'),
                data.get('section'),
                data.get('page'),
                data.get('title'),
                data.get('colour'),
                rate,
                height,
                column,
                ave_value,
                pr_value,
                file_url
            )

            cursor.execute(query, values)
            conn.commit()

            return jsonify({"message": "Project added successfully!", "id": cursor.lastrowid}), 201

        except cloudinary.exceptions.Error as e:
            conn.rollback()
            return jsonify({"error": f"File upload failed: {str(e)}"}), 500
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()


@app.route('/api/categories', methods=['GET', 'POST', 'DELETE'])
def handle_categories():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM categories")
            categories = cursor.fetchall()
            return jsonify(categories)

        elif request.method == 'POST':
            data = request.json
            cursor.execute("INSERT INTO categories (name) VALUES (%s)", (data['name'],))
            conn.commit()
            return jsonify({"message": "Category added successfully!"}), 201

        elif request.method == 'DELETE':
            # Accept either name or id
            name = request.args.get('name')
            item_id = request.args.get('id')

            if not name and not item_id:
                return jsonify({"error": "Either name or id must be provided"}), 400

            # First check if category exists
            if name:
                cursor.execute("SELECT id FROM categories WHERE name = %s", (name,))
            else:
                cursor.execute("SELECT id FROM categories WHERE id = %s", (item_id,))

            category = cursor.fetchone()

            if not category:
                return jsonify({"error": "Category not found"}), 404

            # Check for references in projects table
            cursor.execute("SELECT COUNT(*) as count FROM projects WHERE category = %s",
                           (name if name else category['name'],))
            project_count = cursor.fetchone()['count']

            if project_count > 0:
                return jsonify({
                    "error": "Cannot delete category - it's referenced by existing projects",
                    "projectCount": project_count
                }), 400

            # Check for references in user_access table
            cursor.execute("SELECT COUNT(*) as count FROM user_access WHERE category_id = %s",
                           (category['id'],))
            access_count = cursor.fetchone()['count']

            if access_count > 0:
                return jsonify({
                    "error": "Cannot delete category - users have access to it",
                    "accessCount": access_count
                }), 400

            # If no references, proceed with deletion
            if name:
                cursor.execute("DELETE FROM categories WHERE name = %s", (name,))
            else:
                cursor.execute("DELETE FROM categories WHERE id = %s", (item_id,))

            conn.commit()
            return jsonify({"message": "Category deleted successfully!"}), 200

    except mysql.connector.IntegrityError as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/user-access', methods=['GET'])
def get_user_access():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email parameter is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get categories the user has access to
        cursor.execute("""
            SELECT c.name 
            FROM user_access ua
            JOIN categories c ON ua.category_id = c.id
            WHERE ua.user_email = %s
        """, (email,))

        categories = cursor.fetchall()
        return jsonify([category['name'] for category in categories])

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/companies', methods=['GET', 'POST', 'DELETE'])
def handle_companies():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM companies")
            companies = cursor.fetchall()
            return jsonify(companies)

        elif request.method == 'POST':
            data = request.json
            cursor.execute("INSERT INTO companies (name) VALUES (%s)", (data['name'],))
            conn.commit()
            return jsonify({"message": "Company added successfully!"}), 201

        elif request.method == 'DELETE':
            name = request.args.get('name')
            item_id = request.args.get('id')

            if name:
                cursor.execute("DELETE FROM companies WHERE name = %s", (name,))
            elif item_id:
                cursor.execute("DELETE FROM companies WHERE id = %s", (item_id,))
            else:
                return jsonify({"error": "Either name or id must be provided"}), 400

            conn.commit()
            return jsonify({"message": "Company deleted successfully!"}), 200

    except mysql.connector.IntegrityError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/publications', methods=['GET', 'POST', 'DELETE'])
def handle_publications():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM publications")
            publications = cursor.fetchall()
            return jsonify(publications)

        elif request.method == 'POST':
            data = request.json
            cursor.execute("INSERT INTO publications (name) VALUES (%s)", (data['name'],))
            conn.commit()
            return jsonify({"message": "Publication added successfully!"}), 201

        elif request.method == 'DELETE':
            name = request.args.get('name')
            item_id = request.args.get('id')

            if name:
                cursor.execute("DELETE FROM publications WHERE name = %s", (name,))
            elif item_id:
                cursor.execute("DELETE FROM publications WHERE id = %s", (item_id,))
            else:
                return jsonify({"error": "Either name or id must be provided"}), 400

            conn.commit()
            return jsonify({"message": "Publication deleted successfully!"}), 200

    except mysql.connector.IntegrityError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/sections', methods=['GET', 'POST', 'DELETE'])
def handle_sections():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM sections")
            sections = cursor.fetchall()
            return jsonify(sections)

        elif request.method == 'POST':
            data = request.json
            cursor.execute("INSERT INTO sections (name) VALUES (%s)", (data['name'],))
            conn.commit()
            return jsonify({"message": "Section added successfully!"}), 201

        elif request.method == 'DELETE':
            name = request.args.get('name')
            item_id = request.args.get('id')

            if name:
                cursor.execute("DELETE FROM sections WHERE name = %s", (name,))
            elif item_id:
                cursor.execute("DELETE FROM sections WHERE id = %s", (item_id,))
            else:
                return jsonify({"error": "Either name or id must be provided"}), 400

            conn.commit()
            return jsonify({"message": "Section deleted successfully!"}), 200

    except mysql.connector.IntegrityError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/report/add', methods=['POST', 'OPTIONS'])
def add_to_report():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Ensure request has JSON data
        if not request.is_json:
            return _corsify_response(jsonify({"error": "Missing JSON in request"})), 400  # Fixed

        data = request.get_json(silent=True) or {}

        # Debugging - print received data
        print("Received data:", data)

        project_id = data.get('project_id')

        if not project_id:
            return _corsify_response(jsonify({"error": "Project ID is required"})), 400  # Fixed

        # Check if project exists
        cursor.execute("SELECT * FROM projects WHERE id = %s", (project_id,))
        project = cursor.fetchone()

        if not project:
            return _corsify_response(jsonify({"error": "Project not found"})), 404

        # Check if already in report
        cursor.execute("SELECT id FROM report_items WHERE project_id = %s", (project_id,))
        if cursor.fetchone():
            return _corsify_response(jsonify({"message": "Project already in report"})), 200

        # Add to report with all project data
        cursor.execute("""
            INSERT INTO report_items 
            (project_id, category, company, date, publication, section, 
             page, title, colour, rate, height, column_count, ave_value, pr_value, file_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            project_id,
            project['category'],
            project['company'],
            project['date'],
            project['publication'],
            project['section'],
            project['page'],
            project['title'],
            project['colour'],
            project['rate'],
            project['height'],
            project['column_count'],
            project['ave_value'],
            project['pr_value'],
            project['file_path']
        ))

        conn.commit()
        return _corsify_response(jsonify({"message": "Added to report successfully"})), 201

    except Exception as e:
        conn.rollback()
        return _corsify_response(jsonify({"error": str(e)})), 500
    finally:
        cursor.close()
        conn.close()

def _build_cors_preflight_response():
    response = jsonify({"message": "Preflight accepted"})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "*")
    return response

def _corsify_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response


@app.route('/api/report/remove/<int:project_id>', methods=['DELETE'])
def remove_from_report(project_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM report_items WHERE project_id = %s", (project_id,))
        conn.commit()
        return jsonify({"message": "Removed from report successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/report/items', methods=['GET'])
def get_report_items():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT p.*, ri.id as report_item_id 
            FROM report_items ri
            JOIN projects p ON ri.project_id = p.id
            ORDER BY ri.date_added DESC
        """)
        items = cursor.fetchall()

        # Add full URL to each item with a file_path
        for item in items:
            if item['file_path']:
                item['file_url'] = f"http://{request.host}/uploads/{os.path.basename(item['file_path'])}"
            else:
                item['file_url'] = None

        return jsonify(items)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
def delete_project(project_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # First get the file URL so we can delete from Cloudinary
        cursor.execute("SELECT file_path FROM projects WHERE id = %s", (project_id,))
        project = cursor.fetchone()

        if not project:
            return jsonify({"error": "Project not found"}), 404

        # Delete from Cloudinary if exists
        if project['file_path']:
            try:
                # Extract public_id from URL
                from urllib.parse import urlparse
                url_path = urlparse(project['file_path']).path
                public_id = os.path.splitext(url_path.split('/')[-1])[0]
                cloudinary.uploader.destroy(
                    f"{os.getenv('CLOUDINARY_FOLDER')}/{public_id}"
                )
            except Exception as e:
                print(f"Error deleting file from Cloudinary: {str(e)}")

        # Delete the project
        cursor.execute("DELETE FROM projects WHERE id = %s", (project_id,))
        conn.commit()

        return jsonify({"message": "Project deleted successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Add to your existing Flask app.py

@app.route('/api/contact', methods=['POST'])
def handle_contact():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.json
        query = """
        INSERT INTO contact_messages 
        (name, email, subject, message)
        VALUES (%s, %s, %s, %s)
        """
        values = (
            data.get('name'),
            data.get('email'),
            data.get('subject'),
            data.get('message')
        )

        cursor.execute(query, values)
        conn.commit()

        return jsonify({"message": "Message sent successfully!"}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/contact-messages', methods=['GET'])
def get_contact_messages():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT * FROM contact_messages 
            ORDER BY created_at DESC
        """)
        messages = cursor.fetchall()
        return jsonify(messages)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/contact-messages/<int:message_id>', methods=['PUT'])
def mark_message_as_read(message_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE contact_messages 
            SET is_read = 1 
            WHERE id = %s
        """, (message_id,))
        conn.commit()
        return jsonify({"message": "Message marked as read"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/contact-messages/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM contact_messages WHERE id = %s", (message_id,))
        conn.commit()
        return jsonify({"message": "Message deleted successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Security key management
@app.route('/api/security-key', methods=['GET', 'POST'])
def handle_security_key():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM security_keys ORDER BY expires_at DESC LIMIT 1")
            key = cursor.fetchone()
            return jsonify(key)

        elif request.method == 'POST':
            # Generate new key (simple random string for demo)
            import random
            import string
            new_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            expires_at = datetime.now() + timedelta(hours=1)

            cursor.execute(
                "INSERT INTO security_keys (key_value, expires_at) VALUES (%s, %s)",
                (new_key, expires_at)
            )
            conn.commit()
            return jsonify({"message": "Security key generated", "key": new_key}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# User management
@app.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
def handle_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == 'GET':
            # Get all users (for admin)
            cursor.execute("""
                SELECT id, first_name, last_name, email, phone, is_active, is_admin 
                FROM users 
                WHERE is_super_admin = FALSE
            """)
            users = cursor.fetchall()
            return jsonify(users)

        elif request.method == 'POST':
            # User registration
            data = request.json
            required_fields = ['firstName', 'lastName', 'email', 'phone', 'password', 'securityKey']

            if not all(field in data for field in required_fields):
                return jsonify({"error": "Missing required fields"}), 400

            # Verify security key
            cursor.execute("SELECT * FROM security_keys WHERE key_value = %s AND expires_at > NOW()",
                           (data['securityKey'],))
            key = cursor.fetchone()

            if not key:
                return jsonify({"error": "Invalid or expired security key"}), 400

            # Check if email exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (data['email'],))
            if cursor.fetchone():
                return jsonify({"error": "Email already registered"}), 400

            # Hash password (use bcrypt in production)
            password = data['password']
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

            cursor.execute(
                """INSERT INTO users 
                (first_name, last_name, email, phone, password_hash) 
                VALUES (%s, %s, %s, %s, %s)""",
                (data['firstName'], data['lastName'], data['email'],
                 data['phone'], password_hash)
            )
            conn.commit()
            return jsonify({"message": "User registered successfully"}), 201

        elif request.method == 'PUT':
            # Update user status (activate/deactivate)
            data = request.json
            if 'userId' not in data or 'isActive' not in data:
                return jsonify({"error": "Missing userId or isActive"}), 400

            cursor.execute(
                "UPDATE users SET is_active = %s WHERE id = %s",
                (data['isActive'], data['userId'])
            )
            conn.commit()
            return jsonify({"message": "User status updated"}), 200

        elif request.method == 'DELETE':
            # Delete user
            user_id = request.args.get('id')
            if not user_id:
                return jsonify({"error": "User ID required"}), 400

            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            return jsonify({"message": "User deleted"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Update login endpoint to check user status
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')  # In production, verify hashed password

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not user['is_active']:
            return jsonify({"error": "Account suspended. Please contact admin."}), 403

        # In production, verify password hash here
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({"error": "Invalid credentials"}), 401

        # Return user data (without password hash)
        user_data = {
            "id": user['id'],
            "firstName": user['first_name'],
            "lastName": user['last_name'],
            "email": user['email'],
            "isAdmin": user['is_admin']
        }

        return jsonify(user_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/category-access', methods=['GET'])
def get_category_access():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get all categories
        cursor.execute("SELECT id, name FROM categories")
        categories = cursor.fetchall()

        # Get access for each category
        result = {}
        for category in categories:
            cursor.execute("""
                SELECT u.email 
                FROM user_access ua
                JOIN users u ON ua.user_email = u.email
                WHERE ua.category_id = %s
            """, (category['id'],))
            users = cursor.fetchall()
            result[category['name']] = [user['email'] for user in users]

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/user-access', methods=['DELETE'])
def remove_user_access():
    category_name = request.args.get('category')
    email = request.args.get('email')

    if not category_name or not email:
        return jsonify({"error": "Category and email required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get category ID
        cursor.execute("SELECT id FROM categories WHERE name = %s", (category_name,))
        category = cursor.fetchone()

        if not category:
            return jsonify({"error": "Category not found"}), 404

        # Delete access
        cursor.execute("""
            DELETE FROM user_access 
            WHERE category_id = %s AND user_email = %s
        """, (category[0], email))
        conn.commit()

        return jsonify({"message": "Access removed successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/user-access', methods=['POST'])
def grant_user_access():
    data = request.json
    category_name = data.get('category')
    email = data.get('email')

    if not category_name or not email:
        return jsonify({"error": "Category and email required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # First get the category ID
        cursor.execute("SELECT id FROM categories WHERE name = %s", (category_name,))
        category = cursor.fetchone()

        if not category:
            return jsonify({"error": "Category not found"}), 404

        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if not cursor.fetchone():
            return jsonify({"error": "User not found"}), 404

        # Check if access already exists
        cursor.execute("""
            SELECT id FROM user_access 
            WHERE category_id = %s AND user_email = %s
        """, (category[0], email))
        if cursor.fetchone():
            return jsonify({"message": "Access already granted"}), 200

        # Grant access
        cursor.execute("""
            INSERT INTO user_access (category_id, user_email)
            VALUES (%s, %s)
        """, (category[0], email))
        conn.commit()

        return jsonify({"message": "Access granted successfully"}), 201

    except mysql.connector.IntegrityError as e:
        conn.rollback()
        return jsonify({"error": "Database integrity error"}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Add these to your config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')   # Replace with your Gmail
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')     # Use App Password from Google Account
app.config['MAIL_DEFAULT_SENDER'] = 'info.mediasense2025@gmail.com'

# Temporary storage for OTPs (in production, use Redis or database)
otp_storage = {}

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = to

    with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if email belongs to an admin
        cursor.execute("SELECT is_admin FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Email not found"}), 404

        if not user['is_admin']:
            return jsonify({"error": "You can't reset your password. Please contact system administrator."}), 403

        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        expires_at = datetime.now() + timedelta(minutes=10)

        # Store OTP (in production, use database)
        otp_storage[email] = {
            'otp': otp,
            'expires_at': expires_at
        }

        # Send email
        subject = "Your Password Reset OTP"
        body = f"""
        You requested a password reset for your admin account.
        Your OTP is: {otp}
        This OTP will expire in 10 minutes.
        """
        send_email(email, subject, body)

        return jsonify({"message": "OTP sent to your email"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('newPassword')

    if not all([email, otp, new_password]):
        return jsonify({"error": "All fields are required"}), 400

    # Verify OTP
    stored_otp = otp_storage.get(email)

    if not stored_otp:
        return jsonify({"error": "OTP not found or expired"}), 400

    if datetime.now() > stored_otp['expires_at']:
        return jsonify({"error": "OTP expired"}), 400

    if stored_otp['otp'] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Hash new password
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        # Update password
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (password_hash, email)
        )
        conn.commit()

        # Remove used OTP
        otp_storage.pop(email, None)

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/admin/reset-password', methods=['POST'])
def admin_reset_password():
    data = request.json
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    email = data.get('email')  # Get email from request

    if not all([email, current_password, new_password]):
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get the user's current password hash
        cursor.execute("SELECT password_hash FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({"error": "Current password is incorrect"}), 401

        # Hash new password
        salt = bcrypt.gensalt()
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        # Update password
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (new_password_hash, email)
        )
        conn.commit()

        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/users/admin', methods=['PUT'])
def toggle_admin_status():
    data = request.json
    if 'userId' not in data or 'isAdmin' not in data:
        return jsonify({"error": "Missing userId or isAdmin"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # First check if the user is a super admin (prevent modifying super admins)
        cursor.execute("SELECT is_super_admin FROM users WHERE id = %s", (data['userId'],))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        if user[0]:  # is_super_admin is True
            return jsonify({"error": "Cannot modify super admin status"}), 403

        # Update admin status
        cursor.execute(
            "UPDATE users SET is_admin = %s WHERE id = %s",
            (data['isAdmin'], data['userId'])
        )
        conn.commit()
        return jsonify({"message": "Admin status updated"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response



#if __name__ == '__main__':
#    app.run(debug=True, port=5000)