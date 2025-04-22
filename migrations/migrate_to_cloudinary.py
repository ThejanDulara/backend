import os
import mysql.connector
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader

# Load environment variables
load_dotenv()

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)

# Database configuration from your original app
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': os.getenv('DATABASE_PORT')
}


def get_db_connection():
    return mysql.connector.connect(**db_config)


def migrate_files():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get all projects with local file paths
        cursor.execute("""
            SELECT id, file_path FROM projects 
            WHERE file_path IS NOT NULL 
            AND file_path NOT LIKE 'http%'
        """)
        projects = cursor.fetchall()

        print(f"Found {len(projects)} projects to migrate")

        for project in projects:
            try:
                local_path = os.path.join('uploads', os.path.basename(project['file_path']))

                if os.path.exists(local_path):
                    print(f"Migrating {local_path}...")

                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(
                        local_path,
                        folder=os.getenv('CLOUDINARY_FOLDER'),
                        resource_type="auto"
                    )

                    # Update database with Cloudinary URL
                    update_cursor = conn.cursor()
                    update_cursor.execute(
                        "UPDATE projects SET file_path = %s WHERE id = %s",
                        (upload_result['secure_url'], project['id'])
                    )
                    conn.commit()
                    update_cursor.close()

                    print(f"Successfully migrated to {upload_result['secure_url']}")
                else:
                    print(f"File not found: {local_path}")

            except Exception as e:
                conn.rollback()
                print(f"Failed to migrate {project['file_path']}: {str(e)}")

    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    migrate_files()