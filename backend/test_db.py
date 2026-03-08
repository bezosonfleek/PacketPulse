import psycopg2
from psycopg2 import extras

def get_db_connection():
    try:
        conn = psycopg2.connect(
            # Use 'localhost' or '127.0.0.1' since it's not in a Docker bridge yet
            host="localhost",
            
            port="5432", 
            
            database="demo-db", # Or your specific DB name
            user="postgres",    #insert db name
            password="",        #insert db password
            
            # This ensures UUIDs and JSONB are handled as Python dicts/strings
            cursor_factory=psycopg2.extras.RealDictCursor 
        )
        return conn
    except Exception as e:
        print(f"Error connecting to local DB: {e}")
        return None
    

if __name__ == "__main__":
    print("Attempting to connect to the database...")
    connection = get_db_connection()
    
    if connection:
        print("✅ Success! The backend can talk to the database.")
        # Always close the connection when testing is done
        connection.close()
    else:
        print("❌ Failed to connect. Check the error message above.")