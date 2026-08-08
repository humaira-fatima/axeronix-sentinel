from sqlalchemy import create_engine, text

# Connection string: postgresql://username:password@host:port/database
DATABASE_URL = "postgresql://postgres:mysecretpassword@localhost:5432/postgres"

engine = create_engine(DATABASE_URL)

try:
    with engine.connect() as connection:
        result = connection.execute(text("SELECT 'Axeronix Sentinel DB Connected!'"))
        print(result.scalar())
except Exception as e:
    print("Connection failed:", e)