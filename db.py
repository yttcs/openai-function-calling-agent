from sqlmodel import Session, create_engine

db_name = "users"
mysql_url = f"mysql+pymysql://root:<password@ip_address>/{db_name}"
engine = create_engine(mysql_url, echo=True)

def get_session():
    with Session(engine) as session:
        yield session

