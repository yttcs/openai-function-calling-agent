from sqlmodel import Session, create_engine

db_name = "users"
mysql_url = f"mysql+pymysql://root:xcr223@188.166.217.197:3306/{db_name}"
engine = create_engine(mysql_url, echo=True)

def get_session():
    with Session(engine) as session:
        yield session

