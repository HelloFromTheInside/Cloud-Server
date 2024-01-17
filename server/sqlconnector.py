import sqlite3
import datetime


def create_db(
    db_name: str, sql_file_name: str
) -> tuple[sqlite3.Cursor, sqlite3.Connection]:
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    with open(sql_file_name, "r") as sql_file:
        sql_commands = sql_file.read()
        try:
            cursor.executescript(sql_commands)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return cursor, conn


cur, conn = create_db("Users.db", "SQL-Tables.sql")


def get_password(username: bytes) -> str:
    return cur.execute(
        "SELECT PasswordHash FROM Users WHERE Username = ?", (username,)
    ).fetchall()[0][0]


def store_user(username: bytes, password: bytes, timestamp: datetime.datetime) -> None:
    cur.execute(
        "INSERT INTO Users (Username, PasswordHash, CreationDate) VALUES(?, ?, ?)",
        (username, password, timestamp),
    )
    conn.commit()


def update_last_login(username: bytes, timestamp: datetime.datetime) -> None:
    cur.execute(
        "UPDATE Users SET LastLogin  = ? WHERE Username = ?", (timestamp, username)
    )
    conn.commit()
