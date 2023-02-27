from login.db import get_db
from datetime import datetime

def logger_register(event,user):
    db = get_db()
    date = datetime.now()
    time = date.strftime('%D - %H:%M')
    db.execute("INSERT INTO logger (event, date, user) VALUES (?, ?, ?)", 
            (event, time, user),)
    db.commit()