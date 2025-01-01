import sqlite3

connection = sqlite3.connect('database.db')


with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

cur.execute("INSERT INTO posts (title, date, description, amount, category) VALUES (?, ?, ?, ?, ?)",
            ('First Budget', '21st September 2024', 'Entry of the first budget', '40000', 'Income')
            )

cur.execute("INSERT INTO posts (title, date, description, amount, category) VALUES (?, ?, ?, ?, ?)",
            ('Second Budget', '24th September 2024', 'Entry of the second budget', '50000', 'Expense')
            )
            
connection.commit()
connection.close()