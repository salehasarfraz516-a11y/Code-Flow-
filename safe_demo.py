"""Safe counterpart: untrusted input is cleaned or bound as data."""
import shlex
import subprocess
import sqlite3

name = input("Enter a name: ")
subprocess.run(["echo", name])  # list form, no shell
print("echo " + shlex.quote(name))

connection = sqlite3.connect("demo.db")
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))  # parameterized

fixed = "hello"
eval("1 + 1")
