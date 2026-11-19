"""Intentionally vulnerable demo for the CodeFlow lab. Never run this file."""
import os
import sqlite3


def run_command(command):
    os.system(command)


def lookup(connection, name):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


user_input = input("Enter a value: ")
run_command("echo " + user_input)

connection = sqlite3.connect("demo.db")
lookup(connection, user_input)

expression = input("Expression: ")
eval(expression)
