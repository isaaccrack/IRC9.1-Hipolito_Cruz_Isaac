from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient
import os
from datetime import datetime

app = Flask(__name__)

# Configuración de MongoDB
mongodb_host = os.environ.get('MONGODB_HOST', 'localhost')
mongodb_port = int(os.environ.get('MONGODB_PORT', 27017))
client = MongoClient(f'mongodb://{mongodb_host}:{mongodb_port}/')
db = client.flask_db
todos = db.todos

@app.route('/')
def index():
    all_todos = list(todos.find())
    return render_template('index.html', todos=all_todos)

@app.route('/add', methods=['POST'])
def add_todo():
    todo_name = request.form.get('todo')
    todo_description = request.form.get('description')

    if todo_name:
        todos.insert_one({
            'name': todo_name,
            'description': todo_description,
            'completed': False,
            'created_at': datetime.now()
        })

    return redirect(url_for('index'))

@app.route('/complete/<todo_id>')
def complete_todo(todo_id):
    from bson.objectid import ObjectId
    todo = todos.find_one({'_id': ObjectId(todo_id)})
    if todo:
        todos.update_one(
            {'_id': ObjectId(todo_id)},
            {'$set': {'completed': not todo.get('completed', False)}}
        )
    return redirect(url_for('index'))

@app.route('/delete/<todo_id>')
def delete_todo(todo_id):
    from bson.objectid import ObjectId
    todos.delete_one({'_id': ObjectId(todo_id)})
    return redirect(url_for('index'))

@app.template_filter('format_date')
def format_date(date):
    if date:
        return date.strftime('%d-%m-%Y %H:%M')
    return ''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
