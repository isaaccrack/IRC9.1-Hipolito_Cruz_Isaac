from flask import Flask, render_template, request
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_playbook():
    playbook = request.form.get('playbook')
    if playbook:
        cmd = f"ansible-playbook -i ../ansible/hosts ../ansible/playbooks/{playbook}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            output = e.output
        return render_template('index.html', output=output)
    return render_template('index.html', output="No se seleccionó ningún playbook.")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
