from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/our-team')
def our_team():
    return render_template('our-team.html')


if __name__ == '__main__':
    app.run(debug=True, port=5001)
