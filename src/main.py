from flask import Flask, render_template, request, url_for, send_file
from werkzeug.utils import secure_filename
from mod_rc4 import ModRC4

app = Flask(__name__)
mod_rc4 = ModRC4()

@app.route('/')
def index():
   return render_template('index.html')

@app.route('/input', methods=['POST'])
def input():
   return render_template('input.html', action = request.form['action'])

@app.route('/action', methods=['POST'])
def action():
   if request.form['option'] == 'file':
      return render_template('file.html', action = request.form['action'])
   return render_template('keyboard.html', action = request.form['action'])

@app.route('/action/<option>', methods=['POST'])
def result(option):
   if option == 'file':
      file = request.files['file']
      inp_file = bytearray(file.read())
      key_1 = request.form['key_1']
      key_2 = request.form['key_2']
      filename = file.filename
      output = []
      if request.form['action'] == 'encrypt':
         output = mod_rc4.encrypt_binary(inp_file, key_1, key_2)
         filename = 'encrypted_' + filename
      elif request.form['action'] == 'decrypt':
         output = mod_rc4.decrypt_binary(inp_file, key_1, key_2)
         filename = 'decrypted_' + filename

      write_file_bin(output, filename)
      return send_file(filename, as_attachment=True)

   inp = request.form['input_text']
   key_1 = request.form['key_1']
   key_2 = request.form['key_2']

   output = ""
   if request.form['action'] == 'encrypt':
      output = mod_rc4.encrypt(inp, key_1, key_2)
   elif request.form['action'] == 'decrypt':
      output = mod_rc4.decrypt(inp, key_1, key_2)
   return render_template('result.html', text = {'input_text': inp, 'key_1': key_1, 'key_2': key_2, 'output_text': output, 'action': request.form['action']})

@app.route('/download', methods=['POST'])
def download():
   write_file(request.form['output_text'],'output.txt')
   return send_file('output.txt', as_attachment=True)

def write_file_bin(bin, dest):
   file = open(dest, "wb")
   file.write(bytearray(bin))
   file.close()

def write_file(str, dest):
   file = open(dest, "w+")
   file.write(str)
   file.close()


if __name__ == '__main__':
   app.run(debug=True)