from flask import Flask, request, jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
# Chave secreta para segurança de sessões
app.config['SECRET_KEY'] = "your_secret_key"
# Local do banco de dados do SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

#Inicializa o gerenciador de login e o conecta à aplicação
login_manager=LoginManager()
db.init_app(app)
login_manager.init_app(app)
#Define a rota para redirecionar usuários não autenticados
login_manager.login_view = 'login'

#Carrega um usuário a partir do ID armazenado na função
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        #login
        user = User.query.filter_by(username = username).first()
        
        if user and user.password == password:
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message" : "Autenticação realizada com sucesso"})
        
    return jsonify({"message":"crendenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
#Protege a rota
@login_required
def logout():
    #Faz logout do usuário atual
    logout_user()
    return jsonify({"message":"Logout realizado com sucesso!"})
    
@app.route('/user', methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        user = User(username=username,password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message":"usuário cadastrado com sucesso"})
    
    return jsonify({"message":"Dados inválidos"}), 400

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    
    if user:
        return {"username":user.username}
    
    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)
    
    if user and data.get("password"):
        user.password= data.get("password")
        db.session.commit()
        
        return jsonify({"message":f"Usuário {id_user} atualizado com sucesso"})

    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)
    
    if user == current_user.id:
        return jsonify({"message":"Você não pode se deletar"}), 403
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso"})
    
    return jsonify({"message":"Usuário não encontrado ou já deletado"}), 404

if __name__ == "__main__":
    app.run(debug=True)