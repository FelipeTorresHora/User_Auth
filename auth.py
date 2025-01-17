from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime

SECRET_KEY = "seu_segredo_super_secreto"

def connect_db():
    client = MongoClient('mongodb://localhost:27017/')
    db = client['auth']
    return db["users"]

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

def generate_jwt(user_id):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'iat': datetime.datetime.utcnow(),
        'sub': str(user_id)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token expirado. Faça login novamente.'
    except jwt.InvalidTokenError:
        return 'Token inválido. Faça login novamente.'


def register_user(users_collection):
    print("=== Cadastro de Usuário ===")
    name = input("Nome: ").strip()
    email = input("E-mail: ").strip()
    password = input("Senha: ").strip()

    if users_collection.find_one({"email": email}):
        print("Erro: Este e-mail já está cadastrado!")
        return

    hashed_pw = hash_password(password)
    user = {"name": name, "email": email, "password": hashed_pw}
    result = users_collection.insert_one(user)
    print("Usuário cadastrado com sucesso!")

def login_user(users_collection):
    print("=== Login de Usuário ===")
    email = input("E-mail: ").strip()
    password = input("Senha: ").strip()

    user = users_collection.find_one({"email": email})
    if not user:
        print("Erro: Usuário não encontrado!")
        return


    if verify_password(user['password'], password):
        token = generate_jwt(user['_id'])
        print(f"Login realizado com sucesso! Aqui está seu token JWT:\n{token}")
    else:
        print("Erro: Senha incorreta!")

def validate_token(token):
    user_id = decode_jwt(token)
    if user_id:
        user = users_collection.find_one({"_id": user_id})
        if user:
            print(f"Token válido! Bem-vindo, {user['name']}")
        else:
            print("Usuário não encontrado.")
    else:
        print("Token inválido. Faça login novamente.")

def main():
    users_collection = connect_db()

    while True:
        print("\n=== Sistema de Autenticação ===")
        print("1. Cadastrar")
        print("2. Logar")
        print("3. Validar Token")
        print("4. Sair")
        option = input("Escolha uma opção: ").strip()

        if option == "1":
            register_user(users_collection)
        elif option == "2":
            login_user(users_collection)
        elif option == "3":
            token = input("Digite o token JWT: ").strip()
            validate_token(token)
        elif option == "4":
            print("Saindo... Até logo!")
            break
        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    main()