from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime
import os
import re
from typing import Optional, Dict, Any
from dataclasses import dataclass
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

@dataclass
class AuthConfig:
    """Configurações de autenticação"""
    SECRET_KEY: str = os.getenv('JWT_SECRET_KEY') or os.urandom(32).hex()
    MONGO_URI: str = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    JWT_EXPIRATION_DAYS: int = int(os.getenv('JWT_EXPIRATION_DAYS', '1'))
    MIN_PASSWORD_LENGTH: int = 4
    PASSWORD_PATTERN = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{4,}$')

class AuthError(Exception):
    """Exceção personalizada para erros de autenticação"""
    pass

class DatabaseConnection:
    """Gerenciador de conexão com o banco de dados"""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.client = MongoClient(AuthConfig.MONGO_URI)
            cls._instance.db = cls._instance.client['auth']
        return cls._instance

    def __enter__(self):
        return self.db["users"]

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()

class AuthService:
    """Serviço de autenticação"""
    
    def __init__(self):
        self._email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def validate_email(self, email: str) -> bool:
        """Valida formato do email"""
        return bool(self._email_pattern.match(email))

    def validate_password(self, password: str) -> bool:
        """Valida força da senha"""
        return bool(AuthConfig.PASSWORD_PATTERN.match(password))

    def hash_password(self, password: str) -> bytes:
        """Gera hash da senha"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))

    def verify_password(self, hashed_password: bytes, user_password: str) -> bool:
        """Verifica se a senha está correta"""
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

    def generate_jwt(self, user_id: str) -> str:
        """Gera token JWT"""
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=AuthConfig.JWT_EXPIRATION_DAYS),
            'iat': datetime.datetime.utcnow(),
            'sub': str(user_id)
        }
        return jwt.encode(payload, AuthConfig.SECRET_KEY, algorithm='HS256')

    def decode_jwt(self, token: str) -> Optional[str]:
        """Decodifica e valida token JWT"""
        try:
            payload = jwt.decode(token, AuthConfig.SECRET_KEY, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise AuthError('Token expirado. Faça login novamente.')
        except jwt.InvalidTokenError:
            raise AuthError('Token inválido. Faça login novamente.')

class UserService:
    """Serviço de gerenciamento de usuários"""
    
    def __init__(self):
        self.auth_service = AuthService()

    def register_user(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Registra novo usuário"""
        # Validações
        if not name or len(name.strip()) < 3:
            raise AuthError("Nome deve ter pelo menos 3 caracteres.")
        
        if not self.auth_service.validate_email(email):
            raise AuthError("Formato de e-mail inválido.")
            
        if not self.auth_service.validate_password(password):
            raise AuthError(
                "Senha deve ter pelo menos 8 caracteres, incluindo letras, "
                "números e caracteres especiais."
            )

        with DatabaseConnection() as users_collection:
            # Verifica se email já existe
            if users_collection.find_one({"email": email}):
                raise AuthError("Este e-mail já está cadastrado!")

            # Cria usuário
            user = {
                "name": name.strip(),
                "email": email.lower().strip(),
                "password": self.auth_service.hash_password(password),
                "created_at": datetime.datetime.utcnow()
            }
            
            result = users_collection.insert_one(user)
            return {"user_id": str(result.inserted_id)}

    def login_user(self, email: str, password: str) -> Dict[str, str]:
        """Realiza login do usuário"""
        if not email or not password:
            raise AuthError("E-mail e senha são obrigatórios.")

        with DatabaseConnection() as users_collection:
            user = users_collection.find_one({"email": email.lower().strip()})
            if not user:
                raise AuthError("Usuário não encontrado!")

            if not self.auth_service.verify_password(user['password'], password):
                raise AuthError("Senha incorreta!")

            token = self.auth_service.generate_jwt(user['_id'])
            return {
                "token": token,
                "user": {
                    "id": str(user['_id']),
                    "name": user['name'],
                    "email": user['email']
                }
            }

    def validate_token(self, token: str) -> Dict[str, Any]:
        """Valida token JWT e retorna informações do usuário"""
        if not token:
            raise AuthError("Token não fornecido.")

        user_id = self.auth_service.decode_jwt(token)
        
        with DatabaseConnection() as users_collection:
            user = users_collection.find_one({"_id": ObjectId(user_id)})
            if not user:
                raise AuthError("Usuário não encontrado.")
                
            return {
                "user": {
                    "id": str(user['_id']),
                    "name": user['name'],
                    "email": user['email']
                }
            }

def main():
    """Função principal do programa"""
    user_service = UserService()

    while True:
        try:
            print("\n=== Sistema de Autenticação ===")
            print("1. Cadastrar")
            print("2. Logar")
            print("3. Validar Token")
            print("4. Sair")
            option = input("Escolha uma opção: ").strip()

            if option == "1":
                print("\n=== Cadastro de Usuário ===")
                name = input("Nome: ").strip()
                email = input("E-mail: ").strip()
                password = input("Senha: ").strip()
                
                result = user_service.register_user(name, email, password)
                print("Usuário cadastrado com sucesso!")
                print(f"ID do usuário: {result['user_id']}")

            elif option == "2":
                print("\n=== Login de Usuário ===")
                email = input("E-mail: ").strip()
                password = input("Senha: ").strip()
                
                result = user_service.login_user(email, password)
                print("Login realizado com sucesso!")
                print(f"Token JWT: {result['token']}")
                print(f"Bem-vindo, {result['user']['name']}!")

            elif option == "3":
                token = input("Digite o token JWT: ").strip()
                result = user_service.validate_token(token)
                print(f"Token válido! Bem-vindo, {result['user']['name']}")

            elif option == "4":
                print("Saindo... Até logo!")
                break

            else:
                print("Opção inválida! Tente novamente.")

        except AuthError as e:
            print(f"Erro: {str(e)}")
        except Exception as e:
            print(f"Erro inesperado: {str(e)}")

if __name__ == "__main__":
    main()