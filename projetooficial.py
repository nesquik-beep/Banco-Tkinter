import tkinter as tk
from tkinter import simpledialog, messagebox
import re

ARQUIVO_USUARIOS = "usuarios.txt"  # Alterando o formato para .txt

usuarios = {}

# Carregar os usuários existentes ao iniciar o programa
def carregar_usuarios():
    global usuarios
    try:
        with open(ARQUIVO_USUARIOS, "r") as arquivo:
            for linha in arquivo:
                dados = linha.strip().split(', ')

                # Verifica se os dados têm pelo menos 5 elementos (Nome, E-mail, CPF, Senha, Idade)
                if len(dados) < 5:
                    continue  # Pula linhas inválidas

                nome = dados[0].split(': ')[1]
                email = dados[1].split(': ')[1]
                cpf = dados[2].split(': ')[1]
                senha = dados[3].split(': ')[1]
                idade = dados[4].split(': ')[1] if len(dados) > 4 else "0"  # Se não houver idade, define como "0"
                saldo = float(dados[5].split(': ')[1]) if len(dados) > 5 else 0.0  # Se não houver saldo, define como 0.0

                usuarios[email] = {
                    "nome": nome,
                    "email": email,
                    "cpf": cpf,
                    "senha": senha,
                    "idade": idade,
                    "saldo": saldo
                }
    except FileNotFoundError:
        usuarios = {}


# Salvar os dados dos usuários no arquivo .txt
def salvar_usuarios():
    with open(ARQUIVO_USUARIOS, "w") as arquivo:
        for usuario in usuarios.values():
            arquivo.write(f"Nome: {usuario['nome']}, E-mail: {usuario['email']}, CPF: {usuario['cpf']}, Senha: {usuario['senha']}, Idade: {usuario['idade']}, Saldo: {usuario['saldo']}\n")

# Função para validar o formato do e-mail com domínio restrito a @gmail.com
def validar_email(email):
    if email.endswith("@gmail.com"):
        padrao_email = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
        if re.match(padrao_email, email):
            return True
    return False

# Função para validar o CPF (11 dígitos)
def validar_cpf(cpf):
    return cpf.isdigit() and len(cpf) == 11

# Função para registrar o usuário
def cadastrar_usuario():
    nome = entry_cadastro_nome.get()
    email = entry_cadastro_email.get()
    cpf = entry_cadastro_cpf.get()
    senha = entry_cadastro_senha.get()
    idade = entry_cadastro_idade.get()

    if not nome or not email or not cpf or not senha or not idade:
        messagebox.showwarning("Erro", "Preencha todos os campos obrigatórios!")
    elif not validar_email(email):
        messagebox.showerror("Erro", "E-mail inválido! O e-mail deve ser um Gmail válido (ex: usuario@gmail.com).")
    elif not validar_cpf(cpf):
        messagebox.showerror("Erro", "CPF inválido! O CPF deve ter 11 dígitos.")
    elif not idade.isdigit() or int(idade) < 0:
        messagebox.showerror("Erro", "Idade inválida! Insira uma idade válida.")
    elif int(idade) < 18:
        messagebox.showerror("Erro", "Você deve ter 18 anos ou mais para se cadastrar.")
    elif email in usuarios:
        messagebox.showwarning("Erro", "E-mail já cadastrado!")
    else:
        usuarios[email] = {"nome": nome, "email": email, "cpf": cpf, "senha": senha, "idade": idade, "saldo": 0.0}
        salvar_usuarios()  # Salva os dados após o cadastro
        messagebox.showinfo("Sucesso", f"Cadastro realizado com sucesso!\nBem-vindo, {nome}!")
        janela_cadastro.destroy()

# Função para abrir a tela de cadastro
def abrir_tela_cadastro():
    """Abre a janela de cadastro."""
    global janela_cadastro, entry_cadastro_nome, entry_cadastro_email, entry_cadastro_cpf, entry_cadastro_senha, entry_cadastro_idade

    janela_cadastro = tk.Toplevel(janela_inicial)
    janela_cadastro.title("Cadastro - Banco do Brasil")
    janela_cadastro.geometry("400x400")

    tk.Label(janela_cadastro, text="Nome Completo:").pack(pady=5)
    entry_cadastro_nome = tk.Entry(janela_cadastro, width=40)
    entry_cadastro_nome.pack(pady=5)

    tk.Label(janela_cadastro, text="E-mail:").pack(pady=5)
    entry_cadastro_email = tk.Entry(janela_cadastro, width=40)
    entry_cadastro_email.pack(pady=5)

    tk.Label(janela_cadastro, text="CPF (11 dígitos):").pack(pady=5)
    entry_cadastro_cpf = tk.Entry(janela_cadastro, width=40)
    entry_cadastro_cpf.pack(pady=5)

    tk.Label(janela_cadastro, text="Senha:").pack(pady=5)
    entry_cadastro_senha = tk.Entry(janela_cadastro, width=40, show="*")  # Esconde a senha
    entry_cadastro_senha.pack(pady=5)

    tk.Label(janela_cadastro, text="Idade:").pack(pady=5)
    entry_cadastro_idade = tk.Entry(janela_cadastro, width=40)
    entry_cadastro_idade.pack(pady=5)

    tk.Button(janela_cadastro, text="Cadastrar", command=cadastrar_usuario).pack(pady=10)
    tk.Button(janela_cadastro, text="Cancelar", command=janela_cadastro.destroy).pack(pady=5)

# Função para verificar o login do usuário
def verificar_login():
    email = entry_login_email.get()
    cpf = entry_login_cpf.get()
    senha = entry_login_senha.get()

    if not validar_email(email):
        messagebox.showerror("Erro", "E-mail inválido! O e-mail deve ser um Gmail válido (ex: usuario@gmail.com).")
    elif email in usuarios and usuarios[email]["cpf"] == cpf and usuarios[email]["senha"] == senha:
        messagebox.showinfo("Login bem-sucedido", f"Bem-vindo, {email}!")
        abrir_pagina_principal(email)
    else:
        messagebox.showerror("Erro", "E-mail, CPF ou senha incorretos!")

# Função para abrir a página principal após login
def abrir_pagina_principal(email):
    """Abre a janela principal e exibe as informações do usuário logado."""
    janela_inicial.destroy()

    janela_principal = tk.Tk()
    janela_principal.title("Banco Tkinter - Página Principal")
    janela_principal.geometry("400x500")

    usuario_info = usuarios[email]

    tk.Label(janela_principal, text="Bem-vindo ao Banco Tkinter!", font=("Arial", 14)).pack(pady=10)
    tk.Label(janela_principal, text=f"Nome: {usuario_info['nome']}").pack(pady=5)
    tk.Label(janela_principal, text=f"E-mail: {usuario_info['email']}").pack(pady=5)
    tk.Label(janela_principal, text=f"CPF: {usuario_info['cpf']}").pack(pady=5)
    tk.Label(janela_principal, text=f"Idade: {usuario_info['idade']}").pack(pady=5)

    # Botões para interagir com a conta
    tk.Button(janela_principal, text="Verificar Saldo", command=lambda: verificar_saldo(email)).pack(pady=10)
    tk.Button(janela_principal, text="Depositar", command=lambda: depositar(email)).pack(pady=10)
    tk.Button(janela_principal, text="Sacar", command=lambda: sacar(email)).pack(pady=10)
    tk.Button(janela_principal, text="Sair", command=janela_principal.quit).pack(pady=20)

    janela_principal.mainloop()

# Função para verificar saldo
def verificar_saldo(email):
    saldo = usuarios.get(email, {}).get("saldo", 0.0)
    messagebox.showinfo("Saldo", f"Seu saldo atual é R$ {saldo:.2f}")

# Função para realizar depósito
def depositar(email):
    valor = simpledialog.askfloat("Depósito", "Digite o valor a ser depositado:", minvalue=0)
    if valor is not None and valor > 0:
        usuarios[email]["saldo"] += valor
        salvar_usuarios()
        messagebox.showinfo("Depósito", f"Depósito de R$ {valor:.2f} realizado com sucesso!")

# Função para realizar saque
def sacar(email):
    valor = simpledialog.askfloat("Saque", "Digite o valor a ser sacado:", minvalue=0)
    saldo = usuarios[email]["saldo"]
    if valor is not None:
        if valor <= saldo:
            usuarios[email]["saldo"] -= valor
            salvar_usuarios()
            messagebox.showinfo("Saque", f"Saque de R$ {valor:.2f} realizado com sucesso!")
        else:
            messagebox.showerror("Erro", "Saldo insuficiente!")

# Função para cancelar o cadastro
def cancelar_cadastro():
    email = entry_cancelar_email.get()
    cpf = entry_cancelar_cpf.get()

    if email in usuarios and usuarios[email]["cpf"] == cpf:
        del usuarios[email]
        salvar_usuarios()
        messagebox.showinfo("Cancelamento", "Cadastro cancelado com sucesso!")
        janela_cancelamento.destroy()
    else:
        messagebox.showerror("Erro", "E-mail ou CPF não encontrados!")

# Função para abrir a tela de cancelamento
def abrir_tela_cancelamento():
    """Abre a janela de cancelamento de cadastro."""
    global janela_cancelamento, entry_cancelar_email, entry_cancelar_cpf

    janela_cancelamento = tk.Toplevel(janela_inicial)
    janela_cancelamento.title("Cancelar Cadastro - Banco Tkinter")
    janela_cancelamento.geometry("400x300")

    tk.Label(janela_cancelamento, text="E-mail:").pack(pady=5)
    entry_cancelar_email = tk.Entry(janela_cancelamento, width=40)
    entry_cancelar_email.pack(pady=5)

    tk.Label(janela_cancelamento, text="CPF (11 dígitos):").pack(pady=5)
    entry_cancelar_cpf = tk.Entry(janela_cancelamento, width=40)
    entry_cancelar_cpf.pack(pady=5)

    tk.Button(janela_cancelamento, text="Cancelar Cadastro", command=cancelar_cadastro).pack(pady=10)
    tk.Button(janela_cancelamento, text="Cancelar", command=janela_cancelamento.destroy).pack(pady=5)

# Função para verificar todos os cadastros
def verificar_cadastros():
    cadastros = "\n".join([f"Nome: {usuario['nome']}, E-mail: {usuario['email']}, CPF: {usuario['cpf']}, Idade: {usuario['idade']}" for usuario in usuarios.values()])
    if cadastros:
        messagebox.showinfo("Lista de Cadastros", cadastros)
    else:
        messagebox.showinfo("Lista de Cadastros", "Nenhum usuário cadastrado!")

# Função para criar a janela inicial
def criar_janela_inicial():
    """Cria a janela inicial com as opções 'Entrar', 'Cadastrar', 'Cancelar Cadastro', 'Verificar Cadastros' e 'Sair'."""
    global janela_inicial

    janela_inicial = tk.Tk()
    janela_inicial.title("Banco Tkinter")
    janela_inicial.geometry("400x350")

    tk.Label(janela_inicial, text="Bem-vindo ao Banco Tkinter!", font=("Arial", 16)).pack(pady=20)
    tk.Label(janela_inicial, text="O que deseja fazer?").pack(pady=5)

    # Botões para as opções da tela inicial
    tk.Button(janela_inicial, text="Entrar", command=abrir_tela_login).pack(pady=10)
    tk.Button(janela_inicial, text="Cadastrar", command=abrir_tela_cadastro).pack(pady=10)
    tk.Button(janela_inicial, text="Cancelar Cadastro", command=abrir_tela_cancelamento).pack(pady=10)
    tk.Button(janela_inicial, text="Verificar Cadastros", command=verificar_cadastros).pack(pady=10)
    tk.Button(janela_inicial, text="Sair", command=janela_inicial.quit).pack(pady=10)

    janela_inicial.mainloop()

# Função para abrir a tela de login
def abrir_tela_login():
    """Abre a janela de login."""
    global janela_login, entry_login_email, entry_login_cpf, entry_login_senha

    janela_login = tk.Toplevel(janela_inicial)
    janela_login.title("Login - Banco Tkinter")
    janela_login.geometry("400x400")

    tk.Label(janela_login, text="E-mail:").pack(pady=5)
    entry_login_email = tk.Entry(janela_login, width=40)
    entry_login_email.pack(pady=5)

    tk.Label(janela_login, text="CPF (11 dígitos):").pack(pady=5)
    entry_login_cpf = tk.Entry(janela_login, width=40)
    entry_login_cpf.pack(pady=5)

    tk.Label(janela_login, text="Senha:").pack(pady=5)
    entry_login_senha = tk.Entry(janela_login, width=40, show="*")  # Esconde a senha
    entry_login_senha.pack(pady=5)

    tk.Button(janela_login, text="Entrar", command=verificar_login).pack(pady=10)
    tk.Button(janela_login, text="Cancelar", command=janela_login.destroy).pack(pady=5)

# Carregar os usuários existentes ao iniciar o programa
carregar_usuarios()

# Criar a janela inicial
criar_janela_inicial()
