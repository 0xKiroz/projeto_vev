from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout


def register(request):
    if request.method == 'POST':
        # Use `.get()` para evitar erros caso a chave não exista
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        email = request.POST.get('email', '').strip()

        # Verificar se todos os campos foram preenchidos
        if not username or not password or not email:
            messages.error(request, "Todos os campos são obrigatórios.")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Usuário já existe.")
        else:
            # Criação do usuário
            User.objects.create_user(username=username, password=password, email=email)
            messages.success(request, "Usuário criado com sucesso!")
            return redirect('login')  # Redireciona para a tela de login

    return render(request, 'base/register.html')


def login_user(request):
    if request.method == 'POST':
        # Use `.get()` para evitar erros caso a chave não exista
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, f"Bem-vindo, {user.username}!")
            return redirect('home')  # Redirecione para a tela inicial/painel
        else:
            messages.error(request, "Credenciais inválidas. Verifique seu username e senha.")

    return render(request, 'base/login.html')


def logout_user(request):
    logout(request)
    messages.success(request, "Você saiu com sucesso.")
    return redirect('login')
