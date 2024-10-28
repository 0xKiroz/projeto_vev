from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Usuário já existe")
        else:
            User.objects.create_user(username=username, password=password, email=email)
            messages.success(request, "Usuário criado com sucesso!")
            return redirect('login')
    
    return render(request, 'base/register.html')


def login_user(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Credenciais inválidas")
    
    return render(request, 'base/login.html')


def logout_user(request):
    logout(request)
    return redirect('login')
