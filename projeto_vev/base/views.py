from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, permission_required
from django.http import HttpResponse
from django.core.exceptions import PermissionDenied
from .forms import UserRegistrationForm

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()  # Salva o novo usuário
            return redirect('login')  # Redireciona para a página de login
        else:
            # Se o formulário for inválido, renderiza a página com os erros
            return render(request, 'base/register.html', {'form': form})
    else:
        form = UserRegistrationForm()  # Formulário vazio para GET
    return render(request, 'base/register.html', {'form': form})


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


from django.contrib.auth.decorators import permission_required
from django.shortcuts import render

@permission_required('auth.view_user', raise_exception=True)  # Substitua 'auth.view_user' pelo codename correto
def restricted_view(request):
    return render(request, 'base/restricted.html')

from django.core.exceptions import PermissionDenied

@login_required
@permission_required('auth.can_access_restricted_area', raise_exception=True)
def restricted_view(request):
    return HttpResponse("Área restrita")

def custom_password_change_done(request):
    messages.success(request, 'Sua senha foi alterada com sucesso!')
    return redirect('login')  # ou qualquer outra URL que você queira redirecionar