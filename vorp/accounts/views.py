from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.urls import reverse
from django.core.mail import EmailMessage
from django.conf import settings
from itsdangerous import URLSafeTimedSerializer
from .forms import RegisterForm  # Certifique-se de ter definido um RegisterForm em accounts/forms.py

User = get_user_model()
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

def register_view(request):
    """
    Exibe o formulário de registro e processa o POST para criar um novo usuário.
    """
    if request.user.is_authenticated:
        messages.info(request, "Você já está logado.")
        return redirect('core:index')
    
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Usuário registrado com sucesso! Faça login.")
            return redirect('accounts:login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegisterForm()
        
    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    """
    Exibe o formulário de login e processa o POST para autenticação.
    """
    if request.user.is_authenticated:
        return redirect('core:index')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login realizado com sucesso!")
            return redirect('core:index')
        else:
            messages.error(request, "Usuário ou senha inválidos.")
            
    return render(request, 'accounts/login.html')


def logout_view(request):
    """
    Realiza logout do usuário e redireciona para a página de login.
    """
    logout(request)
    messages.success(request, "Logout realizado com sucesso!")
    return redirect('accounts:login')


def forgot_password(request):
    """
    Processa a solicitação para recuperação de senha: 
    - Se o e-mail estiver cadastrado, gera um token e envia o link via email.
    - Caso contrário, exibe uma mensagem de erro.
    """
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        try:
            user = User.objects.get(email=email)
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = request.build_absolute_uri(reverse('accounts:reset_password', kwargs={'token': token}))
            
            subject = "Recuperação de Senha - Vorp"
            body = f"Olá, clique no link para redefinir sua senha:\n{reset_url}"
            EmailMessage(subject, body, to=[email]).send()
            
            messages.success(request, "Verifique seu e-mail para redefinir sua senha.")
            return redirect('accounts:login')
        except User.DoesNotExist:
            messages.error(request, "E-mail não encontrado.")
            return redirect('accounts:forgot_password')
            
    return render(request, 'accounts/forgot_password.html')


def reset_password(request, token):
    """
    Permite que o usuário defina uma nova senha, validando o token recebido.
    """
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except Exception:
        messages.error(request, "Token inválido ou expirado.")
        return redirect('accounts:forgot_password')
    
    user = get_object_or_404(User, email=email)
    
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if not password or password != confirm_password:
            messages.error(request, "As senhas não coincidem ou estão vazias.")
            return redirect('accounts:reset_password', token=token)
        
        user.set_password(password)
        user.save()
        messages.success(request, "Senha redefinida com sucesso!")
        return redirect('accounts:login')
    
    return render(request, 'accounts/reset_password.html', {'token': token})
