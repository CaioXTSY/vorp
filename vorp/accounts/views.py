from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from .forms import RegisterForm, ProfileEditForm
from itsdangerous import URLSafeTimedSerializer
from db.accounts_models import User
from django.core.mail import EmailMessage

serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

def generate_reset_token(email):
    return serializer.dumps(email, salt='reset-senha')

def verify_reset_token(token, expiration=1800):
    try:
        email = serializer.loads(token, salt='reset-senha', max_age=expiration)
    except Exception:
        return None
    return email

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            messages.success(request, "Login realizado com sucesso!")
            return redirect('notes:list_notes')
        else:
            messages.error(request, "Usuário ou senha inválidos.")
    return render(request, 'accounts/login.html')

@login_required
def logout_view(request):
    logout(request)
    messages.success(request, "Logout realizado com sucesso!")
    return redirect('accounts:login')

def register_view(request):
    if request.user.is_authenticated:
        messages.info(request, "Você já está logado.")
        return redirect('notes:list_notes')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Usuário registrado com sucesso! Faça login.")
            return redirect('accounts:login')
        else:
            messages.error(request, "Verifique os erros no formulário.")
    else:
        form = RegisterForm()
    return render(request, 'accounts/register.html', {'form': form})

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        user = User.objects.filter(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = request.build_absolute_uri(reverse('accounts:reset_password', args=[token]))
            subject = "Recuperação de Senha - VORP"
            body = f"Olá, clique no link para redefinir sua senha:\n{reset_url}"
            mail = EmailMessage(subject, body, to=[email])
            mail.send()
            messages.info(request, "Verifique seu e-mail para redefinir a senha.")
            return redirect('accounts:login')
        else:
            messages.error(request, "E-mail não encontrado.")
            return redirect('accounts:forgot_password')
    return render(request, 'accounts/forgot_password.html')

def reset_password(request, token):
    email = verify_reset_token(token)
    if not email:
        messages.error(request, "Token inválido ou expirado.")
        return redirect('accounts:forgot_password')

    user = User.objects.filter(email=email).first()
    if not user:
        messages.error(request, "Usuário não encontrado.")
        return redirect('accounts:forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        if not new_password or new_password != confirm_password:
            messages.error(request, "As senhas não coincidem ou estão vazias.")
            return redirect('accounts:reset_password', token=token)
        user.set_password(new_password)
        user.save()
        messages.success(request, "Senha atualizada com sucesso!")
        return redirect('accounts:login')

    return render(request, 'accounts/reset_password.html', {'token': token})

@login_required
def profile_view(request, username):
    user_obj = get_object_or_404(User, username=username)
    if request.user == user_obj:
        notes = user_obj.notes.order_by('-updated_at')
    else:
        notes = user_obj.notes.filter(is_public=True).order_by('-updated_at')

    return render(request, 'accounts/profile.html', {
        'user_obj': user_obj,
        'notes_count': notes.count(),
        'recent_notes': notes[:3],
    })

@login_required
def profile_edit(request):
    if request.method == 'POST':
        form = ProfileEditForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            current_password = form.cleaned_data.get('current_password')
            new_password = form.cleaned_data.get('new_password')
            confirm_password = form.cleaned_data.get('confirm_password')

            if new_password or confirm_password:
                if not request.user.check_password(current_password):
                    messages.error(request, "Senha atual incorreta.")
                    return redirect('accounts:profile_edit')
                if new_password != confirm_password:
                    messages.error(request, "Nova senha e confirmação não coincidem.")
                    return redirect('accounts:profile_edit')
                request.user.set_password(new_password)

            form.save()
            messages.success(request, "Perfil atualizado com sucesso!")
            if new_password:
                user = authenticate(username=request.user.username, password=new_password)
                if user:
                    login(request, user)
            return redirect('accounts:profile', username=request.user.username)
        else:
            messages.error(request, "Verifique os erros no formulário.")
    else:
        form = ProfileEditForm(instance=request.user)

    return render(request, 'accounts/profile_edit.html', {'form': form})
