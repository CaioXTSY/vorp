from django import forms
from django.contrib.auth.forms import UserCreationForm
from db.accounts_models import User

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

class ProfileEditForm(forms.ModelForm):
    current_password = forms.CharField(required=False, widget=forms.PasswordInput)
    new_password = forms.CharField(required=False, widget=forms.PasswordInput)
    confirm_password = forms.CharField(required=False, widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'bio', 'gender', 'profile_photo']

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if new_password or confirm_password:
            if new_password != confirm_password:
                self.add_error('confirm_password', "As senhas não coincidem.")
        return cleaned_data
