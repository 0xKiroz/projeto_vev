from django import forms
from django.contrib.auth.models import User

class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,
        min_length=6,
        max_length=20,
        label="Senha",
        error_messages={
            'min_length': "A senha deve ter no mínimo 6 caracteres.",
            'max_length': "A senha deve ter no máximo 20 caracteres.",
        },
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_username(self):
        username = self.cleaned_data.get('username')
        # Verifica se o usuário já existe
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Usuário já existe.")
        # Verifica o comprimento do nome de usuário
        if len(username) < 6:
            raise forms.ValidationError("Certifique-se de que o valor tenha no mínimo 6 caracteres (ele possui {}).".format(len(username)))
        if len(username) > 150:
            raise forms.ValidationError("Certifique-se de que o valor tenha no máximo 150 caracteres (ele possui {}).".format(len(username)))
        return username