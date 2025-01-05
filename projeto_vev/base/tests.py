from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse

class UserTests(TestCase):
    def setUp(self):
        # Criação de um usuário para testes de login e logout
        self.user = User.objects.create_user(username="testuser", password="password123", email="testuser@example.com")
        self.login_url = reverse('login')  # Nome da URL para login
        self.register_url = reverse('register')  # Nome da URL para registro
        self.logout_url = reverse('logout')  # Nome da URL para logout

    def test_register_user_success(self):
        """Testa se o registro de um novo usuário funciona corretamente."""
        response = self.client.post(self.register_url, {
            'username': 'newuser',
            'password': 'newpassword123',
            'email': 'newuser@example.com',
        })
        self.assertEqual(response.status_code, 302)  # Redirecionamento esperado
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_register_user_existing_username(self):
        """Testa se o sistema detecta um nome de usuário já existente."""
        response = self.client.post(self.register_url, {
            'username': 'testuser',  # Nome de usuário já existente
            'password': 'password123',
            'email': 'duplicate@example.com',
        })
        self.assertEqual(response.status_code, 200)  # Não deve redirecionar
        self.assertContains(response, "Usuário já existe")  # Verifica a mensagem de erro

    def test_login_user_success(self):
        """Testa se um usuário pode fazer login com credenciais válidas."""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'password123',
        })
        self.assertEqual(response.status_code, 302)  # Redirecionamento esperado após login
        self.assertRedirects(response, reverse('home'))  # Redireciona para a página inicial

    def test_login_user_invalid_credentials(self):
        """Testa se o login falha com credenciais inválidas."""
        response = self.client.post(self.login_url, {
            'username': 'wronguser',
            'password': 'wrongpassword',
        })
        self.assertEqual(response.status_code, 200)  # Não deve redirecionar
        self.assertContains(response, "Credenciais inválidas")  # Verifica a mensagem de erro

    def test_logout_user(self):
        """Testa se o logout funciona corretamente."""
        self.client.login(username='testuser', password='password123')  # Faz login antes do teste
        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)  # Redirecionamento esperado após logout
        self.assertRedirects(response, self.login_url)  # Redireciona para a página de login
