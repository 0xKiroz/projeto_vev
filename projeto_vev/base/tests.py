from django.test import TestCase
from django.contrib.auth.models import User, Permission
from django.urls import reverse
from django.contrib.contenttypes.models import ContentType


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

    def test_user_permissions(self):
        """Testa se usuários sem permissão não conseguem acessar áreas restritas."""
        # Usuário sem permissão tenta acessar
        response = self.client.get(reverse('restricted_area'))
        self.assertEqual(response.status_code, 403)  # Esperado: acesso negado

    def test_user_permissions_granted(self):
        """Testa se usuários com permissão podem acessar áreas restritas."""
        permission = Permission.objects.get(codename='can_access_restricted_area')
        self.user.user_permissions.add(permission)
        self.user.save()
        self.client.login(username='testuser', password='password123')
        self.assertTrue(self.user.has_perm('auth.can_access_restricted_area'))  # Verificação adicional
        
        response = self.client.get(reverse('restricted_area'))
        self.assertEqual(response.status_code, 200)  # Esperado: acesso permitido

    def test_register_user_invalid_username_format(self):
        """Testa se o sistema rejeita nomes de usuários com caracteres especiais."""
        response = self.client.post(self.register_url, {
            'username': 'invalid!user',  # Nome com caracteres especiais
            'password': 'password123',
            'email': 'invaliduser@example.com',
        })
        self.assertEqual(response.status_code, 200)  # Não deve redirecionar
        self.assertContains(response, "Informe um nome de usuário válido. Este valor pode conter apenas letras, números e os seguintes caracteres @/./+/-/_.")  # Mensagem correta
        self.assertFalse(User.objects.filter(username='invalid!user').exists())

    def test_register_user_short_password(self):
        """Testa se o sistema rejeita senhas com menos de 6 caracteres."""
        response = self.client.post(self.register_url, {
            'username': 'shortpassuser',
            'password': '123',  # Senha muito curta
            'email': 'shortpass@example.com',
        })
        self.assertEqual(response.status_code, 200)  # Formulário deve retornar sem redirecionar
        self.assertContains(response, "A senha deve ter no mínimo 6 caracteres.")
        self.assertFalse(User.objects.filter(username='shortpassuser').exists())

    def test_register_user_long_password(self):
        """Testa se o sistema rejeita senhas com mais de 20 caracteres."""
        response = self.client.post(self.register_url, {
            'username': 'longpassuser',
            'password': 'a' * 21,  # Senha muito longa
            'email': 'longpass@example.com',
        })
        self.assertEqual(response.status_code, 200)  # Formulário deve retornar sem redirecionar
        self.assertContains(response, "A senha deve ter no máximo 20 caracteres.")
        self.assertFalse(User.objects.filter(username='longpassuser').exists())

    def test_register_user_empty_username(self):
        """Testa se o sistema rejeita um nome de usuário vazio."""
        response = self.client.post(self.register_url, {
            'username': '',
            'password': 'password123',
            'email': 'emptyuser@example.com',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Este campo é obrigatório.")
        self.assertFalse(User.objects.filter(username='').exists())

    def test_register_user_invalid_email_format(self):
        """Testa se o sistema rejeita um formato de e-mail inválido."""
        response = self.client.post(self.register_url, {
            'username': 'invalidemailuser',
            'password': 'password123',
            'email': 'invalidemail@',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Informe um endereço de email válido.")
        self.assertFalse(User.objects.filter(username='invalidemailuser').exists())

    def test_register_user_short_username(self):
        """Testa se o sistema rejeita um nome de usuário com menos de 6 caracteres."""
        response = self.client.post(self.register_url, {
            'username': 'short',
            'password': 'password123',
            'email': 'short@example.com',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Certifique-se de que o valor tenha no mínimo 6 caracteres (ele possui 5).")
        self.assertFalse(User.objects.filter(username='short').exists())
   
    def test_register_user_long_username(self):
        """Testa se o sistema rejeita um nome de usuário com mais de 150 caracteres."""
        long_username = 'a' * 151
        response = self.client.post(self.register_url, {
            'username': long_username,
            'password': 'password123',
            'email': 'long@example.com',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Certifique-se de que o valor tenha no máximo 150 caracteres (ele possui 151).")
        self.assertFalse(User.objects.filter(username=long_username).exists())

    def test_register_user_valid_username_length(self):
        """Testa se o sistema aceita um nome de usuário com exatamente 6 ou 150 caracteres."""
        # Teste para 6 caracteres
        response = self.client.post(self.register_url, {
            'username': 'abcdef',
            'password': 'password123',
            'email': 'valid6@example.com',
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username='abcdef').exists())

        # Teste para 150 caracteres
        valid_username_150 = 'a' * 150
        response = self.client.post(self.register_url, {
            'username': valid_username_150,
            'password': 'password123',
            'email': 'valid150@example.com',
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username=valid_username_150).exists())

class PermissionTests(TestCase):
    def setUp(self):
        # Criação de um usuário comum para testes
        self.common_user = User.objects.create_user(username="commonuser", password="commonpass123", email="commonuser@example.com")
        
        # Criação de um usuário com permissão 'can_access_restricted_area'
        self.admin_user = User.objects.create_user(username="adminuser", password="adminpass123", email="adminuser@example.com")
        
        # Criação da permissão 'can_access_restricted_area' para testes
        content_type = ContentType.objects.get_for_model(User)  # Ou qualquer outro modelo que faça sentido
        admin_permission, created = Permission.objects.get_or_create(codename='can_access_restricted_area', name='Can access restricted area', content_type=content_type)
        
        self.admin_user.user_permissions.add(admin_permission)
        self.admin_user.save()

        self.login_url = reverse('login')
        self.restricted_area_url = reverse('restricted_area')

    def test_access_restricted_area_with_admin_permission(self):
        """Testa se um usuário com permissão 'can_access_restricted_area' pode acessar a área restrita."""
        self.client.login(username='adminuser', password='adminpass123')
        response = self.client.get(self.restricted_area_url)
        self.assertEqual(response.status_code, 200)  # Acesso permitido

    def test_access_restricted_area_without_admin_permission(self):
        """Testa se um usuário sem permissão 'can_access_restricted_area' não pode acessar a área restrita."""
        self.client.login(username='commonuser', password='commonpass123')
        response = self.client.get(self.restricted_area_url)
        self.assertEqual(response.status_code, 403)  # Acesso negado

    def test_access_restricted_area_newly_granted_admin_permission(self):
        """Testa com um usuário que recentemente obteve acesso 'can_access_restricted_area'."""
        # Criação de um novo usuário sem permissão
        new_user = User.objects.create_user(username="newadminuser", password="newadminpass123", email="newadminuser@example.com")
        
        # Login com o novo usuário
        self.client.login(username='newadminuser', password='newadminpass123')
        
        # Primeiro, tenta acessar a área restrita sem permissão
        response = self.client.get(self.restricted_area_url)
        self.assertEqual(response.status_code, 403)  # Acesso negado
        
        # Adiciona a permissão 'can_access_restricted_area' ao novo usuário
        new_user.user_permissions.add(Permission.objects.get(codename='can_access_restricted_area'))
        new_user.save()
        
        # Tenta acessar a área restrita novamente
        response = self.client.get(self.restricted_area_url)
        self.assertEqual(response.status_code, 200)  # Acesso permitido após a concessão da permissão

    def test_access_restricted_area_with_session_about_to_expire(self):
        """Testa com um usuário no limite do acesso permitido (exemplo: sessões quase expiradas)."""
        self.client.login(username='adminuser', password='adminpass123')
        
        # Simulação de um acesso à área restrita
        response = self.client.get(self.restricted_area_url)
        self.assertEqual(response.status_code, 200)  # Acesso permitido

class PasswordChangeTests(TestCase):
    def setUp(self):
        # Criação de um usuário para testes
        self.user = User.objects.create_user(username="testuser", password="oldpassword123", email="testuser@example.com")
        self.change_password_url = reverse('change_password')

    def test_change_password_with_valid_credentials(self):
        """Testa se a senha é alterada com sucesso quando a senha atual e a nova senha são válidas."""
        self.client.login(username='testuser', password='oldpassword123')
        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': 'newpassword1A',
            'new_password2': 'newpassword1A',
        })
        self.assertEqual(response.status_code, 302)  # Redirecionamento esperado após a mudança de senha
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword1A'))

    def test_change_password_with_invalid_current_password(self):
        """Testa se a mudança de senha falha com uma senha atual incorreta."""
        self.client.login(username='testuser', password='oldpassword123')
        response = self.client.post(self.change_password_url, {
            'old_password': 'wrongpassword123',
            'new_password1': 'newpassword1A',
            'new_password2': 'newpassword1A',
        })
        self.assertEqual(response.status_code, 200)  # Não deve redirecionar
        self.assertContains(response, "Senha atual incorreta")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('oldpassword123'))  # A senha deve permanecer a mesma

    def test_change_password_with_invalid_new_password_format(self):
        """Testa se a mudança de senha falha quando a nova senha não contém letras e números."""
        self.client.login(username='testuser', password='oldpassword123')
        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': 'onlyletters',  # Apenas letras
            'new_password2': 'onlyletters',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A nova senha deve conter pelo menos uma letra e um número")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('oldpassword123'))  # A senha deve permanecer a mesma

        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': '1234567890',  # Apenas números
            'new_password2': '1234567890',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A nova senha deve conter pelo menos uma letra e um número")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('oldpassword123'))  # A senha deve permanecer a mesma

    def test_change_password_with_valid_length_limits(self):
        """Testa a mudança de senha com a senha mais curta permitida (8 caracteres) e a mais longa (20 caracteres)."""
        self.client.login(username='testuser', password='oldpassword123')
        # Teste para 8 caracteres
        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': 'short8A1',
            'new_password2': 'short8A1',
        })
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('short8A1'))

        # Teste para 20 caracteres
        self.user.set_password('oldpassword123')
        self.user.save()
        self.client.login(username='testuser', password='oldpassword123')
        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': 'longpassword12345678',
            'new_password2': 'longpassword12345678',
        })
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('longpassword12345678'))

    def test_change_password_with_invalid_length_limits(self):
        """Testa a mudança de senha com senhas inválidas de 7 caracteres e 21 caracteres."""
        self.client.login(username='testuser', password='oldpassword123')
        # Teste para 7 caracteres (inválido)
        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': 'short7A',
            'new_password2': 'short7A',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A nova senha deve ter pelo menos 8 caracteres")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('oldpassword123'))  # A senha deve permanecer a mesma

        # Teste para 21 caracteres (inválido)
        response = self.client.post(self.change_password_url, {
            'old_password': 'oldpassword123',
            'new_password1': 'longpassword12345678901',
            'new_password2': 'longpassword12345678901',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A nova senha deve ter pelo menos 8 caracteres e no máximo 20 caracteres.")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('oldpassword123'))  # A senha deve permanecer inalterada.

class UserActivationTests(TestCase):
    def setUp(self):
        # Criando usuários para os testes
        self.active_user = User.objects.create_user(
            username="active_user",
            password="validpassword",
            is_active=True
        )
        self.inactive_user = User.objects.create_user(
            username="inactive_user",
            password="validpassword",
            is_active=False
        )

    def test_login_with_active_user_and_valid_credentials(self):
        """Usuário ativo com credenciais válidas deve conseguir fazer login."""
        response = self.client.post(
            reverse("login"), 
            {"username": "active_user", "password": "validpassword"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Bem-vindo")  # Substitua pelo conteúdo esperado após login bem-sucedido.

    def test_login_with_inactive_user_and_valid_credentials(self):
        """Usuário inativo com credenciais válidas não deve conseguir fazer login."""
        response = self.client.post(
            reverse("login"), 
            {"username": "inactive_user", "password": "validpassword"}
        )
        self.assertEqual(response.status_code, 200)  # O Django geralmente retorna o mesmo código em caso de erro.
        self.assertContains(response, "Sua conta está desativada.")  # Mensagem esperada.

    def test_login_with_invalid_credentials(self):
        """Nenhum usuário deve conseguir fazer login com credenciais inválidas."""
        response = self.client.post(
            reverse("login"), 
            {"username": "active_user", "password": "wrongpassword"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Credenciais inválidas.")  # Mensagem esperada.

    def test_transition_from_active_to_inactive(self):
        """Teste a transição de is_active de True para False."""
        self.active_user.is_active = False
        self.active_user.save()
        response = self.client.post(
            reverse("login"), 
            {"username": "active_user", "password": "validpassword"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sua conta está desativada.")  # Mensagem esperada.

    def test_system_during_manual_deactivation(self):
        """Teste o sistema no momento exato da inativação."""
        self.active_user.is_active = True
        self.active_user.save()
        # Simulando uma tentativa de login enquanto o usuário é desativado
        self.active_user.is_active = False
        self.active_user.save()

        response = self.client.post(
            reverse("login"), 
            {"username": "active_user", "password": "validpassword"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sua conta está desativada.")  # Mensagem esperada.

