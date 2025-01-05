from django.urls import path
from . import views
from django.http import HttpResponse

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('home/', lambda request: HttpResponse("Página inicial"), name='home'),  # Adicione esta linha
]