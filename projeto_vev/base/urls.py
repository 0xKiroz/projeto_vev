from django.urls import path
from . import views
from django.http import HttpResponse
from django.contrib.auth.views import PasswordChangeView
from .views import custom_password_change_done

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('restricted/', views.restricted_view, name='restricted_area'),
    path('home/', lambda request: HttpResponse("Página inicial"), name='home'),
    path('change-password/', PasswordChangeView.as_view(success_url='/change-password/done/'), name='change_password'),
    path('change-password/done/', custom_password_change_done, name='password_change_done'),
]