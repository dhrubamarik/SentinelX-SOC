"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from home import views
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    #AUTH
    path('login/',views.loginuser,name='login'),
    path("register/",views.register,name="register"),
    path("logout/",views.logoutuser,name="logout"),
    path("welcome/",views.welcome,name="welcome"),
    # SOC Routes
    path('soc/login/', views.soc_login, name='soc_login'),
    path('soc/dashboard/', views.soc_dashboard, name='soc_dashboard'),
    path('soc/map/', views.threat_map_page, name='threat_map_page'),
    path('soc/map-data/', views.threat_map_data, name='threat_map_data'),
    path('soc/analytics/', views.soc_analytics_page, name='soc_analytics_page'),
    path('soc/analytics-data/', views.soc_analytics_data, name='soc_analytics_data'),
    path('soc/users/', views.user_directory_view, name='user_directory_view'),
    path('soc/users/<str:username>/', views.user_detail_view, name='user_detail_view'),
    path('api/chat/', views.chat_with_ai, name='chat_with_ai'),
    path('soc/risk-detail/<int:event_id>/', views.risk_detail_view, name='risk_detail_view'),
    path('soc/users/<str:username>/report/', views.generate_pdf_report, name='generate_pdf_report'),
    path('soc/ai-chat/', views.ai_chat_view, name='ai_chat_view'),



]
