from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('accounts/', include('django.contrib.auth.urls')),
    path('api/system/', views.host_fingerprint, name='system_info'),
    path('api/arp/', views.arp_discover, name='arp_discover'),
    path('api/scan/', views.scan_target, name='scan_target'),
    path('api/history/', views.recent_scan_history, name='recent_scan_history'),
    path('api/chat/', views.ai_chat, name='ai_chat'),
    path('api/download-script/', views.download_host_script, name='download_script'),
    path('api/kill-ports/', views.kill_ports_script, name='kill_ports'),
]